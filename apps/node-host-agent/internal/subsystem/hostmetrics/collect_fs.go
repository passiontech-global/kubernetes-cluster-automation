// collect_fs.go — filesystem inode stats + the hung-mount statfs
// probe (H3/H7) and the state-filesystem-readonly latch (W5.3).
// Split out of hostmetrics.go.
package hostmetrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

const (
	// defaultFSProbeTimeout bounds one statfs probe — a hung mount
	// blocks the syscall in uninterruptible sleep, so the deadline
	// is the only "still alive" signal (H7).
	defaultFSProbeTimeout = 2 * time.Second
)

// defaultFilesystemTargets are the mounts statfs'd per scrape —
// the inode + hung-mount canaries for the dirs that hurt most when
// the fs underneath wedges or runs out of inodes (host /etc, the
// k0s data dir, the OpenEBS local-path provisioner root).
var defaultFilesystemTargets = []string{
	"/host/etc", "/host/var/lib/k0s", "/var/openebs/local",
}

// --- H3+H7: filesystem inode stats + hung-mount probe ---

// fsResult is one statfs probe outcome.
type fsResult struct {
	st  unix.Statfs_t
	err error
}

// fsProbeState is the hung-mount probe domain — one slice of what
// used to be the Collector's shared mu-guarded fields. inflight
// holds the start time of each mount's in-kernel statfs probe — a
// hung syscall can't be cancelled, so a scrape that finds an
// in-flight probe reports stalled only once the deadline has
// elapsed, WITHOUT spawning another (bounds stuck goroutines at one
// per mount). stalledLogged edge-triggers the hung-mount Warn: the
// stall logs once per mount per episode instead of once per scrape
// for the whole outage. The mutex is private — the fs domain
// shares no state with the other collect domains.
type fsProbeState struct {
	mu            sync.Mutex
	inflight      map[string]time.Time
	stalledLogged map[string]bool
}

// probeStart registers a fresh in-flight probe for mount stamped at
// now and reports true — or, when a probe is already in flight,
// returns its start and false so the caller serves the running
// probe's deadline verdict instead of piling up a second statfs
// goroutine.
func (s *fsProbeState) probeStart(mount string, now time.Time) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if start, inflight := s.inflight[mount]; inflight {
		return start, false
	}
	s.inflight[mount] = now
	return now, true
}

// probeDone clears mount's in-flight stamp — the statfs goroutine's
// completion path (a timed-out scrape still lets it finish).
func (s *fsProbeState) probeDone(mount string) {
	s.mu.Lock()
	delete(s.inflight, mount)
	s.mu.Unlock()
}

// noteStall edge-updates the stall-log bookkeeping — set while
// stalled, cleared on recovery — and returns the previous flag so
// the caller logs only on transitions.
func (s *fsProbeState) noteStall(mount string, stalled bool) (wasLogged bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wasLogged = s.stalledLogged[mount]
	if stalled {
		s.stalledLogged[mount] = true
	} else {
		delete(s.stalledLogged, mount)
	}
	return wasLogged
}

// probeFS statfs's one mount under the fsProbeTimeout deadline. A
// hung mount blocks the syscall in uninterruptible sleep — it can't
// be cancelled — so the call runs on a goroutine and the scrape
// moves on after the deadline. stalled=true means the deadline
// passed with the syscall still stuck (or an earlier probe of the
// same mount has been in the kernel past the deadline — at most one
// goroutine per mount is allowed to pile up). A scrape that lands
// while a still-fresh probe is in flight reports stalled=0, not 1:
// "probe running" is not "probe hung", and two overlapping scrapers
// must not manufacture a hung-mount alert. ok=true only when statfs
// completed without error.
func (c *Collector) probeFS(mount string) (st unix.Statfs_t, stalled, ok bool) {
	start, fresh := c.fs.probeStart(mount, c.cfg.Clock.Now())
	if !fresh {
		return unix.Statfs_t{},
			c.cfg.Clock.Now().Sub(start) >= c.cfg.fsProbeTimeout, false
	}

	res := make(chan fsResult, 1)
	go func() {
		var r fsResult
		r.err = c.cfg.statfsFn(mount, &r.st)
		c.fs.probeDone(mount)
		res <- r // buffered — never blocks after a timed-out scrape
	}()

	timer := time.NewTimer(c.cfg.fsProbeTimeout)
	defer timer.Stop()
	select {
	case r := <-res:
		if r.err != nil {
			return unix.Statfs_t{}, false, false
		}
		return r.st, false, true
	case <-timer.C:
		return unix.Statfs_t{}, true, false
	}
}

var (
	descFSInodesTotal = prometheus.NewDesc(
		"node_host_agent_filesystem_inodes_total",
		"Total inodes on the probed mount (statfs Files).",
		[]string{"node", "mount"}, nil)
	descFSInodesFree = prometheus.NewDesc(
		"node_host_agent_filesystem_inodes_free",
		"Free inodes on the probed mount (statfs Ffree).",
		[]string{"node", "mount"}, nil)
	descFSInodesRatio = prometheus.NewDesc(
		"node_host_agent_filesystem_inodes_used_ratio",
		"Used-inode share of the probed mount ((Files-Ffree)/Files; emitted only when statfs succeeds).",
		[]string{"node", "mount"}, nil)
	descFSProbeStalled = prometheus.NewDesc(
		"node_host_agent_filesystem_probe_stalled",
		"statfs probe of this mount exceeded the deadline (1 = hung mount; emitted for every configured target).",
		[]string{"node", "mount"}, nil)
	descFSReadonly = prometheus.NewDesc(
		"node_host_agent_filesystem_readonly",
		"Probed mount reports ST_RDONLY via statfs (1 = filesystem remounted read-only; emitted only when statfs succeeds).",
		[]string{"node", "mount"}, nil)
)

// collectFilesystem emits per-mount inode gauges plus the
// probe_stalled signal for EVERY configured target — a 0 means the
// probe answered in time (even with an error), so "reachable but
// boring" stays distinguishable from "never probed". Inode gauges
// emit only on a successful statfs — a failed/hung probe emits no
// fake numbers. A successful probe also exports the ST_RDONLY flag
// (W5.3): one read-only mount latches state-filesystem-readonly for
// nodereporter's FilesystemReadOnly condition.
func (c *Collector) collectFilesystem(ch chan<- prometheus.Metric) {
	anyRO := false
	probed := false // at least one statfs answered — the latch's evidence base
	for _, mount := range c.cfg.FilesystemTargets {
		st, stalled, ok := c.probeFS(mount)
		v := 0.0
		if stalled {
			v = 1
		}
		// Edge-triggered log: a stall warns once per mount per
		// episode (a hung mount stays stalled for the whole outage),
		// and recovery logs once — per-scrape repeats would drown
		// the log without adding information.
		wasLogged := c.fs.noteStall(mount, stalled)
		switch {
		case stalled && !wasLogged:
			logger().Warn("hostmetrics: statfs probe exceeded deadline — "+
				"possible hung mount",
				"mount", mount,
				"timeout", c.cfg.fsProbeTimeout)
		case !stalled && wasLogged:
			logger().Info("hostmetrics: statfs probe answering again — "+
				"mount recovered",
				"mount", mount)
		}
		ch <- prometheus.MustNewConstMetric(descFSProbeStalled,
			prometheus.GaugeValue, v, c.cfg.NodeName, mount)
		if !ok {
			continue
		}
		probed = true
		ro := 0.0
		if st.Flags&unix.ST_RDONLY != 0 {
			ro = 1
			anyRO = true
		}
		ch <- prometheus.MustNewConstMetric(descFSReadonly,
			prometheus.GaugeValue, ro, c.cfg.NodeName, mount)
		ch <- prometheus.MustNewConstMetric(descFSInodesTotal,
			prometheus.GaugeValue, float64(st.Files), c.cfg.NodeName, mount)
		ch <- prometheus.MustNewConstMetric(descFSInodesFree,
			prometheus.GaugeValue, float64(st.Ffree), c.cfg.NodeName, mount)
		if st.Files > 0 && st.Ffree <= st.Files {
			// Ffree > Files wraps uint64 — pseudo/network filesystems
			// can report free inodes above the total.
			used := float64(st.Files-st.Ffree) / float64(st.Files)
			ch <- prometheus.MustNewConstMetric(descFSInodesRatio,
				prometheus.GaugeValue, used, c.cfg.NodeName, mount)
		}
	}
	c.updateFSReadonlyLatch(anyRO, probed)
}

// updateFSReadonlyLatch drives state-filesystem-readonly (W5.3):
// set when ANY successfully probed mount carries ST_RDONLY, cleared
// once every probed mount is rw again. probed=false (every statfs
// failed or stalled) leaves the latch untouched — inconclusive
// evidence must neither set nor clear it, the same rule the
// overload latch follows on an unparseable PSI file. Enter/Exit
// carry the file contract AND the STATE-ENTER/STATE-EXIT log lines
// nodereporter's FilesystemReadOnly event rule consumes.
func (c *Collector) updateFSReadonlyLatch(anyRO, probed bool) {
	switch {
	case anyRO:
		c.state.Enter(latchdefs.LatchFilesystemReadonly,
			"a probed mount reports ST_RDONLY")
	case probed:
		c.state.Exit(latchdefs.LatchFilesystemReadonly, nil)
	}
}

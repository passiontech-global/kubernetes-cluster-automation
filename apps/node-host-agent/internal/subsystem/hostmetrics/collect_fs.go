// collect_fs.go — filesystem inode stats + the hung-mount statfs
// probe (H3/H7) and the state-filesystem-readonly latch (filesystem-readonly).
// Split out of hostmetrics.go.
package hostmetrics

import (
	"fmt"
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

// fsFlight is one in-flight statfs probe shared by every concurrent
// probeFS caller for the same mount (singleflight): the leader's
// statfs goroutine publishes its result into res then closes done —
// close broadcasts to EVERY waiter, where a single-element channel
// would hand the result to exactly one sharer and strand the rest
// on the deadline (a fabricated stalled=true). Each waiter races
// done against the FLIGHT's deadline (start + fsProbeTimeout), not
// a fresh per-caller timer. Sharing the verdict is what keeps a
// scrape landing mid-probe from dropping the mount's
// inode/bytes metrics (ok=false used to mean "someone else is
// probing") and — worse — from feeding updateFSReadonlyLatch a
// probed=true/anyRO=false pass that cleared
// state-filesystem-readonly while the read-only mount's own probe
// was still in flight.
type fsFlight struct {
	start time.Time
	done  chan struct{}
	res   fsResult
}

// fsProbeState is the hung-mount probe domain — one slice of what
// used to be the Collector's shared mu-guarded fields. inflight
// holds each mount's live fsFlight — a hung syscall can't be
// cancelled, so a scrape that finds an in-flight probe reports
// stalled only once the flight's deadline has elapsed, WITHOUT
// spawning another (bounds stuck goroutines at one per mount).
// stalledLogged edge-triggers the hung-mount Warn: the stall logs
// once per mount per episode instead of once per scrape for the
// whole outage. The mutex is private — the fs domain shares no
// state with the other collect domains.
type fsProbeState struct {
	mu            sync.Mutex
	inflight      map[string]*fsFlight
	stalledLogged map[string]bool
}

// probeStart returns mount's live flight — or, when none is in
// flight, registers a fresh one stamped at now and reports
// leader=true so the caller spawns the statfs goroutine.
func (s *fsProbeState) probeStart(mount string, now time.Time) (*fsFlight, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, inflight := s.inflight[mount]; inflight {
		return f, false
	}
	f := &fsFlight{start: now, done: make(chan struct{})}
	s.inflight[mount] = f
	return f, true
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
// moves on after the deadline. stalled=true means the flight's
// deadline passed with the syscall still stuck (or an earlier probe
// of the same mount has been in the kernel past the deadline — at
// most one goroutine per mount is allowed to pile up). Concurrent
// callers share the in-flight flight's result: "probe running" is
// not "probe hung", and two overlapping scrapers must not
// manufacture a hung-mount alert — nor a fabricated ok=false that
// drops the mount's metrics or clears its read-only latch. ok=true
// only when statfs completed without error.
func (c *Collector) probeFS(mount string) (st unix.Statfs_t, stalled, ok bool) {
	flight, leader := c.fs.probeStart(mount, c.cfg.Clock.Now())
	if leader {
		go func() {
			var r fsResult
			r.err = c.cfg.statfsFn(mount, &r.st)
			c.fs.probeDone(mount)
			flight.res = r
			close(flight.done) // wakes every sharer, not just one
		}()
	}

	// A result already published wins even past the deadline — the
	// flight answered, it just landed late relative to a waiter
	// that arrived near the wire.
	select {
	case <-flight.done:
		if flight.res.err != nil {
			return unix.Statfs_t{}, false, false
		}
		return flight.res.st, false, true
	default:
	}

	// Wait out the FLIGHT's remaining deadline — every sharer gets
	// the same stalled verdict the leader would have produced.
	wait := flight.start.Add(c.cfg.fsProbeTimeout).
		Sub(c.cfg.Clock.Now())
	if wait <= 0 {
		return unix.Statfs_t{}, true, false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-flight.done:
		if flight.res.err != nil {
			return unix.Statfs_t{}, false, false
		}
		return flight.res.st, false, true
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

// fsProbe is one mount's scrape-scoped statfs answer — the verdict
// Collect computes once per mount and both fs domains read.
type fsProbe struct {
	st      unix.Statfs_t
	stalled bool
	ok      bool
}

// scrapeFSProbes probes every FilesystemTargets + FSBytesTargets
// mount ONCE per scrape (config order, deduped) — the k0s data dir
// and the OpenEBS local root sit in BOTH target lists, and two
// statfs calls per mount per scrape doubled the hung-mount window
// for no extra information. The answers ride scrapeCtx (per-scrape,
// like psi/cert) instead of a Collector field that would race under
// concurrent Collect. The deadline/singleflight machinery stays in
// probeFS — the latch ticker (refreshLatches) still probes on its
// own cadence.
func (c *Collector) scrapeFSProbes() map[string]fsProbe {
	mounts := make([]string, 0, len(c.cfg.FilesystemTargets)+len(c.cfg.FSBytesTargets))
	seen := make(map[string]bool, cap(mounts))
	for _, list := range [][]string{c.cfg.FilesystemTargets, c.cfg.FSBytesTargets} {
		for _, m := range list {
			if !seen[m] {
				seen[m] = true
				mounts = append(mounts, m)
			}
		}
	}
	out := make(map[string]fsProbe, len(mounts))
	for _, m := range mounts {
		st, stalled, ok := c.probeFS(m)
		out[m] = fsProbe{st: st, stalled: stalled, ok: ok}
	}
	return out
}

// collectFilesystem emits per-mount inode gauges plus the
// probe_stalled signal for EVERY configured target — a 0 means the
// probe answered in time (even with an error), so "reachable but
// boring" stays distinguishable from "never probed". Inode gauges
// emit only on a successful statfs — a failed/hung probe emits no
// fake numbers. A successful probe also exports the ST_RDONLY flag
// (filesystem-readonly): the state-filesystem-readonly latch itself
// is driven by refreshLatches on the ticker, never by this scrape.
func (c *Collector) collectFilesystem(ch chan<- prometheus.Metric, sc scrapeCtx) {
	for _, mount := range c.cfg.FilesystemTargets {
		pr := sc.fs[mount]
		st, stalled, ok := pr.st, pr.stalled, pr.ok
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
		ro := 0.0
		if st.Flags&unix.ST_RDONLY != 0 {
			ro = 1
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
	// The filesystem-readonly + inode-pressure latch transitions
	// are NOT made here — Collect is read-only; refreshLatches
	// owns every state-* write on the 30s ticker.
}

// updateFSReadonlyLatch drives state-filesystem-readonly (filesystem-readonly):
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

// --- inode-pressure: filesystem inode-pressure hysteresis ---

// fsInodeEvidence is one pass's inode-pressure verdict over the
// configured filesystem targets — the input both the scrape path
// (collectFilesystem) and the latch ticker (refreshLatches) hand to
// updateInodePressureLatch. probed counts mounts whose statfs
// answered; parsed the subset whose verdict is decidable — a
// computable ratio, or Files==0 (no inode table: never under
// pressure, ratio 0). Ffree > Files wraps uint64 on pseudo/network
// filesystems — that is inconclusive evidence, not a healthy ratio;
// worstMount/worstRatio name the fullest mount for the STATE-ENTER
// detail.
type fsInodeEvidence struct {
	probed     int
	parsed     int
	worstMount string
	worstRatio float64
}

// noteInodeEvidence folds one successful statfs answer into the
// pass's verdict.
func (c *Collector) noteInodeEvidence(e *fsInodeEvidence, mount string, st unix.Statfs_t) {
	e.probed++
	if st.Files == 0 {
		// btrfs (dynamic inodes) and pseudo-filesystems report no
		// inode table at all: such a mount can never be under inode
		// pressure, so it counts as PARSED evidence with ratio 0 —
		// treating it as inconclusive wedged a once-entered latch
		// open forever (parsed never reached probed, the heartbeat
		// kept refreshing the condition and the sweeper/gates never
		// saw a clearable pass). Check this BEFORE the wrap guard:
		// Ffree can exceed Files == 0.
		e.parsed++
		return
	}
	if st.Ffree > st.Files {
		// Ffree > Files wraps uint64 — inconclusive evidence,
		// not a healthy ratio.
		return
	}
	e.parsed++
	used := float64(st.Files-st.Ffree) / float64(st.Files)
	if e.worstMount == "" || used > e.worstRatio {
		e.worstMount, e.worstRatio = mount, used
	}
}

// inodePressureEnter reports whether any parsed mount crossed the
// enter threshold.
func (e fsInodeEvidence) inodePressureEnter() bool {
	return e.parsed > 0 && e.worstRatio >= inodePressureEnterRatio
}

// inodePressureClear reports whether the evidence justifies clearing:
// every probed mount answered AND every parsed ratio sits at or below
// the clear threshold. Between the thresholds the verdict is neither
// — the latch holds (hysteresis), and an inconclusive pass (a statfs
// failure or an unparseable ratio) never moves it either way, the
// same rule updateFSReadonlyLatch follows.
func (e fsInodeEvidence) inodePressureClear() bool {
	return e.probed > 0 && e.parsed == e.probed &&
		e.worstRatio <= inodePressureClearRatio
}

// updateInodePressureLatch drives state-inode-pressure (inode-pressure): an
// exhausted inode table makes kubelet's own imagefs/nodefs GC and
// every pod's tmpfs write fail before DiskPressure ever fires — the
// condition surfaces as nodecond.InodePressure with the offending
// mountpoint + ratio in the STATE-ENTER detail.
func (c *Collector) updateInodePressureLatch(e fsInodeEvidence) {
	switch {
	case e.inodePressureEnter():
		c.state.Enter(latchdefs.LatchInodePressure, fmt.Sprintf(
			"mount=%s ratio=%.3f >= %.2f",
			e.worstMount, e.worstRatio, inodePressureEnterRatio))
	case e.inodePressureClear():
		c.state.Exit(latchdefs.LatchInodePressure, nil)
	}
}

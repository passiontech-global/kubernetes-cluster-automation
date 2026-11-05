// collect_fs.go — filesystem inode stats + the hung-mount statfs
// probe (H3/H7) and the state-filesystem-readonly latch (W5.3).
// Split out of hostmetrics.go.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
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
	c.mu.Lock()
	if start, inflight := c.fsInflight[mount]; inflight {
		c.mu.Unlock()
		return unix.Statfs_t{},
			c.cfg.nowFn().Sub(start) >= c.cfg.fsProbeTimeout, false
	}
	c.fsInflight[mount] = c.cfg.nowFn()
	c.mu.Unlock()

	res := make(chan fsResult, 1)
	go func() {
		var r fsResult
		r.err = c.cfg.statfsFn(mount, &r.st)
		c.mu.Lock()
		delete(c.fsInflight, mount)
		c.mu.Unlock()
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
		c.mu.Lock()
		wasLogged := c.fsStalledLogged[mount]
		if stalled {
			c.fsStalledLogged[mount] = true
		} else {
			delete(c.fsStalledLogged, mount)
		}
		c.mu.Unlock()
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
// overload latch follows on an unparseable PSI file.
func (c *Collector) updateFSReadonlyLatch(anyRO, probed bool) {
	p := c.state.Path(hoststate.LatchFilesystemReadonly)
	_, err := os.Stat(p)
	switch {
	case anyRO && err != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
		if werr := os.WriteFile(tmp, []byte(content), 0o644); werr != nil {
			logger().Warn("hostmetrics: filesystem-readonly latch write failed",
				"path", p, "error", werr)
		} else if rerr := os.Rename(tmp, p); rerr != nil {
			logger().Warn("hostmetrics: filesystem-readonly latch install failed",
				"path", p, "error", rerr)
		} else {
			logger().Warn("hostmetrics: filesystem-readonly latch set — "+
				"a probed mount reports ST_RDONLY",
				"path", p)
		}
	case probed && !anyRO && err == nil:
		if rerr := os.Remove(p); rerr != nil {
			logger().Warn("hostmetrics: filesystem-readonly latch remove failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: filesystem-readonly latch cleared — "+
				"all probed mounts rw again",
				"path", p)
		}
	}
}

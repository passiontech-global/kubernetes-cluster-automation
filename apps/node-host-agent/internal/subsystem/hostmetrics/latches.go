// latches.go — W8 latch maintenance (BUG-H5/H6, W8-KR3).
//
// hostmetrics was a pure scrape-time collector: the watchdog-state
// file contract (state-node-overloaded, state-filesystem-readonly,
// state-nebula-cert-expiring, state-kernel-keys-pressure) only moved
// when Prometheus scraped — a DaemonSet pod that isn't scraped every
// 30s (or at all) left stale or missing latches for the file
// consumers (nodereporter conditions, the restart gates). Run() is
// the scrape-independent 30s ticker that keeps them fresh — it runs
// in BOTH modes (Standalone only changes where series are rendered,
// not who owns the latches).
//
// While a latch stays held its mtime is refreshed (BUG-H6) so the
// janitor's 24h reap can't retire an active signal.
package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/prometheus/client_golang/prometheus"
)

// Name identifies the subsystem for the agent loop.
func (c *Collector) Name() string { return "hostmetrics" }

// Run drives the latch-maintenance ticker until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	cycle.Every("hostmetrics", c.cfg.LatchInterval,
		func(context.Context) { c.refreshLatches() }).Run(ctx)
}

// refreshLatches re-evaluates every file-contract latch once — the
// same logic Collect runs per scrape, decoupled from scrapes
// (BUG-H5). Each updater is already idempotent + hysteresis-safe.
func (c *Collector) refreshLatches() {
	if avg60, ok := c.psiAvg60(); ok {
		c.updateOverloadLatch(avg60)
	}
	days, certOK := c.nebulaCertDaysLeft()
	c.updateCertLatch(days, certOK)
	// Filesystem read-only: probe each target like collectFilesystem
	// but only for the latch (metrics are scrape-side).
	anyRO, probed := false, false
	for _, mount := range c.cfg.FilesystemTargets {
		st, _, ok := c.probeFS(mount)
		if !ok {
			continue
		}
		probed = true
		if st.Flags&1 != 0 { // unix.ST_RDONLY without importing unix twice
			anyRO = true
		}
	}
	c.updateFSReadonlyLatch(anyRO, probed)
	// W8-KR3: kernel keyring quota pressure.
	if ratio, ok := c.kernelKeysUsedRatio(); ok {
		c.updateKernelKeysLatch(ratio)
	}
	// W10-KR1: kernel dmesg/kmsg deep-error scan — filesystem/block
	// errors, conntrack table-full drops, host-level OOM kills.
	// Writes evidence markers (kmsg-fs-error, kmsg-conntrack-drops,
	// kmsg-host-oom-*) that the latches below and workerhygiene's
	// SystemOOMVictim emitter consume. Ticker-only: a scrape-side
	// drain would steal records from this loop.
	c.checkKernelDmesg()
	// W10-KR2: pid/thread/fd utilization → state-pid-fd-pressure
	// plus the node_agent_*_utilization_ratio textfile gauges.
	c.updatePidFDPressure()
	// W10-KR5: chronyc/adjtimex clock-skew probe → state-clock-skew
	// + rate-limited chronyc makestep.
	c.checkClockSkew()
	// W10-ST1+KR1: the state-fs-readonly evidence latch — a fresh
	// kernel fs error OR an ro ext4/xfs/btrfs mount under a PVC
	// dir, ahead of statfs ever reporting ST_RDONLY.
	c.updateFSReadonlyEvidence()
	// BUG-H6: while a latch stays held keep its mtime fresh so the
	// janitor's LatchMaxAge reap can't retire an active signal.
	for _, name := range []string{
		"state-node-overloaded",
		"state-filesystem-readonly",
		"state-nebula-cert-expiring",
		"state-kernel-keys-pressure",
		// W10 maintained latches — same reap protection.
		"state-fs-readonly",
		"state-pid-fd-pressure",
		"state-clock-skew",
	} {
		p := filepath.Join(c.cfg.WatchdogStateDir, name)
		if _, err := os.Stat(p); err == nil {
			now := c.cfg.nowFn()
			if cerr := os.Chtimes(p, now, now); cerr != nil {
				logger().Debug("hostmetrics: latch touch failed",
					"path", p, "error", cerr)
			}
		}
	}
}

// --- W8-KR3: /proc/key-users kernel keyring quota ---

// kernelKeysUsedRatio returns the highest fill ratio across the
// per-UID rows of /proc/key-users ("uid: usage nkeys nikeys maxkeys
// maxbytes" — nikeys vs maxkeys is the enforced quota). ok=false on
// a missing/unparseable file (kernel keyring disabled or proc
// absent) — inconclusive evidence must not move the latch.
func (c *Collector) kernelKeysUsedRatio() (float64, bool) {
	data, err := os.ReadFile(c.cfg.KeyUsersFile)
	if err != nil {
		return 0, false
	}
	best := -1.0
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		// Fields after the "uid:" label: usage nkeys nikeys maxkeys
		// maxbytes — column order of proc_key_users_show.
		nikeys, errN := strconv.ParseFloat(f[3], 64)
		maxkeys, errM := strconv.ParseFloat(f[4], 64)
		if errN != nil || errM != nil || maxkeys <= 0 {
			continue
		}
		seen = true
		if r := nikeys / maxkeys; r > best {
			best = r
		}
	}
	if !seen {
		return 0, false
	}
	return best, true
}

// updateKernelKeysLatch drives state-kernel-keys-pressure (W8-KR3):
// set above 0.80 of the enforced quota — a full keyring fails
// keyctl_join/add_key silently for new sessions.
func (c *Collector) updateKernelKeysLatch(ratio float64) {
	p := filepath.Join(c.cfg.WatchdogStateDir, "state-kernel-keys-pressure")
	_, err := os.Stat(p)
	switch {
	case ratio > kernelKeysPressureRatio && err != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
		if werr := os.WriteFile(tmp, []byte(content), 0o644); werr != nil {
			logger().Warn("hostmetrics: kernel-keys-pressure latch write failed",
				"path", p, "error", werr)
		} else if rerr := os.Rename(tmp, p); rerr != nil {
			logger().Warn("hostmetrics: kernel-keys-pressure latch install failed",
				"path", p, "error", rerr)
		} else {
			logger().Warn("hostmetrics: kernel-keys-pressure latch set",
				"ratio", ratio, "threshold", kernelKeysPressureRatio, "path", p)
		}
	case ratio <= kernelKeysPressureRatio && err == nil:
		if rerr := os.Remove(p); rerr != nil {
			logger().Warn("hostmetrics: kernel-keys-pressure latch remove failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: kernel-keys-pressure latch cleared",
				"ratio", ratio, "path", p)
		}
	}
}

// collectKernelKeys emits the W8-KR3 used-ratio gauge — absent when
// the file doesn't parse (no fake 0).
func (c *Collector) collectKernelKeys(ch chan<- prometheus.Metric) {
	ratio, ok := c.kernelKeysUsedRatio()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descKernelKeys,
		prometheus.GaugeValue, ratio, c.cfg.NodeName)
}

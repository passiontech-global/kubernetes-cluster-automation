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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Name identifies the subsystem for the agent loop.
func (c *Collector) Name() string { return "hostmetrics" }

// Run drives the latch-maintenance ticker until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	c.refreshLatches()
	t := time.NewTicker(c.cfg.LatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refreshLatches()
		}
	}
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
	// BUG-H6: while a latch stays held keep its mtime fresh so the
	// janitor's LatchMaxAge reap can't retire an active signal.
	for _, name := range []string{
		"state-node-overloaded",
		"state-filesystem-readonly",
		"state-nebula-cert-expiring",
		"state-kernel-keys-pressure",
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

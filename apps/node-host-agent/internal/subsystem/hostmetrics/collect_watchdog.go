// collect_watchdog.go — watchdog state-* latch scan: the
// node_host_agent_watchdog_state family plus the emit-0 bookkeeping
// that keeps cleared latches emitting 0 until seenStateTTL. Split
// out of hostmetrics.go — see that file for the package contract.
package hostmetrics

import (
	"os"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
)

const (
	// seenStateTTL bounds how long a cleared dynamic latch keeps
	// emitting an explicit 0 — long enough for any Prometheus
	// for:/auto-resolve window, then the bookkeeping entry is dropped
	// so the map cannot grow forever.
	seenStateTTL = 6 * time.Hour
	// maxSeenStates hard-bounds the seenStates map — the
	// longest-cleared entries are evicted first when it overflows.
	maxSeenStates = 256
)

// collectWatchdog scans state-* latch files. certDays/certOK fold the
// agent-computed nebula cert expiry into the latch bookkeeping: the
// shell module 13 used to own the state-nebula-cert-expiring file —
// now the series is driven by cert parsing whenever the cert reads.
func (c *Collector) collectWatchdog(ch chan<- prometheus.Metric, certDays int64, certOK bool) {
	present := map[string]bool{}
	entries, err := os.ReadDir(c.cfg.WatchdogStateDir)
	switch {
	case err == nil:
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			if name, ok := strings.CutPrefix(e.Name(),
				hoststate.LatchFilePrefix); ok && name != "" {
				present[name] = true
			}
		}
	case os.IsNotExist(err):
		// The dir is gone — the latches really are absent, so the
		// emit-0 cleared bookkeeping below is honest (a node
		// without node-watchdog keeps exporting 0s).
	default:
		// A ReadDir error other than NotExist leaves `present`
		// empty — letting it fall through would stamp every latched
		// state cleared and emit a false 0 for the whole family
		// despite on-disk latches. Serve the last-known values
		// unchanged instead (active entries keep 1, cleared
		// entries keep their emit-0 state); the bookkeeping map
		// is left untouched so no TTL eviction is manufactured.
		logger().Debug("hostmetrics: watchdog state dir unreadable — "+
			"serving previous watchdog_state values",
			"dir", c.cfg.WatchdogStateDir, "error", err)
		c.mu.Lock()
		prev := make(map[string]bool, len(c.seenStates))
		for s, clearedAt := range c.seenStates {
			prev[s] = clearedAt.IsZero()
		}
		c.mu.Unlock()
		for name, active := range prev {
			v := 0.0
			if active {
				v = 1
			}
			ch <- prometheus.MustNewConstMetric(c.descWatchdog,
				prometheus.GaugeValue, v, c.cfg.NodeName, name)
			ch <- prometheus.MustNewConstMetric(c.descWatchdogLegacy,
				prometheus.GaugeValue, v, name)
		}
		return
	}
	if certOK && certDays < nebulaCertWarnDays {
		present[hoststate.LatchNebulaCertExpiring] = true
	}
	c.mu.Lock()
	now := c.cfg.nowFn()
	// Cleared-state bookkeeping: an entry absent from this scrape's
	// latches is stamped with now on the first cleared scrape and
	// dropped once it has emitted 0 for seenStateTTL. The cert-owned
	// series counts as active while the cert parses — the signal
	// must emit an explicit 0 from then on (alert contract), even if
	// the cert later disappears.
	for s, clearedAt := range c.seenStates {
		if present[s] || (certOK && s == hoststate.LatchNebulaCertExpiring) {
			continue
		}
		if clearedAt.IsZero() {
			c.seenStates[s] = now
		} else if now.Sub(clearedAt) >= seenStateTTL {
			delete(c.seenStates, s)
		}
	}
	for name := range present {
		c.seenStates[name] = time.Time{}
	}
	if certOK {
		c.seenStates[hoststate.LatchNebulaCertExpiring] = time.Time{}
	}
	// Hard bound: a latch storm must not grow the map without limit —
	// evict the longest-cleared entries first (active entries, zero
	// time, are never evicted). Single pass: collect the cleared
	// entries, sort oldest-first, delete the overflow — if the map is
	// still over-cap afterwards it is all-active and stays so.
	if len(c.seenStates) > maxSeenStates {
		type clearedState struct {
			state string
			at    time.Time
		}
		var evictable []clearedState
		for s, at := range c.seenStates {
			if !at.IsZero() {
				evictable = append(evictable, clearedState{s, at})
			}
		}
		slices.SortFunc(evictable, func(a, b clearedState) int { return a.at.Compare(b.at) })
		over := min(len(c.seenStates)-maxSeenStates, len(evictable))
		for _, e := range evictable[:over] {
			delete(c.seenStates, e.state)
		}
	}
	seen := make([]string, 0, len(c.seenStates))
	for name := range c.seenStates {
		seen = append(seen, name)
	}
	c.mu.Unlock()
	for _, name := range seen {
		v := 0.0
		if present[name] {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.descWatchdog,
			prometheus.GaugeValue, v, c.cfg.NodeName, name)
		// Legacy alias: prom_emit's node_watchdog_state{signal} —
		// the fluxcd PrometheusRules query this exact series.
		ch <- prometheus.MustNewConstMetric(c.descWatchdogLegacy,
			prometheus.GaugeValue, v, name)
	}
}

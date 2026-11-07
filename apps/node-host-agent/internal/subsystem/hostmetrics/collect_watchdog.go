// collect_watchdog.go — watchdog state-* latch scan: the
// node_host_agent_watchdog_state family plus the emit-0 bookkeeping
// that keeps cleared latches emitting 0 until seenStateTTL. Split
// out of hostmetrics.go — see that file for the package contract.
package hostmetrics

import (
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
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

// latchSeenBook is the emit-0 bookkeeping behind the watchdog_state
// family — one slice of what used to be the Collector's shared
// mu-guarded fields. A map entry's value is zero while the latch is
// active on disk (or the cert-owned series is live); a non-zero
// stamp is the scrape that first saw it cleared — the entry emits 0
// until seenStateTTL then drops. The mutex is private.
type latchSeenBook struct {
	mu sync.Mutex
	m  map[string]time.Time
}

// prev snapshots the last-known active flags (zero stamp = active)
// for the degraded path — an unreadable state dir serves the
// previous values unchanged so no false cleared-0s are emitted.
func (b *latchSeenBook) prev() map[string]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	prev := make(map[string]bool, len(b.m))
	for s, clearedAt := range b.m {
		prev[s] = clearedAt.IsZero()
	}
	return prev
}

// update folds this scrape's present set into the bookkeeping —
// first-cleared stamps, TTL drops, the cert-owned series (certOK
// counts nebula-cert-expiring as active) and the maxSeenStates
// eviction — then returns every state name that emits this scrape.
// The caller maps present[name] onto 1/0.
func (b *latchSeenBook) update(present map[string]bool, certOK bool,
	now time.Time) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Cleared-state bookkeeping: an entry absent from this scrape's
	// latches is stamped with now on the first cleared scrape and
	// dropped once it has emitted 0 for seenStateTTL. The cert-owned
	// series counts as active while the cert parses — the signal
	// must emit an explicit 0 from then on (alert contract), even
	// if the cert later disappears.
	for s, clearedAt := range b.m {
		if present[s] || (certOK && s == hoststate.LatchNebulaCertExpiring) {
			continue
		}
		if clearedAt.IsZero() {
			b.m[s] = now
		} else if now.Sub(clearedAt) >= seenStateTTL {
			delete(b.m, s)
		}
	}
	for name := range present {
		b.m[name] = time.Time{}
	}
	if certOK {
		b.m[hoststate.LatchNebulaCertExpiring] = time.Time{}
	}
	// Hard bound: a latch storm must not grow the map without
	// limit — evict the longest-cleared entries first (active
	// entries, zero time, are never evicted). Single pass: collect
	// the cleared entries, sort oldest-first, delete the overflow —
	// if the map is still over-cap afterwards it is all-active and
	// stays so.
	if len(b.m) > maxSeenStates {
		type clearedState struct {
			state string
			at    time.Time
		}
		var evictable []clearedState
		for s, at := range b.m {
			if !at.IsZero() {
				evictable = append(evictable, clearedState{s, at})
			}
		}
		slices.SortFunc(evictable, func(a, b clearedState) int { return a.at.Compare(b.at) })
		over := min(len(b.m)-maxSeenStates, len(evictable))
		for _, e := range evictable[:over] {
			delete(b.m, e.state)
		}
	}
	seen := make([]string, 0, len(b.m))
	for name := range b.m {
		seen = append(seen, name)
	}
	return seen
}

var (
	descWatchdog = prometheus.NewDesc(
		"node_host_agent_watchdog_state",
		"node-watchdog state-* latch present (1) or previously seen and cleared (0).",
		[]string{"node", "state"}, nil)
	// descWatchdogLegacy is the prom_emit node_watchdog_state{signal}
	// alias — the fluxcd PrometheusRules still alert on it. Emitted
	// alongside the node_host_agent_* name so the same registry
	// serves pods AND the standalone textfile writer keeps the
	// node-exporter contract on out-of-cluster hosts.
	descWatchdogLegacy = prometheus.NewDesc(
		"node_watchdog_state",
		"Signal currently active on node-watchdog (1 = state file exists).",
		[]string{"signal"}, nil)
)

// collectWatchdog scans state-* latch files. sc.certDays/sc.certOK
// fold the agent-computed nebula cert expiry into the latch
// bookkeeping: the shell module 13 used to own the
// state-nebula-cert-expiring file — now the series is driven by
// cert parsing whenever the cert reads.
func (c *Collector) collectWatchdog(ch chan<- prometheus.Metric, sc scrapeCtx) {
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
		for name, active := range c.seen.prev() {
			v := 0.0
			if active {
				v = 1
			}
			ch <- prometheus.MustNewConstMetric(descWatchdog,
				prometheus.GaugeValue, v, c.cfg.NodeName, name)
			ch <- prometheus.MustNewConstMetric(descWatchdogLegacy,
				prometheus.GaugeValue, v, name)
		}
		return
	}
	if sc.certOK && sc.certDays < nebulaCertWarnDays {
		present[hoststate.LatchNebulaCertExpiring] = true
	}
	for _, name := range c.seen.update(present, sc.certOK, c.cfg.Clock.Now()) {
		v := 0.0
		if present[name] {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(descWatchdog,
			prometheus.GaugeValue, v, c.cfg.NodeName, name)
		// Legacy alias: prom_emit's node_watchdog_state{signal} —
		// the fluxcd PrometheusRules query this exact series.
		ch <- prometheus.MustNewConstMetric(descWatchdogLegacy,
			prometheus.GaugeValue, v, name)
	}
}

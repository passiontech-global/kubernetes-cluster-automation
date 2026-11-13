// liveness.go — the /healthz wedged-loop detector: the per-subsystem
// beat registry (subBeat) the supervisor maintains and
// Agent.livenessWedged's staleness scan. Split out of agent.go so the
// runtime file stays under the ~500-LOC bar.
package agent

import (
	"sync/atomic"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
)

// subBeat pairs a subsystem's liveness registry with the
// supervisor's active flag — /healthz only judges subsystems
// currently inside Run (one in restart backoff is /readyz's
// concern, and its beats are legitimately paused). live is an
// atomic.Pointer because the supervisor RENEWS the whole registry
// before every Run attempt while /healthz reads it concurrently:
// a panic-recovered restart must not inherit the dead run's
// stamps, whose age would trip the staleness check permanently.
type subBeat struct {
	live   atomic.Pointer[cycle.Liveness]
	active atomic.Bool
}

// subsystemLivenessStaleAfter is the DEFAULT staleness bound for
// beats that carry no budget of their own (the shared fallback
// beat) — comfortably above the longest per-cycle deadline so a
// slow-but-alive sweep never trips it; only a genuinely wedged
// loop does. cycle.Runner loops get their own larger budgets
// (max(3*interval+cycle budget, 15m)) so a 1h sweeper or 6h kinedb
// maint pass is not killed by a constant sized for 30s loops.
const subsystemLivenessStaleAfter = 15 * time.Minute

// livenessWedged reports whether any active subsystem has a loop
// beat stale beyond ITS OWN budget. Subsystems in restart backoff
// (active=false), exempt registries (cycle.Idle parked loops) and
// never-yet-stamped beats are exempt. The shared fallback beat is
// judged only for subsystems with NO Runner loops — Runner-only
// registries stamp it once at run entry and judging it would
// false-positive every 15 minutes.
func (a *Agent) livenessWedged() bool {
	now := time.Now()
	wedged := false
	a.beats.Range(func(_, v any) bool {
		sb := v.(*subBeat)
		live := sb.live.Load()
		if !sb.active.Load() || live == nil || live.IsExempt() {
			return true
		}
		stale := func(b *cycle.Beat) bool {
			last := b.LastProgress.Load()
			if last == 0 {
				return false
			}
			budget := b.StaleAfter()
			if budget <= 0 {
				budget = subsystemLivenessStaleAfter
			}
			return now.Sub(time.Unix(0, last)) > budget
		}
		for _, b := range live.LoopBeats() {
			if stale(b) {
				wedged = true
				return false
			}
		}
		// Fallbacks carries the per-scope rule: only registries
		// whose subtree holds no Runner loops are judged on their
		// fallback beat (run-entry stamp / bare Heartbeat callers).
		for _, b := range live.Fallbacks() {
			if stale(b) {
				wedged = true
				return false
			}
		}
		return true
	})
	return wedged
}

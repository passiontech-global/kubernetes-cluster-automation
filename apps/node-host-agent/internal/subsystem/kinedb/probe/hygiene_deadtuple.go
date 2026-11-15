// hygiene_deadtuple.go — item 2's dead-tuple remediation: the
// dead/live tuple READ moved into hygiene_stats.go's merged census;
// this file keeps the advisory-locked emergency VACUUM (ANALYZE)
// trigger when autovacuum is visibly losing.
package probe

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygieneDeadTuple — item 2's REMEDIATION half: the dead/live
// tuple read itself moved into hygieneScalarStats' merged census
// (h.deadTup/h.deadSeen/h.deadRatio are already filled); this
// function only judges the ratio and fires the emergency VACUUM.
func (p *Probe) hygieneDeadTuple(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	if !h.deadSeen {
		return // census failed or unparsed — nothing to judge
	}
	dead := h.deadTup
	if h.deadRatio <= deadTupleRatioMax || dead <= deadTupleMinCount {
		return
	}
	if p.d.Cfg.ReadOnly {
		note(fmt.Sprintf("read-only: dead-tuple VACUUM (ANALYZE) suppressed (dead=%d ratio=%.2f)",
			dead, h.deadRatio))
		return
	}
	if p.deadTupleVacuum(ctx, pg, user, pass, note) {
		h.vacuumFired = true
		logger().Warn("kinedb: emergency dead-tuple VACUUM (ANALYZE)",
			"table", p.d.Cfg.Table, "dead_tup", dead, "ratio", h.deadRatio)
	}
}

// deadTupleVacuum runs VACUUM (ANALYZE) inside a single psql session
// gated by the compact guard's advisory lock — a busy lock means a
// compact session (which ends in VACUUM anyway) is running, so skip
// instead of queueing. The RateTrySpend lands on the ATTEMPT like
// the pgb-restart budget: a failing vacuum does not retry every
// probe round.
func (p *Probe) deadTupleVacuum(ctx context.Context, pg, user, pass string,
	note func(string)) bool {
	if !p.d.GuardRateTrySpend(deadTupleVacuumFile, deadTupleVacuumBudget) {
		note("dead-tuple-vacuum-cooldown (<30m)")
		return false
	}
	script := kdeps.WrapAdvisoryLockScript(p.d.Cfg.AdvisoryLockID, "kh_locked",
		fmt.Sprintf("VACUUM (ANALYZE) %s;\n", kdeps.SQLIdent(p.d.Cfg.Table)))
	sout, err := p.d.PsqlScript(ctx, pg, user, pass, kdeps.AppNameProbe, script)
	switch {
	case err != nil:
		note(fmt.Sprintf("dead-tuple-vacuum-fail: %v", err))
	case strings.Contains(sout, kdeps.LockBusyMarker):
		note("dead-tuple-vacuum lock busy (compact running)")
	default:
		return true
	}
	return false
}

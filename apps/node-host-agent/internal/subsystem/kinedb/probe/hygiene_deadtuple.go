// hygiene_deadtuple.go — items 1–2: the idle-in-transaction census
// and the dead-tuple ratio with its advisory-locked emergency
// VACUUM (ANALYZE) remediation.
package probe

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygieneIdleInTx — item 1: sessions idle-in-transaction >3min on
// the postgres/kine databases. COUNT(pid) rather than COUNT(*): the
// probe contract bans a bare COUNT(*) in the 2-minute loop (the
// tests guard against the kine heap seq-scan creeping back), and
// counting a NOT NULL column is identical semantics on a stats view.
func (p *Probe) hygieneIdleInTx(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := p.d.PsqlQuery(ctx, pg, user, pass,
		"SELECT COUNT(pid) FROM pg_stat_activity "+
			"WHERE datname IN ('postgres', 'kine') "+
			"AND state = 'idle in transaction' "+
			"AND state_change < now() - interval '3 minutes'")
	if err != nil {
		note(fmt.Sprintf("idle-tx-fail: %v", err))
		return
	}
	v, perr := strconv.ParseInt(kdeps.FirstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("idle-tx-unparsed: %v", perr))
		return
	}
	h.idleInTx, h.idleSeen = v, true
}

// hygieneDeadTuple — item 2: dead-tuple ratio plus the emergency
// VACUUM trigger when autovacuum is visibly losing.
func (p *Probe) hygieneDeadTuple(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := p.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT n_dead_tup, n_live_tup FROM pg_stat_user_tables "+
			"WHERE relname=%s", kdeps.SQLQuote(p.d.Cfg.Table)))
	if err != nil {
		note(fmt.Sprintf("dead-tuple-fail: %v", err))
		return
	}
	dead, live, perr := kdeps.ParsePair(out)
	if perr != nil {
		// An empty result means the stats view has no row for the
		// table yet — inconclusive, like a parse failure.
		note(fmt.Sprintf("dead-tuple-unparsed: %v", perr))
		return
	}
	h.deadTup, h.deadSeen = dead, true
	h.deadRatio = float64(dead) / float64(max(live, 1))
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
	// MkdirAll before the spend — Store.WriteEpochFile does not
	// create the state dir itself (same note as checkPGBWedge).
	_ = os.MkdirAll(p.d.Cfg.GuardStateDir, 0o755)
	if !p.d.State.RateTrySpend(deadTupleVacuumFile, deadTupleVacuumBudget) {
		note("dead-tuple-vacuum-cooldown (<30m)")
		return false
	}
	var b strings.Builder
	fmt.Fprintf(&b,
		"SELECT CASE WHEN pg_try_advisory_lock(%d) THEN 'on' ELSE 'off' END AS kh_locked;\n",
		p.d.Cfg.AdvisoryLockID)
	b.WriteString("\\gset\n\\if :kh_locked\n")
	fmt.Fprintf(&b, "VACUUM (ANALYZE) %s;\n", kdeps.SQLIdent(p.d.Cfg.Table))
	fmt.Fprintf(&b, "SELECT pg_advisory_unlock(%d);\n", p.d.Cfg.AdvisoryLockID)
	b.WriteString("\\else\n\\echo '" + kdeps.LockBusyMarker + "'\n\\endif\n")
	sout, err := p.d.PsqlScript(ctx, pg, user, pass, b.String())
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

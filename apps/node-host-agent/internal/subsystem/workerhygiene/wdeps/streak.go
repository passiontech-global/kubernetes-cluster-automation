// streak.go — the per-cycle Run bookkeeping every Check shares:
// the k0sworker-active head gate, the Cycles{check,result} counter
// bumps and the consecutive-fail streak observer. Before this
// lived here, each of the ~43 checks hand-rolled the same five
// lines of gating, the same `(check %d/%d)` suspect suffix and the
// same ok-counter tail — the drift this file removes. The streak
// counters themselves stay plain ints ON the check structs (some
// are exported test surface — CiliumWGCheck.Fails etc.), so the
// helpers take *int and no check state moves.
//
// The streak advance + progress suffix themselves live in
// platform/checkkit — nethealth and the hand-rolled workerhygiene
// sites share the same contract; this method is the wdeps spelling
// (ConsecNeeded off Cfg, AppendLog off State) kept so the ~16
// domain files' call sites stay untouched.
package wdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
)

// Gated applies the WD_REQUIRES: k0sworker head gate. When the
// worker is intentionally down it has already bumped the
// Cycles{check,"gated"} counter and the caller must return — the
// verdict is "skip, not healthy". A false return means run.
func (d *Deps) Gated(e *CycleEnv, check string) bool {
	if e.WorkerActive {
		return false
	}
	d.Cycles.WithLabelValues(check, "gated").Inc()
	return true
}

// CycleResult bumps the Cycles{check,result} counter — the
// per-cycle verdict label ("ok", "gated", "abort",
// "inconclusive") every Run path ends with. One seam so the label
// vocabulary stays exactly the four values the dashboards already
// know.
func (d *Deps) CycleResult(check, result string) {
	d.Cycles.WithLabelValues(check, result).Inc()
}

// StreakPending advances the consecutive-fail streak one cycle —
// checkkit.Pending with this subsystem's ConsecNeeded and the
// state store's AppendLog. While the streak is still below
// ConsecNeeded it appends the suspect line suffixed with the
// shared " (check %d/%d)" progress marker and reports true — the
// caller bumps its cycle result and returns (streak not yet
// confirmed, latch untouched). Once the streak reaches
// ConsecNeeded it reports false and the caller proceeds to its
// latch/remedy tail. The line is everything before the suffix —
// callers keep their per-check suspect wording. The healthy tails
// stay inline: checks clear their counter and latch (Exit vs
// ExitFrom, which of several latches, the counter bump order)
// differently enough that a StreakClear would obscure, not dedupe.
func (d *Deps) StreakPending(fails *int, line string) bool {
	return checkkit.Pending(d.Cfg.ConsecNeeded, fails, line,
		d.State.AppendLog)
}

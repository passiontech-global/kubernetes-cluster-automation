// hygiene_seqscan.go — item 7b (invalid-index-reaper): the seq-scan
// regression guard reacting on the census hygieneCatalog samples,
// with the immediate ANALYZE under the last-kine-analyze budget.
package probe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygieneSeqScan — item 7b (invalid-index-reaper): the
// seq_scan/seq_tup_read census itself is sampled inside
// hygieneCatalog's combined exec; this half reacts on it. A planner
// regression to
// sequential scan (stale statistics after a churn burst, or a
// poisoned index) shows as a seq_tup_read spike BEFORE the CPU
// storm makes apiserver LIST/WATCH time out — the Datadog/Rancher
// k3s failure mode. Past seqTupReadDeltaMax between probes the
// planner stats get refreshed immediately: ANALYZE under the 30m
// last-kine-analyze budget (spend-on-attempt, same contract as
// last-dead-tuple-vacuum).
func (p *Probe) hygieneSeqScan(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	if !h.seqSeen {
		// The census in hygieneCatalog failed or went unparseable —
		// nothing to react on this round.
		return
	}
	tupRead := h.seqTupRead
	// Delta vs the previous probe — persisted under GuardStateDir
	// so the guard survives an agent restart. A pg_stat reset (DB
	// restart) reads as a negative delta and simply re-baselines.
	prevPath := filepath.Join(p.d.Cfg.GuardStateDir, seqTupReadFile)
	prev, perr := kdeps.ReadIntFile(prevPath)
	if p.d.Cfg.ReadOnly {
		// Diagnostics only — never the baseline write, the
		// ANALYZE, or the last-kine-analyze budget spend.
		return
	}
	kdeps.WriteIntFile(prevPath, tupRead)
	if perr != nil {
		// First observation (or an unreadable baseline): the
		// lifetime seq_tup_read is NOT a delta — seed prev with the
		// current value and skip, or the first probe after every
		// agent restart fires a bogus ANALYZE.
		return
	}
	delta := tupRead - prev
	if delta <= seqTupReadDeltaMax {
		return
	}
	note(fmt.Sprintf("seq-tup-read +%d>%d between probes — planner fell back to seq scan; ANALYZE %s",
		delta, seqTupReadDeltaMax, p.d.Cfg.Table))
	// MkdirAll before the spend — Store.WriteEpochFile does not
	// create the state dir itself (same note as deadTupleVacuum).
	_ = os.MkdirAll(p.d.Cfg.GuardStateDir, 0o755)
	if !p.d.State.RateTrySpend(kineAnalyzeFile, kineAnalyzeBudget) {
		note("kine-analyze cooldown (<30m)")
		return
	}
	if _, aerr := p.d.ExecLongEnv(ctx, p.d.PsqlMaintEnv(pass), p.d.PsqlMaintArgs(pg, user, false,
		"-qc", "ANALYZE "+kdeps.SQLIdent(p.d.Cfg.Table)), ""); aerr != nil {
		note(fmt.Sprintf("kine-analyze-fail: %v", aerr))
		return
	}
	h.analyzeFired = true
	logger().Warn("kinedb: seq-scan regression — ran ANALYZE",
		"table", p.d.Cfg.Table, "seq_tup_read_delta", delta)
}

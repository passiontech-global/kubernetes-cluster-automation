// compact_run.go — the compact guardRun executor: runs the
// compact/sweep scripts against postgres and emits the guard
// Result. Split out of compact.go — compact.go keeps guard
// state, trigger math and the SQL script builders.

package compact

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// guardRun does the stats read, freeze bookkeeping, trigger decision
// and (on fire) the locked compact session.
func (g *Guard) guardRun(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {

	out, err := g.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT COALESCE((SELECT MAX(id) FROM %s),0), "+
			"COALESCE((SELECT MAX(prev_revision) FROM %s WHERE name='%s'),0), "+
			"COUNT(*), COALESCE(MIN(id),0) FROM %[1]s",
		kdeps.SQLIdent(g.d.Cfg.Table), kdeps.SQLIdent(g.d.Cfg.Table), kdeps.CompactRevKey))
	if err != nil {
		res.ok = false
		note(fmt.Sprintf("stats query fail: %v", err))
		return
	}
	head, crev, rows, minID, perr := kdeps.ParseQuad(out)
	if perr != nil {
		res.ok = false
		note(fmt.Sprintf("stats unparsed: %v", perr))
		return
	}
	res.head, res.compact, res.rows = head, crev, rows
	res.statsOK = true

	// compact_rev frozen detection: identical compact_rev while head
	// advanced = neither kine nor apiserver lived long enough to
	// compact (OOM-loop signature). A guard fire advances compact_rev
	// itself, so the counter resets naturally on the next run.
	prev := g.readGuardState()
	res.frozen = 0
	if prev.seen && crev == prev.compactRev && head > prev.head {
		res.frozen = prev.freeze + 1
	}
	retained := head - crev
	trig, reason := g.guardTrigger(head, crev, rows, retained, res.frozen, prev)
	g.writeGuardState(head, crev, res.frozen)
	if !trig {
		return
	}
	res.reason = reason
	// head <= Tail means the entire retained history already fits
	// inside the watch tail — there is no safely-deletable range.
	// compacting to head here would advance compact_rev past every
	// revision a watcher could resume from (apiserver 410 Gone
	// storm), so skip the session entirely. Unreachable under the
	// default thresholds (every trigger needs retained/rows far
	// above Tail) but config drift must not open the hole.
	if head <= g.d.Cfg.Tail {
		note(fmt.Sprintf("compact skipped: head=%d <= tail=%d — nothing safely deletable",
			head, g.d.Cfg.Tail))
		return
	}
	res.fired = true

	// Marker off-by-one parity with the shell: compact to head-TAIL,
	// except when the marker is already ahead (then hold at crev).
	// target <= crev implies crev > 0 — the head <= Tail / crev == 0
	// combinations that used to fall back to target=head are skipped
	// above, so no never-compacted overshoot remains.
	target := head - g.d.Cfg.Tail
	sweepBelow := false
	if target <= crev {
		// Fewer than Tail new revisions since the last compact —
		// pushing compact_revision to head would erase the watch
		// tail buffer and storm the apiserver with 410 Gone. Hold
		// at crev instead so the DELETE only sweeps history.
		target = crev
		// rows-debt with the marker already at/ahead of the safe
		// horizon: the forward compact has NO window to advance
		// through (cur == target → zero chunks), yet dead rows
		// BELOW compact_rev keep piling up — the table stays over
		// RowsMax and every cycle re-fires into an empty session.
		// Sweep [minID, crev] in bounded chunks instead: rows under
		// the marker are already-compacted history, safe to drop
		// WITHOUT advancing compact_rev_key (there is no forward
		// progress to record — the marker only gates deletions).
		sweepBelow = rows > g.d.Cfg.RowsMax && minID < crev
		if sweepBelow {
			note(fmt.Sprintf(
				"below-horizon sweep: rows=%d min_id=%d compact_rev=%d",
				rows, minID, crev))
		}
	}
	// compact-step-cap: never step the whole window in one cycle.
	target = g.clampStepTarget(crev, target)
	t0 := g.d.Cfg.Clock.Now()
	var script string
	if sweepBelow {
		script = g.buildSweepScript(minID, crev)
	} else {
		script = g.buildCompactScript(crev, target)
	}
	sout, err := g.d.PsqlScript(ctx, pg, user, pass, script)
	if err != nil && g.d.LongBudgetExceeded(t0, err) {
		// The client kill can orphan the server-side session —
		// still holding the advisory lock. Reap it now.
		if n, rerr := g.d.ReapOrphanedMaintSessions(ctx, pg, user, pass); rerr != nil {
			note(fmt.Sprintf("orphan-reap-fail: %v", rerr))
		} else if n > 0 {
			note(fmt.Sprintf("terminated %d orphaned maintenance backend(s) after exec timeout", n))
			logger().Warn("kinedb: terminated orphaned maintenance backends after exec timeout",
				"count", n)
		}
	}
	switch {
	case err != nil:
		res.ok = false
		note(fmt.Sprintf("compact-fail: %v", err))
	case strings.Contains(sout, kdeps.LockBusyMarker):
		res.fired = false
		note("guard already running")
	default:
		res.deleted = sumDeleted(sout)
		g.writeGuardCompactTS(g.d.Cfg.Clock.Now().Unix())
		// The bash re-read compact_rev + rows after the loop —
		// how far the chunks actually got and the post-VACUUM
		// table size. Failure only means the after-gauges go
		// stale, never the run.
		if aout, aerr := g.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
			"SELECT COALESCE((SELECT MAX(prev_revision) FROM %s WHERE name='%s'),0), "+
				"COUNT(*) FROM %[1]s",
			kdeps.SQLIdent(g.d.Cfg.Table), kdeps.CompactRevKey)); aerr == nil {
			if after, rows, perr := kdeps.ParsePair(aout); perr == nil {
				res.revAfter, res.revSeen = after, true
				res.rows = rows
			}
		}
	}
}

// emitGuard renders the textfile and updates the collectors.
func (g *Guard) emitGuard(res *Result) {
	var p promfile.Builder
	ok := 0.0
	if res.ok {
		ok = 1
	}
	p.Gauge("kine_db_guard_ok",
		"Compact guard result (1 = ok/skip, 0 = fail)", ok)
	g.d.M.GuardOK.Set(ok)
	fired := 0.0
	if res.fired {
		fired = 1
	}
	p.Gauge("kine_db_guard_fired",
		"1 when the last guard run executed a compact session", fired)
	g.d.M.GuardFired.Set(fired)
	// freeze_cycles + kine_db_rows come out of the stats read —
	// kine_db_rows lives here, not in the probe textfile, because
	// the COUNT(*) it needs seq-scans the table (10-min cadence)
	// and emitting it in both files would fail the scrape
	// (duplicate series across textfiles). Both gauges are skipped
	// when the stats read failed — a fabricated 0 overwriting a
	// meaningful freeze count (or row count) is worse than stale.
	if res.statsOK {
		p.Gauge("kine_db_guard_freeze_cycles",
			"Consecutive runs compact_rev stayed frozen while head advanced",
			float64(res.frozen))
		g.d.M.GuardFreeze.Set(float64(res.frozen))
		p.Gauge("kine_db_rows",
			"Row count of the kine table — kine boot fill cost",
			float64(res.rows))
		g.d.M.Rows.Set(float64(res.rows))
	}
	if res.revSeen {
		p.Gauge("kine_db_guard_compact_rev_after",
			"compact_rev re-read after the last completed compact run",
			float64(res.revAfter))
		g.d.M.GuardRevAfter.Set(float64(res.revAfter))
	}
	p.Gauge("kine_db_guard_last_deleted_rows",
		"Rows deleted by the last compact run", float64(res.deleted))
	g.d.M.GuardLastDeleted.Set(float64(res.deleted))
	lastCompact := float64(g.readGuardCompactTS())
	p.Gauge("kine_db_guard_last_compact_timestamp_seconds",
		"Timestamp of the last completed compact run", lastCompact)
	g.d.M.GuardLastCompact.Set(lastCompact)
	ts := float64(g.d.Cfg.Clock.Now().Unix())
	p.Gauge("kine_db_guard_last_run_timestamp_seconds",
		"Last guard run", ts)
	g.d.M.GuardLastRun.Set(ts)
	// kine-churn: the probe loop's top-5 churn sample renders here —
	// this file owns the churn series (the probe's own .prom must
	// never duplicate it). The probe goroutine refreshes ChurnTop
	// asynchronously — snapshot it under ChurnMu. And the GaugeVec
	// is Reset+repopulated rather than merged: a resource that
	// falls out of the top-5 must lose its series instead of
	// pinning a stale value on /metrics forever.
	g.d.ChurnMu.RLock()
	churnTop := append([]kdeps.ChurnEntry(nil), g.d.ChurnTop...)
	churnKeys := append([]kdeps.ChurnKeyEntry(nil), g.d.ChurnKeys...)
	g.d.ChurnMu.RUnlock()
	g.d.M.TopChurn.Reset()
	for _, e := range churnTop {
		p.GaugeLabels("kine_db_top_churn_revisions_5m",
			"Top-5 resource prefixes by revision count in the last 5-minute window",
			fmt.Sprintf("resource=%q", e.Resource), float64(e.Revs))
		g.d.M.TopChurn.WithLabelValues(e.Resource).Set(float64(e.Revs))
	}
	// selfheal-alert-coverage hot-key twin: same window, full Kine keys — the SSA
	// managedFields ping-pong names its victim object. Same
	// Reset+repopulate contract: a key falling out of the top-5
	// loses its series instead of pinning a stale value.
	g.d.M.TopHotkey.Reset()
	for _, e := range churnKeys {
		p.GaugeLabels("kine_db_top_hotkey_revisions_5m",
			"Top-5 full Kine object keys by revision count in the last 5-minute window (>=50 revs, leases/events excluded)",
			fmt.Sprintf("key=%q", e.Key), float64(e.Revs))
		g.d.M.TopHotkey.WithLabelValues(e.Key).Set(float64(e.Revs))
	}
	// backup-health: physical-backup verifier series — seen-gated like
	// the stats series: an unmeasured cycle must not fabricate a
	// passing backup state.
	if res.backupSeen {
		valid := 0.0
		if res.backupValid {
			valid = 1
		}
		p.Gauge("kine_db_backup_age_seconds",
			"Age of the newest physical pg_dump in the backup dir",
			float64(res.backupAge))
		p.Gauge("kine_db_backup_valid",
			"1 when the newest physical pg_dump passed header verification",
			valid)
		g.d.M.BackupAge.Set(float64(res.backupAge))
		g.d.M.BackupValid.Set(valid)
	}
	g.d.EmitTextfile("kine-compact-guard.prom", &p)
}

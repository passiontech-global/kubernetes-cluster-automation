// maint_repack.go — the maintRun repack executor: builds the
// in-pod pg_repack invocation, streams its combined output and
// folds the result into the maint Result. Split out of maint.go
// — maint.go keeps epoch bookkeeping, size reads and invalid-
// index reaping.

package maint

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

func (m *Maint) maintRun(ctx context.Context, pg, user, pass string,
	res *Result, note func(string), heavy bool) {

	// The epoch stamps only after the FULL heavy block — reindex +
	// freeze AND the repack phase — has run to its end. Stamping
	// after the reindex alone let a restart mid-repack read a fresh
	// epoch and park the unfinished repack (heap still bloated) for
	// another full window. The flag is set once the locked psql
	// script succeeded; the deferred stamp then fires on EVERY
	// exit past that point (repack done, skipped, failed, or
	// unattempted) — a repack that already tried must not replay the
	// reindex storm next cycle either. A crash mid-repack never
	// reaches the defer, so the next cycle re-runs the whole block.
	stampEpoch := false
	defer func() {
		if stampEpoch {
			m.stampMaintEpoch()
		}
	}()

	// (a0) invalid-index-reaper invalid-index reaper — BEFORE the reindex: an
	// interrupted REINDEX CONCURRENTLY or pg_repack leaves *_ccnew /
	// *_ccold shells with indisvalid=false, and those shells make
	// the next reindex error out ("cannot reindex invalid index")
	// while still taxing every INSERT. Best-effort: a failed
	// listing or drop only notes, never fails the maint run.
	m.reapInvalidIndexes(ctx, pg, user, pass, res, note)

	// (b) XID wraparound — read MAX(age(datfrozenxid)) first so the
	// FREEZE vacuum can ride the locked session below (runs before
	// the repack gate so a failing stats read cannot skip it).
	freeze := m.readXidAge(ctx, pg, user, pass, res, note)

	if !heavy {
		// Startup guard: a heavy block completed <24h ago. cycle.RunAll
		// fires Cycle immediately on every agent (re)start, and
		// replaying REINDEX + VACUUM FREEZE + pg_repack on the heels
		// of the last run is pure churn on the same locks/snapshots
		// the compact guard needs. The cheap reads above (and the
		// stats below) still ran, so the gauges stay fresh.
		res.okReindex = true
		res.freezeState = "skipped"
		note("heavy block skipped: last-maint-run epoch inside the " +
			"skip window")
		logger().Info("kinedb: maint heavy block skipped — epoch inside the skip window")
		m.readSizes(ctx, pg, user, pass, res, note)
		// urgent-reindex (bloat.go): the sizes read above is exactly
		// the gate input — a post-storm bloat discovered mid-interval
		// reindexes TODAY under the advisory lock, epoch window or
		// not.
		m.urgentReindex(ctx, pg, user, pass, res, note)
		return
	}

	// (a) REINDEX CONCURRENTLY — always, cheap on a small table —
	// plus the (b) FREEZE vacuum when the XID age triggers, inside
	// ONE psql session holding the compact guard's advisory lock
	// (session-level: held from the try-lock to the unlock / psql
	// exit, so a concurrent compact guard cannot interleave its
	// chunked deletes + VACUUM). A busy lock means a compact guard
	// session is mid-run — skip the heavy block this cycle (it
	// repeats daily; the compact ends in VACUUM anyway) without
	// failing the maint cycle.
	t0 := m.d.Cfg.Clock.Now()
	sout, serr := m.d.PsqlScript(ctx, pg, user, pass,
		m.buildHeavyScript(freeze))
	if serr != nil && m.d.LongBudgetExceeded(t0, serr) {
		// The client kill can orphan the server-side session —
		// still holding the advisory lock. Reap it now instead of
		// waiting out the session, then clear any pg_repack debris
		// the reaped session leaves behind (trigger + shadow tables
		// pin disk until dropped).
		m.reapOrphanedMaint(ctx, pg, user, pass, note)
		m.dropRepackLeftovers(ctx, pg, user, pass, note)
	}
	switch {
	case serr != nil:
		// ON_ERROR_STOP aborted the script — attribute the failure
		// to every statement it may have carried.
		res.okReindex = false
		note(fmt.Sprintf("reindex-fail: %v", serr))
		if freeze {
			res.okFreeze = false
			res.freezeState = "fail"
			note(fmt.Sprintf("freeze-vacuum-fail: %v", serr))
		}
	case strings.Contains(sout, kdeps.LockBusyMarker):
		// Skipped, not failed — the same skip-counts-as-ok parity the
		// repack gates use; the block repeats next daily window.
		res.okReindex = true
		logger().Warn("kinedb: maint heavy block skipped — compact-guard advisory lock busy")
		note("heavy block skipped: compact-guard advisory lock busy")
		if freeze {
			note(fmt.Sprintf("freeze skipped: lock busy (xid-age=%d)", res.xidAge))
		}
	default:
		res.okReindex = true
		if freeze {
			res.freezeState = "done"
		}
		// The locked heavy script completed — arm the epoch stamp.
		// It lands only after the repack phase below has run its
		// course (the deferred stamp at maintRun's exit), so a
		// restart mid-repack finds no fresh epoch and replays the
		// full block, repack included.
		stampEpoch = true
	}

	// (c) sizes + dead-tuple estimate from pg_stat_user_tables.
	// Indexes via pg_indexes_size like the bash — total−heap would
	// count TOAST as index bytes.
	m.readSizes(ctx, pg, user, pass, res, note)
	if !res.statsOK {
		// deadPct=0 + heapBytes=0 reads as "not bloated" — a failed
		// assessment must not skip repack and still report OK.
		res.okRepack = false
		res.repackState = "assess-fail"
		return
	}
	// urgent-reindex rides the heavy path too: the reindex above may
	// have failed or lock-skipped and left the bloat standing — the
	// gate (with its cooldown) decides, not the epoch.
	m.urgentReindex(ctx, pg, user, pass, res, note)

	// (d) pg_repack ONLY when the heap is genuinely bloated —
	// autovacuum keeps it roughly compact, so this fires rarely.
	if res.deadPct <= m.d.Cfg.RepackDeadPct ||
		res.heapBytes <= m.d.Cfg.RepackMinHeapBytes {
		return
	}
	// A previously interrupted pg_repack (client kill / orphaned
	// session reaped above) leaves its trigger + repack.log_<oid> /
	// repack.table_<oid> shadow objects behind. Until the extension
	// is dropped they pin disk and can wedge every later repack, so
	// clear the leftovers BEFORE the headroom gate — otherwise the
	// gate measures a heap inflated by the very debris we are about
	// to remove and skips the repair that would free it. The DROP
	// rides a 5s lock_timeout so a busy table aborts the cleanup
	// instead of stalling the maint budget; the next window retries.
	m.dropRepackLeftovers(ctx, pg, user, pass, note)
	// kinedb-maintenance item 3: repack shadows the heap + WAL churn — require
	// free >= 2.5*(heap+wal) on the data fs first; otherwise run
	// only a VACUUM (ANALYZE) and warn (repack would fill the disk).
	free, wal, headroom := m.repackHeadroom(ctx, pg, user, pass,
		res.heapBytes, note)
	if !headroom {
		note(fmt.Sprintf("repack-skipped-insufficient-headroom (free=%dB heap=%dB wal=%dB)",
			free, res.heapBytes, wal))
		logger().Warn("kinedb: pg_repack skipped — insufficient disk headroom, VACUUM only",
			"free", free, "heap", res.heapBytes, "wal", wal)
		res.repackState = "skipped-headroom"
		if _, err := m.d.ExecLongEnv(ctx, m.d.PsqlMaintEnv(pass), m.d.PsqlMaintArgs(pg, user, false,
			"-qc", "VACUUM (ANALYZE) "+kdeps.SQLIdent(m.d.Cfg.Table)), ""); err != nil {
			note(fmt.Sprintf("fallback-vacuum-fail: %v", err))
		}
		return
	}
	// pg_repack runs in its own session, so it cannot hold the
	// advisory lock — probe it and skip the repack this cycle when a
	// compact guard is mid-run (best-effort: the probe releases
	// before repack starts, but the compact is 10-minute-cadenced and
	// retries next daily window).
	if pout, perr := m.d.PsqlScript(ctx, pg, user, pass, m.buildLockProbe()); perr != nil {
		note(fmt.Sprintf("repack-lock-probe-fail: %v", perr))
	} else if strings.Contains(pout, kdeps.LockBusyMarker) {
		res.repackState = "skipped-lock-busy"
		note("repack skipped: compact-guard advisory lock busy")
		logger().Warn("kinedb: pg_repack skipped — compact-guard advisory lock busy")
		return
	}
	repackBin, rerr := repackBinPath(ctx, m.d, pg)
	if rerr != nil {
		// A failed lookup reads identically to "no binary
		// installed" below — record which it was.
		note(fmt.Sprintf("repack-lookup-fail: %v", rerr))
	}
	repackBin = strings.TrimSpace(repackBin)
	if repackBin == "" {
		res.repackState = "no-binary"
		note(fmt.Sprintf(
			"repack-needed-no-binary (heap=%dB dead=%d%%)", res.heapBytes, res.deadPct))
		return
	}
	if _, err := m.d.ExecEnv(ctx, kdeps.PsqlPassEnv(pass), m.d.PsqlArgs(pg, user, false,
		"-qc", "CREATE EXTENSION IF NOT EXISTS pg_repack"), ""); err != nil {
		// pg_repack cannot run without the extension — attempting
		// it anyway fails identically and doubles the error noise.
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-ext-fail: %v", err))
		return
	}
	// --wait-timeout=10 bounds each lock wait inside pg_repack so a
	// wedged table lock fails the run instead of hanging to the
	// client kill; --no-kill-backend keeps it from terminating the
	// client backends it waits on (the session reaper owns that
	// decision, not the repack tool).
	rt0 := m.d.Cfg.Clock.Now()
	if _, err := m.d.ExecLongEnv(ctx, m.d.PsqlMaintEnv(pass), []string{m.d.Cfg.Runtime, "exec",
		"-e", "PGPASSWORD", "-e", "PGOPTIONS", pg, repackBin,
		"-h", "127.0.0.1", "-U", user, "-d", "postgres",
		"-t", "public." + m.d.Cfg.Table,
		"--no-superuser-check", "--no-order",
		"--wait-timeout=10", "--no-kill-backend"}, ""); err == nil {
		res.repackState = "done"
	} else {
		if m.d.LongBudgetExceeded(rt0, err) {
			m.reapOrphanedMaint(ctx, pg, user, pass, note)
			// A killed pg_repack leaves repack_trigger plus
			// repack.log_<oid>/repack.table_<oid> shadow objects —
			// clear them now or they inflate every table until the
			// next daily window's dropRepackLeftovers.
			m.dropRepackLeftovers(ctx, pg, user, pass, note)
		}
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-fail: %v", err))
	}
}

// dropRepackLeftovers clears the debris a killed pg_repack leaves
// behind: the repack_trigger on the target table plus the
// repack.log_<oid> / repack.table_<oid> shadow tables. DROP
// EXTENSION ... CASCADE removes the extension and everything its
// scripts created. lock_timeout caps each lock wait at 5s so a
// table under live write traffic fails the cleanup fast instead of
// queueing behind it for the maint budget. Best-effort: a failure
// only notes — the repack attempt below recreates the extension
// (CREATE EXTENSION IF NOT EXISTS) anyway.
func (m *Maint) dropRepackLeftovers(ctx context.Context, pg, user, pass string,
	note func(string)) {
	script := "SET lock_timeout = '5s';\n" +
		"DROP EXTENSION IF EXISTS pg_repack CASCADE;"
	if _, err := m.d.PsqlScript(ctx, pg, user, pass, script); err != nil {
		note(fmt.Sprintf("repack-leftover-cleanup-fail: %v", err))
		return
	}
	note("repack leftovers cleared (DROP EXTENSION pg_repack CASCADE)")
}

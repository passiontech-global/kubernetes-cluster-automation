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
	// freeze AND the repack phase — has run to its end.
	stampEpoch := false
	defer func() {
		if stampEpoch {
			m.stampMaintEpoch()
		}
	}()

	// (a0) invalid-index-reaper — BEFORE the reindex.
	m.reapInvalidIndexes(ctx, pg, user, pass, res, note)

	// (b) XID wraparound — read MAX(age(datfrozenxid)) first so the
	// FREEZE vacuum can ride the locked session below.
	freeze := m.readXidAge(ctx, pg, user, pass, res, note)

	if !heavy {
		res.okReindex = true
		res.freezeState = "skipped"
		note("heavy block skipped: last-maint-run epoch inside the " +
			"skip window")
		logger().Info("kinedb: maint heavy block skipped — epoch inside the skip window")
		m.readSizes(ctx, pg, user, pass, res, note)
		m.urgentReindex(ctx, pg, user, pass, res, note)
		return
	}

	stampEpoch = m.runHeavyReindexAndFreeze(ctx, pg, user, pass, freeze, res, note)

	// (c) sizes + dead-tuple estimate from pg_stat_user_tables.
	m.readSizes(ctx, pg, user, pass, res, note)
	if !res.statsOK {
		res.okRepack = false
		res.repackState = "assess-fail"
		return
	}
	m.urgentReindex(ctx, pg, user, pass, res, note)

	// (d) pg_repack ONLY when the heap is genuinely bloated.
	m.runRepackIfBloated(ctx, pg, user, pass, res, note)
}

func (m *Maint) runHeavyReindexAndFreeze(
	ctx context.Context,
	pg, user, pass string,
	freeze bool,
	res *Result,
	note func(string),
) (stampEpoch bool) {
	t0 := m.d.Cfg.Clock.Now()
	sout, serr := m.d.PsqlScript(ctx, pg, user, pass,
		m.buildHeavyScript(freeze))
	if serr != nil && m.d.LongBudgetExceeded(t0, serr) {
		m.reapOrphanedMaint(ctx, pg, user, pass, note)
		m.dropRepackLeftovers(ctx, pg, user, pass, note)
	}
	switch {
	case serr != nil:
		res.okReindex = false
		note(fmt.Sprintf("reindex-fail: %v", serr))
		if freeze {
			res.okFreeze = false
			res.freezeState = "fail"
			note(fmt.Sprintf("freeze-vacuum-fail: %v", serr))
		}
		return false
	case strings.Contains(sout, kdeps.LockBusyMarker):
		res.okReindex = true
		logger().Warn("kinedb: maint heavy block skipped — compact-guard advisory lock busy")
		note("heavy block skipped: compact-guard advisory lock busy")
		if freeze {
			note(fmt.Sprintf("freeze skipped: lock busy (xid-age=%d)", res.xidAge))
		}
		return false
	default:
		res.okReindex = true
		if freeze {
			res.freezeState = "done"
		}
		return true
	}
}

func (m *Maint) runRepackIfBloated(
	ctx context.Context,
	pg, user, pass string,
	res *Result,
	note func(string),
) {
	if res.deadPct <= m.d.Cfg.RepackDeadPct ||
		res.heapBytes <= m.d.Cfg.RepackMinHeapBytes {
		return
	}
	m.dropRepackLeftovers(ctx, pg, user, pass, note)
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
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-ext-fail: %v", err))
		return
	}
	rt0 := m.d.Cfg.Clock.Now()
	if _, err := m.d.ExecLongEnv(ctx, m.d.PsqlMaintEnv(pass), []string{m.d.Cfg.Runtime, "exec",
		"-e", "PGPASSWORD", "-e", "PGOPTIONS", pg, repackBin,
		"-h", "127.0.0.1", "-U", user, "-d", "postgres",
		"-t", "public." + m.d.Cfg.Table,
		"--no-superuser-check", "--no-order",
		"--wait-timeout=10", "--no-kill-backend"}, ""); err == nil {
		res.repackState = "done"
		return
	} else {
		if m.d.LongBudgetExceeded(rt0, err) {
			m.reapOrphanedMaint(ctx, pg, user, pass, note)
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

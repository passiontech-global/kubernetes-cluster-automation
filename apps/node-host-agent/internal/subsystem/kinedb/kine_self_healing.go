// kine_self_healing.go — Wave 8 kine-DB self-healing:
//
//  1. Session reaper — every probe round terminates stuck kine
//     sessions (idle-in-transaction >5m, non-maintenance active
//     queries >10m) so they stop holding locks/snapshots the
//     compact guard needs.
//  2. PgBouncer wedge restart — cl_waiting > WaitMax, or e2e_auth
//     failing PGBWedgeCycles consecutive probes while the raw
//     backend login (backend_env) still works, means the pooler
//     itself is the wedge → `runtime restart kine-pgbouncer`
//     under the GuardStateDir last-pgb-restart budget (15m).
//  3. pg_repack headroom gate — a repack shadows the heap plus WAL
//     churn, so it only runs when the data filesystem's free space
//     covers 2.5*(heap+wal); otherwise the cycle falls back to a
//     VACUUM (ANALYZE) and warns.
package kinedb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// pgbWedgeRestartBudget — the last-pgb-restart cooldown file
	// under GuardStateDir (15m between pooler restarts).
	pgbWedgeRestartBudget = 15 * time.Minute
	// repackHeadroomFactor — free space must cover this multiple of
	// (heap + WAL) before pg_repack may run.
	repackHeadroomFactor = 2.5
	// pgbE2EFailFile counts consecutive e2e-auth failures under
	// GuardStateDir (cross-restart persistence).
	pgbE2EFailFile   = "e2e-auth-fails"
	pgbRestartFile   = "last-pgb-restart"
	defaultPGDataDir = "/var/lib/postgresql/data"
)

// reapStuckSessions terminates stuck kine sessions — W8-CP2 item 1.
// Best-effort: a failed query only notes, never fails the probe.
func (k *KineDB) reapStuckSessions(ctx context.Context, pg, user, pass string,
	note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "+
			"WHERE datname = '%s' AND ((state = 'idle in transaction' "+
			"AND state_change < now() - interval '5 minutes') OR "+
			"(state = 'active' AND query_start < now() - interval '10 minutes' "+
			"AND query NOT ILIKE '%%VACUUM%%' AND query NOT ILIKE '%%REINDEX%%' "+
			"AND query NOT ILIKE '%%pg_repack%%'))", "kine"))
	if err != nil {
		note(fmt.Sprintf("reap-sessions-fail: %v", err))
		return
	}
	// -tA returns one 't' per terminated backend.
	if n := strings.Count(out, "t\n") + boolToInt(strings.TrimSpace(out) == "t"); n > 0 {
		note(fmt.Sprintf("reaped %d stuck kine session(s)", n))
		logger().Warn("kinedb: terminated stuck kine sessions", "count", n)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// checkPGBWedge restarts the pooler on saturation/auth wedge — W8-CP2
// item 2. Fire conditions: cl_waiting > WaitMax this cycle, or
// e2e_auth failed PGBWedgeCycles consecutive probes while the raw
// backend login (backend_env) is still ok — i.e. postgres itself is
// healthy, so the wedge lives in pgbouncer.
func (k *KineDB) checkPGBWedge(ctx context.Context, pgb string,
	res *probeResult, note func(string)) {
	dir := k.cfg.GuardStateDir
	failPath := filepath.Join(dir, pgbE2EFailFile)

	saturated := res.poolSeen && res.pool.clWaiting > k.cfg.WaitMax
	// e2e failed AND the raw backend env login still succeeded —
	// backend_env==0 means postgres itself is broken and a pooler
	// restart can't help.
	authWedge := res.checks[checkE2EAuth] == 0 &&
		res.checks[checkBackendEnv] == 1
	fails := 0
	if authWedge {
		prev, _ := readIntFile(failPath)
		fails = int(prev) + 1
		writeIntFile(failPath, int64(fails))
	} else {
		writeIntFile(failPath, 0)
	}
	fires := 2 // e2e_auth must fail twice consecutively
	if saturated || fails >= fires {
		// last-pgb-restart is a last-* rate budget — the shared
		// hoststate rateOK/rateSpend parity (absent/garbage/expired
		// → ok; the spend lands on the restart ATTEMPT).
		if !k.state.RateOK(pgbRestartFile, pgbWedgeRestartBudget) {
			note(fmt.Sprintf("pgb-wedge but in restart cooldown (<15m) cl_waiting=%d e2e_fails=%d",
				res.pool.clWaiting, fails))
			return
		}
		reason := fmt.Sprintf("auth wedge (e2e fail %dx, backend_env ok)", fails)
		if saturated {
			reason = fmt.Sprintf("cl_waiting=%d>%d", res.pool.clWaiting, k.cfg.WaitMax)
		}
		note(fmt.Sprintf("pgbouncer wedge: %s — restarting %s", reason, pgb))
		logger().Warn("kinedb: pgbouncer wedge — restarting pooler",
			"reason", reason, "container", pgb)
		// writeIntFile's lazy MkdirAll — Store.WriteEpochFile does
		// not create the state dir itself.
		_ = os.MkdirAll(dir, 0o755)
		k.state.RateSpend(pgbRestartFile)
		if _, err := k.exec(ctx,
			[]string{k.cfg.Runtime, "restart", pgb}, ""); err != nil {
			note(fmt.Sprintf("pgb-restart-fail: %v", err))
			return
		}
		k.m.cycles.WithLabelValues("probe", "pgb_restart").Inc()
	}
}

// repackHeadroom checks whether the postgres data filesystem has
// >= 2.5*(heap+wal) free before pg_repack — W8-CP2 item 3. walBytes
// comes from pg_ls_waldir; free bytes from `df -B1 <datadir>` inside
// the container. Returns ok=false (and a note) when the check itself
// can't run — inconclusive means DON'T repack, same as assess-fail.
func (k *KineDB) repackHeadroom(ctx context.Context, pg, user, pass string,
	heapBytes int64, note func(string)) (free, wal int64, ok bool) {
	dataDir := k.cfg.PGDataDir
	if dataDir == "" {
		dataDir = defaultPGDataDir
	}
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE((SELECT SUM(size) FROM pg_ls_waldir()),0)")
	if err != nil {
		note(fmt.Sprintf("wal-size-fail: %v", err))
		return 0, 0, false
	}
	wal, err = strconv.ParseInt(firstLine(out), 10, 64)
	if err != nil {
		note(fmt.Sprintf("wal-size-unparsed: %v", err))
		return 0, 0, false
	}
	df, err := k.exec(ctx, []string{k.cfg.Runtime, "exec", pg,
		"df", "-B1", "--output=avail", dataDir}, "")
	if err != nil {
		note(fmt.Sprintf("df-fail: %v", err))
		return 0, 0, false
	}
	// df --output=avail prints a header line then the number.
	var lastLine string
	for _, l := range strings.Split(strings.TrimSpace(df), "\n") {
		lastLine = strings.TrimSpace(l)
	}
	free, err = strconv.ParseInt(lastLine, 10, 64)
	if err != nil {
		note(fmt.Sprintf("df-unparsed: %v", err))
		return 0, 0, false
	}
	need := int64(repackHeadroomFactor * float64(heapBytes+wal))
	if free < need {
		return free, wal, false
	}
	return free, wal, true
}

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
//     W12-CP1 rides the same check: a starved wait queue
//     (maxwait > 10s, or cl_waiting > 0 with sv_active == 0)
//     while the backend runs FEWER active queries than the
//     pool holds server conns means stalled half-open conns →
//     `RECONNECT` on the admin console (restart fallback),
//     2 consecutive probes, same 15m budget.
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
	pgbE2EFailFile = "e2e-auth-fails"
	// pgbStarveFile counts consecutive server-pool-starvation probes
	// (W12-CP1) under GuardStateDir — same cross-restart contract.
	pgbStarveFile = "pgb-starve-cycles"
	// pgbMaxWaitStarveSecs — a client queue older than this marks
	// starvation; a healthy pool drains its queue in milliseconds.
	pgbMaxWaitStarveSecs = 10
	// pgbStarveCycles — consecutive starved probes before the
	// RECONNECT fires (same "two probes" convention as e2e-auth).
	pgbStarveCycles  = 2
	pgbRestartFile   = "last-pgb-restart"
	defaultPGDataDir = "/var/lib/postgresql/data"
)

// reapStuckSessions terminates stuck kine sessions — W8-CP2 item 1.
// The kine TABLE lives inside the database named 'postgres' (the
// psqlArgs -d postgres contract), so datname='kine' alone matched
// nothing: the IN list covers both the real backend database and
// stacks that did create a dedicated kine database. Best-effort: a
// failed query only notes, never fails the probe.
func (k *KineDB) reapStuckSessions(ctx context.Context, pg, user, pass string,
	note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "+
			"WHERE datname IN ('postgres', 'kine') AND ((state = 'idle in transaction' "+
			"AND state_change < now() - interval '5 minutes') OR "+
			"(state = 'active' AND query_start < now() - interval '10 minutes' "+
			"AND query NOT ILIKE '%VACUUM%' AND query NOT ILIKE '%REINDEX%' "+
			"AND query NOT ILIKE '%pg_repack%'))")
	if err != nil {
		note(fmt.Sprintf("reap-sessions-fail: %v", err))
		return
	}
	// -tA returns one 't' per terminated backend.
	if n := strings.Count(out, "t\n") + boolToInt(strings.TrimSpace(out) == "t"); n > 0 {
		k.m.idleTxTerm.Add(float64(n))
		k.m.idleTermTotal += int64(n) // textfile mirror of the counter
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

// activeBackendQueries counts backends currently running a query on
// the postgres/kine databases (self excluded). The W12-CP1
// starvation detector compares this against the pooler's held server
// conns: far fewer active queries than server conns means the conns
// sit in a stalled half-open state (sv_login/sv_tested wedge), not
// real backend load — a RECONNECT flushes them, not a backend fix.
func (k *KineDB) activeBackendQueries(ctx context.Context, pg, user, pass string,
	note func(string)) (int64, bool) {
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT COUNT(pid) FROM pg_stat_activity "+
			"WHERE datname IN ('postgres', 'kine') AND state = 'active' "+
			"AND pid <> pg_backend_pid()")
	if err != nil {
		note(fmt.Sprintf("active-queries-fail: %v", err))
		return 0, false
	}
	v, perr := strconv.ParseInt(firstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("active-queries-unparsed: %v", perr))
		return 0, false
	}
	return v, true
}

// checkPGBWedge remediates the pooler on saturation/auth wedge —
// W8-CP2 item 2 + W12-CP1 starvation. Fire conditions:
//   - cl_waiting > WaitMax this cycle (hard saturation) → restart;
//   - e2e_auth failed 2 consecutive probes while the raw backend
//     login (backend_env) is still ok — postgres itself is healthy,
//     so the wedge lives in pgbouncer → restart;
//   - W12-CP1: the wait queue starved (maxwait > 10s, or cl_waiting
//     > 0 with sv_active == 0) for 2 consecutive probes while
//     backend_env == 1 and pg_stat_activity runs fewer active
//     queries than the pool holds open server conns — the conns are
//     stalled half-open, not busy → RECONNECT on the admin console
//     (drops+reopens the backend conns without bouncing client
//     sockets), falling back to the container restart when the
//     console itself is unreachable.
//
// All three share the last-pgb-restart budget (15m) so the paths
// cannot double-fire inside one cooldown window.
func (k *KineDB) checkPGBWedge(ctx context.Context, pg, pgb, user, pass string,
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

	// W12-CP1: server-pool starvation streak. The backend-env gate
	// is required like the auth wedge's — a broken postgres can
	// legitimately starve the queue and RECONNECT cannot fix it. The
	// active-query count is only asked for once the SHOW POOLS
	// pre-conditions hold (a failed read is inconclusive → resets
	// the streak, never evidence).
	starved := false
	if res.poolSeen && res.checks[checkBackendEnv] == 1 &&
		res.pool.serverConns > 0 &&
		(res.pool.maxWaitSec > pgbMaxWaitStarveSecs ||
			(res.pool.clWaiting > 0 && res.pool.svActive == 0)) {
		if n, ok := k.activeBackendQueries(ctx, pg, user, pass, note); ok {
			starved = n < res.pool.serverConns
		}
	}
	starvePath := filepath.Join(dir, pgbStarveFile)
	streaks := 0
	if starved {
		prev, _ := readIntFile(starvePath)
		streaks = int(prev) + 1
		writeIntFile(starvePath, int64(streaks))
	} else {
		writeIntFile(starvePath, 0)
	}

	fires := 2 // e2e_auth + starvation must persist two consecutive probes
	starveFire := streaks >= pgbStarveCycles
	if !saturated && fails < fires && !starveFire {
		return
	}
	// last-pgb-restart is a last-* rate budget — the shared
	// hoststate rateOK/rateSpend parity (absent/garbage/expired
	// → ok; the spend lands on the remediation ATTEMPT).
	if !k.state.RateOK(pgbRestartFile, pgbWedgeRestartBudget) {
		note(fmt.Sprintf("pgb-wedge but in restart cooldown (<15m) cl_waiting=%d e2e_fails=%d starve_streak=%d",
			res.pool.clWaiting, fails, streaks))
		return
	}
	reason := fmt.Sprintf("auth wedge (e2e fail %dx, backend_env ok)", fails)
	switch {
	case saturated:
		reason = fmt.Sprintf("cl_waiting=%d>%d", res.pool.clWaiting, k.cfg.WaitMax)
	case starveFire:
		reason = fmt.Sprintf("server-pool starvation (maxwait=%ds cl_waiting=%d sv_active=%d sv=%d, streak=%d)",
			res.pool.maxWaitSec, res.pool.clWaiting, res.pool.svActive,
			res.pool.serverConns, streaks)
	}
	note(fmt.Sprintf("pgbouncer wedge: %s — remediating %s", reason, pgb))
	logger().Warn("kinedb: pgbouncer wedge — remediating pooler",
		"reason", reason, "container", pgb)
	// writeIntFile's lazy MkdirAll — Store.WriteEpochFile does
	// not create the state dir itself.
	_ = os.MkdirAll(dir, 0o755)
	k.state.RateSpend(pgbRestartFile)

	// A starvation-only wedge gets RECONNECT first: it closes and
	// reopens every backend conn — the half-open conns are the
	// wedge — without dropping the client sockets a `runtime
	// restart` would kill. Saturation/auth wedges skip it: a queue
	// past WaitMax or a broken auth path wants the full bounce.
	if starveFire && !saturated && fails < fires {
		if _, err := k.exec(ctx, []string{k.cfg.Runtime, "exec",
			"-e", "PGPASSWORD=" + pass, pg,
			"psql", "-h", pgb, "-p", k.cfg.PoolerPort,
			"-U", user, "-d", pgbAdminDB, "-Aqc", "RECONNECT"}, ""); err == nil {
			k.m.cycles.WithLabelValues("probe", "pgb_reconnect").Inc()
			return
		} else {
			note(fmt.Sprintf("pgb-reconnect-fail: %v — falling back to restart", err))
		}
	}
	if _, err := k.exec(ctx,
		[]string{k.cfg.Runtime, "restart", pgb}, ""); err != nil {
		note(fmt.Sprintf("pgb-restart-fail: %v", err))
		return
	}
	k.m.cycles.WithLabelValues("probe", "pgb_restart").Inc()
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

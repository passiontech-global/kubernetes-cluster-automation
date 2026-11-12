// selfheal_test.go — the pgbouncer-pool-starvation pgbouncer server-pool starvation
// tests, lifted out of the flat package's kinedb_test.go.
package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// starvePoolsOut is the pgbouncer-pool-starvation starvation shape: maxwait=12s (>10s)
// on a pool still holding 10 server conns while the queue is short
// — clients wait while the backend is not actually busy.
const starvePoolsOut = `database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode
postgres|postgres|4|0|3|7|0|0|0|12|0|transaction
pgbouncer|pgbouncer|1|0|0|0|0|0|0|0|0|transaction
`

// starveNoActivePoolsOut is the other starvation shape: clients
// queued (cl_waiting=5, still under WaitMax) while NO server conn
// is actually running a query (sv_active=0).
const starveNoActivePoolsOut = `database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode
postgres|postgres|4|5|0|7|0|0|0|2|0|transaction
pgbouncer|pgbouncer|1|0|0|0|0|0|0|0|0|transaction
`

func TestParseShowPoolsMaxWait(t *testing.T) {
	out := "database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode\n" +
		"postgres|postgres|4|2|3|7|0|0|0|42|12345|transaction\n"
	st, ok := parseShowPools(out, "postgres")
	if !ok || st.maxWaitSec != 42 {
		t.Fatalf("maxWaitSec=%d ok=%v want 42", st.maxWaitSec, ok)
	}
	// A multi-row pool takes the worst maxwait across rows (same
	// aggregation rule as cl_waiting).
	multi := "database|user|maxwait|sv_active\n" +
		"postgres|postgres|4|1\npostgres|kine|9|1\npgbouncer|pgbouncer|99|0\n"
	st, ok = parseShowPools(multi, "postgres")
	if !ok || st.maxWaitSec != 9 {
		t.Fatalf("maxWaitSec=%d ok=%v want 9", st.maxWaitSec, ok)
	}
}

// starveFixture returns a Probe whose SHOW POOLS reports the given
// pool output and whose pg_stat_activity claims zero active queries
// — the "conns held but nobody running" half-open shape.
func starveFixture(t *testing.T, poolsOut string) (*Probe, *testutil.FakeExec, string) {
	k, fr, dir := fixture(t, kdepstest.ProbeOKRules)
	fr.On("SHOW POOLS", poolsOut)
	fr.On("pid <> pg_backend_pid", "0\n")
	fr.On("RECONNECT", "RECONNECT\n")
	return k, fr, dir
}

// Two consecutive starved probes → RECONNECT on the admin console
// (no client-socket drop); a third inside the 15m budget is eaten
// by the shared last-pgb-restart cooldown.
func TestPGBStarveReconnectAfterTwoProbes(t *testing.T) {
	k, fr, dir := starveFixture(t, starvePoolsOut)

	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.pool.maxWaitSec != 12 {
		t.Fatalf("maxWaitSec=%d want 12", res.pool.maxWaitSec)
	}
	if fr.Ran("RECONNECT") || fr.Ran("restart kine-pgbouncer") {
		t.Fatalf("remediation fired on the FIRST starved probe:\n%s", fr.Joined())
	}
	// The new series land in the probe textfile.
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
	for _, want := range []string{
		"kine_pgbouncer_client_waiting_connections 0",
		"kine_pgbouncer_maxwait_seconds 12",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}

	k.Cycle(context.Background())
	j := fr.Joined()
	if !strings.Contains(j, "-d pgbouncer -Aqc RECONNECT") {
		t.Fatalf("RECONNECT did not fire on the second starved probe:\n%s", j)
	}
	if strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("restart ran where RECONNECT should have sufficed:\n%s", j)
	}
	if v, err := kdeps.ReadIntFile(filepath.Join(
		k.d.Cfg.GuardStateDir, pgbStarveFile)); err != nil || v != 2 {
		t.Fatalf("starve streak=%d err=%v want 2", v, err)
	}

	// Third probe still starved but inside the 15m budget →
	// cooldown, nothing runs.
	fr.ClearLog()
	res = k.Cycle(context.Background())
	j = fr.Joined()
	if strings.Contains(j, "RECONNECT") ||
		strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("remediation re-fired inside the 15m budget:\n%s", j)
	}
	found := false
	for _, n := range res.notes {
		if strings.Contains(n, "cooldown") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no cooldown note on the third probe: %v", res.notes)
	}
}

// cl_waiting>0 with sv_active==0 is the other starvation shape —
// the queue exists but no server conn actually runs.
func TestPGBStarveOnQueueWithNoActiveConns(t *testing.T) {
	k, fr, _ := starveFixture(t, starveNoActivePoolsOut)
	k.Cycle(context.Background())
	k.Cycle(context.Background())
	if !strings.Contains(fr.Joined(), "-d pgbouncer -Aqc RECONNECT") {
		t.Fatalf("RECONNECT did not fire for cl_waiting+sv_active=0:\n%s",
			fr.Joined())
	}
}

// backend_env==0 vetoes the starve count: a broken backend can
// legitimately starve the queue and RECONNECT cannot help it.
func TestPGBStarveNotCountedWhenBackendBroken(t *testing.T) {
	k, fr, _ := starveFixture(t, starvePoolsOut)
	// The backend-env check is the ONLY query ending in
	// `-tAc select 1` over the loopback psql path — fail it alone
	// (e2e through the pooler keeps succeeding).
	fr.FailOn("-h 127.0.0.1 -U postgres -d postgres -tAc select 1",
		errors.New("password authentication failed"))
	for i := 0; i < 3; i++ {
		k.Cycle(context.Background())
	}
	j := fr.Joined()
	if strings.Contains(j, "RECONNECT") ||
		strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("remediation fired with backend_env=0:\n%s", j)
	}
	if v, _ := kdeps.ReadIntFile(filepath.Join(
		k.d.Cfg.GuardStateDir, pgbStarveFile)); v != 0 {
		t.Fatalf("starve streak=%d want 0 with backend_env=0", v)
	}
}

// A backend that IS busy (active queries >= held server conns) is
// real saturation evidence, not stalled conns — no starvation.
func TestPGBStarveNotCountedWhenBackendBusy(t *testing.T) {
	k, fr, _ := starveFixture(t, starvePoolsOut)
	fr.On("pid <> pg_backend_pid", "10\n") // 10 active == 10 held conns
	k.Cycle(context.Background())
	k.Cycle(context.Background())
	j := fr.Joined()
	if strings.Contains(j, "RECONNECT") ||
		strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("remediation fired on a genuinely busy backend:\n%s", j)
	}
	if v, _ := kdeps.ReadIntFile(filepath.Join(
		k.d.Cfg.GuardStateDir, pgbStarveFile)); v != 0 {
		t.Fatalf("starve streak=%d want 0 on a busy backend", v)
	}
}

// A failed RECONNECT (admin console itself wedged) falls back to
// the container restart inside the same budget spend.
func TestPGBStarveReconnectFallsBackToRestart(t *testing.T) {
	k, fr, _ := starveFixture(t, starvePoolsOut)
	fr.FailOn("RECONNECT", errors.New("console unreachable"))
	k.Cycle(context.Background())
	k.Cycle(context.Background())
	j := fr.Joined()
	if !strings.Contains(j, "RECONNECT") {
		t.Fatalf("RECONNECT not attempted:\n%s", j)
	}
	if !strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("restart fallback missing after RECONNECT failure:\n%s", j)
	}
}

// half-open-pool-starvation: the starvation shape/verdict matrix — including the
// half-open sv_active shape (clients queued, servers "active",
// Postgres running zero queries).
func TestPGBStarveShapeVerdictMatrix(t *testing.T) {
	cases := []struct {
		name                         string
		maxWait, clWaiting, svActive int64
		activeQueries, serverConns   int64
		want                         bool
	}{
		{"quiet pool", 0, 0, 3, 3, 7, false},
		{"old queue, backend busy", 12, 2, 3, 10, 10, false},
		{"old queue, backend idle", 12, 2, 3, 1, 10, true},
		{"queue, no active server", 0, 5, 0, 2, 10, true},
		// Half-open: clients wait on "active" servers but Postgres
		// runs nothing → starved even with a fresh maxwait.
		{"half-open, zero queries", 0, 5, 4, 0, 7, true},
		// Half-open shape but the backend IS running queries →
		// real work, not a wedge.
		{"half-open but busy", 0, 5, 4, 3, 7, false},
		// No queue → neither shape.
		{"no queue", 0, 0, 4, 0, 7, false},
	}
	for _, c := range cases {
		classic, halfOpen := pgbStarveShape(c.maxWait, c.clWaiting, c.svActive)
		if got := starveVerdict(classic, halfOpen, c.activeQueries, c.serverConns); got != c.want {
			t.Fatalf("%s: got %v want %v (classic=%v halfOpen=%v)",
				c.name, got, c.want, classic, halfOpen)
		}
	}
}

// halfOpenPoolsOut is the half-open-pool-starvation shape: clients queued
// (cl_waiting=5, under WaitMax), server conns held AND sv_active>0,
// maxwait fresh — the pool LOOKS healthy while the backend runs
// nothing (the fixture answers 0 active queries).
const halfOpenPoolsOut = `database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode
postgres|postgres|4|5|4|3|0|0|0|0|0|transaction
pgbouncer|pgbouncer|1|0|0|0|0|0|0|0|0|transaction
`

// half-open-pool-starvation end-to-end: the half-open shape sustains 2 consecutive
// probes → RECONNECT; a backend running queries vetoes it.
func TestPGBStarveHalfOpenSvActive(t *testing.T) {
	k, fr, dir := starveFixture(t, halfOpenPoolsOut)

	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if fr.Ran("RECONNECT") {
		t.Fatalf("RECONNECT fired on the FIRST half-open probe:\n%s", fr.Joined())
	}
	k.Cycle(context.Background())
	if !strings.Contains(fr.Joined(), "-d pgbouncer -Aqc RECONNECT") {
		t.Fatalf("RECONNECT did not fire on the second half-open probe:\n%s", fr.Joined())
	}
	if v, err := kdeps.ReadIntFile(filepath.Join(
		k.d.Cfg.GuardStateDir, pgbStarveFile)); err != nil || v != 2 {
		t.Fatalf("starve streak=%d err=%v want 2", v, err)
	}

	// The same shape with a genuinely busy backend (3 active
	// queries) is real work → never counted.
	k, fr, _ = starveFixture(t, halfOpenPoolsOut)
	fr.On("pid <> pg_backend_pid", "3\n")
	k.Cycle(context.Background())
	k.Cycle(context.Background())
	if strings.Contains(fr.Joined(), "RECONNECT") {
		t.Fatalf("RECONNECT fired on a busy backend:\n%s", fr.Joined())
	}
	if v, _ := kdeps.ReadIntFile(filepath.Join(
		dir, pgbStarveFile)); v != 0 {
		t.Fatalf("busy-backend starve streak=%d want 0", v)
	}
}

// The reaper's exemption filter must carry the maintenance-tool
// application_name list AND the query ILIKE guards — a pg_repack /
// pg_dump mid-copy (or our own maint block's statements) must never
// be terminated, or the bloat remediation reaps itself.
func TestStuckSessionPredicateExemptions(t *testing.T) {
	for _, want := range []string{
		"application_name NOT IN ('pg_repack', 'pg_dump', 'node_host_agent_maint')",
		"query NOT ILIKE '%VACUUM%'",
		"query NOT ILIKE '%REINDEX%'",
		"query NOT ILIKE '%pg_repack%'",
		"query NOT ILIKE '%repack.%'",
		"query NOT ILIKE '%ANALYZE%'",
		"query NOT ILIKE '%DROP INDEX%'",
	} {
		if !strings.Contains(stuckSessionPredicate, want) {
			t.Fatalf("stuckSessionPredicate missing %q:\n%s", want,
				stuckSessionPredicate)
		}
	}
}

// TestProbePsqlSessionsCarryAppName: every psql session the probe
// loop spawns must present the exempted application_name — the
// predicate matches on application_name, not on pid, so a session
// without kdeps.PGAPPNAME shows up as 'psql' in pg_stat_activity
// and the reaper would terminate our own long-running maintenance /
// remediation statements. PsqlPassEnv pins the marker; this walks
// the recorded child envs of one full probe cycle.
func TestProbePsqlSessionsCarryAppName(t *testing.T) {
	k, fr, _ := fixture(t, kdepstest.ProbeOKRules)
	fr.On("pg_stat_activity", "0\n")
	k.Cycle(context.Background())

	envs := fr.Envs()
	if len(envs) == 0 {
		t.Fatal("probe cycle spawned no exec children")
	}
	seenPG := false
	for _, env := range envs {
		hasPass := false
		hasAppName := false
		for _, kv := range env {
			if strings.HasPrefix(kv, "PGPASSWORD=") {
				hasPass = true
			}
			if kv == "PGAPPNAME="+kdeps.PGAPPNAME {
				hasAppName = true
			}
		}
		if hasPass {
			seenPG = true
			if !hasAppName {
				t.Fatalf("psql child env missing PGAPPNAME=%s: %v",
					kdeps.PGAPPNAME, env)
			}
		}
	}
	if !seenPG {
		t.Fatal("probe cycle spawned no psql child (fixture drift)")
	}
}

// --- reaper + wedge: read-only diagnostics and failure paths ---

// TestReapStuckSessionsReadOnly: the check-kine-db contract — COUNT
// what the reaper WOULD kill, run no terminate statement, stay
// silent on a clean count.
func TestReapStuckSessionsReadOnly(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "pg_terminate_backend", Err: errors.New("must not run")},
	})
	k.d.Cfg.ReadOnly = true
	var notes []string
	note := func(s string) { notes = append(notes, s) }

	fr.On("COUNT(pid)", "3\n")
	k.reapStuckSessions(context.Background(), "pg", "postgres", "secret", note)
	if len(notes) != 1 ||
		!strings.Contains(notes[0], "read-only: 3 stuck kine session(s) would be reaped") {
		t.Fatalf("notes=%v want one would-reap note", notes)
	}
	if fr.Ran("pg_terminate_backend") {
		t.Fatal("read-only probe ran the terminate statement")
	}

	// A clean count reports nothing.
	fr.On("COUNT(pid)", "0\n")
	notes = nil
	k.reapStuckSessions(context.Background(), "pg", "postgres", "secret", note)
	if len(notes) != 0 {
		t.Fatalf("notes=%v want none for a stuck-free read", notes)
	}
}

// A failed read (either mode) notes and moves on — best-effort reaper.
func TestReapStuckSessionsQueryFail(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		k, _, _ := fixture(t, []testutil.ExecRule{
			{Substr: "pg_stat_activity", Err: errors.New("connection reset")},
		})
		k.d.Cfg.ReadOnly = readOnly
		var notes []string
		k.reapStuckSessions(context.Background(), "pg", "postgres", "secret",
			func(s string) { notes = append(notes, s) })
		if len(notes) != 1 || !strings.Contains(notes[0], "reap-sessions-fail") {
			t.Fatalf("readOnly=%v notes=%v", readOnly, notes)
		}
	}
}

// The terminate path counts one 't' per killed backend — including
// the single-trailing-'t' reply where the text ends without a
// newline (boolToInt's reason to exist).
func TestReapStuckSessionsTerminateCounts(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want int64
	}{
		{"t\nt\nt\n", 3},
		{"t", 1}, // single backend, -tA no trailing newline
	} {
		k, fr, _ := fixture(t, []testutil.ExecRule{
			{Substr: "pg_terminate_backend", Out: tc.out},
		})
		var notes []string
		k.reapStuckSessions(context.Background(), "pg", "postgres", "secret",
			func(s string) { notes = append(notes, s) })
		if got := k.d.M.IdleTermTotal; got != tc.want {
			t.Fatalf("out=%q total=%d want %d", tc.out, got, tc.want)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "reaped") {
			t.Fatalf("out=%q notes=%v", tc.out, notes)
		}
		_ = fr
	}
	if boolToInt(true) != 1 || boolToInt(false) != 0 {
		t.Fatal("boolToInt broken")
	}
}

// activeBackendQueries: the count, and the two inconclusive shapes
// (query failure, unparseable reply) that reset the starve streak.
func TestActiveBackendQueriesPaths(t *testing.T) {
	var notes []string
	note := func(s string) { notes = append(notes, s) }

	k2, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "pid <> pg_backend_pid", Out: "4\n"},
	})
	if n, ok := k2.activeBackendQueries(context.Background(),
		"pg", "postgres", "secret", note); !ok || n != 4 {
		t.Fatalf("n=%d ok=%v want 4,true", n, ok)
	}

	k3, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "pid <> pg_backend_pid", Err: errors.New("down")},
	})
	notes = nil
	if n, ok := k3.activeBackendQueries(context.Background(),
		"pg", "postgres", "secret", note); ok || n != 0 ||
		len(notes) != 1 || !strings.Contains(notes[0], "active-queries-fail") {
		t.Fatalf("n=%d ok=%v notes=%v", n, ok, notes)
	}

	k4, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "pid <> pg_backend_pid", Out: "not-a-number\n"},
	})
	notes = nil
	if n, ok := k4.activeBackendQueries(context.Background(),
		"pg", "postgres", "secret", note); ok || n != 0 ||
		len(notes) != 1 || !strings.Contains(notes[0], "active-queries-unparsed") {
		t.Fatalf("n=%d ok=%v notes=%v", n, ok, notes)
	}
}

// wedgeRes builds the Result half checkPGBWedge consumes — the pool
// snapshot and the two auth checks drive every fire condition.
func wedgeRes(e2eAuth, backendEnv int64, pool poolStats, poolSeen bool) *Result {
	return &Result{
		Checks: map[string]int64{
			CheckE2EAuth:    e2eAuth,
			CheckBackendEnv: backendEnv,
			CheckWire:       1,
			CheckContainers: 1,
		},
		poolSeen: poolSeen,
		pool:     pool,
	}
}

// The three read-only diagnostics: saturation, server-pool
// starvation and the auth wedge each note (and only note) their
// remediation is suppressed.
func TestCheckPGBWedgeReadOnlyDiagnostics(t *testing.T) {
	ctx := context.Background()
	var notes []string
	note := func(s string) { notes = append(notes, s) }

	// Saturated: cl_waiting far past WaitMax.
	k, fr, _ := fixture(t, nil)
	k.d.Cfg.ReadOnly = true
	fr.On("pid <> pg_backend_pid", "0\n") // halfOpen shape → backend queried
	res := wedgeRes(1, 1, poolStats{clWaiting: 50, serverConns: 3}, true)
	k.checkPGBWedge(ctx, "pg", "pgb", "postgres", "secret", res, note)
	if len(notes) != 1 || !strings.Contains(notes[0],
		"read-only: pgbouncer saturated cl_waiting=50") {
		t.Fatalf("saturated notes=%v", notes)
	}

	// Starved: classic queue shape, backend idle → RECONNECT suppressed.
	k, fr, _ = fixture(t, nil)
	k.d.Cfg.ReadOnly = true
	fr.On("pid <> pg_backend_pid", "1\n")
	notes = nil
	res = wedgeRes(1, 1,
		poolStats{clWaiting: 3, svActive: 0, serverConns: 5}, true)
	k.checkPGBWedge(ctx, "pg", "pgb", "postgres", "secret", res, note)
	if len(notes) != 1 || !strings.Contains(notes[0],
		"server-pool starvation") {
		t.Fatalf("starved notes=%v", notes)
	}

	// Auth wedge: e2e failed while the backend login still works.
	k, _, _ = fixture(t, nil)
	k.d.Cfg.ReadOnly = true
	notes = nil
	res = wedgeRes(0, 1, poolStats{}, false)
	k.checkPGBWedge(ctx, "pg", "pgb", "postgres", "secret", res, note)
	if len(notes) != 1 || !strings.Contains(notes[0],
		"read-only: pgbouncer auth wedge") {
		t.Fatalf("auth wedge notes=%v", notes)
	}
}

// A pooler restart failure is noted and counts the cycle as failed —
// the rate budget was spent on the attempt.
func TestCheckPGBWedgeRestartFail(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "restart", Err: errors.New("container locked")},
		{Substr: "pid <> pg_backend_pid", Out: "0\n"},
	})
	var notes []string
	res := wedgeRes(1, 1, poolStats{clWaiting: 99, serverConns: 3}, true)
	k.checkPGBWedge(context.Background(), "pg", "kine-pgbouncer",
		"postgres", "secret", res,
		func(s string) { notes = append(notes, s) })
	// Note 1: the wedge itself; note 2: the failed restart.
	if len(notes) != 2 || !strings.Contains(notes[1], "pgb-restart-fail") {
		t.Fatalf("notes=%v", notes)
	}
	if !fr.Ran("restart kine-pgbouncer") {
		t.Fatalf("restart did not run:\n%s", fr.Joined())
	}
	if _, err := os.Stat(filepath.Join(dir, "guard", pgbRestartFile)); err != nil {
		t.Fatalf("restart budget not spent: %v", err)
	}
}

// The e2e-auth-fail streak persists across probes and resets to 0 on
// a clean probe — the two-consecutive-probes contract.
func TestCheckPGBWedgeE2EStreakPersistsAndResets(t *testing.T) {
	failPath := func(k *Probe) string {
		return filepath.Join(k.d.Cfg.GuardStateDir, pgbE2EFailFile)
	}
	// Stale streak from before a restart: one prior failure.
	k, fr, dir := fixture(t, nil)
	if err := os.MkdirAll(k.d.Cfg.GuardStateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	kdeps.WriteIntFile(filepath.Join(dir, "guard", pgbE2EFailFile), 1)
	var notes []string
	res := wedgeRes(0, 1, poolStats{}, false)
	k.checkPGBWedge(context.Background(), "pg", "pgb", "postgres", "secret",
		res, func(s string) { notes = append(notes, s) })
	if v, err := kdeps.ReadIntFile(failPath(k)); err != nil || v != 2 {
		t.Fatalf("streak=%d err=%v want 2", v, err)
	}
	// fails=2 fires the restart — the auth-wedge reason text.
	if !strings.Contains(fr.Joined(), "restart pgb") {
		t.Fatalf("auth wedge streak 2 did not remediate:\n%s", fr.Joined())
	}

	// A clean probe resets the counter.
	k2, _, _ := fixture(t, nil)
	res = wedgeRes(1, 1, poolStats{}, false)
	k2.checkPGBWedge(context.Background(), "pg", "pgb", "postgres", "secret",
		res, func(string) {})
	if v, err := kdeps.ReadIntFile(failPath(k2)); err != nil || v != 0 {
		t.Fatalf("reset streak=%d err=%v want 0", v, err)
	}
}

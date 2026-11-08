// selfheal_test.go — the W12-CP1 pgbouncer server-pool starvation
// tests, lifted out of the flat package's kinedb_test.go.
package probe

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// starvePoolsOut is the W12-CP1 starvation shape: maxwait=12s (>10s)
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

	res = k.Cycle(context.Background())
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

// W16-CP3: the starvation shape/verdict matrix — including the
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

// halfOpenPoolsOut is the W16-CP3 shape: clients queued
// (cl_waiting=5, under WaitMax), server conns held AND sv_active>0,
// maxwait fresh — the pool LOOKS healthy while the backend runs
// nothing (the fixture answers 0 active queries).
const halfOpenPoolsOut = `database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode
postgres|postgres|4|5|4|3|0|0|0|0|0|transaction
pgbouncer|pgbouncer|1|0|0|0|0|0|0|0|0|transaction
`

// W16-CP3 end-to-end: the half-open shape sustains 2 consecutive
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

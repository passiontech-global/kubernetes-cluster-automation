package kinedb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

const testNow = 1700000000

// fixture builds a KineDB with temp paths, a fake runner and a frozen
// clock. rules answer commands in order.
func fixture(t *testing.T, rules []testutil.ExecRule) (*KineDB, *testutil.FakeExec, string) {
	t.Helper()
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile,
		[]byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := testutil.NewFakeExec(rules...)
	k, err := New(Config{
		EnvFile:       envFile,
		TextfileDir:   filepath.Join(dir, "textfile"),
		GuardStateDir: filepath.Join(dir, "guard"),
		Runtime:       "podman",
		nowFn:         func() time.Time { return time.Unix(testNow, 0) },
		run:           fr.RunStdin,
		wireFn:        func(context.Context, string) bool { return true },
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return k, fr, dir
}

func readText(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "textfile", name))
	if err != nil {
		t.Fatalf("read textfile %s: %v", name, err)
	}
	return string(data)
}

func TestEnvValue(t *testing.T) {
	data := "POSTGRES_USER=\"admin\"\n" +
		"POSTGRES_PASSWORD= 's e c'\n" + // quoted: inner spaces keep
		"export POSTGRES_DB=kine\n" + // export prefix
		"POSTGRES_HOST=db.local # the db vm\n" + // trailing comment
		"POSTGRES_OPTS=\"a # b\"\n" + // quoted '#' is literal
		"POSTGRES_BROKEN='oops\n" + // unclosed quote: leading quote stripped (tr -d parity)
		"OTHER=x\n"
	cases := map[string]string{
		"POSTGRES_USER":     "admin",
		"POSTGRES_PASSWORD": "s e c",
		"POSTGRES_DB":       "kine",
		"POSTGRES_HOST":     "db.local",
		"POSTGRES_OPTS":     "a # b",
		"POSTGRES_BROKEN":   "oops",
		"MISSING":           "",
	}
	for key, want := range cases {
		if got := envValue(data, key); got != want {
			t.Fatalf("%s=%q want %q", key, got, want)
		}
	}
}

func TestWriteTextfileAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := promfile.Write(dir, "kine-db.prom", []byte("m 1\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "kine-db.prom"))
	if err != nil || string(data) != "m 1\n" {
		t.Fatalf("content=%q err=%v", data, err)
	}
	// no tmp leftovers
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
	// second write replaces
	if err := promfile.Write(dir, "kine-db.prom", []byte("m 2\n")); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "kine-db.prom"))
	if string(data) != "m 2\n" {
		t.Fatalf("content=%q", data)
	}
}

func TestParseTripleQuad(t *testing.T) {
	p, q, err := parsePair("10|20\n")
	if err != nil || p != 10 || q != 20 {
		t.Fatalf("pair=%d,%d err=%v", p, q, err)
	}
	if _, _, err := parsePair("garbage\n"); err == nil {
		t.Fatal("expected error on garbage pair")
	}
	a, b, c, err := parseTriple("100|20|300\n")
	if err != nil || a != 100 || b != 20 || c != 300 {
		t.Fatalf("triple=%d,%d,%d err=%v", a, b, c, err)
	}
	if _, _, _, err := parseTriple("garbage\n"); err == nil {
		t.Fatal("expected error on garbage")
	}
	w, x, y, z, err := parseQuad("1|2|3|4\n")
	if err != nil || w != 1 || x != 2 || y != 3 || z != 4 {
		t.Fatalf("quad=%d,%d,%d,%d err=%v", w, x, y, z, err)
	}
}

func TestMatchKineDBHost(t *testing.T) {
	entries := []extraHost{
		{Name: "lb-vm", IP: "10.0.0.1"},
		{Name: "db-vm", IP: "10.0.0.9", KineDB: true},
		{Name: "other-db", IP: "10.0.0.10", KineDB: true},
	}
	if !matchKineDBHost(entries, "db-vm", nil) {
		t.Fatal("hostname match failed")
	}
	if !matchKineDBHost(entries, "unrelated", map[string]bool{"10.0.0.10": true}) {
		t.Fatal("ip match failed")
	}
	if matchKineDBHost(entries, "lb-vm", map[string]bool{"10.0.0.1": true}) {
		t.Fatal("matched entry without kine_db")
	}
	if matchKineDBHost(nil, "db-vm", nil) {
		t.Fatal("matched empty list")
	}
}

func TestDetectByEnvFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "opt/apps/postgres"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "opt/apps/postgres/.env"),
		[]byte("POSTGRES_USER=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Detect(root, "") {
		t.Fatal("Detect missed the .env marker")
	}
	if Detect(t.TempDir(), "") {
		t.Fatal("Detect fired on a bare host")
	}
}

func TestDetectByClusterVars(t *testing.T) {
	root := t.TempDir() // no .env → falls through to vars
	vars := t.TempDir()
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		t.Skip("no hostname")
	}
	cluster := "node_exporter_extra_hosts:\n" +
		"  - { name: lb-vm, ip: \"10.0.0.1\" }\n" +
		"  - { name: " + hostname + ", ip: \"10.0.0.9\", kine_db: true }\n"
	if err := os.WriteFile(filepath.Join(vars, "cluster.yaml"),
		[]byte(cluster), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Detect(root, vars) {
		t.Fatal("Detect missed the kine_db host entry")
	}
	cluster = "node_exporter_extra_hosts:\n  - { name: db-vm, ip: \"10.0.0.9\" }\n"
	if err := os.WriteFile(filepath.Join(vars, "cluster.yaml"),
		[]byte(cluster), 0o644); err != nil {
		t.Fatal(err)
	}
	if Detect(root, vars) {
		t.Fatal("Detect fired without kine_db: true")
	}
	if Detect(root, t.TempDir()) {
		t.Fatal("Detect fired without cluster.yaml")
	}
}

func TestDiscoverContainer(t *testing.T) {
	// Preferred name gone → auto-discover the running postgres-ish
	// container that is not pgbouncer (the 2026-10-01 rename
	// resilience).
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect kine-postgres", Err: errors.New("no such container")},
		{Substr: "ps --format", Out: "kine-pgbouncer\npercona-postgres\ncleanup-old\n"},
		{Substr: "inspect -f", Out: "true"},
	})
	pg := k.pgContainerName(context.Background())
	if pg != "percona-postgres" {
		t.Fatalf("pg=%q want percona-postgres", pg)
	}
	pgb := k.pgbContainerName(context.Background())
	if pgb != "kine-pgbouncer" {
		t.Fatalf("pgb=%q want kine-pgbouncer", pgb)
	}
}

// --- W12-CP1: PgBouncer server-pool starvation & WAIT queue ---

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

// starveFixture returns a KineDB whose SHOW POOLS reports the given
// pool output and whose pg_stat_activity claims zero active queries
// — the "conns held but nobody running" half-open shape.
func starveFixture(t *testing.T, poolsOut string) (*KineDB, *testutil.FakeExec, string) {
	k, fr, dir := fixture(t, probeOKRules)
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

	res := k.probeCycle(context.Background())
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
	content := readText(t, dir, "kine-db.prom")
	for _, want := range []string{
		"kine_pgbouncer_client_waiting_connections 0",
		"kine_pgbouncer_maxwait_seconds 12",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}

	res = k.probeCycle(context.Background())
	j := fr.Joined()
	if !strings.Contains(j, "-d pgbouncer -Aqc RECONNECT") {
		t.Fatalf("RECONNECT did not fire on the second starved probe:\n%s", j)
	}
	if strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("restart ran where RECONNECT should have sufficed:\n%s", j)
	}
	if v, err := readIntFile(filepath.Join(
		k.cfg.GuardStateDir, pgbStarveFile)); err != nil || v != 2 {
		t.Fatalf("starve streak=%d err=%v want 2", v, err)
	}

	// Third probe still starved but inside the 15m budget →
	// cooldown, nothing runs.
	fr.ClearLog()
	res = k.probeCycle(context.Background())
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
	k.probeCycle(context.Background())
	k.probeCycle(context.Background())
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
		k.probeCycle(context.Background())
	}
	j := fr.Joined()
	if strings.Contains(j, "RECONNECT") ||
		strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("remediation fired with backend_env=0:\n%s", j)
	}
	if v, _ := readIntFile(filepath.Join(
		k.cfg.GuardStateDir, pgbStarveFile)); v != 0 {
		t.Fatalf("starve streak=%d want 0 with backend_env=0", v)
	}
}

// A backend that IS busy (active queries >= held server conns) is
// real saturation evidence, not stalled conns — no starvation.
func TestPGBStarveNotCountedWhenBackendBusy(t *testing.T) {
	k, fr, _ := starveFixture(t, starvePoolsOut)
	fr.On("pid <> pg_backend_pid", "10\n") // 10 active == 10 held conns
	k.probeCycle(context.Background())
	k.probeCycle(context.Background())
	j := fr.Joined()
	if strings.Contains(j, "RECONNECT") ||
		strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("remediation fired on a genuinely busy backend:\n%s", j)
	}
	if v, _ := readIntFile(filepath.Join(
		k.cfg.GuardStateDir, pgbStarveFile)); v != 0 {
		t.Fatalf("starve streak=%d want 0 on a busy backend", v)
	}
}

// A failed RECONNECT (admin console itself wedged) falls back to
// the container restart inside the same budget spend.
func TestPGBStarveReconnectFallsBackToRestart(t *testing.T) {
	k, fr, _ := starveFixture(t, starvePoolsOut)
	fr.FailOn("RECONNECT", errors.New("console unreachable"))
	k.probeCycle(context.Background())
	k.probeCycle(context.Background())
	j := fr.Joined()
	if !strings.Contains(j, "RECONNECT") {
		t.Fatalf("RECONNECT not attempted:\n%s", j)
	}
	if !strings.Contains(j, "restart kine-pgbouncer") {
		t.Fatalf("restart fallback missing after RECONNECT failure:\n%s", j)
	}
}

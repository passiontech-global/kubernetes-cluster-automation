package kdeps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// fixture builds a *Deps over a tempdir: stack .env, fake exec, the
// shell-mirroring paths — the same shape the kdepstest fixture gives
// consumers, but package-internal (kdepstest imports kdeps, so it
// cannot be imported here).
func fixture(t *testing.T, rules []testutil.ExecRule) (*Deps, *testutil.FakeExec, string) {
	t.Helper()
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile,
		[]byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := testutil.NewFakeExec(rules...)
	cfg := Config{
		EnvFile:       envFile,
		TextfileDir:   filepath.Join(dir, "textfile"),
		GuardStateDir: filepath.Join(dir, "guard"),
		Runtime:       "podman",
		Clock:         timex.NewCell(func() time.Time { return time.Unix(1700000000, 0) }),
		Run:           fr.RunStdin,
	}
	if err := cfg.ApplyDefaults(); err != nil {
		t.Fatal(err)
	}
	d, err := NewDeps(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return d, fr, dir
}

func TestFirstLine(t *testing.T) {
	for in, want := range map[string]string{
		"100|200\n":         "100|200",
		"\n  \n10|20\n":     "10|20",
		"":                  "",
		"\n\n":              "",
		"  spaced line  \n": "spaced line",
	} {
		if got := FirstLine(in); got != want {
			t.Fatalf("FirstLine(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParsePairErrors(t *testing.T) {
	if _, _, err := ParsePair("one\n"); err == nil {
		t.Fatal("expected error on 1-field row")
	}
	if _, _, err := ParsePair("10|xx\n"); err == nil {
		t.Fatal("expected error on non-int field")
	}
}

func TestParseTripleErrors(t *testing.T) {
	a, b, c, err := ParseTriple(" 1 | 2 | 3 \n")
	if err != nil || a != 1 || b != 2 || c != 3 {
		t.Fatalf("triple=%d,%d,%d err=%v", a, b, c, err)
	}
	if _, _, _, err := ParseTriple("1|2\n"); err == nil {
		t.Fatal("expected error on 2-field row")
	}
	if _, _, _, err := ParseTriple("1|2|x\n"); err == nil {
		t.Fatal("expected error on non-int field")
	}
	if _, _, _, err := ParseTriple("1|x|3\n"); err == nil {
		t.Fatal("expected error on non-int middle field")
	}
}

func TestParseQuadErrors(t *testing.T) {
	a, b, c, d, err := ParseQuad("1|2|3|4\n")
	if err != nil || a != 1 || b != 2 || c != 3 || d != 4 {
		t.Fatalf("quad=%d,%d,%d,%d err=%v", a, b, c, d, err)
	}
	if _, _, _, _, err := ParseQuad("1|2|3\n"); err == nil {
		t.Fatal("expected error on 3-field row")
	}
	if _, _, _, _, err := ParseQuad("1|2|3|x\n"); err == nil {
		t.Fatal("expected error on non-int field")
	}
}

func TestEnvValueEmpty(t *testing.T) {
	if got := EnvValue("KEY=\n", "KEY"); got != "" {
		t.Fatalf("empty value=%q", got)
	}
	if got := EnvValue("", "KEY"); got != "" {
		t.Fatalf("missing=%q", got)
	}
}

func TestSQLQuoteIdent(t *testing.T) {
	if got := SQLQuote("it's"); got != `'it''s'` {
		t.Fatalf("SQLQuote=%q", got)
	}
	if got := SQLIdent(`ta"ble`); got != `"ta""ble"` {
		t.Fatalf("SQLIdent=%q", got)
	}
}

func TestFormatters(t *testing.T) {
	if IntOrNA(true, 42) != "42" || IntOrNA(false, 42) != "NA" {
		t.Fatal("IntOrNA wrong")
	}
	if ReasonOrDash("") != "-" || ReasonOrDash("vacuum") != "vacuum" {
		t.Fatal("ReasonOrDash wrong")
	}
}

func TestParseGIDs(t *testing.T) {
	got := ParseGIDs("1234\n  \n\nabc-9 \n")
	if len(got) != 2 || got[0] != "1234" || got[1] != "abc-9" {
		t.Fatalf("ParseGIDs=%v", got)
	}
	if ParseGIDs("") != nil {
		t.Fatal("expected nil on empty input")
	}
}

func TestIntFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "last-head")
	if _, err := ReadIntFile(path); err == nil {
		t.Fatal("expected error on missing file")
	}
	WriteIntFile(path, 12345)
	got, err := ReadIntFile(path)
	if err != nil || got != 12345 {
		t.Fatalf("read=%d err=%v", got, err)
	}
	if err := os.WriteFile(path, []byte("  77 \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadIntFile(path); got != 77 {
		t.Fatalf("trimmed read=%d", got)
	}
	if err := os.WriteFile(path, []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadIntFile(path); err == nil {
		t.Fatal("expected error on non-int content")
	}
	// Failure branches are logged, not panicked: MkdirAll under a
	// regular file, and an unwritable target.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	WriteIntFile(filepath.Join(blocker, "last-head"), 1)
	WriteIntFile(filepath.Join(blocker, "sub", "last-head"), 1)
}

func TestEmitTextfileLogsFailure(t *testing.T) {
	d, _, dir := fixture(t, nil)
	// TextfileDir is a regular file → WriteLogged fails on MkdirAll;
	// the failure must go through the injected logger, not panic.
	if err := os.WriteFile(filepath.Join(dir, "textfile"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.EmitTextfile("test.prom", &promfile.Builder{})
}

func TestExecBudgetsAndPiping(t *testing.T) {
	d, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "short", Out: "ok-short"},
		{Substr: "long", Out: "ok-long"},
	})
	out, err := d.Exec(context.Background(), []string{"podman", "short"}, "")
	if err != nil || out != "ok-short" {
		t.Fatalf("Exec=%q err=%v", out, err)
	}
	// Exec rides ExecEnv with nil env.
	out, err = d.ExecEnv(context.Background(), nil, []string{"podman", "short"}, "")
	if err != nil || out != "ok-short" {
		t.Fatalf("ExecEnv=%q err=%v", out, err)
	}
	// Env + stdin reach the runner.
	out, err = d.ExecEnv(context.Background(),
		[]string{"PGPASSWORD=secret"}, []string{"podman", "exec", "short"}, "script-body")
	if err != nil || out != "ok-short" {
		t.Fatalf("ExecEnv env=%q err=%v", out, err)
	}
	lastEnv := fr.Envs()[len(fr.Envs())-1]
	if len(lastEnv) != 1 || lastEnv[0] != "PGPASSWORD=secret" {
		t.Fatalf("child env=%v", lastEnv)
	}
	out, err = d.ExecLongEnv(context.Background(), nil, []string{"podman", "long"}, "stdin-body")
	if err != nil || out != "ok-long" {
		t.Fatalf("ExecLongEnv=%q err=%v", out, err)
	}
	// Budgets are observable through the ctx deadline the seam sees.
	// ExecEnv rides CmdTimeout, ExecLongEnv LongCmdTimeout.
	var seen map[string]time.Duration
	spy := func(ctx context.Context, _ []string, argv []string, _ string) (string, error) {
		d, _ := ctx.Deadline()
		seen[strings.Join(argv, " ")] = time.Until(d)
		return "", nil
	}
	d.Cfg.Run = spy
	seen = map[string]time.Duration{}
	_, _ = d.ExecEnv(context.Background(), nil, []string{"short-cmd"}, "")
	_, _ = d.ExecLongEnv(context.Background(), nil, []string{"long-cmd"}, "")
	if dl := seen["short-cmd"]; dl > d.Cfg.CmdTimeout+50*time.Millisecond {
		t.Fatalf("short budget=%v want ~%v", dl, d.Cfg.CmdTimeout)
	}
	if dl := seen["long-cmd"]; dl <= d.Cfg.CmdTimeout+50*time.Millisecond {
		t.Fatalf("long budget=%v want ~%v", dl, d.Cfg.LongCmdTimeout)
	}
	d.Cfg.Run = fr.RunStdin
}

func TestDiscoverContainerFallbacks(t *testing.T) {
	// Preferred exists → returned without scanning ps.
	d, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect kine-postgres", Out: "[]"},
		{Substr: "ps --format", Out: "other\n"},
	})
	if got := d.DiscoverContainer(context.Background(), "kine-postgres", rePGName, rePGExclude); got != "kine-postgres" {
		t.Fatalf("preferred not kept: %q", got)
	}
	if fr.Ran("ps --format") {
		t.Fatal("inspect success must skip the ps scan")
	}
	// Preferred missing, ps fails → preferred returned anyway.
	d, _, _ = fixture(t, []testutil.ExecRule{
		{Substr: "inspect kine-postgres", Err: errors.New("no such container")},
		{Substr: "ps --format", Err: errors.New("docker down")},
	})
	if got := d.DiscoverContainer(context.Background(), "kine-postgres", rePGName, rePGExclude); got != "kine-postgres" {
		t.Fatalf("ps-fail fallback=%q", got)
	}
}

func TestDiscoverContainerMatchExclude(t *testing.T) {
	d, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect preferred", Err: errors.New("gone")},
		{Substr: "ps --format", Out: "\nweb-1\npgbouncer-x\npercona-postgres\ncleanup-postgres\nnot-matching\n"},
	})
	got := d.DiscoverContainer(context.Background(), "preferred",
		regexp.MustCompile(`postgres`), regexp.MustCompile(`cleanup`))
	if got != "percona-postgres" {
		t.Fatalf("discovered=%q", got)
	}
	// Nothing matches → preferred returned.
	d, _, _ = fixture(t, []testutil.ExecRule{
		{Substr: "inspect preferred", Err: errors.New("gone")},
		{Substr: "ps --format", Out: "web-1\n"},
	})
	if got := d.DiscoverContainer(context.Background(), "preferred", rePGName, rePGExclude); got != "preferred" {
		t.Fatalf("no-match fallback=%q", got)
	}
}

func TestPGPGBContainerNames(t *testing.T) {
	// Configured names inspect fine → returned verbatim.
	d, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "[]"},
	})
	if got := d.PGContainerName(context.Background()); got != "kine-postgres" {
		t.Fatalf("pg=%q", got)
	}
	if got := d.PGBContainerName(context.Background()); got != "kine-pgbouncer" {
		t.Fatalf("pgb=%q", got)
	}
	// pg name gone → auto-discovery picks the pgbouncer-looking name
	// only for PGB (pgb match), never for PG (pgbouncer excluded).
	d, _, _ = fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Err: errors.New("gone")},
		{Substr: "ps --format", Out: "pgbouncer-1\npercona-postgres\n"},
	})
	if got := d.PGContainerName(context.Background()); got != "percona-postgres" {
		t.Fatalf("pg auto=%q", got)
	}
	if got := d.PGBContainerName(context.Background()); got != "pgbouncer-1" {
		t.Fatalf("pgb auto=%q", got)
	}
}

func TestContainerRunning(t *testing.T) {
	d, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect -f {{.State.Running}} up", Out: "true\n"},
		{Substr: "inspect -f {{.State.Running}} down", Out: "false\n"},
		{Substr: "inspect -f {{.State.Running}} dead", Err: errors.New("no such container")},
	})
	if !d.ContainerRunning(context.Background(), "up") {
		t.Fatal("running container reported not running")
	}
	if d.ContainerRunning(context.Background(), "down") {
		t.Fatal("stopped container reported running")
	}
	if d.ContainerRunning(context.Background(), "dead") {
		t.Fatal("inspect error reported running")
	}
}

func TestCreds(t *testing.T) {
	d, _, dir := fixture(t, nil)
	user, pass, ok := d.Creds()
	if !ok || user != "postgres" || pass != "secret" {
		t.Fatalf("creds=%q/%q ok=%v", user, pass, ok)
	}
	// Missing file → not ok.
	if err := os.Remove(d.Cfg.EnvFile); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := d.Creds(); ok {
		t.Fatal("missing env file reported ok")
	}
	// Either field blank → not ok.
	envFile := filepath.Join(dir, ".env2")
	if err := os.WriteFile(envFile,
		[]byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.Cfg.EnvFile = envFile
	if _, _, ok := d.Creds(); ok {
		t.Fatal("empty password reported ok")
	}
}

func TestPsqlArgsAndPassEnv(t *testing.T) {
	d, _, _ := fixture(t, nil)
	argv := d.PsqlArgs("kine-postgres", "postgres", false, "-tAc", "select 1")
	want := []string{"podman", "exec", "-e", "PGPASSWORD", "kine-postgres",
		"psql", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres", "-tAc", "select 1"}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Fatalf("PsqlArgs=%v", argv)
	}
	if got := d.PsqlArgs("pg", "u", true); !strings.Contains(strings.Join(got, " "), "exec -i -e PGPASSWORD") {
		t.Fatalf("interactive PsqlArgs=%v", got)
	}
	if got := PsqlPassEnv("s3cret"); len(got) != 2 ||
		got[0] != "PGPASSWORD=s3cret" || got[1] != "PGAPPNAME="+PGAPPNAME {
		t.Fatalf("PsqlPassEnv=%v", got)
	}
	if PGAPPNAME != "node_host_agent_maint" {
		t.Fatalf("PGAPPNAME=%q — the reaper's exemption list must match it",
			PGAPPNAME)
	}
}

func TestPsqlQueryAndScript(t *testing.T) {
	d, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "-tAc", Out: "42\n"},
		{Substr: "ON_ERROR_STOP", Out: "done\n"},
	})
	out, err := d.PsqlQuery(context.Background(), "kine-postgres", "postgres", "pw", "select 1")
	if err != nil || out != "42\n" {
		t.Fatalf("PsqlQuery=%q err=%v", out, err)
	}
	joined := fr.Joined()
	if !strings.Contains(joined, "-tAc select 1") {
		t.Fatalf("query argv missing -tAc: %s", joined)
	}
	envs := fr.Envs()
	lastEnv := envs[len(envs)-1]
	if len(envs) == 0 || len(lastEnv) != 2 ||
		lastEnv[0] != "PGPASSWORD=pw" || lastEnv[1] != "PGAPPNAME="+PGAPPNAME {
		t.Fatalf("query child env=%v", lastEnv)
	}
	out, err = d.PsqlScript(context.Background(), "kine-postgres", "postgres", "pw2", "LOCK; VACUUM;")
	if err != nil || out != "done\n" {
		t.Fatalf("PsqlScript=%q err=%v", out, err)
	}
	last := fr.Last()
	for _, want := range []string{"-i", "-v", "ON_ERROR_STOP=1", "-f", "-"} {
		if !strings.Contains(last, want) {
			t.Fatalf("script argv missing %q: %s", want, last)
		}
	}
}

func TestEmitTextfile(t *testing.T) {
	d, _, dir := fixture(t, nil)
	b := &promfile.Builder{}
	b.Gauge("kine_db_test_metric", "test", 7)
	d.EmitTextfile("test.prom", b)
	data, err := os.ReadFile(filepath.Join(dir, "textfile", "test.prom"))
	if err != nil {
		t.Fatalf("read textfile: %v", err)
	}
	if !strings.Contains(string(data), "kine_db_test_metric 7") {
		t.Fatalf("textfile=%q", data)
	}
}

func TestApplyDefaultsAndValidation(t *testing.T) {
	var cfg Config
	if err := cfg.ApplyDefaults(); err != nil {
		t.Fatalf("ApplyDefaults: %v", err)
	}
	if cfg.ProbeInterval != 2*time.Minute || cfg.GuardInterval != 10*time.Minute ||
		cfg.MaintInterval != 24*time.Hour || cfg.Table != "kine" ||
		cfg.Runtime == "" || cfg.EnvFile != DefaultEnvFile ||
		cfg.PGDataDir != "" || cfg.Clock == nil || cfg.Run == nil || cfg.StatFSFn == nil {
		t.Fatalf("defaults incomplete: %+v", cfg)
	}
	// Non-identifier table rejected.
	bad := Config{Table: "kine; drop table x"}
	if err := bad.ApplyDefaults(); err == nil {
		t.Fatal("expected table validation error")
	}
	// Explicit table kept, clock/seams preserved.
	cell := timex.NewCell(nil)
	keep := Config{Table: "kine2", Clock: cell,
		Run:    func(context.Context, []string, []string, string) (string, error) { return "", nil },
		WireFn: func(context.Context, string) bool { return true }}
	if err := keep.ApplyDefaults(); err != nil {
		t.Fatal(err)
	}
	if keep.Table != "kine2" || keep.Clock != cell {
		t.Fatalf("explicit values clobbered: %+v", keep)
	}
}

// compact-step-cap: the compact step-cap env (NODE_HOST_AGENT_KINEDB_GUARD_MAX_
// STEP_REVISIONS) — set to a positive integer it becomes the compact
// step cap; unset/0/garbage stays disabled.
func TestMaxStepRevisionsEnv(t *testing.T) {
	var absent Config
	if err := absent.ApplyDefaults(); err != nil {
		t.Fatal(err)
	}
	if absent.MaxStepRevisions != 0 {
		t.Fatalf("absent env: MaxStepRevisions=%d want 0 (disabled)", absent.MaxStepRevisions)
	}

	t.Setenv(envnames.EnvKinedbGuardMaxStepRevisions, "250000")
	var set Config
	if err := set.ApplyDefaults(); err != nil {
		t.Fatal(err)
	}
	if set.MaxStepRevisions != 250000 {
		t.Fatalf("set env: MaxStepRevisions=%d want 250000", set.MaxStepRevisions)
	}
	if viaEnv := ConfigFromEnv(EnvDeps{}).MaxStepRevisions; viaEnv != 250000 {
		t.Fatalf("ConfigFromEnv: MaxStepRevisions=%d want 250000", viaEnv)
	}

	t.Setenv(envnames.EnvKinedbGuardMaxStepRevisions, "garbage")
	var junk Config
	if err := junk.ApplyDefaults(); err != nil {
		t.Fatal(err)
	}
	if junk.MaxStepRevisions != 0 {
		t.Fatalf("garbage env: MaxStepRevisions=%d want 0 (disabled)", junk.MaxStepRevisions)
	}
}

func TestStatFSFree(t *testing.T) {
	ratio, err := statfsFree("/tmp")
	if err != nil || ratio <= 0 || ratio > 1 {
		t.Fatalf("statfs /tmp ratio=%v err=%v", ratio, err)
	}
	if _, err := statfsFree(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error on missing path")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(envnames.EnvKinedbEnvFile, "/custom/.env")
	t.Setenv(envnames.EnvKinedbGuardStateDir, "/custom/guard")
	t.Setenv(envnames.EnvKinedbPgDataDir, "/custom/pgdata")
	t.Setenv(envnames.EnvKinedbBackupDir, "/custom/backups")
	t.Setenv(envnames.EnvKinedbBackupInterval, "30m")
	d := EnvDeps{Deps: hostctx.Deps{
		HostPath:    func(p string) string { return "/host" + p },
		TextfileDir: "/tf",
		Clock:       timex.NewCell(nil),
	}}
	cfg := ConfigFromEnv(d)
	if cfg.EnvFile != "/custom/.env" || cfg.GuardStateDir != "/custom/guard" ||
		cfg.PGDataDir != "/custom/pgdata" || cfg.BackupDir != "/custom/backups" ||
		cfg.BackupInterval != 30*time.Minute || cfg.TextfileDir != "/tf" || cfg.Clock == nil {
		t.Fatalf("env config: %+v", cfg)
	}
	// Env unset → host-root-joined defaults.
	t.Setenv(envnames.EnvKinedbEnvFile, "")
	t.Setenv(envnames.EnvKinedbGuardStateDir, "")
	t.Setenv(envnames.EnvKinedbBackupDir, "")
	os.Unsetenv(envnames.EnvKinedbBackupInterval)
	os.Unsetenv(envnames.EnvKinedbPgDataDir)
	cfg = ConfigFromEnv(d)
	if cfg.EnvFile != "/host"+DefaultEnvFile ||
		cfg.GuardStateDir != "/host/var/lib/kine-compact-guard" ||
		cfg.BackupDir != "/host/var/backups/kine" ||
		cfg.BackupInterval != 6*time.Hour || cfg.PGDataDir != "" {
		t.Fatalf("default env config: %+v", cfg)
	}
	// Nil HostPath → identity join.
	cfg = ConfigFromEnv(EnvDeps{})
	if cfg.EnvFile != DefaultEnvFile || cfg.GuardStateDir != "/var/lib/kine-compact-guard" {
		t.Fatalf("identity join config: %+v", cfg)
	}
}

func TestNewDepsBindsState(t *testing.T) {
	d, _, _ := fixture(t, nil)
	if d.M == nil || d.State == nil || d.Cfg.Runtime != "podman" {
		t.Fatalf("NewDeps incomplete: %+v", d.Cfg)
	}
	if _, err := NewDeps(Config{Table: "bad name"}); err == nil {
		t.Fatal("expected ApplyDefaults error to surface from NewDeps")
	}
}

func TestNewMetricsCollectors(t *testing.T) {
	m := NewMetrics()
	// Vec families gather only with children — populate each one.
	m.ProbeOK.WithLabelValues("containers").Set(1)
	m.ServerConns.WithLabelValues("active").Set(1)
	m.MaintOK.WithLabelValues("reindex").Set(1)
	m.MaintRelBytes.WithLabelValues("heap").Set(1)
	m.TopChurn.WithLabelValues("pods").Set(1)
	m.Cycles.WithLabelValues("probe", "ok").Inc()
	if m == nil {
		t.Fatal("nil metrics")
	}
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		if err := reg.Register(c); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range fams {
		names[f.GetName()] = true
	}
	for _, want := range []string{
		"kine_db_probe_ok", "kine_db_head_revision", "kine_db_guard_ok",
		"kine_db_maint_ok", "node_agent_kine_pg_idle_in_tx_terminated_total",
		"kine_db_seq_scans_total", "kine_db_seq_tuples_read_total",
		"kine_db_top_churn_revisions_5m", "kine_db_backup_valid",
		"node_host_agent_kinedb_cycles_total",
	} {
		if !names[want] {
			t.Fatalf("metric %q missing from gather (%d families)", want, len(names))
		}
	}
	// The seq-scan CounterFuncs must track their atomic values and be
	// settable through the domain-set surface.
	m.SeqScansVal.Store(11)
	m.SeqTupReadVal.Store(22)
	fams, _ = reg.Gather()
	vals := map[string]float64{}
	for _, f := range fams {
		for _, mf := range f.GetMetric() {
			vals[f.GetName()] = mf.GetCounter().GetValue()
		}
	}
	if vals["kine_db_seq_scans_total"] != 11 || vals["kine_db_seq_tuples_read_total"] != 22 {
		t.Fatalf("counterfunc values: %v", vals)
	}
}

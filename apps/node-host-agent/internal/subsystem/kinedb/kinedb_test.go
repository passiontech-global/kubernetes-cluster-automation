package kinedb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/prometheus/client_golang/prometheus"
)

// fixture builds a KineDB with temp paths, a fake runner and a frozen
// clock. rules answer commands in order.
func fixture(t *testing.T, rules []testutil.ExecRule) (*KineDB, *testutil.FakeExec, string) {
	t.Helper()
	cfg, fr, dir := kdepstest.Config(t, rules)
	k, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return k, fr, dir
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
		if got := kdeps.EnvValue(data, key); got != want {
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
	p, q, err := kdeps.ParsePair("10|20\n")
	if err != nil || p != 10 || q != 20 {
		t.Fatalf("pair=%d,%d err=%v", p, q, err)
	}
	if _, _, err := kdeps.ParsePair("garbage\n"); err == nil {
		t.Fatal("expected error on garbage pair")
	}
	a, b, c, err := kdeps.ParseTriple("100|20|300\n")
	if err != nil || a != 100 || b != 20 || c != 300 {
		t.Fatalf("triple=%d,%d,%d err=%v", a, b, c, err)
	}
	if _, _, _, err := kdeps.ParseTriple("garbage\n"); err == nil {
		t.Fatal("expected error on garbage")
	}
	w, x, y, z, err := kdeps.ParseQuad("1|2|3|4\n")
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
	pg := k.PGContainerName(context.Background())
	if pg != "percona-postgres" {
		t.Fatalf("pg=%q want percona-postgres", pg)
	}
	pgb := k.PGBContainerName(context.Background())
	if pgb != "kine-pgbouncer" {
		t.Fatalf("pgb=%q want kine-pgbouncer", pgb)
	}
}

func TestName(t *testing.T) {
	k, _, _ := fixture(t, nil)
	if k.Name() != "kinedb" {
		t.Fatalf("Name=%q", k.Name())
	}
}

func TestNewRegistrationConflict(t *testing.T) {
	// A pre-registered duplicate gauge name must fail New via the
	// RegisterAll rollback, not panic on duplicate registration.
	cfg, _, _ := kdepstest.Config(t, nil)
	reg := prometheus.NewRegistry()
	if err := reg.Register(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kine_db_head_revision",
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, reg); err == nil {
		t.Fatal("expected duplicate-registration error")
	}
}

func TestRunLoopsRunUntilCancel(t *testing.T) {
	cfg, fr, _ := kdepstest.Config(t, kdepstest.ProbeOKRules)
	// Tiny cadences so every loop lands at least one cycle before the
	// bounded wait elapses.
	cfg.ProbeInterval = 5 * time.Millisecond
	cfg.GuardInterval = 5 * time.Millisecond
	cfg.MaintInterval = 5 * time.Millisecond
	k, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { k.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && fr.Count() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	if fr.Count() == 0 {
		t.Fatal("no cycle ran")
	}
	// The guard/maint cycles also fire — their runners share the fake.
	if !fr.Ran("MAX(id)") && !fr.Ran("SHOW POOLS") {
		t.Fatalf("unexpected commands: %s", fr.Joined())
	}
}

func TestRunCountsPanics(t *testing.T) {
	cfg, _, _ := kdepstest.Config(t, kdepstest.ProbeOKRules)
	cfg.ProbeInterval = 5 * time.Millisecond
	cfg.GuardInterval = 5 * time.Millisecond
	cfg.MaintInterval = 5 * time.Millisecond
	// A panicking runner must be recovered: cycles{loop,"panic"}
	// increments and the loop keeps ticking until ctx is cancelled.
	cfg.Run = func(context.Context, []string, []string, string) (string, error) {
		panic("boom")
	}
	reg := prometheus.NewRegistry()
	k, err := New(cfg, reg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { k.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	panics := 0.0
	for _, f := range fams {
		if f.GetName() != "node_host_agent_kinedb_cycles_total" {
			continue
		}
		for _, mf := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range mf.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["result"] == "panic" {
				panics += mf.GetCounter().GetValue()
			}
		}
	}
	if panics == 0 {
		t.Fatalf("no panic cycles counted (%v)", fams)
	}
}

// New must surface a rejected config (non-identifier table) as an
// error, not a partially-wired KineDB.
func TestNewRejectsBadTable(t *testing.T) {
	cfg, _, _ := kdepstest.Config(t, nil)
	cfg.Table = "kine; DROP TABLE kine"
	if k, err := New(cfg, nil); err == nil || k != nil {
		t.Fatalf("k=%v err=%v want error and nil k", k, err)
	}
}

// TestDetectHostRootDefaultHostnameMatch: hostRoot "" means "/" —
// the .env fast path probes the live filesystem root and falls
// through to the cluster.yaml match against this host's real
// hostname (read from /etc/hostname on the DB VM, os.Hostname
// fallback in containers).
func TestDetectHostRootDefaultHostnameMatch(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		t.Skip("no hostname")
	}
	vars := t.TempDir()
	cluster := "node_exporter_extra_hosts:\n" +
		"  - { name: " + hostname + ", kine_db: true }\n"
	if err := os.WriteFile(filepath.Join(vars, "cluster.yaml"),
		[]byte(cluster), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Detect("", vars) {
		t.Fatal("hostRoot \"\" must default to / and match the hostname")
	}
}

// A malformed cluster.yaml parses as no entries — detection stays
// fail-quiet instead of panicking on operator YAML drift.
func TestDetectBadYAMLIsQuiet(t *testing.T) {
	root := t.TempDir() // no .env → falls through to vars
	vars := t.TempDir()
	if err := os.WriteFile(filepath.Join(vars, "cluster.yaml"),
		[]byte("node_exporter_extra_hosts: [oops\n\t- broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if Detect(root, vars) {
		t.Fatal("unparseable cluster.yaml must read as no kine_db host")
	}
}

// An empty varsDir skips the cluster.yaml half entirely.
func TestDetectEmptyVarsDir(t *testing.T) {
	if Detect(t.TempDir(), "") {
		t.Fatal("empty varsDir must not detect")
	}
}

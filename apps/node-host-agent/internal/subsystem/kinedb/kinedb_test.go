package kinedb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// rule is one fake-runner reply: first matching substring wins.
type rule struct {
	substr string
	reply  string
	err    error
}

// fakeRun records every argv + stdin and replies by ordered
// substring rules — the same seam style as nethealth's env fixture.
type fakeRun struct {
	mu     sync.Mutex
	cmds   [][]string
	stdins []string
	rules  []rule
}

func (f *fakeRun) run(_ context.Context, argv []string, stdin string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, append([]string{}, argv...))
	f.stdins = append(f.stdins, stdin)
	j := strings.Join(argv, " ")
	for _, r := range f.rules {
		if strings.Contains(j, r.substr) {
			return r.reply, r.err
		}
	}
	return "", nil
}

func (f *fakeRun) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, c := range f.cmds {
		b.WriteString(strings.Join(c, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// lastStdin returns the stdin of the last recorded command ("" if the
// runner never saw stdin).
func (f *fakeRun) lastStdin() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.stdins) - 1; i >= 0; i-- {
		if f.stdins[i] != "" {
			return f.stdins[i]
		}
	}
	return ""
}

const testNow = 1700000000

// fixture builds a KineDB with temp paths, a fake runner and a frozen
// clock. rules answer commands in order.
func fixture(t *testing.T, rules []rule) (*KineDB, *fakeRun, string) {
	t.Helper()
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile,
		[]byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRun{rules: rules}
	k, err := New(Config{
		Enabled:       true,
		EnvFile:       envFile,
		TextfileDir:   filepath.Join(dir, "textfile"),
		GuardStateDir: filepath.Join(dir, "guard"),
		Runtime:       "podman",
		nowFn:         func() time.Time { return time.Unix(testNow, 0) },
		run:           fr.run,
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
	data := "POSTGRES_USER=\"admin\"\nPOSTGRES_PASSWORD= 's e c'\nOTHER=x\n"
	if got := envValue(data, "POSTGRES_USER"); got != "admin" {
		t.Fatalf("user=%q", got)
	}
	// bash `tr -d "\"' "` strips quotes AND spaces.
	if got := envValue(data, "POSTGRES_PASSWORD"); got != "sec" {
		t.Fatalf("pass=%q", got)
	}
	if got := envValue(data, "MISSING"); got != "" {
		t.Fatalf("missing=%q", got)
	}
}

func TestWriteTextfileAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := writeTextfileAtomic(dir, "kine-db.prom", []byte("m 1\n")); err != nil {
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
	if err := writeTextfileAtomic(dir, "kine-db.prom", []byte("m 2\n")); err != nil {
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
	k, _, _ := fixture(t, []rule{
		{substr: "inspect kine-postgres", err: errors.New("no such container")},
		{substr: "ps --format", reply: "kine-pgbouncer\npercona-postgres\ncleanup-old\n"},
		{substr: "inspect -f", reply: "true"},
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

func TestDisabledRunIdles(t *testing.T) {
	k, err := New(Config{Enabled: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { k.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("disabled Run did not exit on cancel")
	}
}

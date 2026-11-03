package kinedb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliConfig builds a Config for RunCheckCLI — the same seams
// fixture() injects, but the runner needs no KineDB wrapper.
func cliConfig(t *testing.T, rules []rule) (Config, *fakeRun) {
	t.Helper()
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile,
		[]byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRun{rules: rules}
	return Config{
		EnvFile: envFile,
		Runtime: "podman",
		run:     fr.run,
		wireFn:  func(context.Context, string) bool { return true },
	}, fr
}

func TestRunCheckCLIAllOK(t *testing.T) {
	cfg, _ := cliConfig(t, probeOKRules)
	var out bytes.Buffer
	code := RunCheckCLI(context.Background(), cfg, &out)
	if code != 0 {
		t.Fatalf("exit=%d output:\n%s", code, out.String())
	}
	got := out.String()
	for _, want := range []string{
		"== kine DB probe tren ",
		"(runtime=podman)",
		"  OK   containers kine-postgres + kine-pgbouncer running",
		"  OK   pgbouncer 127.0.0.1:6432 wire probe",
		"  OK   e2e auth qua pooler",
		"  OK   backend auth: POSTGRES_USER=postgres login duoc postgres",
		"  OK   pgbouncer log sach (server_login_retry/auth fail = 0)",
		"  OK   SHOW POOLS: db postgres co server conn (sv_*>0)",
		"  OK   revision horizon (head=1000 compact_rev=200 live_tup=290)",
		"ALL OK — update an toan.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "  FAIL ") {
		t.Fatalf("unexpected FAIL line:\n%s", got)
	}
}

func TestRunCheckCLIFailures(t *testing.T) {
	cfg, _ := cliConfig(t, []rule{
		{substr: "inspect", reply: "true"},
		{substr: "SHOW POOLS",
			reply: "database|sv_active|sv_idle|cl_waiting\npostgres|0|0|300\n"},
		{substr: "logs --since",
			reply: "server_login_retry\npassword authentication failed\n"},
		{substr: "MAX(id)", reply: "1000|200|290\n"},
		{substr: "select 1", reply: "1\n"},
	})
	cfg.wireFn = func(context.Context, string) bool { return false }
	var out bytes.Buffer
	code := RunCheckCLI(context.Background(), cfg, &out)
	if code != 1 {
		t.Fatalf("exit=%d want 1:\n%s", code, out.String())
	}
	got := out.String()
	for _, want := range []string{
		"  FAIL pgbouncer 127.0.0.1:6432 wire probe",
		"  FAIL pgbouncer log sach (server_login_retry/auth fail = 2)",
		"  FAIL SHOW POOLS:",
		"CO CHECK FAIL — KHONG coi update la xong.",
		"ALTER ROLE <user> WITH PASSWORD",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunCheckCLIContainersDown(t *testing.T) {
	cfg, _ := cliConfig(t, []rule{
		{substr: "inspect", err: errors.New("down")},
		{substr: "ps --format", reply: ""},
	})
	var out bytes.Buffer
	if code := RunCheckCLI(context.Background(), cfg, &out); code != 1 {
		t.Fatalf("exit=%d want 1", code)
	}
	if !strings.Contains(out.String(), "  FAIL containers") {
		t.Fatalf("output:\n%s", out.String())
	}
	// Wire still ran and passed (injected ok) — unconditional check.
	if !strings.Contains(out.String(), "  OK   pgbouncer") {
		t.Fatalf("wire check missing:\n%s", out.String())
	}
}

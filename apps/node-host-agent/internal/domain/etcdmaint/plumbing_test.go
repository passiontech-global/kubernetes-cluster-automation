// plumbing_test.go — the uncovered plumbing edges: Config defaults
// (every empty field + every nil seam), printAlarmList's three
// output branches, flagValue's `--name value` split form,
// findEtcdProcess's unreadable ProcRoot, status's etcdctl error
// propagation, and waitPidExit's timeout.
package etcdmaint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestApplyDefaults fills every empty field and nil seam, then
// proves the default CmdRunner actually reaches hostexec.Run (it
// errors on a nonexistent binary rather than nil-panicking).
func TestApplyDefaults(t *testing.T) {
	var cfg Config
	cfg.applyDefaults()
	if cfg.K0sDir != defaultK0sDir || cfg.Endpoint != defaultEndpoint ||
		cfg.ProcRoot != defaultProcRoot || cfg.Svc != defaultSvc {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.CallTimeout != defaultCallTimeout {
		t.Fatalf("CallTimeout=%v want %v", cfg.CallTimeout, defaultCallTimeout)
	}
	if cfg.CmdRunner == nil || cfg.StartTempEtcd == nil || cfg.SleepFn == nil {
		t.Fatal("nil seam left unwired")
	}
	// The default CmdRunner must be a real exec: a bogus binary
	// surfaces an error, not a panic.
	if _, err := cfg.CmdRunner(context.Background(),
		"/nonexistent/etcdctl", "endpoint", "health"); err == nil {
		t.Fatal("default CmdRunner on missing binary want error")
	}

	// Explicit values win over every default.
	full := Config{
		K0sDir: "/k", Endpoint: "e", ProcRoot: "/p", Svc: "s",
		CallTimeout: time.Second,
		CmdRunner: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("ok"), nil
		},
		StartTempEtcd: func(context.Context, string, []string, string) (TempEtcd, error) {
			return nil, errors.New("unused")
		},
		SleepFn: func(time.Duration) {},
	}
	full.applyDefaults()
	if full.K0sDir != "/k" || full.Endpoint != "e" ||
		full.ProcRoot != "/p" || full.Svc != "s" ||
		full.CallTimeout != time.Second {
		t.Fatalf("explicit fields clobbered: %+v", full)
	}
	if out, _ := full.CmdRunner(context.Background(), "x"); string(out) != "ok" {
		t.Fatal("explicit CmdRunner not preserved")
	}
}

// TestPrintAlarmList drives all three branches: etcdctl error →
// the parenthesised note, empty output → the caller's fallback
// note, non-empty → raw bytes verbatim.
func TestPrintAlarmList(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		out  []byte
		err  error
		want []string
		deny []string
	}{
		{"error", nil, errors.New("fake: alarm list failed"),
			[]string{"(alarm list error: fake: alarm list failed)"}, nil},
		{"empty", []byte("  \n"), nil,
			[]string{"alarm list: (none)"}, nil},
		{"content", []byte("NOSPACE\n"), nil,
			[]string{"NOSPACE"}, []string{"(none)"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			cfg := Config{
				K0sDir:      "/fake/k0s",
				Endpoint:    "https://127.0.0.1:2379",
				Svc:         "k0scontroller",
				CallTimeout: time.Second,
				CmdRunner: func(_ context.Context, _ string,
					args ...string) ([]byte, error) {
					if !strings.Contains(strings.Join(args, " "), "alarm list") {
						t.Fatalf("unexpected args %v", args)
					}
					return tc.out, tc.err
				},
			}
			newRescuer(cfg, &out).printAlarmList(ctx, "alarm list: (none)")
			got := out.String()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("output missing %q: %q", w, got)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(got, d) {
					t.Fatalf("output unexpectedly contains %q: %q", d, got)
				}
			}
		})
	}
}

// TestFlagValue covers both syntaxes (`--name=value` and
// `--name value`) plus the default when absent.
func TestFlagValue(t *testing.T) {
	cases := []struct {
		flags []string
		want  string
	}{
		{[]string{"--data-dir=/x", "--quota-backend-bytes=9"}, "/x"},
		{[]string{"--data-dir", "/y"}, "/y"},
		{[]string{"--other=1"}, "def"},
		// A trailing flag with no value must NOT consume the next
		// flag as its value blindly — i+1<len gates that.
		{[]string{"--data-dir"}, "def"},
	}
	for _, c := range cases {
		if got := flagValue(c.flags, "--data-dir", "def"); got != c.want {
			t.Errorf("flagValue(%v)=%q want %q", c.flags, got, c.want)
		}
	}
}

// TestFindEtcdProcessUnreadableProcRoot: a ProcRoot that does not
// exist surfaces a wrapped read error, not "no process".
func TestFindEtcdProcessUnreadableProcRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-proc")
	r := &rescuer{
		cfg:     Config{ProcRoot: missing},
		etcdBin: "/fake/k0s/bin/etcd",
	}
	_, _, err := r.findEtcdProcess()
	if err == nil || !strings.Contains(err.Error(), "read ") {
		t.Fatalf("err=%v want wrapped read error", err)
	}
}

// TestFindEtcdProcessSkipsNonNumericAndUnreadable: non-pid
// directories and pid dirs whose cmdline is empty/unreadable are
// skipped silently — only a real etcd cmdline match returns.
func TestFindEtcdProcessSkipsNonNumericAndUnreadable(t *testing.T) {
	root := t.TempDir()
	// Non-numeric dir — skipped by the Atoi gate.
	if err := os.MkdirAll(filepath.Join(root, "notapid"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Numeric dir with NO cmdline — ReadFile errors → skipped.
	if err := os.MkdirAll(filepath.Join(root, "777"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Numeric dir with an EMPTY cmdline — skipped (len==0 gate).
	emptyDir := filepath.Join(root, "778")
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emptyDir, "cmdline"),
		nil, 0o644); err != nil {
		t.Fatal(err)
	}

	r := &rescuer{
		cfg:     Config{ProcRoot: root},
		etcdBin: "/fake/k0s/bin/etcd",
	}
	if _, _, err := r.findEtcdProcess(); err == nil ||
		!strings.Contains(err.Error(), "no running etcd process") {
		t.Fatalf("err=%v want the not-found error", err)
	}
}

// TestStatusPropagatesEtcdctlError: `endpoint status -w json`
// failures surface through status() — the caller wraps them.
func TestStatusPropagatesEtcdctlError(t *testing.T) {
	cfg := Config{
		K0sDir: "/fake/k0s", Endpoint: "https://127.0.0.1:2379",
		Svc: "k0scontroller", CallTimeout: time.Second,
		CmdRunner: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("fake: endpoint down")
		},
	}
	r := newRescuer(cfg, &strings.Builder{})
	if _, err := r.status(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "endpoint down") {
		t.Fatalf("err=%v want the etcdctl failure", err)
	}
}

// TestWaitPidExitTimeout: a pid whose /proc dir persists the whole
// budget (never exits, never zombifies) makes waitPidExit report the
// script's "did not exit" failure.
func TestWaitPidExitTimeout(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "4242")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A live (non-zombie) stat entry so procZombie stays false.
	if err := os.WriteFile(filepath.Join(pidDir, "stat"),
		[]byte("4242 (etcd) S 1 1 0 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ProcRoot: procRoot, SleepFn: func(time.Duration) {}}
	r := &rescuer{cfg: cfg}

	if err := r.waitPidExit(context.Background(), 4242); err == nil ||
		!strings.Contains(err.Error(), "did not exit") {
		t.Fatalf("err=%v want the timeout error", err)
	}
}

// TestWaitPidExitZombieCountsAsExited: a Z-state stat file satisfies
// the wait without the /proc dir ever disappearing.
func TestWaitPidExitZombieCountsAsExited(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "4242")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "stat"),
		[]byte("4242 (etcd) Z 1 1 0 0 -1 0 0 0 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ProcRoot: procRoot, SleepFn: func(time.Duration) {}}
	r := &rescuer{cfg: cfg}

	if err := r.waitPidExit(context.Background(), 4242); err != nil {
		t.Fatalf("waitPidExit on zombie: %v", err)
	}
}

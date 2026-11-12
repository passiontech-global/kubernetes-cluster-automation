package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func newFake() *testutil.FakeExec {
	return testutil.NewFakeExec()
}

func TestExecWrapsNsenterUnderHostRoot(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/host", RunCmd: f.Run})
	if _, err := c.systemctl(context.Background(), "is-active", "k0sworker.service"); err != nil {
		t.Fatal(err)
	}
	want := "nsenter -t 1 -m -u -i -n -p -- systemctl is-active k0sworker.service"
	if f.Count() != 1 || f.Nth(0) != want {
		t.Fatalf("argv=%s want [%s]", f.Joined(), want)
	}
}

func TestExecPlainOnHost(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	if _, err := c.systemctl(context.Background(), "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	want := "systemctl daemon-reload"
	if f.Count() != 1 || f.Nth(0) != want {
		t.Fatalf("argv=%s want [%s]", f.Joined(), want)
	}
}

func TestIsActive(t *testing.T) {
	f := newFake()
	f.On("is-active k0sworker.service", "active\n")
	f.On("is-active coredns.service", "inactive\n")
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	ctx := context.Background()
	if !c.IsActive(ctx, "k0sworker.service") {
		t.Fatal("active unit reported down")
	}
	if c.IsActive(ctx, "coredns.service") {
		t.Fatal("inactive unit reported up")
	}
	f.FailOn("is-active nebula.service", errors.New("exit 3"))
	if c.IsActive(ctx, "nebula.service") {
		t.Fatal("errored is-active reported up")
	}
}

func TestActiveSeparatesStateFromProbeFailure(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	ctx := context.Background()
	// `is-active` exits non-zero for every non-active state — a real
	// state word on stdout is a definitive "down", NOT a probe error.
	f.On("is-active coredns.service", "inactive\n")
	if active, err := c.Active(ctx, "coredns.service"); err != nil || active {
		t.Fatalf("Active(inactive)=%v,%v want false,nil", active, err)
	}
	// An error with no state word means the check itself failed —
	// the caller must see the error, not a bare false.
	f.FailOn("is-active dbus.service", errors.New("exit 3"))
	if _, err := c.Active(ctx, "dbus.service"); err == nil {
		t.Fatal("broken systemctl want Active error")
	}
	// Garbage output without an error is still not a state word.
	f.On("is-active weird.service", "??\n")
	if _, err := c.Active(ctx, "weird.service"); err == nil {
		t.Fatal("unparseable is-active output want Active error")
	}
}

func TestUnitExists(t *testing.T) {
	f := newFake()
	f.On("LoadState --value k0sworker.service", "loaded\n")
	f.On("LoadState --value missing.service", "not-found\n")
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	if !c.UnitExists("k0sworker.service") {
		t.Fatal("present unit reported missing")
	}
	if c.UnitExists("missing.service") {
		t.Fatal("absent unit reported present")
	}
	// Probe failure folds to false for the bool wrapper...
	f.FailOn("LoadState --value coredns.service", errors.New("exit 3"))
	if c.UnitExists("coredns.service") {
		t.Fatal("errored LoadState probe reported present")
	}
	// ...but Exists surfaces it so gates can fail closed.
	if _, err := c.Exists(context.Background(), "coredns.service"); err == nil {
		t.Fatal("broken systemctl want Exists error")
	}
	exists, err := c.Exists(context.Background(), "k0sworker.service")
	if err != nil || !exists {
		t.Fatalf("Exists(loaded)=%v,%v want true,nil", exists, err)
	}
	exists, err = c.Exists(context.Background(), "missing.service")
	if err != nil || exists {
		t.Fatalf("Exists(not-found)=%v,%v want false,nil", exists, err)
	}
}

func TestExistsLoadStateClassification(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	ctx := context.Background()
	// Every LoadState word systemd emits: only a working, loaded
	// definition counts as present — masked/bad-setting/stub units
	// exist on disk (or in the manager's references) but cannot be
	// started, so the gate answers absent.
	for _, tc := range []struct {
		name  string
		state string
		want  bool
	}{
		{"loaded", "loaded\n", true},
		{"merged", "merged\n", true},
		{"stub", "stub\n", false},
		{"not-found", "not-found\n", false},
		{"bad-setting", "bad-setting\n", false},
		{"error", "error\n", false},
		{"masked", "masked\n", false},
		{"empty", "", false},
		{"whitespace", "  \n\t\n", false},
		{"unrecognized", "frobnicate\n", false},
	} {
		key := "LoadState --value u.service"
		if tc.state == "" {
			f.Clear(key)
		} else {
			f.On(key, tc.state)
		}
		got, err := c.Exists(ctx, "u.service")
		if err != nil {
			t.Fatalf("Exists(%s) err=%v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("Exists(%s)=%v want %v", tc.name, got, tc.want)
		}
	}
	// rc!=0 is probe failure, not a state answer — Exists reports
	// the error so callers can fail closed.
	f.FailOn("LoadState --value u.service", errors.New("exit 3"))
	if _, err := c.Exists(ctx, "u.service"); err == nil {
		t.Fatal("rc!=0 LoadState probe want Exists error")
	}
}

func TestActiveAge(t *testing.T) {
	f := newFake()
	// Monotonic µs since boot vs /proc/uptime — the shell's method:
	// no wall-clock string, no zone-abbrev parsing. Uptime 10000.25s,
	// unit entered active at 7000000000µs → age ≈ 3000s.
	uptime := filepath.Join(t.TempDir(), "uptime")
	if err := os.WriteFile(uptime, []byte("10000.25 8000.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.On("show -p ActiveEnterTimestampMonotonic --value k0sworker.service", "7000000000\n")
	f.On("show -p ActiveEnterTimestampMonotonic --value dead.service", "0\n")
	c := New(Config{HostRoot: "/", RunCmd: f.Run}, WithProcUptimeFile(uptime))
	ctx := context.Background()
	age, err := c.ActiveAge(ctx, "k0sworker.service")
	if err != nil {
		t.Fatal(err)
	}
	if age < 2999*time.Second || age > 3001*time.Second {
		t.Fatalf("age=%v want ~3000s", age)
	}
	// The exact argv must ask for the monotonic property — the
	// formatted ActiveEnterTimestamp carries an unparseable local
	// zone abbrev.
	joined := f.Last()
	if !strings.Contains(joined, "ActiveEnterTimestampMonotonic --value k0sworker.service") {
		t.Fatalf("argv=%q want the monotonic property", joined)
	}
	if _, err := c.ActiveAge(ctx, "dead.service"); err == nil {
		t.Fatal("zero monotonic timestamp want error")
	}
	f.On("show -p ActiveEnterTimestampMonotonic --value bad.service", "not-a-number\n")
	if _, err := c.ActiveAge(ctx, "bad.service"); err == nil {
		t.Fatal("garbage timestamp want error")
	}
	// Unreadable /proc/uptime → error (never settle blind).
	c2 := New(Config{HostRoot: "/", RunCmd: f.Run},
		WithProcUptimeFile(filepath.Join(t.TempDir(), "missing")))
	if _, err := c2.ActiveAge(ctx, "k0sworker.service"); err == nil {
		t.Fatal("missing uptime file want error")
	}
	// A just-started unit: mono == uptime → age clamps at 0.
	f.On("show -p ActiveEnterTimestampMonotonic --value fresh.service", "10000250000\n")
	age, err = c.ActiveAge(ctx, "fresh.service")
	if err != nil {
		t.Fatal(err)
	}
	if age < 0 || age > time.Second {
		t.Fatalf("fresh unit age=%v want ~0", age)
	}
}

func TestActionCommands(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	ctx := context.Background()
	for _, call := range []func() error{
		func() error { return c.Restart(ctx, "k0sworker.service") },
		func() error { return c.ReloadOrRestart(ctx, "coredns.service") },
		func() error { return c.Signal(ctx, "coredns.service", "SIGUSR1") },
		func() error { return c.DaemonReload(ctx) },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"systemctl restart k0sworker.service",
		"systemctl reload-or-restart coredns.service",
		"systemctl kill -s SIGUSR1 coredns.service",
		"systemctl daemon-reload",
	}
	if f.Count() != len(want) {
		t.Fatalf("cmds=%s", f.Joined())
	}
	for i, w := range want {
		if got := f.Nth(i); got != w {
			t.Fatalf("cmd[%d]=%q want %q", i, got, w)
		}
	}
}

func TestJournal(t *testing.T) {
	f := newFake()
	f.On("journalctl -u k0sworker.service --since -10 min --no-pager",
		"Jan 01 00:00:00 node k0sworker[1]: line\n")
	c := New(Config{HostRoot: "/", RunCmd: f.Run, RunCmdCombined: f.Run})
	out, err := c.Journal(context.Background(), "k0sworker.service", "-10 min")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "line") {
		t.Fatalf("journal out=%q", out)
	}
}

// TestJournalFoldsStderr: journald reports corrupt files on STDERR —
// the snapshot must carry it (ExecCombined/RunCmdCombined), or the
// integrity check's "corrupt" substring test never fires.
func TestJournalFoldsStderr(t *testing.T) {
	combined := newFake()
	combined.On("journalctl -u k0sworker.service --since -10 min --no-pager",
		"File /var/log/journal/a.journal is corrupt, ignoring journal files.\n")
	stdoutOnlyCalled := false
	c := New(Config{
		HostRoot: "/",
		RunCmd: func(context.Context, []string) (string, error) {
			stdoutOnlyCalled = true
			return "", nil
		},
		RunCmdCombined: combined.Run,
	})
	out, err := c.Journal(context.Background(), "k0sworker.service", "-10 min")
	if err != nil {
		t.Fatal(err)
	}
	if stdoutOnlyCalled {
		t.Fatal("Journal must use the combined runner — stderr evidence is lost on Exec")
	}
	if !strings.Contains(out, "corrupt") {
		t.Fatalf("journal out=%q want the stderr corruption notice", out)
	}
}

// TestExecCombinedWrapsNsenter: the combined runner sees the same
// host-namespace wrapping Exec applies.
func TestExecCombinedWrapsNsenter(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/host", RunCmdCombined: f.Run})
	if _, err := c.ExecCombined(context.Background(),
		"journalctl", "-n", "1", "--no-pager"); err != nil {
		t.Fatal(err)
	}
	want := "nsenter -t 1 -m -u -i -n -p -- journalctl -n 1 --no-pager"
	if f.Count() != 1 || f.Nth(0) != want {
		t.Fatalf("argv=%s want [%s]", f.Joined(), want)
	}
}

func TestIsEnabledAcceptsEnabledVocabulary(t *testing.T) {
	// The runner probed `systemctl is-enabled >/dev/null` — rc=0
	// covers every installed-state word, not just literal "enabled".
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	for _, word := range []string{"enabled", "static", "indirect", "alias", "generated", "enabled-runtime", "transient"} {
		f.On("is-enabled u.service", word+"\n")
		if !c.IsEnabled(context.Background(), "u.service") {
			t.Fatalf("is-enabled %q reported disabled", word)
		}
	}
	// disabled / masked / not-found exit non-zero → off.
	f.Clear("is-enabled u.service")
	f.FailOn("is-enabled u.service", errors.New("exit 3"))
	if c.IsEnabled(context.Background(), "u.service") {
		t.Fatal("disabled unit reported enabled")
	}
}

// NOTE: the inherited-pipe WaitDelay test lives in
// platform/hostexec now — that package owns the default
// exec.CommandContext runners, the capped output sink and the
// pipe-close grace bound.

// TestExecBoundedReplacesTimeout: ExecBounded swaps Config.Timeout
// for the per-call budget (the apiserver wedge gate's `timeout 90
// systemctl restart`), while budget <= 0 falls back to
// Config.Timeout.
func TestExecBoundedReplacesTimeout(t *testing.T) {
	var deadline time.Duration
	c := New(Config{
		HostRoot: "/",
		Timeout:  2 * time.Second,
		RunCmd: func(ctx context.Context, argv []string) (string, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				return "", errors.New("ctx has no deadline — budget not applied")
			}
			deadline = time.Until(dl)
			return "ok", nil
		},
	})

	if _, err := c.ExecBounded(context.Background(), 90*time.Second,
		"systemctl", "restart", "k0scontroller.service"); err != nil {
		t.Fatal(err)
	}
	if deadline <= 0 || deadline > 90*time.Second {
		t.Fatalf("budget deadline=%v want (0, 90s]", deadline)
	}

	// budget <= 0 → Config.Timeout (2s) — the unbounded-Exec default.
	if _, err := c.ExecBounded(context.Background(), 0,
		"systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if deadline <= 0 || deadline > 2*time.Second {
		t.Fatalf("fallback deadline=%v want (0, 2s]", deadline)
	}
}

// TestExecBoundedArgvKeepsNsenterWrap: the bounded path enters the
// same NSAll namespace set as Exec — systemctl must reach the HOST
// manager even under a remediation budget.
func TestExecBoundedArgvKeepsNsenterWrap(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/host", RunCmd: f.Run})
	if _, err := c.ExecBounded(context.Background(), 90*time.Second,
		"systemctl", "restart", "k0scontroller.service"); err != nil {
		t.Fatal(err)
	}
	want := "nsenter -t 1 -m -u -i -n -p -- systemctl restart k0scontroller.service"
	if f.Count() != 1 || f.Nth(0) != want {
		t.Fatalf("argv=%s want [%s]", f.Joined(), want)
	}
}

// TestExecCombinedBoundedFoldsStderr: the bounded+combined pairing —
// stderr evidence must survive the per-call budget, which lands on
// the child ctx exactly like ExecBounded.
func TestExecCombinedBoundedFoldsStderr(t *testing.T) {
	combined := newFake()
	combined.On("journalctl -u k0sworker.service --since -10 min",
		"File /var/log/journal/a.journal is corrupt, ignoring journal files.\n")
	stdoutOnlyCalled := false
	var deadline time.Duration
	c := New(Config{
		HostRoot: "/",
		Timeout:  2 * time.Second,
		RunCmd: func(context.Context, []string) (string, error) {
			stdoutOnlyCalled = true
			return "", nil
		},
		RunCmdCombined: func(ctx context.Context, argv []string) (string, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				return "", errors.New("ctx has no deadline — budget not applied")
			}
			deadline = time.Until(dl)
			return combined.Run(ctx, argv)
		},
	})
	out, err := c.ExecCombinedBounded(context.Background(), 45*time.Second,
		"journalctl", "-u", "k0sworker.service", "--since", "-10 min", "--no-pager")
	if err != nil {
		t.Fatal(err)
	}
	if stdoutOnlyCalled {
		t.Fatal("ExecCombinedBounded must use the combined runner — stderr evidence is lost on Exec")
	}
	if !strings.Contains(out, "corrupt") {
		t.Fatalf("out=%q want the stderr corruption notice", out)
	}
	if deadline <= 0 || deadline > 45*time.Second {
		t.Fatalf("budget deadline=%v want (0, 45s]", deadline)
	}
}

// TestEnabledStateWordsAndProbeFailure: the disabled/masked
// vocabulary is a definitive "off" (nil error), while garbage
// output with a clean exit and an error carrying no state word are
// both probe failures — Enabled reports them, IsEnabled folds.
func TestEnabledStateWordsAndProbeFailure(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	ctx := context.Background()

	for _, word := range []string{"disabled", "masked", "masked-runtime", "bad"} {
		f.On("is-enabled u.service", word+"\n")
		enabled, err := c.Enabled(ctx, "u.service")
		if err != nil || enabled {
			t.Fatalf("is-enabled %q = %v,%v want false,nil", word, enabled, err)
		}
	}

	// Garbage stdout + nil error → unexpected-output probe failure.
	f.On("is-enabled weird.service", "??\n")
	if _, err := c.Enabled(ctx, "weird.service"); err == nil {
		t.Fatal("unparseable is-enabled output want Enabled error")
	}
	// Error + state word on stdout is still a real answer — covered
	// by the disabled words above; error + empty output is the
	// probe-failure path IsEnabledAcceptsEnabledVocabulary folds.
}

// TestActionCommandErrors: every systemd action wraps its failure
// with the command + unit in the message — the shell's stderr
// evidence for the journal.
func TestActionCommandErrors(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.Run})
	ctx := context.Background()

	cases := []struct {
		name string
		argv string
		run  func() error
		want string
	}{
		{"restart", "restart u.service", func() error {
			return c.Restart(ctx, "u.service")
		}, "systemctl restart u.service"},
		{"reload-or-restart", "reload-or-restart u.service", func() error {
			return c.ReloadOrRestart(ctx, "u.service")
		}, "systemctl reload-or-restart u.service"},
		{"signal", "kill -s SIGTERM u.service", func() error {
			return c.Signal(ctx, "u.service", "SIGTERM")
		}, "systemctl kill -s SIGTERM u.service"},
		{"daemon-reload", "daemon-reload", func() error {
			return c.DaemonReload(ctx)
		}, "systemctl daemon-reload"},
	}
	for _, tc := range cases {
		f.FailOn(tc.argv, errors.New("exit 1"))
		err := tc.run()
		if err == nil {
			t.Fatalf("%s: want error", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s err=%v want it to name %q", tc.name, err, tc.want)
		}
	}
}

// TestActiveAgeProbeAndClockErrors: ActiveAge surfaces a failed
// systemctl probe, and procfs.UptimeSeconds rejects an unparseable
// uptime file — both mean "not settled" to the caller.
func TestActiveAgeProbeAndClockErrors(t *testing.T) {
	f := newFake()
	uptime := filepath.Join(t.TempDir(), "uptime")
	if err := os.WriteFile(uptime, []byte("10000.25 8000.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(Config{HostRoot: "/", RunCmd: f.Run}, WithProcUptimeFile(uptime))
	ctx := context.Background()

	// systemctl probe failure propagates.
	f.FailOn("show -p ActiveEnterTimestampMonotonic --value u.service",
		errors.New("exit 3"))
	if _, err := c.ActiveAge(ctx, "u.service"); err == nil {
		t.Fatal("broken systemctl want ActiveAge error")
	}

	// Unparseable /proc/uptime → error (never settle blind).
	bad := filepath.Join(t.TempDir(), "uptime")
	if err := os.WriteFile(bad, []byte("not-a-float 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c2 := New(Config{HostRoot: "/", RunCmd: f.Run}, WithProcUptimeFile(bad))
	f.On("show -p ActiveEnterTimestampMonotonic --value v.service", "5000000000\n")
	if _, err := c2.ActiveAge(ctx, "v.service"); err == nil {
		t.Fatal("garbage uptime file want ActiveAge error")
	}

	// procfs.UptimeSeconds (ActiveAge's parser) directly: empty
	// file and missing file.
	empty := filepath.Join(t.TempDir(), "uptime")
	if err := os.WriteFile(empty, []byte("  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := procfs.UptimeSeconds(empty); err == nil {
		t.Fatal("empty uptime file want error")
	}
	if _, err := procfs.UptimeSeconds(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing uptime file want error")
	}
}

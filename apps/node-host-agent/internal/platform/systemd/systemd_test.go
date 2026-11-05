package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fake records every argv the client ran and serves canned replies
// keyed on a substring match of the joined command line.
type fake struct {
	cmds  [][]string
	reply map[string]string // substring → stdout
	fail  map[string]bool   // substring → error
}

func (f *fake) run(_ context.Context, argv []string) (string, error) {
	f.cmds = append(f.cmds, argv)
	joined := strings.Join(argv, " ")
	for k := range f.fail {
		if strings.Contains(joined, k) {
			return "", errors.New("exit 3")
		}
	}
	for k, v := range f.reply {
		if strings.Contains(joined, k) {
			return v, nil
		}
	}
	return "", nil
}

func newFake() *fake {
	return &fake{reply: map[string]string{}, fail: map[string]bool{}}
}

func TestExecWrapsNsenterUnderHostRoot(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/host", RunCmd: f.run})
	if _, err := c.systemctl(context.Background(), "is-active", "k0sworker.service"); err != nil {
		t.Fatal(err)
	}
	want := "nsenter -t 1 -m -u -i -n -p -- systemctl is-active k0sworker.service"
	if len(f.cmds) != 1 || strings.Join(f.cmds[0], " ") != want {
		t.Fatalf("argv=%v want [%s]", f.cmds, want)
	}
}

func TestExecPlainOnHost(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.run})
	if _, err := c.systemctl(context.Background(), "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	want := "systemctl daemon-reload"
	if len(f.cmds) != 1 || strings.Join(f.cmds[0], " ") != want {
		t.Fatalf("argv=%v want [%s]", f.cmds, want)
	}
}

func TestIsActive(t *testing.T) {
	f := newFake()
	f.reply["is-active k0sworker.service"] = "active\n"
	f.reply["is-active coredns.service"] = "inactive\n"
	c := New(Config{HostRoot: "/", RunCmd: f.run})
	ctx := context.Background()
	if !c.IsActive(ctx, "k0sworker.service") {
		t.Fatal("active unit reported down")
	}
	if c.IsActive(ctx, "coredns.service") {
		t.Fatal("inactive unit reported up")
	}
	f.fail["is-active nebula.service"] = true
	if c.IsActive(ctx, "nebula.service") {
		t.Fatal("errored is-active reported up")
	}
}

func TestActiveSeparatesStateFromProbeFailure(t *testing.T) {
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.run})
	ctx := context.Background()
	// `is-active` exits non-zero for every non-active state — a real
	// state word on stdout is a definitive "down", NOT a probe error.
	f.reply["is-active coredns.service"] = "inactive\n"
	if active, err := c.Active(ctx, "coredns.service"); err != nil || active {
		t.Fatalf("Active(inactive)=%v,%v want false,nil", active, err)
	}
	// An error with no state word means the check itself failed —
	// the caller must see the error, not a bare false.
	f.fail["is-active dbus.service"] = true
	if _, err := c.Active(ctx, "dbus.service"); err == nil {
		t.Fatal("broken systemctl want Active error")
	}
	// Garbage output without an error is still not a state word.
	f.reply["is-active weird.service"] = "??\n"
	if _, err := c.Active(ctx, "weird.service"); err == nil {
		t.Fatal("unparseable is-active output want Active error")
	}
}

func TestUnitExists(t *testing.T) {
	f := newFake()
	f.reply["LoadState --value k0sworker.service"] = "loaded\n"
	f.reply["LoadState --value missing.service"] = "not-found\n"
	c := New(Config{HostRoot: "/", RunCmd: f.run})
	if !c.UnitExists("k0sworker.service") {
		t.Fatal("present unit reported missing")
	}
	if c.UnitExists("missing.service") {
		t.Fatal("absent unit reported present")
	}
	// Probe failure folds to false for the bool wrapper...
	f.fail["LoadState --value coredns.service"] = true
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
	c := New(Config{HostRoot: "/", RunCmd: f.run})
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
			delete(f.reply, key)
		} else {
			f.reply[key] = tc.state
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
	f.fail["LoadState --value u.service"] = true
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
	f.reply["show -p ActiveEnterTimestampMonotonic --value k0sworker.service"] = "7000000000\n"
	f.reply["show -p ActiveEnterTimestampMonotonic --value dead.service"] = "0\n"
	c := New(Config{HostRoot: "/", RunCmd: f.run, ProcUptimeFile: uptime})
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
	joined := strings.Join(f.cmds[len(f.cmds)-1], " ")
	if !strings.Contains(joined, "ActiveEnterTimestampMonotonic --value k0sworker.service") {
		t.Fatalf("argv=%q want the monotonic property", joined)
	}
	if _, err := c.ActiveAge(ctx, "dead.service"); err == nil {
		t.Fatal("zero monotonic timestamp want error")
	}
	f.reply["show -p ActiveEnterTimestampMonotonic --value bad.service"] = "not-a-number\n"
	if _, err := c.ActiveAge(ctx, "bad.service"); err == nil {
		t.Fatal("garbage timestamp want error")
	}
	// Unreadable /proc/uptime → error (never settle blind).
	c2 := New(Config{HostRoot: "/", RunCmd: f.run,
		ProcUptimeFile: filepath.Join(t.TempDir(), "missing")})
	if _, err := c2.ActiveAge(ctx, "k0sworker.service"); err == nil {
		t.Fatal("missing uptime file want error")
	}
	// A just-started unit: mono == uptime → age clamps at 0.
	f.reply["show -p ActiveEnterTimestampMonotonic --value fresh.service"] = "10000250000\n"
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
	c := New(Config{HostRoot: "/", RunCmd: f.run})
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
	if len(f.cmds) != len(want) {
		t.Fatalf("cmds=%v", f.cmds)
	}
	for i, w := range want {
		if got := strings.Join(f.cmds[i], " "); got != w {
			t.Fatalf("cmd[%d]=%q want %q", i, got, w)
		}
	}
}

func TestJournal(t *testing.T) {
	f := newFake()
	f.reply["journalctl -u k0sworker.service --since -10 min --no-pager"] =
		"Jan 01 00:00:00 node k0sworker[1]: line\n"
	c := New(Config{HostRoot: "/", RunCmd: f.run, RunCmdCombined: f.run})
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
	combined.reply["journalctl -u k0sworker.service --since -10 min --no-pager"] =
		"File /var/log/journal/a.journal is corrupt, ignoring journal files.\n"
	stdoutOnlyCalled := false
	c := New(Config{
		HostRoot: "/",
		RunCmd: func(context.Context, []string) (string, error) {
			stdoutOnlyCalled = true
			return "", nil
		},
		RunCmdCombined: combined.run,
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
	c := New(Config{HostRoot: "/host", RunCmdCombined: f.run})
	if _, err := c.ExecCombined(context.Background(),
		"journalctl", "-n", "1", "--no-pager"); err != nil {
		t.Fatal(err)
	}
	want := "nsenter -t 1 -m -u -i -n -p -- journalctl -n 1 --no-pager"
	if len(f.cmds) != 1 || strings.Join(f.cmds[0], " ") != want {
		t.Fatalf("argv=%v want [%s]", f.cmds, want)
	}
}

func TestIsEnabledAcceptsEnabledVocabulary(t *testing.T) {
	// The runner probed `systemctl is-enabled >/dev/null` — rc=0
	// covers every installed-state word, not just literal "enabled".
	f := newFake()
	c := New(Config{HostRoot: "/", RunCmd: f.run})
	for _, word := range []string{"enabled", "static", "indirect", "alias", "generated", "enabled-runtime", "transient"} {
		f.reply["is-enabled u.service"] = word + "\n"
		if !c.IsEnabled(context.Background(), "u.service") {
			t.Fatalf("is-enabled %q reported disabled", word)
		}
	}
	// disabled / masked / not-found exit non-zero → off.
	delete(f.reply, "is-enabled u.service")
	f.fail["is-enabled u.service"] = true
	if c.IsEnabled(context.Background(), "u.service") {
		t.Fatal("disabled unit reported enabled")
	}
}

// NOTE: the inherited-pipe WaitDelay test lives in
// platform/hostexec now — that package owns the default
// exec.CommandContext runners, the capped output sink and the
// pipe-close grace bound.

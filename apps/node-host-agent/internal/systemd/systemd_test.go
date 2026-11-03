package systemd

import (
	"context"
	"errors"
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

func TestUnitExists(t *testing.T) {
	f := newFake()
	f.fail["cat missing.service"] = true
	c := New(Config{HostRoot: "/", RunCmd: f.run})
	if !c.UnitExists("k0sworker.service") {
		t.Fatal("present unit reported missing")
	}
	if c.UnitExists("missing.service") {
		t.Fatal("absent unit reported present")
	}
}

func TestActiveAge(t *testing.T) {
	f := newFake()
	ts := time.Now().Add(-5 * time.Minute).UTC().Format("Mon 2006-01-02 15:04:05 MST")
	f.reply["show -p ActiveEnterTimestamp --value k0sworker.service"] = ts + "\n"
	f.reply["show -p ActiveEnterTimestamp --value dead.service"] = "\n"
	c := New(Config{HostRoot: "/", RunCmd: f.run})
	ctx := context.Background()
	age, err := c.ActiveAge(ctx, "k0sworker.service")
	if err != nil {
		t.Fatal(err)
	}
	if age < 4*time.Minute || age > 6*time.Minute {
		t.Fatalf("age=%v want ~5m", age)
	}
	if _, err := c.ActiveAge(ctx, "dead.service"); err == nil {
		t.Fatal("empty timestamp want error")
	}
	f.reply["show -p ActiveEnterTimestamp --value bad.service"] = "not-a-date\n"
	if _, err := c.ActiveAge(ctx, "bad.service"); err == nil {
		t.Fatal("garbage timestamp want error")
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
	c := New(Config{HostRoot: "/", RunCmd: f.run})
	out, err := c.Journal(context.Background(), "k0sworker.service", "-10 min")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "line") {
		t.Fatalf("journal out=%q", out)
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

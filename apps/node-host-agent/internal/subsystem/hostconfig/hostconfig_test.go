package hostconfig

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/topology"
)

type fakeRunner struct{ calls []string }

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "systemctl":
		if len(args) > 0 && args[0] == "is-active" {
			return "inactive", nil
		}
		if len(args) > 0 && args[0] == "show" {
			return "inactive", nil
		}
		return "", nil
	case "sysctl":
		return "bbr\nfq", nil
	}
	return "", nil
}

func newTestReconciler(t *testing.T, varsDir string) *Reconciler {
	t.Helper()
	r, err := New(Config{
		Enabled:            true,
		NodeName:           "node-b",
		HostRoot:           t.TempDir(),
		VarsDir:            varsDir,
		NebulaCertsDir:     t.TempDir(),
		WatchdogScriptsDir: t.TempDir(),
		Runner:             &fakeRunner{},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAtomicWriteIdempotent(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	ch, err := r.writeManaged("/etc/test.conf", []byte("hello"), 0o644)
	if err != nil || !ch {
		t.Fatal("first write should change")
	}
	ch, _ = r.writeManaged("/etc/test.conf", []byte("hello"), 0o644)
	if ch {
		t.Fatal("same content should not change")
	}
	ch, _ = r.writeManaged("/etc/test.conf", []byte("world"), 0o644)
	if !ch {
		t.Fatal("new content should change")
	}
	b, _ := os.ReadFile(filepath.Join(r.cfg.HostRoot, "etc/test.conf"))
	if string(b) != "world" {
		t.Fatal("content mismatch")
	}
	if sha256.Sum256(b) != sha256.Sum256([]byte("world")) {
		t.Fatal("bad hash")
	}
	// tmp file must not linger (converge.Host's staging suffix)
	if _, err := os.Stat(filepath.Join(r.cfg.HostRoot, "etc/test.conf.converge.tmp")); !os.IsNotExist(err) {
		t.Fatal("tmp file lingered")
	}
}

func TestModePreserved(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	_ = os.MkdirAll(filepath.Join(r.cfg.HostRoot, "etc"), 0o755)
	p := filepath.Join(r.cfg.HostRoot, "etc/x.conf")
	_ = os.WriteFile(p, []byte("old"), 0o600)
	if ch, _ := r.writeManaged("/etc/x.conf", []byte("new"), 0o644); !ch {
		t.Fatal("expected change")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v not preserved", st.Mode())
	}
}

func TestPinUnpinHosts(t *testing.T) {
	vars := t.TempDir()
	_ = os.WriteFile(filepath.Join(vars, "interdc_nodes.yaml"), []byte("node-b: {name: b, ip: 10.0.0.1, site: s1}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(vars, "defaults.yaml"), []byte("cp_endpoint: api.test.internal\n"), 0o644)
	_ = os.WriteFile(filepath.Join(vars, "cluster.yaml"), []byte("{}\n"), 0o644)
	r := newTestReconciler(t, vars)
	_ = os.MkdirAll(filepath.Join(r.cfg.HostRoot, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(r.cfg.HostRoot, "etc/hosts"), []byte("127.0.0.1 localhost\n"), 0o644)
	topo, err := topology.Load(topology.Config{VarsDir: vars, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	c := &cyc{r: r, ctx: context.Background(), t: topo}
	c.pinHosts()
	b, _ := os.ReadFile(filepath.Join(r.cfg.HostRoot, "etc/hosts"))
	if !strings.Contains(string(b), "127.0.0.1 api.test.internal") {
		t.Fatalf("hosts not pinned:\n%s", b)
	}
	c.unpinHosts()
	b, _ = os.ReadFile(filepath.Join(r.cfg.HostRoot, "etc/hosts"))
	if strings.Contains(string(b), "api.test.internal") {
		t.Fatal("pin not removed")
	}
}

// TestDirWatcherPollChangedEdge: Poll seeds the baseline without
// firing, latches one edge per fingerprint move, and Changed consumes
// it exactly once — without re-hashing the dirs on the main loop.
func TestDirWatcherPollChangedEdge(t *testing.T) {
	dir := t.TempDir()
	w := &DirWatcher{Dirs: []string{dir}, Period: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Poll(ctx)

	deadline := time.Now().Add(5 * time.Second)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(time.Millisecond)
		}
	}

	waitFor("Poll first scan", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.polled
	})
	if w.Changed() {
		t.Fatal("Changed fired on the freshly-seeded baseline")
	}

	// A file appearing between polls must surface as exactly one edge.
	if err := os.WriteFile(filepath.Join(dir, "vars.yaml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor("dirty latch", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.dirty
	})
	if !w.Changed() {
		t.Fatal("Changed lost the poll-latched edge")
	}
	if w.Changed() {
		t.Fatal("Changed fired twice for one edge")
	}
}

// TestDirWatcherChangedWithoutPoll: the pre-Poll fallback — Changed
// compares a fresh fingerprint against the last snapshot when Poll
// never ran (unit tests calling Changed directly).
func TestDirWatcherChangedWithoutPoll(t *testing.T) {
	dir := t.TempDir()
	w := &DirWatcher{Dirs: []string{dir}}
	if !w.Changed() {
		t.Fatal("first Changed should report a difference vs empty baseline")
	}
	if w.Changed() {
		t.Fatal("second Changed without file modifications should be false")
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !w.Changed() {
		t.Fatal("Changed missed the new file without Poll")
	}
	if w.Changed() {
		t.Fatal("Changed fired twice for the same file without Poll")
	}
}

// TestRunCmdTimeout — a hung host command must fail at the
// per-command deadline, not wedge the converge on the Run ctx.
type hangRunner struct{ entered chan struct{} }

func (h *hangRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	close(h.entered)
	<-ctx.Done()
	return "", ctx.Err()
}

func TestRunCmdTimeout(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	r.cfg.CmdTimeout = 25 * time.Millisecond
	hr := &hangRunner{entered: make(chan struct{})}
	r.cfg.Runner = hr
	done := make(chan error, 1)
	go func() {
		_, err := r.run(context.Background(), "sleep", "999")
		done <- err
	}()
	<-hr.entered
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("hung command returned without error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("per-command deadline did not fire")
	}
}

// TestRunCmdTimeoutDefault — unset CmdTimeout defaults to 120s.
func TestRunCmdTimeoutDefault(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	if r.cfg.CmdTimeout != 120*time.Second {
		t.Fatalf("CmdTimeout = %v, want 120s default", r.cfg.CmdTimeout)
	}
	if r.cfg.CmdTimeoutLong != 10*time.Minute {
		t.Fatalf("CmdTimeoutLong = %v, want 10m default", r.cfg.CmdTimeoutLong)
	}
}

// budgetRunner records the deadline each command ran under — asserts
// the run vs runLong timeout routing.
type budgetRunner struct{ dls map[string]time.Duration }

func (b *budgetRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if b.dls == nil {
		b.dls = map[string]time.Duration{}
	}
	if dl, ok := ctx.Deadline(); ok {
		b.dls[name+" "+strings.Join(args, " ")] = time.Until(dl)
	}
	return "", nil
}

// TestRunLongUsesLongBudget — slow-egress commands must run under
// CmdTimeoutLong while plain queries keep CmdTimeout.
func TestRunLongUsesLongBudget(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	br := &budgetRunner{}
	r.cfg.Runner = br
	ctx := context.Background()
	_, _ = r.run(ctx, "systemctl", "is-active", "x")
	_, _ = r.runLong(ctx, "apt-get", "install", "-y", "x")
	if d := br.dls["systemctl is-active x"]; d <= 115*time.Second || d > 120*time.Second {
		t.Fatalf("run budget = %v, want ~120s", d)
	}
	if d := br.dls["apt-get install -y x"]; d <= 9*time.Minute+55*time.Second || d > 10*time.Minute {
		t.Fatalf("runLong budget = %v, want ~10m", d)
	}
}

// TestRateSpendAtomicLatch — the budget latch is written tmp+rename:
// complete parseable content, no staging file left behind, and
// rateOK honours the fresh latch.
func TestRateSpendAtomicLatch(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	r.cfg.NowFn = func() time.Time { return time.Unix(1_700_000_000, 0) }
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, watchdogStateDir), 0o755); err != nil {
		t.Fatal(err)
	}
	r.state.RateSpend("last-test")
	b, err := os.ReadFile(filepath.Join(r.cfg.HostRoot, watchdogStateDir, "last-test"))
	if err != nil || string(b) != "1700000000\n" {
		t.Fatalf("latch content = %q err %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.HostRoot, watchdogStateDir, ".tmp-last-test")); !os.IsNotExist(err) {
		t.Fatal("staging tmp left behind")
	}
	if r.state.RateOK("last-test", time.Hour) {
		t.Fatal("RateOK ignored a fresh latch")
	}
	if !r.state.RateOK("last-test", 0) {
		t.Fatal("RateOK false on expired latch")
	}
}

// TestRateSpendSweepsTmpOnRenameFailure — when the rename fails the
// .tmp-* staging file must be swept, not stranded in the state dir.
func TestRateSpendSweepsTmpOnRenameFailure(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	// The latch path is a DIRECTORY — os.Rename(tmp, p) onto it
	// fails; the staging tmp must not be left behind.
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, watchdogStateDir, "last-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.state.RateSpend("last-x")
	if _, err := os.Stat(filepath.Join(r.cfg.HostRoot, watchdogStateDir, ".tmp-last-x")); !os.IsNotExist(err) {
		t.Fatal("staging tmp left behind after failed rename")
	}
}

// TestRunStartsWatcherOnce — a panic-restart of Run must not stack a
// second Watcher.Poll goroutine (routeGuardOnce parity).
type countWatcher struct{ polls atomic.Int32 }

func (w *countWatcher) Changed() bool { return false }
func (w *countWatcher) Poll(ctx context.Context) {
	w.polls.Add(1)
	<-ctx.Done()
}

func TestRunStartsWatcherOnce(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	r.cfg.Interval = time.Hour
	w := &countWatcher{}
	r.cfg.Watcher = w
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for w.polls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("watcher never started")
		}
		time.Sleep(time.Millisecond)
	}
	// First Run exits (panic-restart path returns then re-invokes).
	cancel()
	<-done
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go r.Run(ctx2)
	time.Sleep(50 * time.Millisecond) // let a buggy second Poll start
	if got := w.polls.Load(); got != 1 {
		t.Fatalf("Poll started %d times, want 1", got)
	}
}

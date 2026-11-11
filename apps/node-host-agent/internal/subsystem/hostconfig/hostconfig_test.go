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

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func newTestReconciler(t *testing.T, varsDir string) *Reconciler {
	t.Helper()
	r, err := New(Config{
		NodeName:           "node-b",
		HostRoot:           t.TempDir(),
		VarsDir:            varsDir,
		NebulaCertsDir:     t.TempDir(),
		WatchdogScriptsDir: t.TempDir(),
		Runner: testutil.NewFakeRunner(
			testutil.RunnerRule{Substr: "systemctl is-active", Out: "inactive"},
			testutil.RunnerRule{Substr: "systemctl show", Out: "inactive"},
			testutil.RunnerRule{Substr: "sysctl", Out: "bbr\nfq"},
		),
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
	// No staging file may linger (converge.Host stages uniquely as
	// "<base>.converge.tmp-<rand>" — sweep the ".converge.tmp" infix).
	matches, err := filepath.Glob(filepath.Join(r.cfg.HostRoot, "etc", "*converge.tmp*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staging files lingered: %v", matches)
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

// TestRunCmdTimeout — a hung host command must fail at the
// per-command deadline, not wedge the converge on the Run ctx. The
// Hang rule is the wedge; the call is recorded before blocking, so
// Count() is the "the fake is inside Run" signal entered was.
func TestRunCmdTimeout(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	r.cfg.CmdTimeout = 25 * time.Millisecond
	hr := testutil.NewFakeRunner(testutil.RunnerRule{Substr: "sleep", Hang: true})
	r.cfg.Runner = hr
	done := make(chan error, 1)
	go func() {
		_, err := r.run(context.Background(), "sleep", "999")
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for hr.Count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("run never reached the fake runner")
		}
		time.Sleep(time.Millisecond)
	}
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

// TestRunLongUsesLongBudget — slow-egress commands must run under
// CmdTimeoutLong while plain queries keep CmdTimeout. FakeRunner's
// per-call deadline record (DeadlineFor) asserts the routing.
func TestRunLongUsesLongBudget(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	br := testutil.NewFakeRunner()
	r.cfg.Runner = br
	ctx := context.Background()
	_, _ = r.run(ctx, "systemctl", "is-active", "x")
	_, _ = r.runLong(ctx, "apt-get", "install", "-y", "x")
	if d, ok := br.DeadlineFor("systemctl is-active x"); !ok || d <= 115*time.Second || d > 120*time.Second {
		t.Fatalf("run budget = %v (ok=%v), want ~120s", d, ok)
	}
	if d, ok := br.DeadlineFor("apt-get install -y x"); !ok || d <= 9*time.Minute+55*time.Second || d > 10*time.Minute {
		t.Fatalf("runLong budget = %v (ok=%v), want ~10m", d, ok)
	}
}

// TestRateSpendAtomicLatch — the budget latch is written tmp+rename:
// complete parseable content, no staging file left behind, and
// rateOK honours the fresh latch.
func TestRateSpendAtomicLatch(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	r.cfg.Clock.Set(func() time.Time { return time.Unix(1_700_000_000, 0) })
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

// ---------- Reconciler identity + systemd verb wrappers ----------

// TestReconcilerName — the supervisor registry key.
func TestReconcilerName(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	if got := r.Name(); got != "hostconfig" {
		t.Fatalf("Name() = %q want hostconfig", got)
	}
}

// TestIsActiveProbesAndFoldsProbeFailure — isActive reads
// `systemctl is-active`: a clean "active" answer is true, and a
// failing probe (dbus down, systemctl missing) folds to false —
// unknown is not active.
func TestIsActiveProbesAndFoldsProbeFailure(t *testing.T) {
	sr := newScripted(map[string]string{
		"systemctl is-active k0sworker.service": "active\n",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: writeVarsDir(t, ""), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.isActive(context.Background(), "k0sworker.service") {
		t.Fatal("is-active=active must read active")
	}
	sr.FailOn("systemctl is-active", nil)
	if r.isActive(context.Background(), "k0sworker.service") {
		t.Fatal("a failed probe must fold to inactive")
	}
}

// TestStopReloadServiceActionsAndErrorAttribution — stop/reload run
// their systemctl verb and count the action; a failed verb counts the
// active cycle via noteErr, and a clean verb counts nothing.
func TestStopReloadServiceActionsAndErrorAttribution(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	unit := "nebula@interdc.service"

	r.stopService(context.Background(), unit)
	r.reloadService(context.Background(), unit)
	if len(sr.CallsMatching("systemctl stop "+unit)) != 1 {
		t.Fatalf("stop verb not run: %v", sr.CallsMatching("systemctl"))
	}
	if len(sr.CallsMatching("systemctl reload "+unit)) != 1 {
		t.Fatalf("reload verb not run: %v", sr.CallsMatching("systemctl"))
	}
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("stop:" + unit)); got != 1 {
		t.Fatalf("actions{stop:%s} = %v want 1", unit, got)
	}
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("reload:" + unit)); got != 1 {
		t.Fatalf("actions{reload:%s} = %v want 1", unit, got)
	}
	if c.errs != 0 {
		t.Fatalf("errs = %d after clean verbs", c.errs)
	}

	// failed verbs still count their action AND the cycle error.
	sr.FailOn("systemctl stop", nil)
	sr.FailOn("systemctl reload", nil)
	r.stopService(context.Background(), unit)
	r.reloadService(context.Background(), unit)
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("stop:" + unit)); got != 2 {
		t.Fatalf("actions{stop:%s} = %v want 2 (failure must still count)", unit, got)
	}
	if c.errs != 2 {
		t.Fatalf("errs = %d want 2 — failed verbs must count the cycle", c.errs)
	}
}

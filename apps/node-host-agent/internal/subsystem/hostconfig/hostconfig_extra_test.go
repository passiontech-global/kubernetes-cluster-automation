// hostconfig_extra_test.go — Reconciler plumbing coverage beyond the
// core suite: Config.applyDefaults defaults, render failure paths, the
// systemd verb wrappers' error attribution (ensure/enable/start/
// restart/stop), the shPort gate, and Run's vars-change watch edge
// driving a follow-up converge. (DirWatcher coverage moved with the
// type to internal/platform/fileconf/dirwatcher_test.go.)
package hostconfig

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// ---------- Config.applyDefaults ----------

// TestApplyDefaultsTable — every unset knob gets its default and the
// derived fields (NodeName fallback, Standalone) resolve.
func TestApplyDefaultsTable(t *testing.T) {
	var c Config
	c.applyDefaults()
	if c.HostRoot == "" || c.VarsDir == "" || c.NebulaCertsDir == "" ||
		c.WatchdogScriptsDir == "" || c.DownloadDir == "" {
		t.Fatalf("path defaults unset: %+v", c)
	}
	if c.Runner == nil || c.Clock == nil {
		t.Fatal("Runner/Clock defaults unset")
	}
	if c.Interval <= 0 || c.CmdTimeout <= 0 || c.CmdTimeoutLong <= 0 || c.HTTPTimeout <= 0 {
		t.Fatalf("duration defaults unset: %+v", c)
	}

	hn := Config{Hostname: "fallback-host"}
	hn.applyDefaults()
	if hn.NodeName != "fallback-host" {
		t.Fatalf("NodeName = %q, want the Hostname fallback", hn.NodeName)
	}

	root := Config{HostRoot: "/"}
	root.applyDefaults()
	if !root.Standalone {
		t.Fatal("HostRoot / must force Standalone")
	}
	pod := Config{HostRoot: t.TempDir()}
	pod.applyDefaults()
	if pod.Standalone {
		t.Fatal("sandboxed HostRoot must not force Standalone")
	}
}

// ---------- render ----------

// TestRenderUnknownTemplate — a missing embedded template errors with
// the lookup miss instead of rendering empty bytes.
func TestRenderUnknownTemplate(t *testing.T) {
	vars := writeVarsDir(t, "")
	r := newTestReconciler(t, vars)
	if b, err := r.render("no-such.j2", map[string]any{}); err == nil {
		t.Fatalf("render of unknown template returned %q", b)
	}
}

// ---------- systemd verb wrappers ----------

// TestEnsureServiceStopAndFailureAttribution — ensureService(enable,
// false) routes to stop; every failing verb lands its action metric
// AND counts a cycle error via noteErr.
func TestEnsureServiceStopAndFailureAttribution(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.FailOn("systemctl enable", nil)
	sr.FailOn("systemctl start", nil)
	sr.FailOn("systemctl restart", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")

	r.ensureService(c.ctx, "unit-a.service", true, true)
	if n := len(sr.CallsMatching("systemctl stop unit-a.service")); n != 0 {
		t.Fatalf("stop ran on a start=true ensure: %v", sr.Calls())
	}
	if c.errs != 2 {
		t.Fatalf("errs = %d, want enable+start failures counted", c.errs)
	}
	for _, act := range []string{"enable:unit-a.service", "start:unit-a.service"} {
		if got := promtestutil.ToFloat64(r.actions.WithLabelValues(act)); got != 1 {
			t.Fatalf("actions{%s} = %v", act, got)
		}
	}

	c.errs = 0
	sr.ClearLog()
	r.ensureService(c.ctx, "unit-a.service", false, false)
	if len(sr.CallsMatching("systemctl stop unit-a.service")) != 1 {
		t.Fatal("ensure(enable=false) did not stop the unit")
	}
	if len(sr.CallsMatching("systemctl enable")) != 0 {
		t.Fatal("enable ran on a enable=false ensure")
	}

	c.errs = 0
	r.restartService(c.ctx, "unit-a.service")
	if c.errs != 1 {
		t.Fatalf("restart failure not counted: %d", c.errs)
	}
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("restart:unit-a.service")); got != 1 {
		t.Fatalf("actions{restart} = %v", got)
	}
}

// ---------- sh -c gates ----------

// TestShPortRefusalCounts — a non-port value is refused for --dport
// interpolation and counts a cycle error.
func TestShPortRefusalCounts(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	if c.shPort("probe", "6443; rm -rf /") {
		t.Fatal("injection payload accepted as a port")
	}
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the refusal counted", c.errs)
	}
	if !c.shPort("probe", "6443") || !c.shPort("probe", "") {
		t.Fatal("valid/empty ports must pass")
	}
}

// ---------- Run watch edge ----------

// edgeWatcher — false on the startup swallow, true once afterwards so
// Run's watch loop drives exactly one follow-up converge.
type edgeWatcher struct {
	calls atomic.Int32
	polls atomic.Int32
}

func (w *edgeWatcher) Changed() bool {
	n := w.calls.Add(1)
	return n > 1 // first call is Run's startup-edge swallow
}

func (w *edgeWatcher) Poll(ctx context.Context) {
	w.polls.Add(1)
	<-ctx.Done()
}

// TestRunWatchEdgeConverges — a vars/cert change observed by the
// watcher converges a second time through the watch loop (not the
// interval tick), then ctx cancel unwinds Run.
func TestRunWatchEdgeConverges(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{
		"/usr/local/bin/coredns -version":               "CoreDNS-1.14.7",
		"dig @127.0.0.1":                                "10.0.1.10",
		"dpkg-query -W -f=${db:Status-Status} fail2ban": "installed",
		"sshd -T": "passwordauthentication no",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		DownloadDir: t.TempDir(), Runner: sr,
		Clock: timex.NewCell(func() time.Time { return time.Unix(1_700_000_000, 0) })}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &edgeWatcher{}
	r.cfg.Watcher = w
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Two full cycles = the startup converge + the watch-edge one
	// (every cycle runs the verify tail group — the counter probe).
	deadline := time.Now().Add(10 * time.Second)
	for promtestutil.ToFloat64(r.cycles.WithLabelValues("verify", "ok")) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("watch-edge converge never ran (verify cycles=%v, changed calls=%d)",
				promtestutil.ToFloat64(r.cycles.WithLabelValues("verify", "ok")), w.calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not unwind after ctx cancel")
	}
	if w.calls.Load() < 2 {
		t.Fatalf("watch loop called Changed %d times, want the swallow + edge", w.calls.Load())
	}
}

// TestRunBudgetTimeoutStillRecorded — a hung host command fails at
// the CmdTimeout deadline (FakeRunner HangOn) and the error reaches
// the caller instead of wedging the converge.
func TestRunBudgetTimeoutRecorded(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.HangOn("slow probe")
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, CmdTimeout: 30 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.run(context.Background(), "slow", "probe")
	if err == nil {
		t.Fatal("hung command returned without error at the deadline")
	}
	if d, ok := sr.DeadlineFor("slow probe"); !ok || d <= 0 || d > 30*time.Millisecond {
		t.Fatalf("deadline = %v ok=%v, want ~the configured CmdTimeout", d, ok)
	}
}

// TestNewRejectsDuplicateMetricRegistration — registering the same
// collector set twice on one registry errors instead of panicking at
// scrape time.
func TestNewRejectsDuplicateMetricRegistration(t *testing.T) {
	vars := writeVarsDir(t, "")
	reg := prometheus.NewRegistry()
	cfg := Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: newScripted(nil, nil)}
	if _, err := New(cfg, reg); err != nil {
		t.Fatalf("first New failed: %v", err)
	}
	if _, err := New(cfg, reg); err == nil {
		t.Fatal("duplicate registration did not error")
	}
}

// TestStopServiceFailureAttribution — a failed stop keeps its own
// action metric and counts a cycle error.
func TestStopServiceFailureAttribution(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.FailOn("systemctl stop unit-b.service", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	r.stopService(c.ctx, "unit-b.service")
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the stop failure counted", c.errs)
	}
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("stop:unit-b.service")); got != 1 {
		t.Fatalf("actions{stop} = %v", got)
	}
}

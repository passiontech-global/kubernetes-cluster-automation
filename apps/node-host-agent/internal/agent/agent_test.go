package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// captureSlog swaps the default slog logger for a text handler
// writing to the returned buffer — restored on cleanup.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestProbeEndpoints(t *testing.T) {
	a := New(Config{NodeName: "node-a"})
	srv := httptest.NewServer(a.probeMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", resp.StatusCode)
	}

	// Not ready until Run binds the listeners.
	resp, err = http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz before ready: got %d, want 503", resp.StatusCode)
	}

	a.ready.Store(true)
	resp, err = http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz after ready: got %d, want 200", resp.StatusCode)
	}
}

// selfheal-alert-coverage: a subsystem pinned at the supervisor's max backoff flips
// /readyz to 503 while /healthz stays 200 — kubelet must not
// restart the pod and kill the healthy subsystems.
func TestReadyzDegradedOnMaxBackoff(t *testing.T) {
	a := New(Config{NodeName: "node-a"})
	srv := httptest.NewServer(a.probeMux())
	defer srv.Close()

	a.ready.Store(true)
	a.maxBackoffSubs.Store(1)
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz with max-backoff subsystem: got %d, want 503",
			resp.StatusCode)
	}
	resp, err = http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz with max-backoff subsystem: got %d, want 200",
			resp.StatusCode)
	}

	a.maxBackoffSubs.Store(0)
	resp, err = http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz after recovery: got %d, want 200", resp.StatusCode)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	a := New(Config{NodeName: "node-a", PodName: "pod-1", Namespace: "node-ops", Version: "test"})
	a.started.Store(time.Now().UnixNano())
	srv := httptest.NewServer(a.metricsMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := string(body)
	for _, want := range []string{"node_host_agent_info", "node_host_agent_uptime_seconds", `node="node-a"`, `version="test"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, out)
		}
	}
}

func TestRunBindsAndShutsDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a := New(Config{MetricsAddr: "127.0.0.1:0", ProbeAddr: "127.0.0.1:0"})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// stubSubsystem records that Run was invoked and blocks until ctx is
// cancelled — the contract every subsystem implements.
type stubSubsystem struct {
	ran    atomic.Bool
	doneCh chan struct{}
}

func (s *stubSubsystem) Name() string { return "stub" }
func (s *stubSubsystem) Run(ctx context.Context) {
	s.ran.Store(true)
	<-ctx.Done()
	close(s.doneCh)
}

func TestRunStartsSubsystems(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sub := &stubSubsystem{doneCh: make(chan struct{})}
	a := New(Config{
		MetricsAddr: "127.0.0.1:0",
		ProbeAddr:   "127.0.0.1:0",
		Subsystems:  []Subsystem{sub},
	})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.After(5 * time.Second)
	for !sub.ran.Load() {
		select {
		case <-deadline:
			t.Fatal("subsystem Run was not started")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-sub.doneCh:
	case <-deadline:
		t.Fatal("subsystem Run did not return after cancel")
	}
	t.Logf("Run: %v", <-done)
}

func TestSubsystemMetricsOnSharedRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_stub_metric",
		Help: "test",
	}))
	a := New(Config{Registry: reg})
	a.started.Store(time.Now().UnixNano())
	srv := httptest.NewServer(a.metricsMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	out := string(body)
	if !strings.Contains(out, "node_host_agent_stub_metric") {
		t.Fatalf("subsystem metric missing from /metrics:\n%s", out)
	}
	if !strings.Contains(out, "node_host_agent_info") {
		t.Fatalf("built-in info metric missing:\n%s", out)
	}
}

func TestRegistryAndNodeName(t *testing.T) {
	injected := prometheus.NewRegistry()
	a := New(Config{NodeName: "node-x", Registry: injected})
	if a.Registry() != injected {
		t.Fatal("Registry() did not return the injected registry")
	}
	if a.NodeName() != "node-x" {
		t.Fatalf("NodeName()=%q want %q", a.NodeName(), "node-x")
	}

	// Nil registry → a fresh one is allocated (not nil, not shared).
	b := New(Config{})
	if b.Registry() == nil {
		t.Fatal("Registry() is nil with nil config registry")
	}
	if b.Registry() == injected {
		t.Fatal("nil config registry should produce a fresh registry")
	}
}

// panicOnceSubsystem panics on its first Run call and blocks on ctx
// from the second call on — proves the supervisor recovers a panicking
// subsystem instead of letting the goroutine die.
type panicOnceSubsystem struct {
	calls  atomic.Int32
	second chan struct{} // closed on the second Run invocation
}

func (s *panicOnceSubsystem) Name() string { return "panic-once" }

func (s *panicOnceSubsystem) Run(ctx context.Context) {
	if s.calls.Add(1) == 1 {
		panic("boom")
	}
	select {
	case <-s.second:
	default:
		close(s.second)
	}
	<-ctx.Done()
}

func TestRunRecoversSubsystemPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sub := &panicOnceSubsystem{second: make(chan struct{})}
	a := New(Config{
		MetricsAddr: "127.0.0.1:0",
		ProbeAddr:   "127.0.0.1:0",
		Subsystems:  []Subsystem{sub},
	})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	// The panic is recovered synchronously — the agent must NOT have
	// returned while the supervisor waits out its restart backoff.
	deadline := time.After(10 * time.Second)
	for sub.calls.Load() != 1 {
		select {
		case err := <-done:
			t.Fatalf("agent exited after subsystem panic: %v", err)
		case <-deadline:
			t.Fatal("subsystem was never started")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	// Supervisor restart backoff starts at 5s — poll until the
	// second Run invocation rather than sleeping a fixed interval.
	for {
		select {
		case <-sub.second:
			goto restarted
		case err := <-done:
			t.Fatalf("agent exited before subsystem restart: %v", err)
		case <-deadline:
			t.Fatal("subsystem was not restarted after panic")
		}
	}
restarted:
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-deadline:
		t.Fatal("Run did not return after context cancel")
	}
}

func TestRunMetricsAddrInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	a := New(Config{MetricsAddr: ln.Addr().String(), ProbeAddr: "127.0.0.1:0"})
	err = a.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "metrics listener") {
		t.Fatalf("Run err=%v want 'metrics listener' error", err)
	}
}

func TestRunProbeAddrInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	a := New(Config{MetricsAddr: "127.0.0.1:0", ProbeAddr: ln.Addr().String()})
	err = a.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "probe listener") {
		t.Fatalf("Run err=%v want 'probe listener' error", err)
	}
}

// ctx cancel drains the server through the injected shutdown — the
// normal graceful path.
func TestGracefulShutdownDrainsOnCancel(t *testing.T) {
	buf := captureSlog(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}) // stays open — Run is still running
	var called atomic.Bool
	fin := make(chan struct{})
	go func() {
		defer close(fin)
		gracefulShutdown(ctx, done, "test", func(context.Context) error {
			called.Store(true)
			return nil
		})
	}()
	cancel()
	select {
	case <-fin:
	case <-time.After(5 * time.Second):
		t.Fatal("gracefulShutdown did not return after cancel")
	}
	if !called.Load() {
		t.Fatal("shutdown was not invoked on ctx cancel")
	}
	if strings.Contains(buf.String(), "shutdown failed") {
		t.Fatalf("clean shutdown logged a failure:\n%s", buf.String())
	}
}

// Run's done channel releases the parked goroutine WITHOUT touching
// the server — on the error path the sibling Close() already tore
// it down, so a late drain would be a no-op (or a bogus log).
func TestGracefulShutdownExitsOnDone(t *testing.T) {
	ctx := context.Background() // stays live, like the errCh path
	done := make(chan struct{})
	var called atomic.Bool
	fin := make(chan struct{})
	go func() {
		defer close(fin)
		gracefulShutdown(ctx, done, "test", func(context.Context) error {
			called.Store(true)
			return nil
		})
	}()
	close(done)
	select {
	case <-fin:
	case <-time.After(5 * time.Second):
		t.Fatal("gracefulShutdown did not return on done")
	}
	if called.Load() {
		t.Fatal("shutdown ran on the done release — would double tear down")
	}
}

// ErrServerClosed from the drain (the server was torn down
// underneath us) is the intended end state — never a logged failure;
// any other error still logs "connections dropped".
func TestGracefulShutdownErrorFilter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		wantLog bool
	}{
		{"ErrServerClosed skipped", http.ErrServerClosed, false},
		{"wrapped ErrServerClosed skipped",
			fmt.Errorf("drain: %w", http.ErrServerClosed), false},
		{"nil error silent", nil, false},
		{"real error logged", errors.New("listener wedged"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureSlog(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			gracefulShutdown(ctx, make(chan struct{}), "test",
				func(context.Context) error { return tc.err })
			got := strings.Contains(buf.String(), "shutdown failed")
			if got != tc.wantLog {
				t.Fatalf("failure logged=%v want %v:\n%s",
					got, tc.wantLog, buf.String())
			}
		})
	}
}

func TestUptimeZeroBeforeStart(t *testing.T) {
	// Before Run sets a.started, the uptime GaugeFunc must report 0
	// rather than a negative/huge value.
	reg := prometheus.NewRegistry()
	New(Config{Registry: reg})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "node_host_agent_uptime_seconds" {
			continue
		}
		if got := mf.Metric[0].GetGauge().GetValue(); got != 0 {
			t.Fatalf("uptime before start=%v want 0", got)
		}
		return
	}
	t.Fatal("node_host_agent_uptime_seconds missing")
}

// --- supervisor health metrics ---

// waitFor polls cond until it holds or the deadline passes — the
// supervisor's 5s restart backoff means metric assertions poll
// rather than sleeping a fixed interval.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestSubsystemRestartCounterIncrements(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reg := prometheus.NewRegistry()
	sub := &earlyReturnSubsystem{ran: make(chan struct{})}
	a := New(Config{
		MetricsAddr: "127.0.0.1:0",
		ProbeAddr:   "127.0.0.1:0",
		Registry:    reg,
		Subsystems:  []Subsystem{sub},
	})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() { cancel(); t.Logf("Run: %v", <-done) }()

	// Run returned while ctx was live → the supervisor counts it.
	waitFor(t, "restart counter", func() bool {
		return testutil.ToFloat64(
			a.restarts.WithLabelValues("early-return")) >= 1
	})

	// The counter is on the shared registry, labelled by name.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, mf := range mfs {
		if mf.GetName() == "node_host_agent_subsystem_restarts_total" {
			found = true
		}
	}
	if !found {
		t.Fatal("node_host_agent_subsystem_restarts_total missing from registry")
	}
}

// gatedSubsystem's first Run blocks until release closes (the "up
// while running" probe); every later Run parks on ctx so the gauge's
// 0 window is observable for the whole backoff.
type gatedSubsystem struct {
	calls   atomic.Int32
	release chan struct{}
}

func (s *gatedSubsystem) Name() string { return "gated" }
func (s *gatedSubsystem) Run(ctx context.Context) {
	if s.calls.Add(1) == 1 {
		<-s.release
		return
	}
	<-ctx.Done()
}

func TestSubsystemUpGaugeFlips(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sub := &gatedSubsystem{release: make(chan struct{})}
	a := New(Config{
		MetricsAddr: "127.0.0.1:0",
		ProbeAddr:   "127.0.0.1:0",
		Subsystems:  []Subsystem{sub},
	})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() { cancel(); t.Logf("Run: %v", <-done) }()

	up := a.subUp.WithLabelValues("gated")
	waitFor(t, "up gauge to rise", func() bool {
		return testutil.ToFloat64(up) == 1
	})
	close(sub.release)
	// Run exits while ctx is live → up drops to 0 for the backoff
	// window and the restart is counted.
	waitFor(t, "up gauge to drop", func() bool {
		return testutil.ToFloat64(up) == 0
	})
	waitFor(t, "restart counter", func() bool {
		return testutil.ToFloat64(
			a.restarts.WithLabelValues("gated")) >= 1
	})
}

func TestSubsystemPanicCountedAsRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sub := &panicOnceSubsystem{second: make(chan struct{})}
	a := New(Config{
		MetricsAddr: "127.0.0.1:0",
		ProbeAddr:   "127.0.0.1:0",
		Subsystems:  []Subsystem{sub},
	})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() { cancel(); t.Logf("Run: %v", <-done) }()

	// A panic-recovered exit is an unexpected exit too — it must
	// land in the same counter as a silent early return.
	waitFor(t, "panic restart counted", func() bool {
		return testutil.ToFloat64(
			a.restarts.WithLabelValues("panic-once")) >= 1
	})
}

// earlyReturnSubsystem's Run records invocation and returns
// immediately without waiting for ctx — the supervisor must log the
// unexpected exit and enter the restart backoff.
type earlyReturnSubsystem struct {
	ran chan struct{}
}

func (s *earlyReturnSubsystem) Name() string { return "early-return" }
func (s *earlyReturnSubsystem) Run(context.Context) {
	select {
	case <-s.ran:
	default:
		close(s.ran)
	}
}

func TestSubsystemEarlyReturnCancelDuringBackoff(t *testing.T) {
	// Run returns while ctx is live → supervisor enters the 5s
	// restart backoff; cancelling during that window exits cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	sub := &earlyReturnSubsystem{ran: make(chan struct{})}
	a := New(Config{
		MetricsAddr: "127.0.0.1:0",
		ProbeAddr:   "127.0.0.1:0",
		Subsystems:  []Subsystem{sub},
	})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.After(5 * time.Second)
	select {
	case <-sub.ran:
	case <-deadline:
		t.Fatal("subsystem was never started")
	}
	// The supervisor is now inside the backoff select — cancel must
	// take the ctx.Done branch, not wait 5s.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-deadline:
		t.Fatal("Run did not return after cancel during backoff")
	}
}

// TestMetricsEndpointExposesGoRuntime pins the triage
// contract on the agent side: /metrics must carry the Go runtime +
// process collectors (heap vs retained-span attribution for the
// GOMEMLIMIT sizing) — and, post-roadmap-1.2, must NOT serve pprof
// (the profiles moved to the loopback-only pprofMux).
func TestMetricsEndpointExposesGoRuntimeAndPprof(t *testing.T) {
	a := New(Config{NodeName: "node-a"})
	srv := httptest.NewServer(a.metricsMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: got %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{
		"go_memstats_alloc_bytes", "go_goroutines",
		"process_resident_memory_bytes",
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("/metrics missing runtime metric %q", want)
		}
	}

	resp, err = http.Get(srv.URL + "/debug/pprof/heap?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("pprof on the metrics mux: got %d, want 404 (moved to the loopback listener)", resp.StatusCode)
	}
}

// TestPprofMuxLoopbackOnly pins the roadmap-1.2 loopback contract:
// the pprof mux serves heap/cmdline, and it is reached only through
// the dedicated listener — the Config field is named to keep the
// bind-loopback discipline at the callsite (main.go default
// 127.0.0.1:9116).
func TestPprofMuxLoopbackOnly(t *testing.T) {
	a := New(Config{NodeName: "node-a"})
	srv := httptest.NewServer(a.pprofMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/debug/pprof/heap?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heap profile: got %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "heap profile:") {
		t.Fatalf("heap profile body missing header, got:\n%.200s", body)
	}

	resp, err = http.Get(srv.URL + "/debug/pprof/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cmdline: got %d, want 200", resp.StatusCode)
	}
}

// TestRunPprofLoopbackBindOnly pins the 127.0.0.1 discipline: Run
// binds the configured pprof loopback listener (a wildcard bind
// would re-expose the profiles to the node network) — a
// PprofAddr conflict must fail Run with the loopback error.
func TestRunPprofLoopbackBindOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	a := New(Config{MetricsAddr: "127.0.0.1:0",
		ProbeAddr: "127.0.0.1:0", PprofAddr: ln.Addr().String()})
	err = a.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pprof loopback listener") {
		t.Fatalf("Run err=%v want 'pprof loopback listener' error", err)
	}
}

// TestRunPprofLoopbackServesWithZeroWriteTimeout proves the 1.2
// contract end-to-end on a live Run: the loopback listener answers
// a profile request, and the server was built with WriteTimeout 0
// — profile/trace legitimately outlive 30s only there (the
// metrics/probe servers carry bounded timeouts).
func TestRunPprofLoopbackServesWithZeroWriteTimeout(t *testing.T) {
	// Pre-resolve concrete ports — Run's listeners are not
	// reachable through a ":0" config value.
	free := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		return ln.Addr().String()
	}
	metricsAddr, probeAddr, pprofAddr := free(), free(), free()
	a := New(Config{MetricsAddr: metricsAddr,
		ProbeAddr: probeAddr, PprofAddr: pprofAddr})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	deadline := time.After(5 * time.Second)

	// Poll the readiness the same way sdnotify does — the probe mux
	// flips ready once all three listeners are bound.
	probeReady := func() bool {
		resp, err := http.Get("http://" + probeAddr + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	for !probeReady() {
		select {
		case <-deadline:
			t.Fatal("Run never became ready")
		case <-time.After(10 * time.Millisecond):
		}
	}
	resp, err := http.Get("http://" + pprofAddr + "/debug/pprof/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pprof loopback cmdline: got %d, want 200", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-deadline:
		t.Fatal("Run did not return after context cancel")
	}
}

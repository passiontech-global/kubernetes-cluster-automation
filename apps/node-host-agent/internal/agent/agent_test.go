package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestProbeEndpoints(t *testing.T) {
	a := New(Config{NodeName: "node-a"})
	srv := httptest.NewServer(a.probeMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", resp.StatusCode)
	}

	// Not ready until Run binds the listeners.
	resp, err = http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz before ready: got %d, want 503", resp.StatusCode)
	}

	a.ready.Store(true)
	resp, err = http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz after ready: got %d, want 200", resp.StatusCode)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	a := New(Config{NodeName: "node-a", PodName: "pod-1", Namespace: "node-ops", Version: "test"})
	a.started = time.Now()
	srv := httptest.NewServer(a.metricsMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
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
	<-done
}

func TestSubsystemMetricsOnSharedRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_stub_metric",
		Help: "test",
	}))
	a := New(Config{Registry: reg})
	a.started = time.Now()
	srv := httptest.NewServer(a.metricsMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	out := string(body)
	if !strings.Contains(out, "node_host_agent_stub_metric") {
		t.Fatalf("subsystem metric missing from /metrics:\n%s", out)
	}
	if !strings.Contains(out, "node_host_agent_info") {
		t.Fatalf("built-in info metric missing:\n%s", out)
	}
}

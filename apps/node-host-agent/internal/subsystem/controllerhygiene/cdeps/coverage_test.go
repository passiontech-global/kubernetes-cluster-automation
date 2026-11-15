package cdeps

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
)

func newTestDeps(t *testing.T, execFn func(context.Context, bool, time.Duration, string, ...string) (string, error)) *Deps {
	t.Helper()
	dir := t.TempDir()
	st := hoststate.New(dir, dir+"/watchdog.log", time.Now, nil)
	return &Deps{
		Cfg: Config{
			JournalUnit:  "k0scontroller.service",
			QueryTimeout: time.Second,
			HostExecFn:   execFn,
		},
		State:   st,
		Actions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_actions"}, []string{"check", "action"}),
	}
}

func TestHubConfHoldEmergencyHealMainPIDAndJournalGrep(t *testing.T) {
	var gotArgv []string
	d := newTestDeps(t, func(_ context.Context, _ bool, _ time.Duration, name string, args ...string) (string, error) {
		gotArgv = append([]string{name}, args...)
		if name == "systemctl" {
			return "1234\n", nil
		}
		return "match line\n", nil
	})
	d.Cfg.Hub = HubConfig{SelfAPI: "127.0.0.1:6443", PeerAPI: "10.0.0.2:6443"}
	if got := d.HubConf(); got.SelfAPI != "127.0.0.1:6443" || got.PeerAPI != "10.0.0.2:6443" {
		t.Fatalf("HubConf = %+v", got)
	}

	if d.HoldEmergencyHeal(context.Background()) {
		t.Fatal("nil Coord should return false")
	}
	d.Cfg.Coord = &nodecoord.Coord{}
	if d.HoldEmergencyHeal(context.Background()) {
		t.Fatal("empty Coord should return false")
	}

	pid, err := d.MainPID(context.Background(), "k0scontroller.service")
	if err != nil || pid != 1234 {
		t.Fatalf("MainPID = (%d,%v), want (1234,nil)", pid, err)
	}

	out, err := d.JournalTextGrep(context.Background(), time.Unix(1700000000, 0), "panic|fatal")
	if err != nil || !strings.Contains(out, "match line") {
		t.Fatalf("JournalTextGrep = (%q,%v)", out, err)
	}
	if len(gotArgv) == 0 || gotArgv[0] != "journalctl" {
		t.Fatalf("expected journalctl call, got %v", gotArgv)
	}

	// JournalTextGrep error propagates.
	dErr := newTestDeps(t, func(context.Context, bool, time.Duration, string, ...string) (string, error) {
		return "", errors.New("journald down")
	})
	if _, err := dErr.JournalTextGrep(context.Background(), time.Now(), "err"); err == nil {
		t.Fatal("expected JournalTextGrep error")
	}
}

func TestAPIServerReadyEndpointsQuorumAndRestartWithGates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"10.0.0.1"},{"ip":"10.0.0.2"},{"ip":"10.0.0.1"}]}]}`))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	d := newTestDeps(t, func(context.Context, bool, time.Duration, string, ...string) (string, error) {
		return "", nil
	})
	d.Cfg.Hub.PeerAPI = host
	d.Client = srv.Client()

	ready, ok := d.APIServerReadyEndpoints(context.Background())
	if !ok || ready != 2 {
		t.Fatalf("APIServerReadyEndpoints = (%d,%v), want (2,true)", ready, ok)
	}
	if !d.ControllerQuorumReady(context.Background()) {
		t.Fatal("ControllerQuorumReady = false, want true for 2 endpoints")
	}

	// Single-controller (no PeerAPI) always passes quorum.
	d.Cfg.Hub.PeerAPI = ""
	if !d.ControllerQuorumReady(context.Background()) {
		t.Fatal("ControllerQuorumReady(no PeerAPI) = false, want true")
	}

	// RestartWithGates in enforce mode runs restart, then second call hits cooldown.
	outcome, acted := d.RestartWithGates(context.Background(), RestartGateSpec{
		Unit:       "k0scontroller.service",
		State:      "ctrl-wedge",
		Budget:     "last-ctrl-restart",
		Cooldown:   time.Hour,
		Mode:       "enforce",
		HoldPrefix: "ctrl",
	})
	if outcome != "ok" || !acted {
		t.Fatalf("first RestartWithGates = (%q,%v), want (ok,true)", outcome, acted)
	}
	outcome, acted = d.RestartWithGates(context.Background(), RestartGateSpec{
		Unit:       "k0scontroller.service",
		State:      "ctrl-wedge",
		Budget:     "last-ctrl-restart",
		Cooldown:   time.Hour,
		Mode:       "enforce",
		HoldPrefix: "ctrl",
	})
	if outcome != "cooldown" || acted {
		t.Fatalf("second RestartWithGates = (%q,%v), want (cooldown,false)", outcome, acted)
	}
}

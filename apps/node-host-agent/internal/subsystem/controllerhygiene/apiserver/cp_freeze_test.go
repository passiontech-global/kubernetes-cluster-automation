package apiserver_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

func TestCPFreezeRestartsAfterThreeDeadCycles(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\nworkqueue_depth{name=\"a\"} 1\n", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true // peer healthy
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() == 0 {
		t.Fatal("no restart after 3 dead healthz cycles")
	}
	if !e.HasState("cp-component-frozen") {
		t.Fatal("cp-component-frozen latch missing")
	}
}

func TestCPFreezeGatedByDeadPeer(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	// PeerAPI default is alive[...] → false: peer dead → no restart.
	for range 4 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatal("restart fired while peer apiserver dead")
	}
	if !e.HasState("cp-component-frozen") {
		t.Fatal("latch should still record the freeze evidence")
	}
}

// TestCPFreezeSuspectPathKeepsLatchAndCounters is the file-split
// regression: the healthz-dead-below-streak cycle must bare-return
// the way the monolithic Run did — no "ok" outcome stacked on the
// suspect counter and no STATE-EXIT clearing an episode's latch
// (Enter's mtime refresh is the janitor-reap defence, so an early
// Exit also weakens that).
func TestCPFreezeSuspectPathKeepsLatchAndCounters(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 3 {
		e.H.Cycle(context.Background()) // streak reached → frozen + heal
	}
	if e.RstN() == 0 || !e.HasState("cp-component-frozen") {
		t.Fatalf("episode not established: rst=%d latch=%v",
			e.RstN(), e.HasState("cp-component-frozen"))
	}
	e.H.Cycle(context.Background()) // dead again, below streak → suspect
	// Cycles 1, 2 and this one are suspect; cycle 3 was the heal.
	if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckCPFreeze, "suspect")); v != 3 {
		t.Fatalf("suspect counter=%v want 3", v)
	}
	if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckCPFreeze, "ok")); v != 1 {
		t.Fatalf("ok counter=%v want 1 (heal cycle only — suspect must not stack ok)", v)
	}
	if !e.HasState("cp-component-frozen") {
		t.Fatal("suspect cycle cleared the episode latch — bare-return lost")
	}
}

func TestCPFreezeWorkqueueStalledPastGrace(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return stalledKCMBody, nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	e.H.Cycle(context.Background()) // snapshot 1 — no baseline yet
	e.Now = e.Now.Add(61 * time.Second)
	e.H.Cycle(context.Background()) // snapshot 2 → stalled, stamps quiet-since
	if e.RstN() != 0 {
		t.Fatal("restart before the quiet grace")
	}
	e.Now = e.Now.Add(11 * time.Minute)
	e.H.Cycle(context.Background())
	if e.RstN() == 0 {
		t.Fatal("no restart after workqueue stalled >10m")
	}
}

// TestCPFreezeHealthyIdleNeverRestarts is the kcm-queue-stall regression:
// leader + depthSum==0 across many cycles and well past the old
// quiet grace must produce ZERO restarts — the old kcmLeaderIdle
// fired on exactly this body every hour.
func TestCPFreezeHealthyIdleNeverRestarts(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\n" +
			"workqueue_depth{name=\"a\"} 0\n" +
			"workqueue_depth{name=\"b\"} 0\n" +
			"workqueue_adds_total{name=\"a\"} 10\n" +
			"workqueue_adds_total{name=\"b\"} 20\n", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 15 {
		e.H.Cycle(context.Background())
		e.Now = e.Now.Add(61 * time.Second)
	}
	if e.RstN() != 0 {
		t.Fatal("restart fired on healthy idle cluster (kcm-queue-stall regression)")
	}
	if e.HasState("cp-component-frozen") {
		t.Fatal("cp-component-frozen latched on healthy idle cluster")
	}
}

// --- healFreeze gating branches ---

// After a cp-freeze restart the rate budget is spent — the next
// frozen episode must land in the cooldown branch, not burn a second
// restart inside MinRestart.
func TestCPFreezeRestartCooldown(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 1 {
		t.Fatalf("precondition: restarts=%d", e.RstN())
	}
	for range 3 {
		e.H.Cycle(context.Background()) // re-freeze inside cooldown
	}
	if e.RstN() != 1 {
		t.Fatalf("cooldown not honored: restarts=%d", e.RstN())
	}
	if e.CountLogLines("in restart cooldown") == 0 {
		t.Fatalf("cooldown not logged:\n%s", e.LogLines())
	}
}

// A failing restart unit is logged as a suspect warn, not swallowed.
func TestCPFreezeRestartFailureWarns(t *testing.T) {
	e := fixture(t)
	oldExec := e.H.Cfg.HostExecFn
	e.H.Cfg.HostExecFn = func(ctx context.Context, quiet bool, d time.Duration,
		name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) >= 2 && args[0] == "restart" {
			return "", errors.New("systemctl:Job failed")
		}
		return oldExec(ctx, quiet, d, name, args...)
	}
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if !strings.Contains(e.LogLines(),
		"suspect: restart k0scontroller.service failed") {
		t.Fatalf("restart failure not warned:\n%s", e.LogLines())
	}
}

func TestCPFreezeDryRunLogsNoRestart(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Sig13.Mode = cdeps.ModeDryRun
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatalf("dry-run restarted: %v", e.RstAt(0))
	}
	if !strings.Contains(e.LogLines(),
		"DRY-RUN: would restart k0scontroller - cp-component-frozen") {
		t.Fatalf("dry-run action not logged:\n%s", e.LogLines())
	}
}

// scheduler_watchdog_test.go — coverage for the
// scheduler-watchdog check (W8-CP3).
package watchdogs

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// W8-CP3 — a pod Pending >5m with no PodScheduled condition while
// Ready workers exist fails the check and raises the frozen gauge;
// a healthy shape passes and clears it.
func TestCheckSchedulerFrozen(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.PendingUnscheduledPod("apps", "stuck-1", 10*time.Minute, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*schedulerWatchdogCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("frozen scheduler shape passed")
	}
	m := probetest.FindMetric(t, "node_automation_scheduler_frozen", map[string]string{})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scheduler_frozen=%v, want 1", m)
	}
}

func TestCheckSchedulerFrozenHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.PendingUnscheduledPod("apps", "verdict", 10*time.Minute, true))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*schedulerWatchdogCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("PodScheduled=False verdict pod misread as frozen: %+v", res)
	}
}

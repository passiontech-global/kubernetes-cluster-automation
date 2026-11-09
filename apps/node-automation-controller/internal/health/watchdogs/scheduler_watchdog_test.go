// scheduler_watchdog_test.go — coverage for the
// scheduler-watchdog check (W8-CP3 + W12-SC1).
package watchdogs

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

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

// ---------------------------------------------------------------------------
// W12-SC1 — PriorityClass preemption cascade
// ---------------------------------------------------------------------------

// preemptedEvent builds a recent reason=Preempted event — the
// scheduler's domino-eviction signal. The timestamp rides
// LastTimestamp (the recurring-event clock kube.EventTime prefers).
func preemptedEvent(ns, name string, age time.Duration) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Reason:        "Preempted",
		LastTimestamp: metav1.NewTime(time.Now().Add(-age)),
	}
}

// More than schedulerPreemptionMax Preempted events inside the
// window is a domino cascade — FAIL + storm gauge, even on an
// otherwise healthy cluster.
func TestCheckSchedulerPreemptionStorm(t *testing.T) {
	objs := []runtime.Object{probetest.ReadyWorkerNode("w1", "", 0, false)}
	for i := 0; i < schedulerPreemptionMax+1; i++ {
		objs = append(objs,
			preemptedEvent("apps", fmt.Sprintf("ev-%d", i), time.Minute))
	}
	cs := fake.NewSimpleClientset(objs...)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*schedulerWatchdogCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("preemption storm must fail: %+v", res)
	}
	m := probetest.FindMetric(t, "node_automation_scheduler_preemption_storm",
		map[string]string{})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("preemption_storm=%v, want 1", m)
	}
}

// The storm verdict must never read "0 pods pending >=5m..." — with
// nothing stuck pending the all-clear wording carries the storm
// finding alone (the count phrase would misread an all-clear as a
// stuck scheduler).
func TestCheckSchedulerStormZeroPendingVerdict(t *testing.T) {
	objs := []runtime.Object{probetest.ReadyWorkerNode("w1", "", 0, false)}
	for i := range schedulerPreemptionMax + 1 {
		objs = append(objs,
			preemptedEvent("apps", fmt.Sprintf("ev-%d", i), time.Minute))
	}
	cs := fake.NewSimpleClientset(objs...)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*schedulerWatchdogCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("preemption storm must fail: %+v", res)
	}
	if strings.Contains(res.Why, "0 pods pending") {
		t.Fatalf("verdict must not read a 0-pending count: %q", res.Why)
	}
	if !strings.Contains(res.Why, "preemption storm") {
		t.Fatalf("verdict must still carry the storm finding: %q", res.Why)
	}
}

// At-or-under the ceiling, stale events, and non-Preempted noise all
// stay quiet — ordinary placement churn must never read as a storm.
func TestCheckSchedulerPreemptionChurnQuiet(t *testing.T) {
	objs := []runtime.Object{probetest.ReadyWorkerNode("w1", "", 0, false)}
	for i := 0; i < schedulerPreemptionMax; i++ {
		objs = append(objs,
			preemptedEvent("apps", fmt.Sprintf("fresh-%d", i), time.Minute))
	}
	for i := 0; i < 5; i++ {
		// Outside the 5m window — a stale cascade tail is not a
		// live storm.
		objs = append(objs,
			preemptedEvent("apps", fmt.Sprintf("stale-%d", i), 30*time.Minute))
		// Same age, wrong reason — Scheduled chatter never counts.
		e := preemptedEvent("apps", fmt.Sprintf("sched-%d", i), time.Minute)
		e.Reason = "Scheduled"
		objs = append(objs, e)
	}
	cs := fake.NewSimpleClientset(objs...)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*schedulerWatchdogCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("under-ceiling churn must pass: %+v", res)
	}
	m := probetest.FindMetric(t, "node_automation_scheduler_preemption_storm",
		map[string]string{})
	if m == nil || m.GetGauge().GetValue() != 0 {
		t.Fatalf("preemption_storm=%v, want 0", m)
	}
}

// An events-list failure is a tolerated sub-failure — the check
// reports Infra but the frozen signal still judges on its own
// evidence (and an inconclusive storm is never a clean pass).
func TestCheckSchedulerPreemptionListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false))
	cs.PrependReactor("list", "events",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*schedulerWatchdogCheck](t, p).Run(ctx)
	if res.Infra == nil {
		t.Fatalf("events list failure must surface as Infra: %+v", res)
	}
}

// A Pending pod parked behind SchedulingGates is NOT freeze evidence:
// the scheduler is forbidden from touching it by design — a gated pod
// must never raise the frozen gauge on an otherwise healthy cluster.
func TestCheckSchedulerFrozenIgnoresSchedulingGates(t *testing.T) {
	gated := probetest.PendingUnscheduledPod("apps", "gated-1", 10*time.Minute, false)
	gated.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: "example.com/hold"}}
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		gated)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*schedulerWatchdogCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("scheduling-gated pod misread as frozen scheduler: %+v", res)
	}
	m := probetest.FindMetric(t, "node_automation_scheduler_frozen", map[string]string{})
	if m != nil && m.GetGauge().GetValue() != 0 {
		t.Fatalf("scheduler_frozen=%v, want 0 for a gated pod", m.GetGauge().GetValue())
	}
}

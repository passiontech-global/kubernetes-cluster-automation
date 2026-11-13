package deschedulerstormgate

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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// preemption-cascade-signal — PriorityClass preemption cascade
// ---------------------------------------------------------------------------

// preemptedEvent builds a recent reason=Preempted corev1.Event.
func preemptedEvent(name string, age time.Duration) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "apps",
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Reason:        "Preempted",
		LastTimestamp: metav1.NewTime(time.Now().Add(-age)),
	}
}

// Signal (d): a Preempted-event burst past the ceiling is a domino
// eviction storm — the descheduler's own evictions would amplify it,
// so it scales to 0.
func TestStormGateScalesDownOnPreemptionStorm(t *testing.T) {
	objs := []runtime.Object{
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
	}
	for i := 0; i < stormPreemptionMax+1; i++ {
		objs = append(objs, preemptedEvent(
			fmt.Sprintf("ev-%d", i), time.Minute))
	}
	cs := fake.NewSimpleClientset(objs...)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("preemption storm must gate the descheduler, replicas=%d", got)
	}
	// The audit trail records the storm signal too.
	decision := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]
	if !strings.Contains(decision, "preempted=") ||
		!strings.Contains(decision, "verdict=storm") {
		t.Fatalf("decision missing the preempted signal: %q", decision)
	}
}

// At-or-under the ceiling plus stale events is ordinary churn — the
// descheduler keeps running.
func TestStormGatePreemptionChurnIsClear(t *testing.T) {
	objs := []runtime.Object{
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
	}
	for i := 0; i < stormPreemptionMax; i++ {
		objs = append(objs, preemptedEvent(
			fmt.Sprintf("fresh-%d", i), time.Minute))
	}
	for i := 0; i < 5; i++ {
		objs = append(objs, preemptedEvent(
			fmt.Sprintf("stale-%d", i), 30*time.Minute))
	}
	cs := fake.NewSimpleClientset(objs...)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("under-ceiling churn must not gate, replicas=%d", got)
	}
}

// An events-list failure aborts the reconcile — never a "clear"
// verdict on blind data (same posture as the node-list failure).
func TestStormGatePreemptionListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("list", "events",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the events list fails")
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas changed on blind data: %d", got)
	}
}

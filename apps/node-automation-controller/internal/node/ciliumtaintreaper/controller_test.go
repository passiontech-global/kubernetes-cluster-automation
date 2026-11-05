package ciliumtaintreaper

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestCiliumTaintReaper(t *testing.T) {
	stale := corev1.Taint{Key: "node.cilium.io/agent-not-ready", Effect: corev1.TaintEffectNoSchedule}

	// Disabled: never touches taints.
	cs := fake.NewSimpleClientset(testutil.Node("n1", corev1.ConditionTrue, nil, stale))
	r := &ciliumTaintReaper{cs: cs, enabled: false}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !shared.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("disabled reaper removed taint")
	}

	// Enabled + healthy agent -> taint reaped.
	cs = fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, stale),
		ciliumPod("n1", corev1.PodRunning, true))
	r = &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if shared.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("stale taint not reaped with healthy agent")
	}

	// Enabled + agent not ready -> taint kept.
	cs = fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, stale),
		ciliumPod("n1", corev1.PodPending, false))
	r = &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !shared.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("taint removed while agent still not ready")
	}
}

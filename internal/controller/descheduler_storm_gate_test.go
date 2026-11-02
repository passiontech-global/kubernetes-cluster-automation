package controller

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func getDescheduler(t *testing.T, cs *fake.Clientset) *appsv1.Deployment {
	t.Helper()
	d, err := cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get descheduler: %v", err)
	}
	return d
}

// withStormCond returns a Ready node additionally carrying a latched
// storm condition (NPD/kubelet pressure style).
func withStormCond(n *corev1.Node, cond corev1.NodeConditionType) *corev1.Node {
	n.Status.Conditions = append(n.Status.Conditions,
		corev1.NodeCondition{Type: cond, Status: corev1.ConditionTrue})
	return n
}

func TestStormGateScalesDownOnStormCondition(t *testing.T) {
	// Ready=True is not enough — a latched True storm condition
	// (MemoryPressure here, one of stormConds) gates the descheduler.
	cs := fake.NewSimpleClientset(
		withStormCond(node("n1", corev1.ConditionTrue, nil),
			corev1.NodeMemoryPressure),
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 on storm condition, got %d", got)
	}
}

func TestStormGateScalesDownOnStormTaint(t *testing.T) {
	// A stormTaints key (node.ops/kubelet-unresponsive — set by the
	// reaper) on an otherwise healthy node also forces the verdict.
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil, corev1.Taint{
			Key:    "node.ops/kubelet-unresponsive",
			Effect: corev1.TaintEffectNoSchedule,
		}),
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 on storm taint, got %d", got)
	}
}

func TestStormGateIgnoresNonStormSignals(t *testing.T) {
	// A True condition outside stormConds (PIDPressure) plus an
	// unrelated taint must not gate anything.
	n := node("n1", corev1.ConditionTrue, nil, corev1.Taint{
		Key:    "dedicated=special",
		Effect: corev1.TaintEffectNoSchedule,
	})
	n.Status.Conditions = append(n.Status.Conditions,
		corev1.NodeCondition{Type: corev1.NodePIDPressure, Status: corev1.ConditionTrue})
	cs := fake.NewSimpleClientset(n, deschedulerDeploy(1, nil))

	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("non-storm signals must not scale, replicas=%d", got)
	}
}

func TestStormGateDecisionAnnotatedOnce(t *testing.T) {
	// All clear + replicas already correct: the decision annotation
	// must still be written the first time (audit trail), but must
	// never be rewritten afterwards — no annotation churn.
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]; got == "" {
		t.Fatal("decision annotation not written on first clear verdict")
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas churned on a no-op verdict: %d", got)
	}

	// Second pass: a present annotation is left untouched. Write a
	// sentinel through the API and verify the reconciler does not
	// overwrite it.
	d := getDescheduler(t, cs)
	d.Annotations[stormGateDecisionAnno] = "sentinel"
	if _, err := cs.AppsV1().Deployments("kube-system").
		Update(ctx, d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]; got != "sentinel" {
		t.Fatalf("decision annotation churned: %q", got)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas changed on steady state: %d", got)
	}
}

func TestStormGateHoldOnlyWhenTrue(t *testing.T) {
	// passiontech.dev/storm-gate-hold=<anything-but-"true"> is not a
	// hold — scaling still happens during a storm.
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionFalse, nil),
		deschedulerDeploy(1, map[string]string{stormGateHoldAnno: "false"}))
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("hold=false must not block scaling, replicas=%d", got)
	}
}

func TestStormGateNoDeschedulerDeployment(t *testing.T) {
	// Cluster without descheduler — the verdict is computed but the
	// reconcile is a clean no-op.
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionFalse, nil))
	r := &deschedulerStormGate{cs: cs}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("expected 5m requeue, got %s", res.RequeueAfter)
	}
}

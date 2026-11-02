package controller

import (
	"errors"
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
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

// condStatusMap keeps only type->status — kubelet heartbeat churn
// (lastHeartbeatTime/reason/message) must not change the projection,
// or every node update would enqueue a full verdict.
func TestCondStatusMapIgnoresChurn(t *testing.T) {
	a := node("n1", corev1.ConditionTrue, nil)
	a.Status.Conditions[0].LastHeartbeatTime = metav1.NewTime(time.Now())
	a.Status.Conditions[0].Reason = "KubeletReady"
	a.Status.Conditions[0].Message = "kubelet is posting ready"

	b := node("n1", corev1.ConditionTrue, nil)
	b.Status.Conditions[0].LastHeartbeatTime = metav1.NewTime(time.Now().Add(time.Hour))
	b.Status.Conditions[0].Reason = "OtherReason"
	b.Status.Conditions[0].Message = "different message"

	if !reflect.DeepEqual(condStatusMap(a), condStatusMap(b)) {
		t.Fatal("condStatusMap must drop heartbeat churn fields")
	}

	// A real status change DOES change the projection.
	b.Status.Conditions[0].Status = corev1.ConditionFalse
	if reflect.DeepEqual(condStatusMap(a), condStatusMap(b)) {
		t.Fatal("condStatusMap missed a status flip")
	}
}

// taintKeys is the jqFilter projection — keys only, in order.
func TestTaintKeys(t *testing.T) {
	n := node("n1", corev1.ConditionTrue, nil,
		corev1.Taint{Key: "a", Value: "1", Effect: corev1.TaintEffectNoSchedule},
		corev1.Taint{Key: "b", Effect: corev1.TaintEffectNoExecute})
	got := taintKeys(n)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("taintKeys = %v, want [a b]", got)
	}
	if got := taintKeys(node("n2", corev1.ConditionTrue, nil)); len(got) != 0 {
		t.Fatalf("taintKeys on untainted node = %v", got)
	}
}

// An API failure aborts the reconcile — never a "clear" verdict on
// empty data.
func TestStormGateNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset(deschedulerDeploy(1, nil))
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A failed replicas update errors the reconcile — the verdict must not
// be swallowed.
func TestStormGateDeployUpdateError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionFalse, nil), // storm -> want 0
		deschedulerDeploy(1, nil))
	cs.PrependReactor("update", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("update rejected")
		})
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the deployment update fails")
	}
}

// A failed decision-annotation patch errors the reconcile — the audit
// trail is part of the verdict.
func TestStormGateDecisionPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionFalse, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the decision annotation patch fails")
	}
}

// A deployment GET failure that is NOT NotFound is a real reconcile
// error — only a missing descheduler is the benign skip.
func TestStormGateDeployGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("get", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the deployment get fails")
	}
}

// Replicas already correct but no decision annotation recorded yet:
// the elif still annotates, and a patch failure there errors the
// reconcile just like the scale path.
func TestStormGateAnnotateErrorOnSteadyReplicas(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil), // clear verdict, want=1
		deschedulerDeploy(1, nil))             // cur=1 -> elif branch
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the elif annotation patch fails")
	}
}

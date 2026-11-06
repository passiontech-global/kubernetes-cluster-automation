package kube

import (
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// PatchNodeLabels — kubectl label --overwrite merge semantics.
// ---------------------------------------------------------------------------

func TestPatchNodeLabelsMerge(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue,
		map[string]string{"keep": "me", "old": "value"}))

	if err := PatchNodeLabels(ctx, cs, "n1",
		map[string]string{"old": "new", "added": "yes"}); err != nil {
		t.Fatalf("PatchNodeLabels: %v", err)
	}

	got := getNode(t, cs, "n1").Labels
	want := map[string]string{"keep": "me", "old": "new", "added": "yes"}
	if len(got) != len(want) {
		t.Fatalf("labels = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("label %q = %q, want %q (all labels %v)", k, got[k], v, got)
		}
	}
}

func TestPatchNodeLabelsNilMap(t *testing.T) {
	// A node that never had labels — the merge patch must create the
	// labels map rather than fail.
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil))
	if err := PatchNodeLabels(ctx, cs, "n1",
		map[string]string{"first": "label"}); err != nil {
		t.Fatalf("PatchNodeLabels: %v", err)
	}
	if got := getNode(t, cs, "n1").Labels["first"]; got != "label" {
		t.Fatalf("label not created on bare node, labels=%v",
			getNode(t, cs, "n1").Labels)
	}
}

// ---------------------------------------------------------------------------
// NodeReady / IsControlPlane edge cases.
// ---------------------------------------------------------------------------

func TestNodeReadyNoConditions(t *testing.T) {
	// kubelet has never posted a status — no conditions at all.
	bare := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "bare"}}
	if NodeReady(bare) {
		t.Fatal("node with no conditions reported ready")
	}
	if c := NodeCondition(bare, corev1.NodeReady); c != nil {
		t.Fatal("NodeCondition should be nil on a condition-less node")
	}
}

func TestIsControlPlaneMasterLabel(t *testing.T) {
	// The legacy master-role label variant must count too.
	m := node("cp", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/master": ""})
	if !IsControlPlane(m) {
		t.Fatal("master-role label not recognized as control plane")
	}
}

// ---------------------------------------------------------------------------
// patchNodeTaints / TaintNode / UntaintNode edge cases.
// ---------------------------------------------------------------------------

func TestPatchNodeTaintsNilWritesEmptyArray(t *testing.T) {
	// nil marshals as "taints":null — the helper must normalize to []
	// so the merge patch clears the key instead of writing null.
	tainted := node("n1", corev1.ConditionTrue, nil,
		corev1.Taint{Key: "a", Effect: corev1.TaintEffectNoSchedule})
	cs := fake.NewSimpleClientset(tainted)
	if err := patchNodeTaints(ctx, cs, "n1", nil); err != nil {
		t.Fatalf("patchNodeTaints(nil): %v", err)
	}
	got := getNode(t, cs, "n1").Spec.Taints
	if got == nil {
		t.Fatal("spec.taints marshaled as null, want empty array")
	}
	if len(got) != 0 {
		t.Fatalf("taints not cleared: %+v", got)
	}
}

func TestPatchNodeTaintsPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	if err := patchNodeTaints(ctx, cs, "n1",
		[]corev1.Taint{{Key: "a", Effect: corev1.TaintEffectNoSchedule}}); err == nil {
		t.Fatal("expected error when the node patch fails")
	}
}

func TestTaintNodeGetError(t *testing.T) {
	// Node absent -> the get inside TaintNode fails (NotFound).
	cs := fake.NewSimpleClientset()
	if err := TaintNode(ctx, cs, "ghost", "k", "v",
		corev1.TaintEffectNoSchedule); err == nil {
		t.Fatal("expected error when the node does not exist")
	}
}

func TestUntaintNodeGetErrorAndNoop(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil))
	if err := UntaintNode(ctx, cs, "ghost", "k"); err == nil {
		t.Fatal("expected error when the node does not exist")
	}
	// Node exists but carries no matching taint -> clean no-op.
	if err := UntaintNode(ctx, cs, "n1", "never-was-there"); err != nil {
		t.Fatalf("untaint of an absent key must be a no-op: %v", err)
	}
}

func TestListNodesError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	if _, err := ListNodes(ctx, cs); err == nil {
		t.Fatal("expected error when the node list fails")
	}
	if _, err := CountNotReadyNodes(ctx, cs); err == nil {
		t.Fatal("expected CountNotReadyNodes to propagate the list error")
	}
}

func TestPatchNodeLabelsPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	if err := PatchNodeLabels(ctx, cs, "n1",
		map[string]string{"k": "v"}); err == nil {
		t.Fatal("expected error when the node patch fails")
	}
}

// ---------------------------------------------------------------------------
// DaemonSetSettled — every lagging field must veto "settled".
// ---------------------------------------------------------------------------

func TestDaemonSetSettledFields(t *testing.T) {
	t.Run("settled", func(t *testing.T) {
		if !DaemonSetSettled(settledDaemonSet()) {
			t.Fatal("fully caught-up DaemonSet not settled")
		}
	})
	t.Run("observedGeneration lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.ObservedGeneration = 2 // controller hasn't seen gen 3
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite stale observedGeneration")
		}
	})
	t.Run("updatedNumberScheduled lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.UpdatedNumberScheduled = 3 // old pod template on one node
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite pods still on the old revision")
		}
	})
	t.Run("numberReady lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.NumberReady = 3 // updated but not ready yet
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite unready pod")
		}
	})
}

func TestTaintHelpers(t *testing.T) {
	n := node("n1", corev1.ConditionTrue, nil)
	cs := fake.NewSimpleClientset(n)

	if err := TaintNode(ctx, cs, "n1", "passiontech.dev/test", "true", corev1.TaintEffectNoSchedule); err != nil {
		t.Fatalf("TaintNode: %v", err)
	}
	got := getNode(t, cs, "n1")
	if !HasTaint(got.Spec.Taints, "passiontech.dev/test") {
		t.Fatal("taint not applied")
	}
	if len(got.Spec.Taints) != 1 {
		t.Fatalf("expected 1 taint, got %d", len(got.Spec.Taints))
	}

	// Idempotent: same key is not duplicated.
	if err := TaintNode(ctx, cs, "n1", "passiontech.dev/test", "true", corev1.TaintEffectNoSchedule); err != nil {
		t.Fatalf("TaintNode idempotent: %v", err)
	}
	if l := len(getNode(t, cs, "n1").Spec.Taints); l != 1 {
		t.Fatalf("expected still 1 taint, got %d", l)
	}

	if err := UntaintNode(ctx, cs, "n1", "passiontech.dev/test"); err != nil {
		t.Fatalf("UntaintNode: %v", err)
	}
	if HasTaint(getNode(t, cs, "n1").Spec.Taints, "passiontech.dev/test") {
		t.Fatal("taint not removed")
	}
}

func TestDropTaintsByKeyInPlace(t *testing.T) {
	in := []corev1.Taint{
		{Key: "a", Effect: corev1.TaintEffectNoSchedule},
		{Key: "a", Effect: corev1.TaintEffectNoExecute},
		{Key: "b", Effect: corev1.TaintEffectNoSchedule},
	}
	out := dropTaintsByKey(in, "a")
	if len(out) != 1 || out[0].Key != "b" {
		t.Fatalf("expected only taint b, got %+v", out)
	}
	// In-place contract: the result aliases the input's backing
	// array — the surviving taint moved into slot 0 — and the stale
	// tail past len(out) is zeroed so the dropped entries (and their
	// strings) become collectable.
	if in[0].Key != "b" {
		t.Fatalf("result does not alias the input array: in[0]=%+v", in[0])
	}
	for i, stale := range in[len(out):] {
		if stale != (corev1.Taint{}) {
			t.Fatalf("stale tail slot %d not cleared: %+v", len(out)+i, stale)
		}
	}
}

func TestNodeConditionHelpers(t *testing.T) {
	ready := node("w", corev1.ConditionTrue, nil)
	notReady := node("w2", corev1.ConditionFalse, nil)
	cp := node("cp", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/control-plane": ""})

	if !NodeReady(ready) || NodeReady(notReady) {
		t.Fatal("NodeReady wrong")
	}
	if !IsControlPlane(cp) || IsControlPlane(ready) {
		t.Fatal("IsControlPlane wrong")
	}
}

func TestCountNotReadyNodes(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("a", corev1.ConditionTrue, nil),
		node("b", corev1.ConditionFalse, nil),
		node("c", corev1.ConditionTrue, nil))
	n, err := CountNotReadyNodes(ctx, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 NotReady, got %d", n)
	}
}

func TestDaemonSetSettled(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     3,
			DesiredNumberScheduled: 4,
			UpdatedNumberScheduled: 4,
			NumberReady:            4,
		},
	}
	if !DaemonSetSettled(ds) {
		t.Fatal("expected settled")
	}
	ds.Status.NumberReady = 3
	if DaemonSetSettled(ds) {
		t.Fatal("expected not settled when a replica is not ready")
	}
}

// PodReadyCond mirrors the bash Ready=True probe: absent condition and
// Ready=False both count as not ready.
func TestPodReadyCond(t *testing.T) {
	p := &corev1.Pod{}
	if PodReadyCond(p) {
		t.Fatal("pod with no conditions reported ready")
	}
	p.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionFalse},
	}
	if PodReadyCond(p) {
		t.Fatal("Ready=False pod reported ready")
	}
	p.Status.Conditions[0].Status = corev1.ConditionTrue
	if !PodReadyCond(p) {
		t.Fatal("Ready=True pod reported not ready")
	}
}

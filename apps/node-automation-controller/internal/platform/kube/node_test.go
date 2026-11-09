// node_test.go — tests for node.go: condition/role reads, the
// actively-cordoned verdict, taint/label merge patches, and the
// ListNodes/CountNotReadyNodes census.
package kube

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ctx = context.Background()

func node(name string, ready corev1.ConditionStatus, labels map[string]string, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: ready,
		}}},
	}
}

func getNode(t *testing.T, cs *fake.Clientset, name string) *corev1.Node {
	t.Helper()
	n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", name, err)
	}
	return n
}

// ---------------------------------------------------------------------------
// NodeActivelyCordoned — BUG-C4 fresh-cordon verdict + the node-hang-precordon
// precordon exemption.
// ---------------------------------------------------------------------------

// BUG-C4 — NodeActivelyCordoned: only a FRESH cordon counts as an
// active drain; a statically-cordoned node (>45m) does not.
func TestNodeActivelyCordoned(t *testing.T) {
	now := time.Now()
	fresh := metav1.NewTime(now.Add(-10 * time.Minute))
	old := metav1.NewTime(now.Add(-time.Hour))
	for _, tc := range []struct {
		name          string
		unschedulable bool
		taints        []corev1.Taint
		want          bool
	}{
		{"schedulable", false, nil, false},
		{"cordoned no taint (unverifiable)", true, nil, true},
		{"cordoned nil TimeAdded", true,
			[]corev1.Taint{{Key: UnschedulableTaintKey}}, true},
		{"cordoned 10m ago", true,
			[]corev1.Taint{{Key: UnschedulableTaintKey, TimeAdded: &fresh}}, true},
		{"static cordon 60m ago", true,
			[]corev1.Taint{{Key: UnschedulableTaintKey, TimeAdded: &old}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &corev1.Node{Spec: corev1.NodeSpec{
				Unschedulable: tc.unschedulable, Taints: tc.taints}}
			if got := NodeActivelyCordoned(n, now); got != tc.want {
				t.Fatalf("NodeActivelyCordoned=%v, want %v", got, tc.want)
			}
		})
	}
}

// node-hang-precordon — a node pre-cordoned by node-hang-precordon
// (AnnoPreCordonedBy) is the controller's own defensive quarantine
// of a sick worker, not an operator drain: its fresh unschedulable
// taint must NOT trip the active-cordon verdict or the maintenance
// mutex would lock every heal cluster-wide for 45m.
func TestNodeActivelyCordonedPreCordonExempt(t *testing.T) {
	now := time.Now()
	fresh := metav1.NewTime(now.Add(-time.Minute))
	for _, tc := range []struct {
		name  string
		annos map[string]string
		want  bool
	}{
		{"precordoned by node-hang-precordon",
			map[string]string{AnnoPreCordonedBy: "node-hang-precordon"}, false},
		{"precordoned by anything counts as exempt",
			map[string]string{AnnoPreCordonedBy: "other-controller"}, false},
		{"empty precordon anno is an operator cordon",
			map[string]string{AnnoPreCordonedBy: ""}, true},
		{"no precordon anno is an operator cordon", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Annotations: tc.annos},
				Spec: corev1.NodeSpec{
					Unschedulable: true,
					Taints: []corev1.Taint{
						{Key: UnschedulableTaintKey, TimeAdded: &fresh}}},
			}
			if got := NodeActivelyCordoned(n, now); got != tc.want {
				t.Fatalf("NodeActivelyCordoned=%v, want %v", got, tc.want)
			}
		})
	}
}

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
// NodeReady / IsControlPlane / NodeCondition edge cases.
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

// ---------------------------------------------------------------------------
// patchNodeTaints / TaintNode / UntaintNode edge cases.
// ---------------------------------------------------------------------------

func TestPatchNodeTaintsNilWritesEmptyArray(t *testing.T) {
	// nil marshals as "taints":null — the helper must normalize to []
	// so the merge patch clears the key instead of writing null.
	tainted := node("n1", corev1.ConditionTrue, nil,
		corev1.Taint{Key: "a", Effect: corev1.TaintEffectNoSchedule})
	cs := fake.NewSimpleClientset(tainted)
	if err := patchNodeTaints(ctx, cs, getNode(t, cs, "n1"), nil); err != nil {
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
	if err := patchNodeTaints(ctx, cs, getNode(t, cs, "n1"),
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

// ---------------------------------------------------------------------------
// ListNodes / CountNotReadyNodesCached.
// ---------------------------------------------------------------------------

// nodeListReader is a minimal CachedNodeReader fake serving a fixed
// NodeList — the cached path of the storm-gate census.
type nodeListReader struct{ items []corev1.Node }

func (r nodeListReader) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	nl, ok := list.(*corev1.NodeList)
	if !ok {
		return fmt.Errorf("unexpected list type %T", list)
	}
	nl.Items = append(nl.Items, r.items...)
	return nil
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
	if _, err := CountNotReadyNodesCached(ctx, nil, cs); err == nil {
		t.Fatal("expected CountNotReadyNodesCached to propagate the list error")
	}
}

func TestCountNotReadyNodesCached(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("a", corev1.ConditionTrue, nil),
		node("b", corev1.ConditionFalse, nil),
		node("c", corev1.ConditionTrue, nil))
	// nil reader → direct clientset fallback path.
	n, err := CountNotReadyNodesCached(ctx, nil, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 NotReady, got %d", n)
	}
	// wired reader → informer-cache path, no clientset read.
	cached := nodeListReader{items: []corev1.Node{
		*node("a", corev1.ConditionTrue, nil),
		*node("b", corev1.ConditionFalse, nil),
		*node("c", corev1.ConditionFalse, nil),
	}}
	n, err = CountNotReadyNodesCached(ctx, cached, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 NotReady from cache, got %d", n)
	}
}

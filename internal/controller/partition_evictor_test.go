package controller

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// Builders (pe-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

// pePartitionedNode builds a node whose given NWPD condition has been
// True for `age` (already exceeds partitionMinAge when age > 10m).
func pePartitionedNode(name string, condType corev1.NodeConditionType, age time.Duration, taints ...corev1.Taint) *corev1.Node {
	n := node(name, corev1.ConditionTrue, nil, taints...)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               condType,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
	})
	return n
}

func pePod(ns, nodeName, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{NodeName: nodeName},
	}
}

// peHealthyNodes returns n plain Ready nodes named prefix-0..prefix-(n-1).
func peHealthyNodes(prefix string, n int) []runtime.Object {
	objs := make([]runtime.Object, 0, n)
	for i := 0; i < n; i++ {
		objs = append(objs, node(fmt.Sprintf("%s-%d", prefix, i), corev1.ConditionTrue, nil))
	}
	return objs
}

func peCountTaintsWithKey(taints []corev1.Taint, key string) int {
	n := 0
	for _, t := range taints {
		if t.Key == key {
			n++
		}
	}
	return n
}

// pePodExists reports whether a pod still exists in the fake cluster.
func pePodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("get pod %s/%s: %v", ns, name, err)
	return false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// A True network condition that flipped less than partitionMinAge ago
// must not flag the node: no taint, no eviction.
func TestPartitionEvictorFreshConditionNotFlagged(t *testing.T) {
	fresh := pePartitionedNode("p1", "HostNetworkProblems", time.Minute) // 60s < 600s
	objs := append([]runtime.Object{fresh, pePod("flux-system", "p1", "src-ctrl")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if hasTaint(getNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("node with a fresh (<10m) condition must not be tainted")
	}
	if !pePodExists(t, cs, "flux-system", "src-ctrl") {
		t.Fatal("pod evicted off a node that was never flagged")
	}
}

// A True condition with a zero LastTransitionTime does NOT flag the
// node — the bash `[ -n "$ts" ]` guard: no timestamp, no flag.
func TestPartitionEvictorZeroTimestampNotFlagged(t *testing.T) {
	n := node("p1", corev1.ConditionTrue, nil)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:   "ClusterNetworkProblem",
		Status: corev1.ConditionTrue,
		// LastTransitionTime deliberately zero
	})
	objs := append([]runtime.Object{n, pePod("flux-system", "p1", "src-ctrl")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if hasTaint(getNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("node with timestamp-less condition must not be flagged")
	}
	if !pePodExists(t, cs, "flux-system", "src-ctrl") {
		t.Fatal("pod evicted off a node that was never flagged")
	}
}

// The eviction cap bounds churn at partitionEvictCap (8) pods per run:
// with 9 flux-system pods on the flagged node exactly 8 are deleted.
func TestPartitionEvictorEvictionCap(t *testing.T) {
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	for i := 0; i < partitionEvictCap+1; i++ {
		objs = append(objs, pePod("flux-system", "p1", fmt.Sprintf("pod-%02d", i)))
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !hasTaint(getNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted")
	}
	remaining, err := cs.CoreV1().Pods(partitionPodNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 1 {
		t.Fatalf("expected exactly 1 survivor after cap=%d, got %d: %v",
			partitionEvictCap, len(remaining.Items), remaining.Items)
	}
}

// Pods outside flux-system on a flagged node are never evicted, while
// the flux-system pod on the same node is.
func TestPartitionEvictorLeavesOtherNamespaces(t *testing.T) {
	objs := []runtime.Object{
		pePartitionedNode("p1", "ClusterNetworkProblems", 30*time.Minute),
		pePod("flux-system", "p1", "victim"),
		pePod("default", "p1", "unrelated"),
		pePod("monitoring", "p1", "prom-agent"),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if pePodExists(t, cs, "flux-system", "victim") {
		t.Fatal("flux-system pod on flagged node not evicted")
	}
	for _, p := range [][2]string{{"default", "unrelated"}, {"monitoring", "prom-agent"}} {
		if !pePodExists(t, cs, p[0], p[1]) {
			t.Fatalf("pod %s/%s outside %s must not be evicted", p[0], p[1], partitionPodNS)
		}
	}
}

// Two flagged nodes under the 50% guard: each is tainted and flux-system
// pods are evicted off both.
func TestPartitionEvictorMultipleFlaggedUnderHalf(t *testing.T) {
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePartitionedNode("p2", "HostNetworkProblem", 20*time.Minute), // singular spelling
		pePod("flux-system", "p1", "pod-p1"),
		pePod("flux-system", "p2", "pod-p2"),
	}
	objs = append(objs, peHealthyNodes("h", 3)...) // 2/5 flagged < 50%
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p1", "p2"} {
		if !hasTaint(getNode(t, cs, name).Spec.Taints, partitionTaintKey) {
			t.Fatalf("flagged node %s not tainted", name)
		}
	}
	for _, pod := range []string{"pod-p1", "pod-p2"} {
		if pePodExists(t, cs, "flux-system", pod) {
			t.Fatalf("flux-system pod %s not evicted", pod)
		}
	}
}

// Untaint runs before the flagged path: a recovered node loses the
// partition taint while a still-flagged node keeps it (and is not
// tainted twice).
func TestPartitionEvictorUntaintsRecoveredKeepsFlaggedTaint(t *testing.T) {
	partitionTaint := corev1.Taint{
		Key:    partitionTaintKey,
		Value:  "true",
		Effect: corev1.TaintEffectNoSchedule,
	}
	recovered := node("r1", corev1.ConditionTrue, nil, partitionTaint) // tainted, no condition
	flagged := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute, partitionTaint)
	objs := append([]runtime.Object{recovered, flagged}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if hasTaint(getNode(t, cs, "r1").Spec.Taints, partitionTaintKey) {
		t.Fatal("recovered node kept its partition taint")
	}
	taints := getNode(t, cs, "p1").Spec.Taints
	if !hasTaint(taints, partitionTaintKey) {
		t.Fatal("still-flagged node lost its partition taint")
	}
	if n := peCountTaintsWithKey(taints, partitionTaintKey); n != 1 {
		t.Fatalf("partition taint duplicated on flagged node: %d entries", n)
	}
}

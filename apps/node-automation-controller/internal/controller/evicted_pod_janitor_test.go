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
// Builders (epj-prefixed)
// ---------------------------------------------------------------------------

// epjPod builds a Pod in the given phase/reason, `age` old.
func epjPod(ns, name string, phase corev1.PodPhase, reason string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Spec:   corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{Phase: phase, Reason: reason},
	}
}

// epjPodExists reports whether a pod still exists in the fake cluster.
func epjPodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
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

// Every reason in the terminal set is reaped; a Failed pod whose
// reason is not in the set is kept for debugging.
func TestEvictedPodJanitorReasonSet(t *testing.T) {
	objs := []runtime.Object{}
	for i, reason := range []string{
		"Evicted", "NodeAffinity", "NodeLost", "Shutdown",
		"UnexpectedAdmissionError", "OutOfcpu", "OutOfmemory",
		"OutOfephemeral-storage",
	} {
		objs = append(objs,
			epjPod("a", fmt.Sprintf("doomed-%d", i), corev1.PodFailed, reason, 2*time.Hour))
	}
	objs = append(objs,
		epjPod("a", "other-reason", corev1.PodFailed, "ContainerStatusUnknown", 72*time.Hour),
		epjPod("a", "no-reason", corev1.PodFailed, "", 72*time.Hour))
	cs := fake.NewSimpleClientset(objs...)
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if epjPodExists(t, cs, "a", fmt.Sprintf("doomed-%d", i)) {
			t.Fatalf("doomed-%d not deleted", i)
		}
	}
	for _, name := range []string{"other-reason", "no-reason"} {
		if !epjPodExists(t, cs, "a", name) {
			t.Fatalf("pod %s wrongly deleted", name)
		}
	}
}

// The cap bounds churn at evictedPodCap deletions per run: with 12
// eligible pods exactly 10 are deleted and 2 survive for the next run.
func TestEvictedPodJanitorCapTen(t *testing.T) {
	objs := make([]runtime.Object, 0, evictedPodCap+2)
	for i := 0; i < evictedPodCap+2; i++ {
		objs = append(objs,
			epjPod("a", fmt.Sprintf("evicted-%02d", i), corev1.PodFailed, "Evicted", 2*time.Hour))
	}
	cs := fake.NewSimpleClientset(objs...)
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	remaining, err := cs.CoreV1().Pods("a").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 2 {
		t.Fatalf("expected exactly 2 survivors after cap=%d, got %d",
			evictedPodCap, len(remaining.Items))
	}
}

// Pods already terminating belong to the API's grace period — the
// janitor must not touch them (and they must not burn the cap).
func TestEvictedPodJanitorSkipsTerminating(t *testing.T) {
	terminating := epjPod("a", "terminating", corev1.PodFailed, "Evicted", 2*time.Hour)
	now := metav1.NewTime(time.Now())
	terminating.DeletionTimestamp = &now
	cs := fake.NewSimpleClientset(terminating)
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !epjPodExists(t, cs, "a", "terminating") {
		t.Fatal("terminating pod was deleted")
	}
}

// Non-Failed phases are never touched, and a Failed pod younger than
// 1h stays so a fresh eviction remains inspectable.
func TestEvictedPodJanitorKeepsNonFailedAndYoung(t *testing.T) {
	cs := fake.NewSimpleClientset(
		epjPod("a", "running", corev1.PodRunning, "Evicted", 72*time.Hour),
		epjPod("a", "succeeded", corev1.PodSucceeded, "Evicted", 72*time.Hour),
		epjPod("a", "pending", corev1.PodPending, "", 72*time.Hour),
		epjPod("a", "young-evicted", corev1.PodFailed, "Evicted", 30*time.Minute))
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"running", "succeeded", "pending", "young-evicted"} {
		if !epjPodExists(t, cs, "a", name) {
			t.Fatalf("pod %s wrongly deleted", name)
		}
	}
}

// The sweep lists cluster-wide (NamespaceAll): old evicted pods in
// different namespaces are all deleted in one run.
func TestEvictedPodJanitorMultipleNamespaces(t *testing.T) {
	cs := fake.NewSimpleClientset(
		epjPod("ns-a", "old-evicted-a", corev1.PodFailed, "Evicted", 2*time.Hour),
		epjPod("ns-b", "old-evicted-b", corev1.PodFailed, "NodeLost", 48*time.Hour))
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{{"ns-a", "old-evicted-a"}, {"ns-b", "old-evicted-b"}} {
		if epjPodExists(t, cs, p[0], p[1]) {
			t.Fatalf("old evicted pod %s/%s not deleted", p[0], p[1])
		}
	}
}

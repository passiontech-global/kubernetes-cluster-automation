package evictedpodjanitor

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Every reason in the terminal set is reaped; a Failed pod whose
// reason is not in the set is kept for debugging.
func TestEvictedPodJanitorReasonSet(t *testing.T) {
	objs := []runtime.Object{}
	for i, reason := range []string{
		"Evicted", "NodeAffinity", "NodeLost", "Preempted", "Shutdown",
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
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		if testutil.PodExistsStrict(t, cs, "a", fmt.Sprintf("doomed-%d", i)) {
			t.Fatalf("doomed-%d not deleted", i)
		}
	}
	for _, name := range []string{"other-reason", "no-reason"} {
		if !testutil.PodExistsStrict(t, cs, "a", name) {
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
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	remaining, err := cs.CoreV1().Pods("a").List(t.Context(), metav1.ListOptions{})
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
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !testutil.PodExistsStrict(t, cs, "a", "terminating") {
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
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"running", "succeeded", "pending", "young-evicted"} {
		if !testutil.PodExistsStrict(t, cs, "a", name) {
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
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{{"ns-a", "old-evicted-a"}, {"ns-b", "old-evicted-b"}} {
		if testutil.PodExistsStrict(t, cs, p[0], p[1]) {
			t.Fatalf("old evicted pod %s/%s not deleted", p[0], p[1])
		}
	}
}

// Pod age is measured from the latest terminated container
// finishedAt, not object creation: a weeks-old pod evicted 30m ago
// stays inspectable, while one evicted 2h ago is reaped.
func TestEvictedPodJanitorUsesFinishedAt(t *testing.T) {
	fresh := epjPod("a", "old-pod-fresh-eviction", corev1.PodFailed, "Evicted", 72*time.Hour)
	fresh.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
		}},
	}}
	old := epjPod("a", "old-pod-old-eviction", corev1.PodFailed, "Evicted", 72*time.Hour)
	old.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		}},
	}}
	cs := fake.NewSimpleClientset(fresh, old)
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !testutil.PodExistsStrict(t, cs, "a", "old-pod-fresh-eviction") {
		t.Fatal("freshly evicted pod deleted — finishedAt ignored")
	}
	if testutil.PodExistsStrict(t, cs, "a", "old-pod-old-eviction") {
		t.Fatal("old eviction not reaped")
	}
}

// The delete carries a UID precondition — the listed object is what
// the sweep vetted; a same-named pod recreated between list and
// delete must not inherit it.
func TestEvictedPodJanitorDeleteUIDPrecondition(t *testing.T) {
	pod := epjPod("a", "old-evicted", corev1.PodFailed, "Evicted", 2*time.Hour)
	pod.UID = "uid-old-evicted"
	cs := fake.NewSimpleClientset(pod)
	var gotUID *types.UID
	cs.PrependReactor("delete", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if gotUID == nil || *gotUID != pod.UID {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
	if testutil.PodExistsStrict(t, cs, "a", "old-evicted") {
		t.Fatal("old evicted pod not deleted")
	}
}

// The pods list carries a server-side status.phase=Failed field
// selector — only Failed pods can hold an eviction reason, so
// Running/Pending pods must never be fetched. The fake tracker
// ignores field selectors, which is also why the in-code phase
// check stays and this test can still delete.
func TestEvictedPodJanitorFieldSelector(t *testing.T) {
	cs := fake.NewSimpleClientset(
		epjPod("a", "old-evicted", corev1.PodFailed, "Evicted", 2*time.Hour))
	var gotFields string
	cs.PrependReactor("list", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			gotFields = a.(ktesting.ListAction).
				GetListRestrictions().Fields.String()
			return false, nil, nil // fall through to the tracker
		})
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if want := "status.phase=" + string(corev1.PodFailed); gotFields != want {
		t.Fatalf("list field selector = %q, want %q", gotFields, want)
	}
	if testutil.PodExistsStrict(t, cs, "a", "old-evicted") {
		t.Fatal("old evicted pod not deleted")
	}
}

// A pods list failure is a real error — the periodic wrapper meters it.
func TestEvictedPodJanitorListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(t.Context()); err == nil {
		t.Fatal("expected error when the pods list fails")
	}
}

// A failed delete is tolerated (logged + metered) but still counts
// against the per-run cap — exactly evictedPodCap attempts happen even
// when every delete errors.
func TestEvictedPodJanitorDeleteErrorTolerated(t *testing.T) {
	objs := make([]runtime.Object, 0, evictedPodCap+2)
	for i := 0; i < evictedPodCap+2; i++ {
		objs = append(objs,
			epjPod("a", fmt.Sprintf("evicted-%02d", i), corev1.PodFailed, "Evicted", 2*time.Hour))
	}
	cs := fake.NewSimpleClientset(objs...)
	var attempts int32
	cs.PrependReactor("delete", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			atomic.AddInt32(&attempts, 1)
			return true, nil, errors.New("delete rejected")
		})
	j := &evictedPodJanitor{cs: cs}
	if err := j.run(t.Context()); err != nil {
		t.Fatalf("pod delete failures must not error the run: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != int32(evictedPodCap) {
		t.Fatalf("expected exactly cap=%d delete attempts, got %d", evictedPodCap, got)
	}
}

// A delete answered NotFound raced an external cleanup — logged as a
// skip, NOT metered as an error (alert noise stays off the races).
func TestEvictedPodJanitorDeleteNotFoundNotMetered(t *testing.T) {
	cs := fake.NewSimpleClientset(
		epjPod("a", "old-evicted", corev1.PodFailed, "Evicted", 2*time.Hour))
	cs.PrependReactor("delete", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				corev1.Resource("pods"), "old-evicted")
		})
	j := &evictedPodJanitor{cs: cs, queue: "evicted-pod-janitor"}
	before := testutil.QueueErrorCount(t, "evicted-pod-janitor")
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "evicted-pod-janitor") - before; got != 0 {
		t.Fatalf("NotFound race metered as an error: delta = %v, want 0", got)
	}
	if !testutil.PodExistsStrict(t, cs, "a", "old-evicted") {
		t.Fatal("pod vanished despite the rejected delete")
	}
}

// A Conflict answer is the UID precondition firing on a recreated
// same-named pod — equally a race, equally not an error.
func TestEvictedPodJanitorDeleteConflictNotMetered(t *testing.T) {
	cs := fake.NewSimpleClientset(
		epjPod("a", "old-evicted", corev1.PodFailed, "Evicted", 2*time.Hour))
	cs.PrependReactor("delete", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(
				corev1.Resource("pods"), "old-evicted", errors.New("uid mismatch"))
		})
	j := &evictedPodJanitor{cs: cs, queue: "evicted-pod-janitor"}
	before := testutil.QueueErrorCount(t, "evicted-pod-janitor")
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "evicted-pod-janitor") - before; got != 0 {
		t.Fatalf("Conflict race metered as an error: delta = %v, want 0", got)
	}
}

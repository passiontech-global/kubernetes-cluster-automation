package janitor

import (
	"errors"
	"fmt"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// Builders (fjj-prefixed; failedJob() itself is shared from controller_test.go)
// ---------------------------------------------------------------------------

// fjjJobWithConditions builds a Job with arbitrary status conditions —
// for the cases failedJob() cannot express (zero timestamp, Failed=False).
func fjjJobWithConditions(ns, name string, conds ...batchv1.JobCondition) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status:     batchv1.JobStatus{Conditions: conds},
	}
}

// fjjJobExists reports whether a job still exists in the fake cluster.
func fjjJobExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("get job %s/%s: %v", ns, name, err)
	return false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// A Failed=True condition with a zero LastTransitionTime is kept —
// the bash `[ -n "$ts" ]` guard: no timestamp, no deletion.
func TestFailedJobsJanitorKeepsZeroTimestamp(t *testing.T) {
	noTS := fjjJobWithConditions("a", "failed-no-ts", batchv1.JobCondition{
		Type:   batchv1.JobFailed,
		Status: corev1.ConditionTrue,
		// LastTransitionTime deliberately zero
	})
	cs := fake.NewSimpleClientset(noTS)
	j := &failedJobsJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !fjjJobExists(t, cs, "a", "failed-no-ts") {
		t.Fatal("job with timestamp-less Failed condition was deleted")
	}
}

// The cap bounds churn at failedJobCap (50) deletions per run: with 55
// old-failed jobs exactly 50 are deleted and 5 survive for the next run.
func TestFailedJobsJanitorCapFifty(t *testing.T) {
	objs := make([]runtime.Object, 0, failedJobCap+5)
	for i := 0; i < failedJobCap+5; i++ {
		objs = append(objs,
			failedJob("ns-a", fmt.Sprintf("old-failed-%02d", i), 25*time.Hour))
	}
	cs := fake.NewSimpleClientset(objs...)
	j := &failedJobsJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	remaining, err := cs.BatchV1().Jobs("ns-a").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 5 {
		t.Fatalf("expected exactly 5 survivors after cap=%d, got %d",
			failedJobCap, len(remaining.Items))
	}
}

// The sweep lists cluster-wide (NamespaceAll): old-failed jobs in
// different namespaces are all deleted in one run.
func TestFailedJobsJanitorMultipleNamespaces(t *testing.T) {
	cs := fake.NewSimpleClientset(
		failedJob("ns-a", "old-failed-a", 25*time.Hour),
		failedJob("ns-b", "old-failed-b", 72*time.Hour),
		failedJob("ns-b", "recent-failed-b", time.Hour), // fresh — must survive
	)
	j := &failedJobsJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, job := range [][2]string{{"ns-a", "old-failed-a"}, {"ns-b", "old-failed-b"}} {
		if fjjJobExists(t, cs, job[0], job[1]) {
			t.Fatalf("old failed job %s/%s not deleted", job[0], job[1])
		}
	}
	if !fjjJobExists(t, cs, "ns-b", "recent-failed-b") {
		t.Fatal("recently failed job was deleted")
	}
}

// A Failed condition whose status is not True is not a failure — the
// job is kept regardless of age. Same for jobs with no conditions.
func TestFailedJobsJanitorKeepsFailedFalseAndNoCondition(t *testing.T) {
	failedFalse := fjjJobWithConditions("a", "failed-false", batchv1.JobCondition{
		Type:               batchv1.JobFailed,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-72 * time.Hour)),
	})
	running := fjjJobWithConditions("a", "active") // no conditions at all
	suspended := fjjJobWithConditions("a", "suspended", batchv1.JobCondition{
		Type:               batchv1.JobSuspended,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-72 * time.Hour)),
	})
	cs := fake.NewSimpleClientset(failedFalse, running, suspended)
	j := &failedJobsJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"failed-false", "active", "suspended"} {
		if !fjjJobExists(t, cs, "a", name) {
			t.Fatalf("job %s wrongly deleted", name)
		}
	}
}

// A jobs list failure is a real error — the periodic wrapper meters it.
func TestFailedJobsJanitorListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	j := &failedJobsJanitor{cs: cs}
	if err := j.run(ctx); err == nil {
		t.Fatal("expected error when the jobs list fails")
	}
}

// A failed delete is tolerated (logged) — the run still nils out and
// the job survives for the next sweep.
func TestFailedJobsJanitorDeleteErrorTolerated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		failedJob("a", "old-failed", 25*time.Hour),
		failedJob("a", "old-failed-2", 48*time.Hour))
	cs.PrependReactor("delete", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("delete rejected")
		})
	j := &failedJobsJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatalf("job delete failures must not error the run: %v", err)
	}
	for _, name := range []string{"old-failed", "old-failed-2"} {
		if !fjjJobExists(t, cs, "a", name) {
			t.Fatalf("job %s deleted despite the failing delete call", name)
		}
	}
}

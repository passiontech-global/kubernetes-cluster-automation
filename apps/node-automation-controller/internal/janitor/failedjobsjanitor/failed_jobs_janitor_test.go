package failedjobsjanitor

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
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
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
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
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
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
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
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
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
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
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
	if err := j.run(ctx); err == nil {
		t.Fatal("expected error when the jobs list fails")
	}
}

// A Job already Terminating is skipped entirely — re-deleting would
// only burn a per-run cap slot on an object the API already owns.
func TestFailedJobsJanitorSkipsTerminating(t *testing.T) {
	now := metav1.NewTime(time.Now())
	terminating := failedJob("a", "terminating-failed", 25*time.Hour)
	terminating.DeletionTimestamp = &now
	cs := fake.NewSimpleClientset(terminating)
	var attempts int32
	cs.PrependReactor("delete", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			atomic.AddInt32(&attempts, 1)
			return false, nil, nil
		})
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&attempts); got != 0 {
		t.Fatalf("terminating job consumed a delete attempt (%d)", got)
	}
	if !fjjJobExists(t, cs, "a", "terminating-failed") {
		t.Fatal("terminating job vanished")
	}
}

// The delete carries a UID precondition — the listed object is what
// the sweep vetted; a same-named Job recreated between list and
// delete must not inherit it.
func TestFailedJobsJanitorDeleteUIDPrecondition(t *testing.T) {
	job := failedJob("a", "old-failed", 25*time.Hour)
	job.UID = "uid-old-failed"
	cs := fake.NewSimpleClientset(job)
	var gotUID *types.UID
	cs.PrependReactor("delete", "jobs",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if gotUID == nil || *gotUID != job.UID {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
	if fjjJobExists(t, cs, "a", "old-failed") {
		t.Fatal("old failed job not deleted")
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
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
	if err := j.run(ctx); err != nil {
		t.Fatalf("job delete failures must not error the run: %v", err)
	}
	for _, name := range []string{"old-failed", "old-failed-2"} {
		if !fjjJobExists(t, cs, "a", name) {
			t.Fatalf("job %s deleted despite the failing delete call", name)
		}
	}
}

// ---------------------------------------------------------------------------
// C3b stuck-Terminating audit
// ---------------------------------------------------------------------------

// A namespace and a PVC Terminating past the 2h threshold emit the
// stuck series; fresh terminations and live objects do not. For the
// cluster-scoped Namespace the namespace label is the documented "".
// DeleteLabelValues doubles as an exists-probe and the cleanup.
func TestStuckTerminatingAuditMarksStuck(t *testing.T) {
	now := time.Now()
	old := metav1.NewTime(now.Add(-3 * time.Hour))
	fresh := metav1.NewTime(now.Add(-30 * time.Minute))
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "stuck-ns", DeletionTimestamp: &old},
			Spec: corev1.NamespaceSpec{
				Finalizers: []corev1.FinalizerName{"kubernetes"}},
		},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name: "fresh-ns", DeletionTimestamp: &fresh}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "live-ns"}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Namespace: "data", Name: "stuck-pvc", DeletionTimestamp: &old,
			Finalizers: []string{"kubernetes.io/pvc-protection"}}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Namespace: "data", Name: "fresh-pvc", DeletionTimestamp: &fresh}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Namespace: "data", Name: "live-pvc"}},
	)
	j := &failedJobsJanitor{cs: cs, nowFn: func() time.Time { return now }}
	if err := j.auditStuckTerminating(ctx); err != nil {
		t.Fatal(err)
	}
	for _, key := range [][3]string{
		{"Namespace", "", "stuck-ns"},
		{"PersistentVolumeClaim", "data", "stuck-pvc"},
	} {
		if !metrics.StuckTerminatingResources.DeleteLabelValues(key[0], key[1], key[2]) {
			t.Fatalf("missing stuck series for %v", key)
		}
	}
	for _, key := range [][3]string{
		{"Namespace", "", "fresh-ns"},
		{"Namespace", "", "live-ns"},
		{"PersistentVolumeClaim", "data", "fresh-pvc"},
		{"PersistentVolumeClaim", "data", "live-pvc"},
	} {
		if metrics.StuckTerminatingResources.DeleteLabelValues(key[0], key[1], key[2]) {
			t.Fatalf("unexpected stuck series for %v", key)
		}
	}
}

// A VolumeAttachment wedged in Terminating past 2h is surfaced too —
// the volumeattachment-cleaner refuses to delete terminating VAs, so
// the attacher-finalizer wedge is exactly what this audit covers.
// VAs are cluster-scoped: the namespace label is "".
func TestStuckTerminatingAuditMarksStuckVA(t *testing.T) {
	now := time.Now()
	old := metav1.NewTime(now.Add(-3 * time.Hour))
	fresh := metav1.NewTime(now.Add(-30 * time.Minute))
	cs := fake.NewSimpleClientset(
		&storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{
			Name: "va-stuck", DeletionTimestamp: &old,
			Finalizers: []string{"external-attacher/test-csi"}}},
		&storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{
			Name: "va-fresh", DeletionTimestamp: &fresh}},
		&storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{
			Name: "va-live"}},
	)
	j := &failedJobsJanitor{cs: cs, nowFn: func() time.Time { return now }}
	if err := j.auditStuckTerminating(ctx); err != nil {
		t.Fatal(err)
	}
	if !metrics.StuckTerminatingResources.DeleteLabelValues(
		"VolumeAttachment", "", "va-stuck") {
		t.Fatal("missing stuck series for the terminating VolumeAttachment")
	}
	for _, name := range []string{"va-fresh", "va-live"} {
		if metrics.StuckTerminatingResources.DeleteLabelValues(
			"VolumeAttachment", "", name) {
			t.Fatalf("unexpected stuck series for %s", name)
		}
	}
}

// A resource that finishes terminating (or vanishes) gets its series
// pruned on the next audit — /metrics must not leak stale "stuck"
// label triples.
func TestStuckTerminatingAuditPrunesFinished(t *testing.T) {
	now := time.Now()
	old := metav1.NewTime(now.Add(-3 * time.Hour))
	cs := fake.NewSimpleClientset(
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Namespace: "data", Name: "stuck-pvc", DeletionTimestamp: &old}},
	)
	j := &failedJobsJanitor{cs: cs, nowFn: func() time.Time { return now }}
	if err := j.auditStuckTerminating(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := j.stuckEmitted[stuckTerminatingKey{
		kind: "PersistentVolumeClaim", ns: "data", name: "stuck-pvc"}]; !ok {
		t.Fatal("stuck pvc not tracked")
	}
	// The finalizer drained — the object is gone next sweep.
	if err := cs.CoreV1().PersistentVolumeClaims("data").
		Delete(ctx, "stuck-pvc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := j.auditStuckTerminating(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.StuckTerminatingResources.DeleteLabelValues(
		"PersistentVolumeClaim", "data", "stuck-pvc") {
		t.Fatal("stale series survived the prune")
	}
	if len(j.stuckEmitted) != 0 {
		t.Fatalf("stuckEmitted ledger holds %d entries, want 0", len(j.stuckEmitted))
	}
}

// The audit rides the same hourly run() tick — a stuck namespace is
// marked even when there is no failed job to delete.
func TestStuckTerminatingAuditRunsInsideSweep(t *testing.T) {
	now := time.Now()
	old := metav1.NewTime(now.Add(-3 * time.Hour))
	cs := fake.NewSimpleClientset(
		failedJob("a", "old-failed", 25*time.Hour),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name: "stuck-ns", DeletionTimestamp: &old}},
	)
	j := &failedJobsJanitor{cs: cs, nowFn: func() time.Time { return now }}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !metrics.StuckTerminatingResources.DeleteLabelValues("Namespace", "", "stuck-ns") {
		t.Fatal("stuck namespace series missing after full sweep")
	}
}

// A namespaces list failure is a real error — the periodic wrapper
// meters it.
func TestStuckTerminatingAuditListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "namespaces",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	j := &failedJobsJanitor{cs: cs, nowFn: time.Now}
	if err := j.auditStuckTerminating(ctx); err == nil {
		t.Fatal("expected error when the namespaces list fails")
	}
}

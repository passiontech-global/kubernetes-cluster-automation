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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
			Finalizers: []string{"external-provisioner/test"}}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Namespace: "data", Name: "fresh-pvc", DeletionTimestamp: &fresh}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Namespace: "data", Name: "live-pvc"}},
	)
	j := &failedJobsJanitor{cs: cs, now: func() time.Time { return now }}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
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
	j := &failedJobsJanitor{cs: cs, now: func() time.Time { return now }}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
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
	j := &failedJobsJanitor{cs: cs, now: func() time.Time { return now }}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := j.stuckEmitted.Last()[stuckTerminatingKey{
		kind: "PersistentVolumeClaim", ns: "data", name: "stuck-pvc"}]; !ok {
		t.Fatal("stuck pvc not tracked")
	}
	// The finalizer drained — the object is gone next sweep.
	if err := cs.CoreV1().PersistentVolumeClaims("data").
		Delete(ctx, "stuck-pvc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if metrics.StuckTerminatingResources.DeleteLabelValues(
		"PersistentVolumeClaim", "data", "stuck-pvc") {
		t.Fatal("stale series survived the prune")
	}
	if len(j.stuckEmitted.Last()) != 0 {
		t.Fatalf("stuckEmitted ledger holds %d entries, want 0", len(j.stuckEmitted.Last()))
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
	j := &failedJobsJanitor{cs: cs, now: func() time.Time { return now }}
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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
	if err := j.auditStuckTerminating(ctx, nil); err == nil {
		t.Fatal("expected error when the namespaces list fails")
	}
}

// va-stuck-terminating — a PVC stuck Terminating >2h whose only finalizer is
// pvc-protection and which no live pod references gets the finalizer
// stripped.
func TestAuditStuckPVCFinalizerStrip(t *testing.T) {
	now := time.Now()
	termAt := metav1.NewTime(now.Add(-3 * time.Hour))
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "data",
			DeletionTimestamp: &termAt,
			Finalizers:        []string{"kubernetes.io/pvc-protection"},
		},
	}
	cs := fake.NewSimpleClientset(pvc)
	j := &failedJobsJanitor{cs: cs, now: func() time.Time { return now }}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatal(err)
	}
	got, err := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "data", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 0 {
		t.Fatalf("pvc-protection finalizer not stripped: %v", got.Finalizers)
	}
}

// A live pod still claiming the PVC keeps the finalizer — fail closed.
func TestAuditStuckPVCReferencedKept(t *testing.T) {
	now := time.Now()
	termAt := metav1.NewTime(now.Add(-3 * time.Hour))
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "data",
			DeletionTimestamp: &termAt,
			Finalizers:        []string{"kubernetes.io/pvc-protection"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "user"},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "v",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: "data"}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(pvc, pod)
	j := &failedJobsJanitor{cs: cs, now: func() time.Time { return now }}
	if err := j.auditStuckTerminating(ctx, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "data", metav1.GetOptions{})
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizer stripped while a pod still references the claim")
	}
}

// ---------------------------------------------------------------------------
// buildrun-ttl-sweep — Shipwright BuildRun TTL sweep
// ---------------------------------------------------------------------------

// fjjBuildRun builds a BuildRun — succeeded is the Succeeded condition
// status ("True"/"False"/"" for none), completedAgo backs
// status.completionTime (0 omits it).
func fjjBuildRun(ns, name, succeeded string, completedAgo time.Duration) *unstructured.Unstructured {
	return fjjRun(kube.GVRShipwrightBuildRun, "BuildRun", ns, name, succeeded, completedAgo)
}

// fjjRun builds one run object (PipelineRun/TaskRun/BuildRun) in the
// knative-style condition shape all three controllers write —
// succeeded is the Succeeded condition status ("True"/"False"/"" for
// none), completedAgo backs status.completionTime (0 omits it).
func fjjRun(gvr schema.GroupVersionResource, kind, ns, name, succeeded string,
	completedAgo time.Duration) *unstructured.Unstructured {
	status := map[string]any{}
	if completedAgo > 0 {
		status["completionTime"] = time.Now().Add(-completedAgo).UTC().Format(time.RFC3339)
	}
	if succeeded != "" {
		status["conditions"] = []any{map[string]any{
			"type":   "Succeeded",
			"status": succeeded,
		}}
	}
	return testutil.Unstructured(
		gvr.GroupVersion().WithKind(kind), ns, name,
		map[string]any{"status": status})
}

func fjjDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
}

func fjjRunExists(t *testing.T, dyn *dynamicfake.FakeDynamicClient,
	gvr schema.GroupVersionResource, ns, name string) bool {
	t.Helper()
	_, err := dyn.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("get %s %s/%s: %v", gvr.Resource, ns, name, err)
	return false
}

func fjjBuildRunExists(t *testing.T, dyn *dynamicfake.FakeDynamicClient, ns, name string) bool {
	t.Helper()
	return fjjRunExists(t, dyn, kube.GVRShipwrightBuildRun, ns, name)
}

// Completed BuildRuns older than 24h are reaped; fresh completions,
// still-running builds and builds with no Succeeded condition all
// stay.
func TestFailedJobsJanitorBuildRunTTL(t *testing.T) {
	dyn := fjjDynFake(
		fjjBuildRun("cicd", "old-ok", "True", 25*time.Hour),    // delete
		fjjBuildRun("cicd", "old-fail", "False", 30*time.Hour), // delete
		fjjBuildRun("cicd", "fresh", "True", 2*time.Hour),      // keep — inside TTL
		fjjBuildRun("cicd", "running", "", 0),                  // keep — not completed
		fjjBuildRun("cicd", "no-cond", "", 48*time.Hour),       // keep — no condition
		fjjBuildRun("other", "old-ok", "True", 48*time.Hour),   // delete — all namespaces
		// Registers tekton.dev/v1 TaskRun in the fake (the
		// testhelp GVK table covers PipelineRun only) — the
		// table sweep lists every kind, and a non-terminal
		// taskrun doubles as a keep-witness.
		fjjRun(kube.GVRTektonTaskRun, "TaskRun", "cicd", "tr-live", "", 0),
	)
	j := &failedJobsJanitor{
		cs: fake.NewSimpleClientset(), dyn: dyn, now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepCompletedRuns(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"old-ok", "old-fail"} {
		if fjjBuildRunExists(t, dyn, "cicd", name) {
			t.Fatalf("completed BuildRun %s older than TTL must be deleted", name)
		}
	}
	if fjjBuildRunExists(t, dyn, "other", "old-ok") {
		t.Fatal("completed BuildRun in another namespace must be deleted")
	}
	for _, name := range []string{"fresh", "running", "no-cond"} {
		if !fjjBuildRunExists(t, dyn, "cicd", name) {
			t.Fatalf("BuildRun %s must survive", name)
		}
	}
}

// run-workspace-reaper — Tekton PipelineRuns and TaskRuns share the same 24h
// retention horizon: terminal past-TTL objects are reaped while
// running/fresh/unresolved ones stay.
func TestFailedJobsJanitorTektonRunTTL(t *testing.T) {
	dyn := fjjDynFake(
		fjjRun(kube.GVRTektonPipelineRun, "PipelineRun", "cicd", "pr-old-ok", "True", 30*time.Hour), // delete
		fjjRun(kube.GVRTektonPipelineRun, "PipelineRun", "cicd", "pr-fresh", "True", 2*time.Hour),   // keep — inside TTL
		fjjRun(kube.GVRTektonPipelineRun, "PipelineRun", "cicd", "pr-running", "", 0),               // keep — not terminal
		fjjRun(kube.GVRTektonTaskRun, "TaskRun", "cicd", "tr-old-fail", "False", 48*time.Hour),      // delete
		fjjRun(kube.GVRTektonTaskRun, "TaskRun", "cicd", "tr-running", "", 0),                       // keep — not terminal
	)
	j := &failedJobsJanitor{
		cs: fake.NewSimpleClientset(), dyn: dyn, now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepCompletedRuns(ctx); err != nil {
		t.Fatal(err)
	}
	if fjjRunExists(t, dyn, kube.GVRTektonPipelineRun, "cicd", "pr-old-ok") {
		t.Fatal("completed PipelineRun older than TTL must be deleted")
	}
	if fjjRunExists(t, dyn, kube.GVRTektonTaskRun, "cicd", "tr-old-fail") {
		t.Fatal("failed TaskRun older than TTL must be deleted")
	}
	for _, c := range []struct {
		gvr  schema.GroupVersionResource
		name string
	}{
		{kube.GVRTektonPipelineRun, "pr-fresh"},
		{kube.GVRTektonPipelineRun, "pr-running"},
		{kube.GVRTektonTaskRun, "tr-running"},
	} {
		if !fjjRunExists(t, dyn, c.gvr, "cicd", c.name) {
			t.Fatalf("%s %s must survive", c.gvr.Resource, c.name)
		}
	}
}

// A terminal condition without a completionTime is still reaped —
// the condition's lastTransitionTime is the finish stamp (older
// controllers resolved runs without stamping completionTime).
func TestFailedJobsJanitorRunTerminalFallbackTimestamp(t *testing.T) {
	obj := fjjRun(kube.GVRTektonTaskRun, "TaskRun", "cicd", "tr-no-ct", "True", 0)
	if err := unstructured.SetNestedSlice(obj.Object, []any{map[string]any{
		"type":               "Succeeded",
		"status":             "False",
		"lastTransitionTime": time.Now().Add(-30 * time.Hour).UTC().Format(time.RFC3339),
	}}, "status", "conditions"); err != nil {
		t.Fatal(err)
	}
	dyn := fjjDynFake(obj)
	j := &failedJobsJanitor{
		cs: fake.NewSimpleClientset(), dyn: dyn, now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepCompletedRuns(ctx); err != nil {
		t.Fatal(err)
	}
	if fjjRunExists(t, dyn, kube.GVRTektonTaskRun, "cicd", "tr-no-ct") {
		t.Fatal("terminal TaskRun aged by lastTransitionTime must be deleted")
	}
}

// No Shipwright CRD → the sweep is a quiet no-op, not an error.
func TestFailedJobsJanitorBuildRunCRDAbsent(t *testing.T) {
	j := &failedJobsJanitor{
		cs: fake.NewSimpleClientset(), now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	// dyn nil — the sweep must no-op without a dynamic client.
	if err := j.sweepCompletedRuns(ctx); err != nil {
		t.Fatalf("nil dyn must no-op: %v", err)
	}
	// A dyn fake without the BuildRun GVR registered panics on List —
	// simulate the absent-CRD contract via a reactor returning 404.
	dyn := fjjDynFake()
	dyn.PrependReactor("list", "buildruns",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "shipwright.io", Resource: "buildruns"}, "x")
		})
	j.dyn = dyn
	if err := j.sweepCompletedRunKind(ctx, kube.GVRShipwrightBuildRun, "buildrun"); err != nil {
		t.Fatalf("absent Shipwright CRD must be a quiet no-op: %v", err)
	}
	// Absent Tekton (both GVRs 404) must not break the table sweep —
	// Shipwright objects still get reaped. A throwaway TaskRun seed is
	// required only to register the type in the fake (the testhelp GVK
	// table covers PipelineRun only); the list reactor still 404s.
	dyn2 := fjjDynFake(
		fjjBuildRun("cicd", "old-ok", "True", 25*time.Hour),
		fjjRun(kube.GVRTektonTaskRun, "TaskRun", "cicd", "tr-live", "", 0))
	for _, res := range []string{"pipelineruns", "taskruns"} {
		res := res
		dyn2.PrependReactor("list", res,
			func(a ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewNotFound(
					schema.GroupResource{Group: "tekton.dev", Resource: res}, "x")
			})
	}
	j.dyn = dyn2
	if err := j.sweepCompletedRuns(ctx); err != nil {
		t.Fatalf("absent Tekton CRDs must be a quiet no-op: %v", err)
	}
	if fjjBuildRunExists(t, dyn2, "cicd", "old-ok") {
		t.Fatal("completed BuildRun must still be reaped when Tekton is absent")
	}
}

// ---------------------------------------------------------------------------
// run-workspace-reaper — orphaned run-workspace PVC reaper
// ---------------------------------------------------------------------------

// fjjWorkspacePVC builds a PVC age old carrying the given
// ownerReferences and labels.
func fjjWorkspacePVC(ns, name string, age time.Duration,
	refs []metav1.OwnerReference, labels map[string]string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Namespace:         ns,
		Name:              name,
		CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		OwnerReferences:   refs,
		Labels:            labels,
	}}
}

// fjjPVCOwner is the ownerRef literal a run-owned workspace PVC
// carries.
func fjjPVCOwner(apiVersion, kind, name string) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: apiVersion, Kind: kind, Name: name, UID: types.UID("owner-" + name)}
}

// fjjPodClaiming builds a pod in phase that mounts claimName.
func fjjPodClaiming(ns, name, claimName string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "ws",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: claimName}}}}},
		Status: corev1.PodStatus{Phase: phase},
	}
}

func fjjPVCExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("get pvc %s/%s: %v", ns, name, err)
	return false
}

// The orphan matrix: a workspace claim older than 6h is deleted when
// every run ref is gone-or-terminal and no non-terminal pod mounts
// it; live owners, mounting pods, fresh claims, terminating claims
// and claimless PVCs all stay.
func TestOrphanWorkspacePVCReaper(t *testing.T) {
	dyn := fjjDynFake(
		// pr-live is non-terminal (no condition) — its PVC stays.
		fjjRun(kube.GVRTektonPipelineRun, "PipelineRun", "cicd", "pr-live", "", 0),
		// pr-done is terminal but still inside the run TTL — the
		// workspace is already dead weight and goes now.
		fjjRun(kube.GVRTektonPipelineRun, "PipelineRun", "cicd", "pr-done", "True", 30*time.Minute),
	)
	// Already terminating → skipped, not re-deleted.
	terminating := fjjWorkspacePVC("cicd", "pvc-terminating", 8*time.Hour,
		[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil)
	terminating.Finalizers = []string{"kubernetes.io/pvc-protection"}
	termAt := metav1.NewTime(time.Now())
	terminating.DeletionTimestamp = &termAt
	cs := fake.NewSimpleClientset(
		// Owner gone from the API server → delete.
		fjjWorkspacePVC("cicd", "pvc-owner-gone", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil),
		// Owner exists but terminal → delete.
		fjjWorkspacePVC("cicd", "pvc-owner-terminal", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-done")}, nil),
		// Owner live and non-terminal → keep.
		fjjWorkspacePVC("cicd", "pvc-owner-live", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-live")}, nil),
		// tekton.dev/pipelineRun label only (no ownerRef) → delete.
		fjjWorkspacePVC("cicd", "pvc-label-orphan", 8*time.Hour,
			nil, map[string]string{"tekton.dev/pipelineRun": "pr-gone"}),
		// shipwright.io/buildRun label only → delete.
		fjjWorkspacePVC("cicd", "pvc-shipwright-orphan", 8*time.Hour,
			nil, map[string]string{"shipwright.io/buildRun": "br-gone"}),
		// Gone Job owner → delete.
		fjjWorkspacePVC("cicd", "pvc-job-orphan", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("batch/v1", "Job", "job-gone")}, nil),
		// Live incomplete Job owner → keep.
		fjjWorkspacePVC("cicd", "pvc-job-live", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("batch/v1", "Job", "job-live")}, nil),
		// Still mounted by a Running pod → keep.
		fjjWorkspacePVC("cicd", "pvc-mounted", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil),
		// Mounted only by a terminal pod → delete (volumes released).
		fjjWorkspacePVC("cicd", "pvc-terminal-pod", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil),
		// Too young → keep.
		fjjWorkspacePVC("cicd", "pvc-young", 2*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil),
		// No run refs at all → keep.
		fjjWorkspacePVC("cicd", "pvc-plain", 8*time.Hour, nil, nil),
		terminating,
		// The live Job for pvc-job-live.
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "cicd", Name: "job-live"}},
		// Pods: one Running mounting pvc-mounted, one Failed mounting
		// pvc-terminal-pod.
		fjjPodClaiming("cicd", "runner", "pvc-mounted", corev1.PodRunning),
		fjjPodClaiming("cicd", "done-pod", "pvc-terminal-pod", corev1.PodFailed),
	)
	j := &failedJobsJanitor{
		cs: cs, dyn: dyn, now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"pvc-owner-gone", "pvc-owner-terminal", "pvc-label-orphan",
		"pvc-shipwright-orphan", "pvc-job-orphan", "pvc-terminal-pod"} {
		if fjjPVCExists(t, cs, "cicd", name) {
			t.Fatalf("orphan workspace pvc %s must be deleted", name)
		}
	}
	for _, name := range []string{
		"pvc-owner-live", "pvc-job-live", "pvc-mounted",
		"pvc-young", "pvc-plain", "pvc-terminating"} {
		if !fjjPVCExists(t, cs, "cicd", name) {
			t.Fatalf("pvc %s must survive", name)
		}
	}
}

// Orphan deletes carry the UID precondition — a same-named claim
// recreated since the list must not inherit the delete.
func TestOrphanWorkspacePVCUIDPrecondition(t *testing.T) {
	pvc := fjjWorkspacePVC("cicd", "pvc-orphan", 8*time.Hour,
		[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil)
	pvc.UID = "uid-pvc-orphan"
	cs := fake.NewSimpleClientset(pvc)
	var gotUID *types.UID
	cs.PrependReactor("delete", "persistentvolumeclaims",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil
		})
	j := &failedJobsJanitor{
		cs: cs, dyn: fjjDynFake(), now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if gotUID == nil || *gotUID != pvc.UID {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
}

// A ref lookup that errors (not NotFound) fails closed: the claim is
// kept, the run still nils out, the failure is IncError'd once.
func TestOrphanWorkspacePVCFailClosedOnRefGetError(t *testing.T) {
	pvc := fjjWorkspacePVC("cicd", "pvc-orphan", 8*time.Hour,
		[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-maybe")}, nil)
	cs := fake.NewSimpleClientset(pvc)
	dyn := fjjDynFake()
	dyn.PrependReactor("get", "pipelineruns",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	j := &failedJobsJanitor{
		cs: cs, dyn: dyn, now: time.Now, queue: "failed-jobs-janitor",
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	before := testutil.QueueErrorCount(t, "failed-jobs-janitor")
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatalf("unverifiable ref must not error the sweep: %v", err)
	}
	if !fjjPVCExists(t, cs, "cicd", "pvc-orphan") {
		t.Fatal("pvc deleted although its owner could not be verified")
	}
	if got := testutil.QueueErrorCount(t, "failed-jobs-janitor") - before; got != 1 {
		t.Fatalf("unverifiable ref did not IncError once, delta %v", got)
	}
}

// Without a dynamic client, CRD-owned claims cannot be verified and
// stay — but Job-owned orphans still reap through the typed client.
func TestOrphanWorkspacePVCNilDyn(t *testing.T) {
	cs := fake.NewSimpleClientset(
		fjjWorkspacePVC("cicd", "pvc-crd-owned", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil),
		fjjWorkspacePVC("cicd", "pvc-job-owned", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("batch/v1", "Job", "job-gone")}, nil),
	)
	j := &failedJobsJanitor{
		cs: cs, now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !fjjPVCExists(t, cs, "cicd", "pvc-crd-owned") {
		t.Fatal("CRD-owned pvc deleted without a dyn client to verify the owner")
	}
	if fjjPVCExists(t, cs, "cicd", "pvc-job-owned") {
		t.Fatal("Job-owned orphan pvc must reap without a dyn client")
	}
}

// The reaper rides the same hourly run() — an orphan PVC owned by a
// just-reaped PipelineRun reads "owner gone" inside one pass.
func TestOrphanWorkspacePVCReapedAfterRunTTL(t *testing.T) {
	dyn := fjjDynFake(
		fjjRun(kube.GVRTektonPipelineRun, "PipelineRun", "cicd", "pr-old", "True", 30*time.Hour),
		// Registers tekton.dev/v1 TaskRun in the fake — the table
		// sweep lists every kind.
		fjjRun(kube.GVRTektonTaskRun, "TaskRun", "cicd", "tr-live", "", 0))
	cs := fake.NewSimpleClientset(
		fjjWorkspacePVC("cicd", "pvc-workspace", 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-old")}, nil),
	)
	j := &failedJobsJanitor{
		cs: cs, dyn: dyn, now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if fjjRunExists(t, dyn, kube.GVRTektonPipelineRun, "cicd", "pr-old") {
		t.Fatal("past-TTL PipelineRun must be reaped")
	}
	if fjjPVCExists(t, cs, "cicd", "pvc-workspace") {
		t.Fatal("workspace pvc of the reaped run must be deleted in the same pass")
	}
}

// A failed-Job delete answered NotFound raced an external cleanup —
// logged as a skip, NOT metered as an error.
func TestFailedJobDeleteNotFoundNotMetered(t *testing.T) {
	cs := fake.NewSimpleClientset(failedJob("ops", "dead", 48*time.Hour))
	cs.PrependReactor("delete", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				batchv1.Resource("jobs"), "dead")
		})
	j := &failedJobsJanitor{cs: cs, queue: "failed-jobs-janitor"}
	before := testutil.QueueErrorCount(t, "failed-jobs-janitor")
	if err := j.sweepFailedJobs(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "failed-jobs-janitor") - before; got != 0 {
		t.Fatalf("NotFound race metered as an error: delta = %v, want 0", got)
	}
	if !fjjJobExists(t, cs, "ops", "dead") {
		t.Fatal("job vanished despite the rejected delete")
	}
}

// An orphan-workspace-PVC delete answered Conflict is the UID
// precondition firing on a recreated same-name claim — a race, not
// an error.
func TestOrphanWorkspacePVCDeleteConflictNotMetered(t *testing.T) {
	pvc := fjjWorkspacePVC("cicd", "pvc-orphan", 8*time.Hour,
		[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil)
	cs := fake.NewSimpleClientset(pvc)
	cs.PrependReactor("delete", "persistentvolumeclaims",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(
				corev1.Resource("persistentvolumeclaims"), "pvc-orphan",
				errors.New("uid mismatch"))
		})
	j := &failedJobsJanitor{
		cs: cs, dyn: fjjDynFake(), now: time.Now, queue: "failed-jobs-janitor",
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	before := testutil.QueueErrorCount(t, "failed-jobs-janitor")
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "failed-jobs-janitor") - before; got != 0 {
		t.Fatalf("Conflict race metered as an error: delta = %v, want 0", got)
	}
	if !fjjPVCExists(t, cs, "cicd", "pvc-orphan") {
		t.Fatal("pvc vanished despite the rejected delete")
	}
}

// Confirm re-queries the namespace's pods FRESH instead of trusting
// the claimsCache from sweep start: a pod that mounted the claim
// between the collect scan and the confirm re-vet keeps it — the
// cached snapshot cannot see mounts that landed after it was filled.
func TestOrphanWorkspacePVCConfirmRequeriesPods(t *testing.T) {
	pvc := fjjWorkspacePVC("cicd", "pvc-orphan", 8*time.Hour,
		[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil)
	cs := fake.NewSimpleClientset(pvc)
	var podLists int32
	cs.PrependReactor("list", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			// The collect scan (list #1) sees no pods; a claimant
			// lands before the confirm re-query (list #2) runs.
			if atomic.AddInt32(&podLists, 1) == 2 {
				if err := cs.Tracker().Add(
					fjjPodClaiming("cicd", "late-runner", "pvc-orphan", corev1.PodRunning)); err != nil {
					return true, nil, err
				}
			}
			return false, nil, nil // fall through to the tracker
		})
	j := &failedJobsJanitor{
		cs: cs, dyn: fjjDynFake(), now: time.Now, queue: "failed-jobs-janitor",
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !fjjPVCExists(t, cs, "cicd", "pvc-orphan") {
		t.Fatal("pvc deleted although a pod mounted it before confirm")
	}
	if got := atomic.LoadInt32(&podLists); got < 2 {
		t.Fatalf("pod scans = %d, want a fresh re-query at confirm (>= 2)", got)
	}
}

// claimedPVCNames derives the implicit <pod>-<volume> claim of a
// generic ephemeral volume and skips terminal pods' claims.
func TestClaimedPVCNamesIncludesEphemeral(t *testing.T) {
	pods := []runtime.Object{
		// Running pod with a generic ephemeral volume "scratch" —
		// backs the implicit claim "runner-scratch".
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "cicd", Name: "runner"},
			Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
				Name: "scratch",
				VolumeSource: corev1.VolumeSource{
					Ephemeral: &corev1.EphemeralVolumeSource{}},
			}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		// Pending pod with a plain PVC claim — a claimant too.
		fjjPodClaiming("cicd", "mounter", "data", corev1.PodPending),
		// Terminal pod — its claims are released.
		fjjPodClaiming("cicd", "done", "gone", corev1.PodSucceeded),
	}
	cs := fake.NewSimpleClientset(pods...)
	j := &failedJobsJanitor{cs: cs}
	claims, err := j.claimedPVCNames(ctx, "cicd")
	if err != nil {
		t.Fatal(err)
	}
	if !claims["runner-scratch"] {
		t.Fatalf("ephemeral-backed claim missing from %v", claims)
	}
	if !claims["data"] {
		t.Fatalf("pvc claim missing from %v", claims)
	}
	if claims["gone"] {
		t.Fatalf("terminal pod's claim counted: %v", claims)
	}
}

// The reaper must not reap a claim whose only reference is a generic
// ephemeral volume of a live pod — the pre-Ephemeral scan read it as
// unmounted and would have deleted live storage.
func TestOrphanWorkspacePVCEphemeralClaimKept(t *testing.T) {
	pvc := fjjWorkspacePVC("cicd", "runner-scratch", 8*time.Hour, nil,
		map[string]string{"tekton.dev/pipelineRun": "pr-gone"})
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "cicd", Name: "runner"},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "scratch",
			VolumeSource: corev1.VolumeSource{
				Ephemeral: &corev1.EphemeralVolumeSource{}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(pvc, pod)
	j := &failedJobsJanitor{
		cs: cs, dyn: fjjDynFake(), now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !fjjPVCExists(t, cs, "cicd", "runner-scratch") {
		t.Fatal("ephemeral-backed claim deleted while its pod still runs")
	}
}

// The completed-run TTL sweep caps delete attempts at
// failedJobsDeleteCap (500) per sweep — a four-figure backlog drains
// over several hourly runs instead of hammering the apiserver once.
func TestCompletedRunKindCappedAtFiveHundred(t *testing.T) {
	var runs []runtime.Object
	for i := 0; i <= failedJobsDeleteCap; i++ { // cap+1 candidates
		runs = append(runs, fjjRun(kube.GVRTektonPipelineRun, "PipelineRun",
			"cicd", fmt.Sprintf("pr-old-%04d", i), "True", 30*time.Hour))
	}
	dyn := fjjDynFake(runs...)
	j := &failedJobsJanitor{
		cs: fake.NewSimpleClientset(), dyn: dyn, now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepCompletedRuns(ctx); err != nil {
		t.Fatal(err)
	}
	remaining := 0
	for i := 0; i <= failedJobsDeleteCap; i++ {
		if fjjRunExists(t, dyn, kube.GVRTektonPipelineRun, "cicd",
			fmt.Sprintf("pr-old-%04d", i)) {
			remaining++
		}
	}
	if remaining != 1 {
		t.Fatalf("%d runs left after the sweep, want exactly 1 (the cap held)", remaining)
	}
}

// ---------------------------------------------------------------------------
// unstickPVCProtection — the fresh-reproof branches around the
// pvc-protection finalizer strip
// ---------------------------------------------------------------------------

// unstickPVCs builds a Terminating PVC still carrying
// pvc-protection — the audit's strip candidate.
func unstickPVCs() *corev1.PersistentVolumeClaim {
	termAt := metav1.NewTime(time.Now().Add(-3 * time.Hour))
	return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Namespace:         "apps",
		Name:              "data",
		ResourceVersion:   "7",
		DeletionTimestamp: &termAt,
		Finalizers:        []string{"kubernetes.io/pvc-protection"},
	}}
}

// claimPod builds a Running pod in apps mounting claimName.
func claimPod(name, claimName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "v",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: claimName}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// podListReactor answers "list pods" in apps from a queue of
// responses — each claimedPVCNames call consumes the next entry so a
// test can make the audit scan and the fresh re-proof disagree.
func podListReactor(cs *fake.Clientset, responses ...func() (bool, runtime.Object, error)) {
	var calls atomic.Int32
	cs.PrependReactor("list", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			i := int(calls.Add(1)) - 1
			if i >= len(responses) {
				i = len(responses) - 1
			}
			return responses[i]()
		})
}

func podListOK(items ...corev1.Pod) func() (bool, runtime.Object, error) {
	return func() (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: items}, nil
	}
}

func podListErr() func() (bool, runtime.Object, error) {
	return func() (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver down")
	}
}

func pvcFinalizers(t *testing.T, cs *fake.Clientset) []string {
	t.Helper()
	got, err := cs.CoreV1().PersistentVolumeClaims("apps").
		Get(ctx, "data", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return got.Finalizers
}

// The strip needs the claim unreferenced at BOTH reads: the cached
// census probe AND a fresh re-query right before the patch. A claim
// mounted between the two, a failed re-query, or a failed census all
// keep the finalizer — fail closed, metered once per broken read.
func TestUnstickPVCProtectionVerdicts(t *testing.T) {
	now := time.Now()

	// Clean census + clean re-proof → finalizers stripped.
	pvc := unstickPVCs()
	cs := fake.NewSimpleClientset(pvc)
	podListReactor(cs, podListOK())
	j := &failedJobsJanitor{cs: cs, queue: "failed-jobs-janitor",
		now: func() time.Time { return now }}
	j.unstickPVCProtection(ctx, pvc, map[string]pvcUseProbe{})
	if f := pvcFinalizers(t, cs); len(f) != 0 {
		t.Fatalf("unreferenced claim kept finalizers: %v", f)
	}

	// A pod still mounting the claim at census time — the
	// finalizer is doing its job.
	pvc = unstickPVCs()
	cs = fake.NewSimpleClientset(pvc, claimPod("user", "data"))
	podListReactor(cs, podListOK(*claimPod("user", "data")))
	j = &failedJobsJanitor{cs: cs, queue: "failed-jobs-janitor",
		now: func() time.Time { return now }}
	j.unstickPVCProtection(ctx, pvc, map[string]pvcUseProbe{})
	if f := pvcFinalizers(t, cs); len(f) == 0 {
		t.Fatal("referenced claim lost its finalizer")
	}

	// Census clean but the FRESH re-query finds the claim mounted
	// since — the strip is refused.
	pvc = unstickPVCs()
	cs = fake.NewSimpleClientset(pvc)
	podListReactor(cs,
		podListOK(),                          // census: unclaimed
		podListOK(*claimPod("late", "data"))) // fresh: mounted
	j = &failedJobsJanitor{cs: cs, queue: "failed-jobs-janitor",
		now: func() time.Time { return now }}
	j.unstickPVCProtection(ctx, pvc, map[string]pvcUseProbe{})
	if f := pvcFinalizers(t, cs); len(f) == 0 {
		t.Fatal("claim mounted since the audit scan lost its finalizer")
	}

	// Census clean, fresh re-query fails — keep, metered once.
	pvc = unstickPVCs()
	cs = fake.NewSimpleClientset(pvc)
	podListReactor(cs, podListOK(), podListErr())
	j = &failedJobsJanitor{cs: cs, queue: "failed-jobs-janitor",
		now: func() time.Time { return now }}
	before := testutil.QueueErrorCount(t, "failed-jobs-janitor")
	j.unstickPVCProtection(ctx, pvc, map[string]pvcUseProbe{})
	if f := pvcFinalizers(t, cs); len(f) == 0 {
		t.Fatal("fresh re-query failure lost the finalizer")
	}
	if got := testutil.QueueErrorCount(t, "failed-jobs-janitor") - before; got != 1 {
		t.Fatalf("fresh re-query failure metered %v times, want 1", got)
	}

	// Census list itself fails — the probe error is cached and the
	// finalizer stays; repeat calls reuse the probe without
	// re-metering the same broken list.
	pvc = unstickPVCs()
	cs = fake.NewSimpleClientset(pvc)
	podListReactor(cs, podListErr())
	j = &failedJobsJanitor{cs: cs, queue: "failed-jobs-janitor",
		now: func() time.Time { return now }}
	cache := map[string]pvcUseProbe{}
	before = testutil.QueueErrorCount(t, "failed-jobs-janitor")
	j.unstickPVCProtection(ctx, pvc, cache)
	j.unstickPVCProtection(ctx, pvc, cache)
	if f := pvcFinalizers(t, cs); len(f) == 0 {
		t.Fatal("census failure lost the finalizer")
	}
	if got := testutil.QueueErrorCount(t, "failed-jobs-janitor") - before; got != 1 {
		t.Fatalf("census failure metered %v times across two calls, want 1", got)
	}

	// Pre-seeded failed probe (another duty already paid the
	// metering) — kept quietly, zero new IncErrors.
	pvc = unstickPVCs()
	cs = fake.NewSimpleClientset(pvc)
	j = &failedJobsJanitor{cs: cs, queue: "failed-jobs-janitor",
		now: func() time.Time { return now }}
	before = testutil.QueueErrorCount(t, "failed-jobs-janitor")
	j.unstickPVCProtection(ctx, pvc, map[string]pvcUseProbe{
		"apps": {err: errors.New("cached list failure")}})
	if f := pvcFinalizers(t, cs); len(f) == 0 {
		t.Fatal("cached probe failure lost the finalizer")
	}
	if got := testutil.QueueErrorCount(t, "failed-jobs-janitor") - before; got != 0 {
		t.Fatalf("cached probe failure re-metered %v times, want 0", got)
	}
}

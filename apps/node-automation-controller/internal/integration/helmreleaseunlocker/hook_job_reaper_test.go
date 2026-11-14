// hook_job_reaper_test.go — the failed helm-hook Job reaper and the
// live-upgrade progress gate that guards the pending-secret delete.
package helmreleaseunlocker

import (
	"errors"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// On a real unlock, a FAILED helm-hook Job in the HR's target namespace
// is reaped (it would block the retried release's hooks), while a
// still-running hook Job, a non-hook failed Job, a hook Job of
// ANOTHER release (wrong or missing meta.helm.sh/release-name), and
// hook Jobs in other namespaces are all left alone.
func TestHelmReleaseUnlockerReapsFailedHookJobs(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	foreign := hookJob("apps", "foreign-release-hook", "other-release", true)
	unattributed := hookJob("apps", "unattributed-hook", "myapp", true)
	unattributed.Labels = nil // helm.sh/hook without release attribution
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJob("apps", "myapp-pre-upgrade", "myapp", true),   // reaped
		hookJob("apps", "myapp-post-upgrade", "myapp", false), // still running — kept
		plainFailedJob("apps", "unrelated-batch"),             // no hook anno — kept
		foreign,      // another release's hook — kept
		unattributed, // no release label — kept
		hookJob("other-ns", "other-hook", "myapp", true), // wrong ns — kept
	)...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := promtestutil.ToFloat64(
		metrics.HelmHookJobsCleanedTotal.WithLabelValues("apps"))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if jobExists(t, cs, "apps", "myapp-pre-upgrade") {
		t.Fatal("failed helm-hook Job not reaped on unlock")
	}
	for _, n := range []string{"myapp-post-upgrade", "unrelated-batch",
		"foreign-release-hook", "unattributed-hook"} {
		if !jobExists(t, cs, "apps", n) {
			t.Fatalf("job %s reaped — only FAILED Jobs attributed to THIS release may go", n)
		}
	}
	if !jobExists(t, cs, "other-ns", "other-hook") {
		t.Fatal("hook Job outside the target namespace reaped")
	}
	if got := promtestutil.ToFloat64(
		metrics.HelmHookJobsCleanedTotal.WithLabelValues("apps")) - before; got != 1 {
		t.Fatalf("HelmHookJobsCleanedTotal{apps} delta = %v, want 1", got)
	}
}

// The same Job list now feeds the live-upgrade progress gate BEFORE
// the destructive delete, so a failing Job list fails closed: without
// evidence the namespace is quiet, the pending secret must NOT be
// deleted (unlocking blind is exactly what the gate exists to
// prevent). The refusal IncErrors, stamps nothing, and the next sweep
// re-evaluates.
func TestHelmReleaseUnlockerHookJobListErrorFailsClosed(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	cs.PrependReactor("list", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("jobs list boom")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := testutil.QueueErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatalf("per-HR gate failure must not error the run: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "helmrelease-unlocker") - before; got < 1 {
		t.Fatal("hook-job gate failure did not IncError")
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret deleted although progress could not be verified")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR stamped unlocked although the unlock was refused")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("requestedAt stamped although the unlock was refused")
	}
}

// A refused unlock (pending-install with no rollback target) never
// reaches the hook sweep — nothing is touched.
func TestHelmReleaseUnlockerRefusedUnlockSkipsHookSweep(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "Helm install failed: another operation is in progress")
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "pending-install"),
		hookJob("apps", "myapp-pre-install", "myapp", true))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !jobExists(t, cs, "apps", "myapp-pre-install") {
		t.Fatal("hook Job reaped although the unlock was refused")
	}
}

// ---------------------------------------------------------------------------
// Live-upgrade progress gate (before the pending-secret delete)
// ---------------------------------------------------------------------------

// hookJobStarted builds a hook Job with NO terminal condition created
// createdAgo ago; pods sets Status.Active (a genuinely running Job has
// active pods; a wedged or not-yet-scheduled one has none).
func hookJobStarted(ns, name, release string, createdAgo time.Duration, pods int32) *batchv1.Job {
	j := hookJob(ns, name, release, false)
	j.CreationTimestamp = metav1.NewTime(time.Now().Add(-createdAgo))
	j.Status.Active = pods
	return j
}

// Branch 1 — a hook Job still running in the release namespace is
// live reconcile evidence: the pending-secret delete must NOT fire on
// an upgrade that is genuinely mid-flight, and the skip stamps
// neither the unlock cooldown nor the requestedAt hint.
func TestHelmReleaseUnlockerSkipsRunningHookJob(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJobStarted("apps", "myapp-pre-upgrade", "myapp", time.Hour, 1), // Running — upgrade alive
	)...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret deleted although a hook Job is still running")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR stamped unlocked although the upgrade looked alive")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("requestedAt stamped although the upgrade looked alive")
	}
	// The running hook Job itself is never reaped (only FAILED ones are).
	if !jobExists(t, cs, "apps", "myapp-pre-upgrade") {
		t.Fatal("running hook Job reaped although the unlock was skipped")
	}
}

// Branch 1b — a hook Job freshly created (inside helmHookFreshWindow)
// whose pods have not shown up yet is the same evidence: helm just
// started its hook, deleting the pending secret now would truncate it.
func TestHelmReleaseUnlockerSkipsFreshHookJob(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJobStarted("apps", "myapp-pre-upgrade", "myapp", time.Minute, 0), // just created, pods pending
	)...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret deleted although a hook Job was just created")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR stamped unlocked although the upgrade looked alive")
	}
}

// Branch 2 — terminal hook Jobs are the residue of the WEDGED
// attempt, not progress: a Failed hook Job and a stale pod-less hook
// Job (created long before the fresh window, no active pods) both
// leave the unlock free to act exactly as before.
func TestHelmReleaseUnlockerTerminalHookResidueStillUnlocks(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJob("apps", "myapp-pre-upgrade", "myapp", true),               // Failed — residue
		hookJobStarted("apps", "myapp-old-hook", "myapp", 2*time.Hour, 0), // stale, no pods — residue
	)...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("wedged pending secret not unlocked — terminal hook residue blocked the unlock")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; !ok {
		t.Fatal("HR not stamped unlocked")
	}
}

// A hook Job delete losing the race (NotFound) is equally benign for
// the sweep: the unlock still lands and no error is counted.
func TestHelmReleaseUnlockerHookJobDeleteNotFoundIsBenign(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJob("apps", "myapp-pre-upgrade", "myapp", true))...)
	cs.PrependReactor("delete", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				batchv1.Resource("jobs"), "myapp-pre-upgrade")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := testutil.QueueErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatalf("a NotFound race must not error the run: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "helmrelease-unlocker") - before; got != 0 {
		t.Fatalf("NotFound hook delete counted as an error: +%v", got)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("unlock skipped — a benign NotFound hook delete blocked it")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; !ok {
		t.Fatal("unlock undone by a benign NotFound hook delete")
	}
}

// jobFailed is True only on an explicit JobFailed=True condition —
// absent conditions, JobFailed=False, Suspended and Complete all stay.
func TestJobFailedCondition(t *testing.T) {
	cond := func(tpe batchv1.JobConditionType, st corev1.ConditionStatus) *batchv1.Job {
		return &batchv1.Job{Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{{Type: tpe, Status: st}}}}
	}
	for _, tc := range []struct {
		name string
		job  *batchv1.Job
		want bool
	}{
		{"no conditions", &batchv1.Job{}, false},
		{"failed true", cond(batchv1.JobFailed, corev1.ConditionTrue), true},
		{"failed false", cond(batchv1.JobFailed, corev1.ConditionFalse), false},
		{"suspended", cond(batchv1.JobSuspended, corev1.ConditionTrue), false},
		{"complete", cond(batchv1.JobComplete, corev1.ConditionTrue), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := kube.JobHasCondition(tc.job, batchv1.JobFailed); got != tc.want {
				t.Fatalf("JobHasCondition(JobFailed) = %v, want %v", got, tc.want)
			}
		})
	}
}

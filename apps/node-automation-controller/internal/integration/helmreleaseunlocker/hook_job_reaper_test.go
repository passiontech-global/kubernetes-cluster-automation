// hook_job_reaper_test.go — the failed helm-hook Job reaper and the
// live-upgrade progress gate that guards the pending-secret delete.
package helmreleaseunlocker

import (
	"context"
	"errors"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	kfake "k8s.io/client-go/kubernetes/fake"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	batchv1client "k8s.io/client-go/kubernetes/typed/batch/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	policyv1client "k8s.io/client-go/kubernetes/typed/policy/v1"
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

func TestHelmReleaseUnlockerHookJobListDeduplication(t *testing.T) {
	t.Run("two due HRs in same namespace share 1 Job LIST and respect deleted cache", func(t *testing.T) {
		hr1 := hrObj("apps", "myapp", "v2")
		hrReady(hr1, "False", "another operation is in progress")
		hr2 := hrObj("apps", "otherapp", "v2")
		hrReady(hr2, "False", "another operation is in progress")
		dyn := newDynFake(hr1, hr2)

		cs := kfake.NewSimpleClientset(
			helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
			helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"),
			helmRelSecret("apps", "sh.helm.release.v1.otherapp.v1", "otherapp", 1, "deployed"),
			helmRelSecret("apps", "sh.helm.release.v1.otherapp.v2", "otherapp", 2, "pending-upgrade"),
			hookJob("apps", "myapp-pre-upgrade", "myapp", true),
			hookJob("apps", "otherapp-pre-upgrade", "otherapp", true),
		)
		var jobListCalls int
		cs.PrependReactor("list", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
			jobListCalls++
			return false, nil, nil
		})
		u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
		u.pending.firstSeen.Observe("apps/otherapp", time.Now().Add(-time.Hour))

		if err := u.run(ctx); err != nil {
			t.Fatal(err)
		}
		if jobListCalls != 1 {
			t.Fatalf("jobs LIST calls = %d, want 1 across helmUpgradeInProgress + cleanFailedHookJobs for 2 HRs", jobListCalls)
		}
		if jobExists(t, cs, "apps", "myapp-pre-upgrade") || jobExists(t, cs, "apps", "otherapp-pre-upgrade") {
			t.Fatal("failed hook jobs not reaped")
		}
	})

	t.Run("unwedgeAct retry of cleanFailedHookJobs reuses cache and skips already-deleted job", func(t *testing.T) {
		hr := stalledHR("ops", "connect", "onepassword", "stalled resources")
		dyn := newDynFake(hr)
		// Force HR patch failure so unwedgeAct calls cleanFailedHookJobs twice.
		dyn.PrependReactor("patch", "helmreleases", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("hr patch error")
		})
		dep := stalledDeploy("onepassword", "connect", 2)
		oldRS := stallRS("onepassword", "connect-1", "connect", 1, 2, true)
		newRS := stallRS("onepassword", "connect-2", "connect", 2, 1, false)
		cs := kfake.NewSimpleClientset(
			dep, oldRS, newRS,
			stallPod("onepassword", "connect-1-a", "connect-1", "n1", ""),
			stallPod("onepassword", "connect-1-b", "connect-1", "n2", ""),
			stallPod("onepassword", "connect-2-x", "connect-2", "",
				"0/2 nodes are available: didn't satisfy existing pods anti-affinity rules"),
			hookJob("onepassword", "connect-hook", "onepassword-connect", true),
		)
		var jobListCalls, jobDeleteCalls int
		cs.PrependReactor("list", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
			jobListCalls++
			return false, nil, nil
		})
		cs.PrependReactor("delete", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
			jobDeleteCalls++
			return false, nil, nil
		})
		u := newUnlocker(cs, dyn, 0, "")
		u.stall.enabled = true
		u.stall.firstSeen.Observe("ops/connect", time.Now().Add(-time.Hour))

		if err := u.run(ctx); err != nil {
			t.Fatal(err)
		}
		if jobListCalls != 1 {
			t.Fatalf("jobs LIST calls = %d, want 1", jobListCalls)
		}
		if jobDeleteCalls != 1 {
			t.Fatalf("jobs DELETE calls = %d, want 1 (must not re-delete on retry)", jobDeleteCalls)
		}
	})
}

type listOptRecord struct {
	resource string
	rv       string
	limit    int64
}

type recordingDyn struct {
	dynamic.Interface
	records *[]listOptRecord
}

func (d *recordingDyn) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &recordingDynRes{NamespaceableResourceInterface: d.Interface.Resource(gvr), res: gvr.Resource, records: d.records}
}

type recordingDynRes struct {
	dynamic.NamespaceableResourceInterface
	res     string
	records *[]listOptRecord
}

func (r *recordingDynRes) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	*r.records = append(*r.records, listOptRecord{resource: r.res, rv: opts.ResourceVersion, limit: opts.Limit})
	return r.NamespaceableResourceInterface.List(ctx, opts)
}

func (r *recordingDynRes) Namespace(ns string) dynamic.ResourceInterface {
	return &recordingDynNSRes{ResourceInterface: r.NamespaceableResourceInterface.Namespace(ns), res: r.res, records: r.records}
}

type recordingDynNSRes struct {
	dynamic.ResourceInterface
	res     string
	records *[]listOptRecord
}

func (r *recordingDynNSRes) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	*r.records = append(*r.records, listOptRecord{resource: r.res, rv: opts.ResourceVersion, limit: opts.Limit})
	return r.ResourceInterface.List(ctx, opts)
}

type recordingHRCS struct {
	kubernetes.Interface
	records *[]listOptRecord
}

func (c *recordingHRCS) CoreV1() corev1client.CoreV1Interface {
	return &recHRCoreV1{CoreV1Interface: c.Interface.CoreV1(), records: c.records}
}
func (c *recordingHRCS) AppsV1() appsv1client.AppsV1Interface {
	return &recHRAppsV1{AppsV1Interface: c.Interface.AppsV1(), records: c.records}
}
func (c *recordingHRCS) BatchV1() batchv1client.BatchV1Interface {
	return &recHRBatchV1{BatchV1Interface: c.Interface.BatchV1(), records: c.records}
}
func (c *recordingHRCS) PolicyV1() policyv1client.PolicyV1Interface {
	return &recHRPolicyV1{PolicyV1Interface: c.Interface.PolicyV1(), records: c.records}
}

type recHRCoreV1 struct {
	corev1client.CoreV1Interface
	records *[]listOptRecord
}

func (c *recHRCoreV1) Secrets(ns string) corev1client.SecretInterface {
	return &recHRSecrets{SecretInterface: c.CoreV1Interface.Secrets(ns), ns: ns, records: c.records}
}
func (c *recHRCoreV1) Pods(ns string) corev1client.PodInterface {
	return &recHRPods{PodInterface: c.CoreV1Interface.Pods(ns), ns: ns, records: c.records}
}

type recHRSecrets struct {
	corev1client.SecretInterface
	ns      string
	records *[]listOptRecord
}

func (s *recHRSecrets) List(ctx context.Context, opts metav1.ListOptions) (*corev1.SecretList, error) {
	*s.records = append(*s.records, listOptRecord{resource: "secrets:" + s.ns, rv: opts.ResourceVersion, limit: opts.Limit})
	return s.SecretInterface.List(ctx, opts)
}

type recHRPods struct {
	corev1client.PodInterface
	ns      string
	records *[]listOptRecord
}

func (p *recHRPods) List(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	*p.records = append(*p.records, listOptRecord{resource: "pods:" + p.ns, rv: opts.ResourceVersion, limit: opts.Limit})
	return p.PodInterface.List(ctx, opts)
}

type recHRAppsV1 struct {
	appsv1client.AppsV1Interface
	records *[]listOptRecord
}

func (a *recHRAppsV1) Deployments(ns string) appsv1client.DeploymentInterface {
	return &recHRDeps{DeploymentInterface: a.AppsV1Interface.Deployments(ns), ns: ns, records: a.records}
}
func (a *recHRAppsV1) ReplicaSets(ns string) appsv1client.ReplicaSetInterface {
	return &recHRRSs{ReplicaSetInterface: a.AppsV1Interface.ReplicaSets(ns), ns: ns, records: a.records}
}

type recHRDeps struct {
	appsv1client.DeploymentInterface
	ns      string
	records *[]listOptRecord
}

func (d *recHRDeps) List(ctx context.Context, opts metav1.ListOptions) (*appsv1.DeploymentList, error) {
	*d.records = append(*d.records, listOptRecord{resource: "deployments:" + d.ns, rv: opts.ResourceVersion, limit: opts.Limit})
	return d.DeploymentInterface.List(ctx, opts)
}

type recHRRSs struct {
	appsv1client.ReplicaSetInterface
	ns      string
	records *[]listOptRecord
}

func (r *recHRRSs) List(ctx context.Context, opts metav1.ListOptions) (*appsv1.ReplicaSetList, error) {
	*r.records = append(*r.records, listOptRecord{resource: "replicasets:" + r.ns, rv: opts.ResourceVersion, limit: opts.Limit})
	return r.ReplicaSetInterface.List(ctx, opts)
}

type recHRBatchV1 struct {
	batchv1client.BatchV1Interface
	records *[]listOptRecord
}

func (b *recHRBatchV1) Jobs(ns string) batchv1client.JobInterface {
	return &recHRJobs{JobInterface: b.BatchV1Interface.Jobs(ns), ns: ns, records: b.records}
}

type recHRJobs struct {
	batchv1client.JobInterface
	ns      string
	records *[]listOptRecord
}

func (j *recHRJobs) List(ctx context.Context, opts metav1.ListOptions) (*batchv1.JobList, error) {
	*j.records = append(*j.records, listOptRecord{resource: "jobs:" + j.ns, rv: opts.ResourceVersion, limit: opts.Limit})
	return j.JobInterface.List(ctx, opts)
}

type recHRPolicyV1 struct {
	policyv1client.PolicyV1Interface
	records *[]listOptRecord
}

func (p *recHRPolicyV1) PodDisruptionBudgets(ns string) policyv1client.PodDisruptionBudgetInterface {
	return &recHRPDBs{PodDisruptionBudgetInterface: p.PolicyV1Interface.PodDisruptionBudgets(ns), ns: ns, records: p.records}
}

type recHRPDBs struct {
	policyv1client.PodDisruptionBudgetInterface
	ns      string
	records *[]listOptRecord
}

func (p *recHRPDBs) List(ctx context.Context, opts metav1.ListOptions) (*policyv1.PodDisruptionBudgetList, error) {
	*p.records = append(*p.records, listOptRecord{resource: "pdbs:" + p.ns, rv: opts.ResourceVersion, limit: opts.Limit})
	return p.PodDisruptionBudgetInterface.List(ctx, opts)
}

func TestHelmReleaseUnlockerListOptionsEconomy(t *testing.T) {
	hrUnlock := hrObj("apps", "myapp", "v2")
	hrReady(hrUnlock, "False", "another operation is in progress")
	hrStall := stalledHR("ops", "connect", "onepassword", "stalled resources")
	dynBase := newDynFake(hrUnlock, hrStall)

	var dynRecords, csRecords []listOptRecord
	dyn := &recordingDyn{Interface: dynBase, records: &dynRecords}

	dep := stalledDeploy("onepassword", "connect", 2)
	oldRS := stallRS("onepassword", "connect-1", "connect", 1, 2, true)
	newRS := stallRS("onepassword", "connect-2", "connect", 2, 1, false)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "onepassword", Name: "connect-pdb"},
		Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "onepassword-connect"}}},
		Status:     policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 1},
	}

	baseCS := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"),
		dep, oldRS, newRS, pdb,
		stallPod("onepassword", "connect-1-a", "connect-1", "n1", ""),
		stallPod("onepassword", "connect-1-b", "connect-1", "n2", ""),
		stallPod("onepassword", "connect-2-x", "connect-2", "",
			"0/2 nodes are available: didn't satisfy existing pods anti-affinity rules"),
	)
	cs := &recordingHRCS{Interface: baseCS, records: &csRecords}

	u := newUnlocker(baseCS, dynBase, time.Hour, "apps/myapp")
	u.cs = cs
	u.dyn = dyn
	u.stall.enabled = true
	u.stall.firstSeen.Observe("ops/connect", time.Now().Add(-time.Hour))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}

	seen := map[string]listOptRecord{}
	for _, rec := range dynRecords {
		seen[rec.resource] = rec
	}
	for _, rec := range csRecords {
		seen[rec.resource] = rec
	}

	for _, res := range []string{
		"helmreleases",
		"kustomizations",
		"pods:" + helmControllerNS,
		"secrets:apps",
		"jobs:apps",
		"jobs:onepassword",
	} {
		rec, ok := seen[res]
		if !ok {
			t.Fatalf("expected census list for %s", res)
		}
		if rec.rv != "0" || rec.limit != 0 {
			t.Fatalf("%s ListOptions = %+v, want rv=0 limit=0", res, rec)
		}
	}

	for _, res := range []string{
		"deployments:onepassword",
		"replicasets:onepassword",
		"pods:onepassword",
		"pdbs:onepassword",
	} {
		rec, ok := seen[res]
		if !ok {
			t.Fatalf("expected quorum list for %s", res)
		}
		if rec.rv != "" || rec.limit != kube.DefaultListPageSize {
			t.Fatalf("%s ListOptions = %+v, want quorum rv='' limit=%d", res, rec, kube.DefaultListPageSize)
		}
	}
}

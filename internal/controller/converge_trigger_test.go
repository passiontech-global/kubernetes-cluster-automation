package controller

import (
	"strconv"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ---------------------------------------------------------------------------
// converge-trigger
// ---------------------------------------------------------------------------

// fireConvergeEvent arms each CM name (one Reconcile per event, as the
// informer would deliver them), then fires the settle requeue once —
// the drain pass processes every pending CM in a single run.
func fireConvergeEvent(t *testing.T, r *convergeTrigger, cmNames ...string) {
	t.Helper()
	for _, name := range cmNames {
		res, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: convergeNS, Name: name}})
		if err != nil {
			t.Fatalf("arm %q: %v", name, err)
		}
		if res.RequeueAfter != convergeSettle {
			t.Fatalf("arm %q: expected %s requeue, got %s", name, convergeSettle, res.RequeueAfter)
		}
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: convergeNS, Name: cmNames[0]}}); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

func cronJobObjs(names ...string) []runtime.Object {
	objs := make([]runtime.Object, 0, len(names))
	for _, n := range names {
		objs = append(objs, convergeCronJob(n))
	}
	return objs
}

func listNodeOpsJobs(t *testing.T, cs *fake.Clientset) []batchv1.Job {
	t.Helper()
	jobs, err := cs.BatchV1().Jobs(convergeNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	return jobs.Items
}

func triggerJobNames(jobs []batchv1.Job) []string {
	names := make([]string, 0, len(jobs))
	for _, j := range jobs {
		names = append(names, j.Name)
	}
	return names
}

// CM-name prefix -> target CronJob set, straight from the bash mapping.
func TestConvergeTriggerPrefixClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cm       string
		cronjobs []string // existing on this cluster
		wantJobs []string // expected "<cj>-trigger-" name prefixes
	}{
		{
			name:     "api-lb-guard-files targets only api-lb-guard-converge",
			cm:       "api-lb-guard-files-7f9b",
			cronjobs: []string{"api-lb-guard-converge"},
			wantJobs: []string{"api-lb-guard-converge"},
		},
		{
			name:     "node-config-vars targets all four converge cronjobs",
			cm:       "node-config-vars-abc12",
			cronjobs: allConvergeCronJobs,
			wantJobs: allConvergeCronJobs,
		},
		{
			name:     "node-config-playbooks targets all four",
			cm:       "node-config-playbooks-abc",
			cronjobs: allConvergeCronJobs,
			wantJobs: allConvergeCronJobs,
		},
		{
			name:     "node-watchdog-scripts targets all four",
			cm:       "node-watchdog-scripts-abc",
			cronjobs: allConvergeCronJobs,
			wantJobs: allConvergeCronJobs,
		},
		{
			name:     "operator hooks CM creates no job",
			cm:       "node-ops-operator-hooks-xxx",
			cronjobs: allConvergeCronJobs,
			wantJobs: nil,
		},
		{
			name:     "node-labeler CM creates no job",
			cm:       "node-labeler-workload",
			cronjobs: allConvergeCronJobs,
			wantJobs: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(cronJobObjs(tc.cronjobs...)...)
			r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}
			fireConvergeEvent(t, r, tc.cm)

			jobs := listNodeOpsJobs(t, cs)
			if len(jobs) != len(tc.wantJobs) {
				t.Fatalf("expected %d jobs, got %d: %v",
					len(tc.wantJobs), len(jobs), triggerJobNames(jobs))
			}
			for _, cjName := range tc.wantJobs {
				found := false
				for _, j := range jobs {
					if strings.HasPrefix(j.Name, cjName+"-trigger-") {
						found = true
					}
				}
				if !found {
					t.Fatalf("no trigger job for cronjob %s (jobs: %v)",
						cjName, triggerJobNames(jobs))
				}
			}
		})
	}
}

// One Flux commit touching two CMs lands in the same settle window —
// the drain computes the UNION of targets and fires each once.
func TestConvergeTriggerBatchUnion(t *testing.T) {
	cs := fake.NewSimpleClientset(cronJobObjs(allConvergeCronJobs...)...)
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}

	fireConvergeEvent(t, r, "node-config-vars-abc", "api-lb-guard-files-xyz")

	jobs := listNodeOpsJobs(t, cs)
	// all-4 ∪ {api-lb-guard-converge} = 4 distinct jobs, not 5.
	if len(jobs) != len(allConvergeCronJobs) {
		t.Fatalf("expected %d jobs from the union, got %d: %v",
			len(allConvergeCronJobs), len(jobs), triggerJobNames(jobs))
	}
	seen := map[string]int{}
	for _, j := range jobs {
		seen[j.Name]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Fatalf("job %s created %d times", name, n)
		}
	}
}

// A target CronJob absent on this cluster is skipped without error and
// does not stop the remaining targets.
func TestConvergeTriggerMissingCronJob(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cronJobObjs("hub-converge", "api-lb-guard-converge")...)
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}

	fireConvergeEvent(t, r, "node-config-vars-abc")

	jobs := listNodeOpsJobs(t, cs)
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs for the existing cronjobs, got %d: %v",
			len(jobs), triggerJobNames(jobs))
	}
}

// Dedupe on an Active trigger job — even one older than the dedupe
// window, Active alone is enough to skip.
func TestConvergeTriggerDedupeActiveJob(t *testing.T) {
	running := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: convergeNS, Name: "hub-converge-trigger-111",
			// Old enough that ONLY the Active flag can dedupe it.
			CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
		},
		Status: batchv1.JobStatus{Active: 1},
	}
	cs := fake.NewSimpleClientset(convergeCronJob("hub-converge"), running)
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}

	fireConvergeEvent(t, r, "node-config-vars-abc")

	jobs := listNodeOpsJobs(t, cs)
	if len(jobs) != 1 {
		t.Fatalf("active trigger job did not dedupe: %v", triggerJobNames(jobs))
	}
}

// A finished trigger job older than convergeDedupeWin (120s) must NOT
// block a new trigger.
func TestConvergeTriggerOldJobNotDeduped(t *testing.T) {
	stale := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: convergeNS, Name: "hub-converge-trigger-222",
			CreationTimestamp: metav1.NewTime(
				time.Now().Add(-(convergeDedupeWin + 10*time.Second))),
		},
	}
	cs := fake.NewSimpleClientset(convergeCronJob("hub-converge"), stale)
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}

	fireConvergeEvent(t, r, "node-config-vars-abc")

	jobs := listNodeOpsJobs(t, cs)
	if len(jobs) != 2 {
		t.Fatalf("stale trigger job wrongly deduped, jobs: %v", triggerJobNames(jobs))
	}
}

// Dedupe is per-CronJob via the "<cj>-trigger-" name prefix: a young
// trigger job for api-lb-guard-converge suppresses only that target —
// hub-converge still fires.
func TestConvergeTriggerDedupeIsPerCronJob(t *testing.T) {
	young := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: convergeNS, Name: "api-lb-guard-converge-trigger-333",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Second)),
		},
	}
	cs := fake.NewSimpleClientset(
		convergeCronJob("hub-converge"),
		convergeCronJob("api-lb-guard-converge"),
		young)
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}

	fireConvergeEvent(t, r, "node-config-vars-abc")

	jobs := listNodeOpsJobs(t, cs)
	if len(jobs) != 2 {
		t.Fatalf("expected the old api-lb job + one new hub job, got %v",
			triggerJobNames(jobs))
	}
	hub, apiLB := false, false
	for _, j := range jobs {
		if strings.HasPrefix(j.Name, "hub-converge-trigger-") {
			hub = true
		}
		if strings.HasPrefix(j.Name, "api-lb-guard-converge-trigger-") {
			apiLB = true
		}
	}
	if !hub {
		t.Fatalf("hub-converge not triggered: %v", triggerJobNames(jobs))
	}
	if !apiLB {
		t.Fatalf("pre-existing api-lb-guard trigger job gone?: %v", triggerJobNames(jobs))
	}
}

// The cloned Job is `kubectl create job --from=cronjob/<cj>`: name,
// JobTemplate metadata, pod spec and job-level fields all carry over,
// plus the created-by label stamped post-create.
func TestConvergeTriggerJobCloneFidelity(t *testing.T) {
	cj := convergeCronJob("hub-converge")
	backoff := int32(4)
	ttl := int32(300)
	cj.Spec.JobTemplate.Spec.BackoffLimit = &backoff
	cj.Spec.JobTemplate.Spec.TTLSecondsAfterFinished = &ttl

	cs := fake.NewSimpleClientset(cj)
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}
	fireConvergeEvent(t, r, "node-config-vars-abc")

	jobs := listNodeOpsJobs(t, cs)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %v", triggerJobNames(jobs))
	}
	j := jobs[0]

	// Name shape: <cj>-trigger-<unix> (bash `$(date +%s)` suffix).
	if !strings.HasPrefix(j.Name, "hub-converge-trigger-") {
		t.Fatalf("unexpected job name %q", j.Name)
	}
	if _, err := strconv.ParseInt(
		strings.TrimPrefix(j.Name, "hub-converge-trigger-"), 10, 64); err != nil {
		t.Fatalf("job name suffix is not a unix timestamp: %v", err)
	}

	if j.Labels["app.kubernetes.io/created-by"] != "node-ops-operator" {
		t.Fatal("created-by label missing")
	}
	if j.Labels["app"] != "converge" || j.Annotations["a"] != "b" {
		t.Fatal("JobTemplate metadata not cloned")
	}
	if j.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("restartPolicy not cloned: %s", j.Spec.Template.Spec.RestartPolicy)
	}
	if len(j.Spec.Template.Spec.Containers) != 1 ||
		j.Spec.Template.Spec.Containers[0].Name != "c" ||
		j.Spec.Template.Spec.Containers[0].Image != "i" {
		t.Fatalf("pod spec not cloned: %+v", j.Spec.Template.Spec.Containers)
	}
	if j.Spec.BackoffLimit == nil || *j.Spec.BackoffLimit != backoff {
		t.Fatalf("backoffLimit not cloned: %v", j.Spec.BackoffLimit)
	}
	if j.Spec.TTLSecondsAfterFinished == nil || *j.Spec.TTLSecondsAfterFinished != ttl {
		t.Fatalf("ttlSecondsAfterFinished not cloned: %v", j.Spec.TTLSecondsAfterFinished)
	}
}

// The hash-suffixed CMs make Create the only change signal — the
// predicate must fire on real creates but never on the informer's
// initial-sync replay (operator restart must not spawn converge Jobs).
func TestConvergeTriggerCreatePredicate(t *testing.T) {
	startup := time.Now()
	p := convergePredicates(startup)

	oldCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "node-config-vars-old", Namespace: "node-ops",
		CreationTimestamp: metav1.NewTime(startup.Add(-time.Hour)),
	}}
	newCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "node-config-vars-new", Namespace: "node-ops",
		CreationTimestamp: metav1.NewTime(startup.Add(time.Second)),
	}}

	if p.Create(event.CreateEvent{Object: oldCM}) {
		t.Fatal("initial-sync create fired — restart would spawn jobs")
	}
	if !p.Create(event.CreateEvent{Object: newCM}) {
		t.Fatal("real create did not fire — hash-suffixed CMs would never trigger")
	}

	// Update fires on resourceVersion change only.
	oldRV := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1"}}
	newRV := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "2"}}
	if !p.Update(event.UpdateEvent{ObjectOld: oldRV, ObjectNew: newRV}) {
		t.Fatal("update with new resourceVersion did not fire")
	}
	if p.Update(event.UpdateEvent{ObjectOld: oldRV, ObjectNew: oldRV.DeepCopy()}) {
		t.Fatal("update without resourceVersion change fired")
	}

	// Delete and generic never fire.
	if p.Delete(event.DeleteEvent{Object: newCM}) || p.Generic(event.GenericEvent{Object: newCM}) {
		t.Fatal("delete/generic fired")
	}
}

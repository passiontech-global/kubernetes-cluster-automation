package watchdogs

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// cjFixture builds a Forbid CronJob world: the CronJob plus Job/Pod/
// Node objects the test shapes.
func cjFixture(t *testing.T, now time.Time, killRunaway bool,
	objs ...runtime.Object) (*fake.Clientset, *cjForbidZombieCheck) {

	t.Helper()
	cs := fake.NewSimpleClientset(objs...)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	probetest.FreezeNow(d, now)
	return cs, &cjForbidZombieCheck{Deps: d, killRunaway: killRunaway}
}

// forbidCJ builds an unsuspended Forbid CronJob with the given
// status.active job names.
func forbidCJ(ns, name string, active ...string) *batchv1.CronJob {
	refs := make([]corev1.ObjectReference, 0, len(active))
	for _, n := range active {
		refs = append(refs, corev1.ObjectReference{
			APIVersion: "batch/v1", Kind: "Job", Name: n,
		})
	}
	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			UID: types.UID("cj-uid-" + ns + "-" + name),
		},
		Spec: batchv1.CronJobSpec{
			Schedule:          "*/10 * * * *",
			ConcurrencyPolicy: batchv1.ForbidConcurrent,
		},
		Status: batchv1.CronJobStatus{Active: refs},
	}
}

// cjJob builds a Job with the given start age and optional terminal
// condition, controlled by owner (nil = a hand-rolled Job with no
// CronJob controller — the delete path must refuse to touch it).
func cjJob(ns, name string, startAge time.Duration, terminal batchv1.JobConditionType,
	owner *batchv1.CronJob) *batchv1.Job {

	start := metav1.NewTime(time.Now().Add(-startAge))
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status:     batchv1.JobStatus{StartTime: &start},
	}
	if owner != nil {
		job.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "batch/v1", Kind: "CronJob",
			Name: owner.Name, UID: owner.UID, Controller: ptr.To(true),
		}}
	}
	if terminal != "" {
		job.Status.Conditions = []batchv1.JobCondition{{
			Type: terminal, Status: corev1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
		}}
	}
	return job
}

// cjJobPod builds a pod owned by the Job on the given node.
func cjJobPod(ns, jobName, name, node string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "batch/v1", Kind: "Job",
				Name: jobName, Controller: ptr.To(true),
			}},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: phase},
	}
}

// A zombie active ref — the Job already Failed but status.active
// still lists it — is deleted after the 15m evidence window,
// unblocking the Forbid schedule.
func TestCronJobForbidZombieDeletesFailedJob(t *testing.T) {
	now := time.Now()
	cj := forbidCJ("batch", "nightly", "nightly-28300000")
	job := cjJob("batch", "nightly-28300000", 2*time.Hour, batchv1.JobFailed, cj)
	cs, chk := cjFixture(t, now, false, cj, job)

	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arm window
	probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("zombie active ref must flag: %+v", res)
	}
	if _, err := cs.BatchV1().Jobs("batch").Get(ctx, "nightly-28300000", metav1.GetOptions{}); err == nil {
		t.Fatal("zombie Job was not deleted")
	}
	if got := testutil.ToFloat64(cjForbidStalledGauge.WithLabelValues("batch", "nightly", cjStallZombie)); got != 1 {
		t.Fatalf("stalled gauge = %v, want 1", got)
	}
}

// A Job whose every pod sits on a vanished node is zombie evidence
// even without a terminal condition.
func TestCronJobForbidZombieDeletesPodsOnDeadNodes(t *testing.T) {
	now := time.Now()
	cj := forbidCJ("batch", "hourly", "hourly-28300001")
	job := cjJob("batch", "hourly-28300001", 3*time.Hour, "", cj)
	pod := cjJobPod("batch", "hourly-28300001", "hourly-28300001-abc", "node-gone", corev1.PodRunning)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-live"}}
	cs, chk := cjFixture(t, now, false, cj, job, pod, node)

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("dead-node zombie must flag: %+v", res)
	}
	if _, err := cs.BatchV1().Jobs("batch").Get(ctx, "hourly-28300001", metav1.GetOptions{}); err == nil {
		t.Fatal("dead-node zombie Job was not deleted")
	}
}

// Negative: a healthy active Job — running pods on live nodes —
// never flags and is never deleted, even past the runaway floor
// (the kill half is opt-in and this Job is young anyway).
func TestCronJobForbidZombieLeavesHealthyJob(t *testing.T) {
	now := time.Now()
	cj := forbidCJ("batch", "fresh", "fresh-28300002")
	job := cjJob("batch", "fresh-28300002", 10*time.Minute, "", cj)
	pod := cjJobPod("batch", "fresh-28300002", "fresh-28300002-abc", "node-live", corev1.PodRunning)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-live"}}
	cs, chk := cjFixture(t, now, true, cj, job, pod, node)

	probetest.FreezeNow(chk.Deps, now.Add(2*time.Hour))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass {
		t.Fatalf("healthy active Job must pass: %+v", res)
	}
	if _, err := cs.BatchV1().Jobs("batch").Get(ctx, "fresh-28300002", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy Job deleted: %v", err)
	}
}

// Runaway: a Job older than max(6h, 10×interval) always flags the
// stalled gauge but is only killed with the annotation or the env
// opt-in.
func TestCronJobForbidRunawayKillGating(t *testing.T) {
	now := time.Now()

	// No annotation, killRunaway=false → gauge fires, Job survives.
	cj := forbidCJ("batch", "runaway", "runaway-28300003")
	job := cjJob("batch", "runaway-28300003", 8*time.Hour, "", cj)
	pod := cjJobPod("batch", "runaway-28300003", "runaway-28300003-abc", "node-live", corev1.PodRunning)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-live"}}
	cs, chk := cjFixture(t, now, false, cj, job, pod, node)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("runaway Job must flag: %+v", res)
	}
	if _, err := cs.BatchV1().Jobs("batch").Get(ctx, "runaway-28300003", metav1.GetOptions{}); err != nil {
		t.Fatalf("runaway Job killed without opt-in: %v", err)
	}
	if got := testutil.ToFloat64(cjForbidStalledGauge.WithLabelValues("batch", "runaway", cjStallRunaway)); got != 1 {
		t.Fatalf("runaway gauge = %v, want 1", got)
	}

	// Same shape with the annotation → the Job is killed.
	cj2 := forbidCJ("batch", "annotated", "annotated-28300004")
	cj2.Annotations = map[string]string{kube.AnnoCronJobMaxActiveDuration: "4h"}
	job2 := cjJob("batch", "annotated-28300004", 5*time.Hour, "", cj2)
	pod2 := cjJobPod("batch", "annotated-28300004", "annotated-28300004-abc", "node-live", corev1.PodRunning)
	cs2, chk2 := cjFixture(t, now, false, cj2, job2, pod2, node)
	res = chk2.Run(probetest.SweepCtx(ctx, chk2.Deps))
	if res.Pass {
		t.Fatalf("annotated runaway must flag: %+v", res)
	}
	if _, err := cs2.BatchV1().Jobs("batch").Get(ctx, "annotated-28300004", metav1.GetOptions{}); err == nil {
		t.Fatal("annotated runaway Job was not killed")
	}
}

// A malformed max-active-duration annotation must NOT opt into the
// kill — the doc contract is "a typo'd value never engages". The
// runaway gauge still fires (the threshold falls back to the 6h
// floor / 10×interval rule).
func TestCronJobForbidRunawayRejectsMalformedAnnotation(t *testing.T) {
	now := time.Now()
	cj := forbidCJ("batch", "typo", "typo-28300007")
	cj.Annotations = map[string]string{kube.AnnoCronJobMaxActiveDuration: "forever"}
	job := cjJob("batch", "typo-28300007", 8*time.Hour, "", cj)
	pod := cjJobPod("batch", "typo-28300007", "typo-28300007-abc", "node-live", corev1.PodRunning)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-live"}}
	cs, chk := cjFixture(t, now, false, cj, job, pod, node)

	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("runaway Job must still flag on the fallback limit: %+v", res)
	}
	if _, err := cs.BatchV1().Jobs("batch").Get(ctx, "typo-28300007", metav1.GetOptions{}); err != nil {
		t.Fatalf("malformed annotation opted into the kill: %v", err)
	}
}

// When the Job object is already gone but status.active still lists
// it, the ghost ref itself is the wedge — the check must clear it
// via UpdateStatus so the Forbid slot frees without a Job to delete.
func TestCronJobForbidZombieClearsGhostActiveRef(t *testing.T) {
	now := time.Now()
	cj := forbidCJ("batch", "ghost", "ghost-28300008")
	// No Job object — status.active outran it entirely.
	cs, chk := cjFixture(t, now, false, cj)

	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arm the 15m zombie window
	probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("ghost active ref must flag: %+v", res)
	}
	live, err := cs.BatchV1().CronJobs("batch").Get(ctx, "ghost", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get cronjob: %v", err)
	}
	for _, ref := range live.Status.Active {
		if ref.Name == "ghost-28300008" {
			t.Fatal("ghost status.active ref was not cleared")
		}
	}
	if got := testutil.ToFloat64(cjForbidStalledGauge.WithLabelValues("batch", "ghost", cjStallZombie)); got != 1 {
		t.Fatalf("stalled gauge = %v, want 1", got)
	}
}

// A same-named Job that is NOT controlled by this CronJob must never
// be deleted, even when it looks like a zombie: status.active names a
// Job by name, not by identity, and killing a foreign Job to free a
// Forbid slot would take down somebody else's workload.
func TestCronJobForbidZombieSkipsForeignController(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner *batchv1.CronJob
	}{
		{"owned by another cronjob", &batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "other", UID: types.UID("someone-else")},
		}},
		{"no controller at all", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			cj := forbidCJ("batch", "nightly", "nightly-foreign")
			job := cjJob("batch", "nightly-foreign", 2*time.Hour, batchv1.JobFailed, tc.owner)
			cs, chk := cjFixture(t, now, false, cj, job)

			chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arm the 15m zombie window
			probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
			res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			if res.Pass {
				t.Fatalf("zombie ref must still be flagged: %+v", res)
			}
			if _, err := cs.BatchV1().Jobs("batch").Get(ctx, "nightly-foreign", metav1.GetOptions{}); err != nil {
				t.Fatalf("foreign Job was deleted: %v", err)
			}
		})
	}
}

// A 403 on UpdateStatus is a tolerated sub-failure: the audit finding
// still stands (gauge + FAIL), and the cooldown is stamped so the
// doomed write is not retried on every subsequent sweep.
func TestCronJobForbidZombie403StampsCooldown(t *testing.T) {
	now := time.Now()
	cj := forbidCJ("batch", "ghost-rbac", "ghost-rbac-1")
	cs, chk := cjFixture(t, now, false, cj)
	var updates int
	cs.PrependReactor("update", "cronjobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			updates++
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: "batch", Resource: "cronjobs"},
				cj.Name, nil)
		})

	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // too young to heal — arm the window
	probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("ghost ref must be flagged even when the heal write is forbidden: %+v", res)
	}
	if updates != 1 {
		t.Fatalf("update attempts = %d, want 1", updates)
	}
	// Next sweep inside the cooldown must not retry the forbidden write.
	probetest.FreezeNow(chk.Deps, now.Add(17*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if updates != 1 {
		t.Fatalf("forbidden update retried inside cooldown: %d attempts", updates)
	}
}

// A suspended CronJob or an Allow-concurrency one is out of scope.
func TestCronJobForbidZombieSkipsNonForbid(t *testing.T) {
	now := time.Now()
	suspended := forbidCJ("batch", "paused", "paused-28300005")
	suspend := true
	suspended.Spec.Suspend = &suspend
	allow := forbidCJ("batch", "allow-cj", "allow-cj-28300006")
	allow.Spec.ConcurrencyPolicy = batchv1.AllowConcurrent
	failed := cjJob("batch", "paused-28300005", time.Hour, batchv1.JobFailed, suspended)
	failed2 := cjJob("batch", "allow-cj-28300006", time.Hour, batchv1.JobFailed, allow)
	cs, chk := cjFixture(t, now, true, suspended, allow, failed, failed2)

	probetest.FreezeNow(chk.Deps, now.Add(2*time.Hour))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass {
		t.Fatalf("non-Forbid CronJobs must pass: %+v", res)
	}
	for _, n := range []string{"paused-28300005", "allow-cj-28300006"} {
		if _, err := cs.BatchV1().Jobs("batch").Get(ctx, n, metav1.GetOptions{}); err != nil {
			t.Fatalf("out-of-scope Job %s deleted: %v", n, err)
		}
	}
}

func TestCronJobForbidZombieSelfHealKeyspace(t *testing.T) {
	now := time.Now()

	// 1. Stalled Job delete uses SelfHealKey(CheckNameCronJobForbidZombie, ns/name).
	cjJobTarget := forbidCJ("batch", "nightly", "nightly-1")
	job := cjJob("batch", "nightly-1", 2*time.Hour, batchv1.JobFailed, cjJobTarget)
	// 2. Ghost active ref clear uses SelfHealKey(CheckNameCronJobForbidZombie, ns/name+"/active-ref").
	cjGhost := forbidCJ("batch", "ghost", "ghost-1")

	cs, chk := cjFixture(t, now, false, cjJobTarget, job, cjGhost)
	// Seed bare keys to prove no cross-collision / suppression from bare ns/name.
	chk.Heals.Stamp("batch/nightly", now.Add(16*time.Minute))
	chk.Heals.Stamp("batch/ghost/active-ref", now.Add(16*time.Minute))

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("aged zombies must flag: %+v", res)
	}
	if _, err := cs.BatchV1().Jobs("batch").Get(ctx, "nightly-1", metav1.GetOptions{}); err == nil {
		t.Fatal("stalled Job was suppressed by bare key")
	}
	liveGhost, err := cs.BatchV1().CronJobs("batch").Get(ctx, "ghost", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get ghost cronjob: %v", err)
	}
	if len(liveGhost.Status.Active) != 0 {
		t.Fatalf("ghost active ref was suppressed by bare key: %+v", liveGhost.Status.Active)
	}
	if !chk.Heals.CooledDown(probefw.SelfHealKey(CheckNameCronJobForbidZombie, "batch/nightly"), time.Hour, now.Add(16*time.Minute)) {
		t.Fatal("stalled Job heal not stamped under SelfHealKey")
	}
	if !chk.Heals.CooledDown(probefw.SelfHealKey(CheckNameCronJobForbidZombie, "batch/ghost/active-ref"), time.Hour, now.Add(16*time.Minute)) {
		t.Fatal("ghost active-ref heal not stamped under SelfHealKey")
	}
}

func TestCronJobForbidZombieInvalidatesMidSweep(t *testing.T) {
	now := time.Now()
	cjJobTarget := forbidCJ("batch", "nightly", "nightly-1")
	job := cjJob("batch", "nightly-1", 2*time.Hour, batchv1.JobFailed, cjJobTarget)
	cjGhost := forbidCJ("batch", "ghost", "ghost-1")
	cs, chk := cjFixture(t, now, false, cjJobTarget, job, cjGhost)

	var cjLists, jobLists int
	cs.PrependReactor("list", "cronjobs", func(ktesting.Action) (bool, runtime.Object, error) {
		cjLists++
		return false, nil, nil
	})
	cs.PrependReactor("list", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
		jobLists++
		return false, nil, nil
	})

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
	sctx := probetest.SweepCtx(ctx, chk.Deps)
	chk.Run(sctx)

	// Re-reading within the same sweep must see invalidated CronJobs and Jobs.
	_, _ = chk.AllCronJobs(sctx)
	_, _ = chk.AllJobs(sctx)
	if cjLists != 3 {
		t.Fatalf("cronjobs list count = %d, want 3 (2 sweeps + 1 post-InvalidateCronJobs)", cjLists)
	}
	if jobLists != 3 {
		t.Fatalf("jobs list count = %d, want 3 (2 sweeps + 1 post-InvalidateJobs)", jobLists)
	}
}

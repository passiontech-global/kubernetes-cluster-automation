package cronjobcatchup

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

// ---------------------------------------------------------------------------
// Builders (cc-prefixed)
// ---------------------------------------------------------------------------

// ccCronJob builds an opted-in CronJob with a JobTemplate worth
// checking for clone fidelity.
func ccCronJob(ns, name, schedule string, lastSchedule *metav1.Time) *batchv1.CronJob {
	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: map[string]string{catchupAnno: "true"},
			// A real CronJob always carries a creation timestamp —
			// stale() anchors the missed-tick math on it when
			// lastScheduleTime is nil.
			CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		},
		Spec: batchv1.CronJobSpec{
			Schedule: schedule,
			JobTemplate: batchv1.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"app": "nightly"},
					Annotations: map[string]string{"team": "ops"},
				},
				Spec: batchv1.JobSpec{
					BackoffLimit: ptr.To(int32(2)),
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							RestartPolicy: corev1.RestartPolicyNever,
							Containers:    []corev1.Container{{Name: "c", Image: "img:1"}},
						},
					},
				},
			},
		},
		Status: batchv1.CronJobStatus{LastScheduleTime: lastSchedule},
	}
}

func ccJobCount(t *testing.T, cs *fake.Clientset, ns string) int {
	t.Helper()
	jobs, err := cs.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return len(jobs.Items)
}

func newCatchup(cs *fake.Clientset) *cronJobCatchup {
	return &cronJobCatchup{cs: cs, lastCatchup: map[string]string{}}
}

// newCatchupAt pins the clock seam so staleness against a real cron
// schedule is deterministic.
func newCatchupAt(cs *fake.Clientset, now time.Time) *cronJobCatchup {
	return &cronJobCatchup{cs: cs, lastCatchup: map[string]string{},
		nowFn: func() time.Time { return now }}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// A stale CronJob without the opt-in annotation is left alone —
// backlog replay is only safe for jobs known to be idempotent.
func TestCronJobCatchupNoAnnotationSkips(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	delete(cj.Annotations, catchupAnno)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 0 {
		t.Fatalf("catch-up job created for a non-opted-in cronjob (%d jobs)", n)
	}
}

// suspend:true is the operator's explicit "do not run" — even an
// opted-in, stale CronJob must not be replayed.
func TestCronJobCatchupSuspendedSkips(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	cj.Spec.Suspend = ptr.To(true)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 0 {
		t.Fatalf("catch-up job created for a suspended cronjob (%d jobs)", n)
	}
}

// nil lastScheduleTime = never scheduled (or status wiped): the
// creation timestamp anchors the missed-tick math — a job created
// 2h ago on a */5 schedule missed its very first tick long past the
// grace bound, so it IS stale. The spawned Job must be a faithful
// JobTemplate clone living in the CronJob's own namespace.
func TestCronJobCatchupNilLastScheduleCreates(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, err := cs.BatchV1().Jobs("ops").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("expected 1 catch-up job, got %d", len(jobs.Items))
	}
	j := jobs.Items[0]
	if !strings.HasPrefix(j.Name, "nightly-catchup-") {
		t.Fatalf("job name %q lacks the <cj>-catchup- prefix", j.Name)
	}
	if j.Namespace != "ops" {
		t.Fatalf("job landed in %q, want the cronjob namespace ops", j.Namespace)
	}
	// JobTemplate metadata cloned + module stamps applied.
	if j.Labels["app"] != "nightly" || j.Annotations["team"] != "ops" {
		t.Fatalf("JobTemplate metadata not cloned: labels=%v annotations=%v",
			j.Labels, j.Annotations)
	}
	if j.Labels[catchupLabel] != "nightly" {
		t.Fatalf("missed-catchup label missing: %v", j.Labels)
	}
	if j.Annotations["cronjob.kubernetes.io/instantiate"] != "manual" {
		t.Fatal("instantiate=manual annotation missing")
	}
	// Spec DeepCopy'd — including the pointer fields.
	if j.Spec.BackoffLimit == nil || *j.Spec.BackoffLimit != 2 {
		t.Fatalf("spec not cloned: backoffLimit=%v", j.Spec.BackoffLimit)
	}
	if len(j.Spec.Template.Spec.Containers) != 1 ||
		j.Spec.Template.Spec.Containers[0].Image != "img:1" {
		t.Fatal("pod template not cloned")
	}
}

// A brand-new opted-in CronJob whose first tick hasn't arrived yet
// is NOT stale: nil lastScheduleTime anchors at creation, and the
// next tick after a 2h-old creation on a daily schedule always lies
// in the future — the job hasn't missed anything. (The old
// nil-==stale rule would have fired an immediate replay.)
func TestCronJobCatchupFreshCronJobNotStale(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "0 3 * * *", nil)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 0 {
		t.Fatalf("catch-up job created for a cronjob whose first tick hasn't passed (%d jobs)", n)
	}
}

// A CronJob that scheduled recently is healthy — threshold is
// max(2*period, period+30m), and 10m ago is far inside it for an
// hourly job.
func TestCronJobCatchupFreshLastScheduleSkips(t *testing.T) {
	fresh := metav1.NewTime(time.Now().Add(-10 * time.Minute))
	cj := ccCronJob("ops", "hourly", "17 * * * *", &fresh)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 0 {
		t.Fatalf("catch-up job created for a healthy cronjob (%d jobs)", n)
	}
}

// A stale lastScheduleTime (2h ago on a */5 job, threshold 35m)
// triggers exactly one catch-up.
func TestCronJobCatchupStaleCreates(t *testing.T) {
	stale := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	cj := ccCronJob("ops", "frequent", "*/5 * * * *", &stale)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 1 {
		t.Fatalf("expected 1 catch-up job, got %d", n)
	}
}

// An Active Job owned by the CronJob means a scheduled run is in
// flight — a catch-up on top of it would double-fire the workload.
func TestCronJobCatchupActiveOwnedJobSkips(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	active := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ops", Name: "nightly-29381234",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "batch/v1", Kind: "CronJob",
				Name: "nightly", Controller: ptr.To(true),
			}},
		},
		Status: batchv1.JobStatus{Active: 1},
	}
	cs := fake.NewSimpleClientset(cj, active)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 1 {
		t.Fatalf("expected only the owned active job, got %d", n)
	}
}

// A catch-up Job carrying the missed-catchup label younger than 24h
// already covers this CronJob.
func TestCronJobCatchupLabelDedupeSkips(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	prior := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "ops",
			Name:              "nightly-catchup-123",
			Labels:            map[string]string{catchupLabel: "nightly"},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		},
	}
	cs := fake.NewSimpleClientset(cj, prior)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 1 {
		t.Fatalf("label dedupe failed: %d jobs", n)
	}
}

// The in-memory daily cap holds even when the created catch-up Job is
// gone — the label dedupe alone could not cover a deleted Job.
func TestCronJobCatchupDailyCap(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 1 {
		t.Fatalf("expected 1 catch-up job, got %d", n)
	}
	// Simulate the catch-up finishing and being pruned before the
	// next sweep — only the daily cap can block a second spawn.
	jobs, _ := cs.BatchV1().Jobs("ops").List(ctx, metav1.ListOptions{})
	if err := cs.BatchV1().Jobs("ops").Delete(ctx, jobs.Items[0].Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 0 {
		t.Fatalf("daily cap failed: %d jobs after the first catch-up was pruned", n)
	}
}

// An unparseable schedule is warned on and skipped — never blocks the
// rest of the sweep and never errors the run.
func TestCronJobCatchupInvalidScheduleSkips(t *testing.T) {
	bad := ccCronJob("ops", "broken", "not-a-cron", nil)
	good := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	cs := fake.NewSimpleClientset(bad, good)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatalf("invalid schedule errored the run: %v", err)
	}
	jobs, err := cs.BatchV1().Jobs("ops").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 1 || !strings.HasPrefix(jobs.Items[0].Name, "nightly-catchup-") {
		t.Fatalf("expected only the nightly catch-up, got %+v", jobs.Items)
	}
}

// A jobs list failure inside deduped() degrades to "not deduped" —
// a missed catch-up is worse than one extra idempotent Job.
func TestCronJobCatchupDedupeListErrorStillCreates(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	cs := fake.NewSimpleClientset(cj)
	var failed atomic.Bool
	cs.PrependReactor("list", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			if failed.CompareAndSwap(false, true) {
				return true, nil, errors.New("jobs list boom") // dedupe call only
			}
			return false, nil, nil
		})
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 1 {
		t.Fatalf("catch-up job not created when dedupe list failed (%d jobs)", n)
	}
}

// A Job create failure is metered+logged but does NOT arm the in-memory
// daily cap — the next sweep must retry the spawn.
func TestCronJobCatchupCreateErrorDoesNotArmCap(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	cs := fake.NewSimpleClientset(cj)
	var creates int32
	cs.PrependReactor("create", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			atomic.AddInt32(&creates, 1)
			return true, nil, errors.New("quota exhausted")
		})
	c := newCatchup(cs)
	for i := 0; i < 2; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&creates); got != 2 {
		t.Fatalf("expected a create retry on the second run (cap must stay unarmed), got %d attempts", got)
	}
	if len(c.lastCatchup) != 0 {
		t.Fatal("daily cap armed despite the failed create")
	}
}

// A JobTemplate carrying no labels/annotations at all: the spawn must
// still stamp the missed-catchup label and the instantiate annotation
// (maps.Clone(nil) must not leave nil maps behind).
func TestCronJobCatchupBareJobTemplate(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	cj.Spec.JobTemplate.Labels = nil
	cj.Spec.JobTemplate.Annotations = nil
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, err := cs.BatchV1().Jobs("ops").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("expected 1 catch-up job, got %d", len(jobs.Items))
	}
	j := jobs.Items[0]
	if j.Labels[catchupLabel] != "nightly" {
		t.Fatalf("missed-catchup label missing on bare template: %v", j.Labels)
	}
	if j.Annotations["cronjob.kubernetes.io/instantiate"] != "manual" {
		t.Fatalf("instantiate annotation missing on bare template: %v", j.Annotations)
	}
}

// The daily-cap map is pruned for CronJobs that vanished — a deleted
// CronJob must not pin a stale cap entry forever.
func TestCronJobCatchupPrunesCapForDeletedCronJob(t *testing.T) {
	cj := ccCronJob("ops", "nightly", "*/5 * * * *", nil)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	c.lastCatchup["ops/gone"] = "2000-01-01" // vanished CJ's stale entry
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.lastCatchup["ops/gone"]; ok {
		t.Fatal("cap entry for a deleted CronJob not pruned")
	}
	// The live stale CronJob still spawned and re-armed today's cap —
	// the prune must only drop absent keys.
	today := time.Now().UTC().Format("2006-01-02")
	if got := c.lastCatchup["ops/nightly"]; got != today {
		t.Fatalf("live CronJob's cap entry = %q, want today's %q", got, today)
	}
}

// A CronJob list failure aborts the sweep — the periodic wrapper
// meters the error.
func TestCronJobCatchupListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "cronjobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	c := newCatchup(cs)
	if err := c.run(ctx); err == nil {
		t.Fatal("expected error when the cronjob list fails")
	}
}

// capped lazily initializes the daily-cap map — a reconciler built
// without Setup (e.g. an early test construct) must not panic.
func TestCronJobCatchupCappedLazyInit(t *testing.T) {
	c := &cronJobCatchup{} // lastCatchup nil
	if c.capped("ops/nightly") {
		t.Fatal("never-fired cronjob reported as capped")
	}
	if c.lastCatchup == nil {
		t.Fatal("cap map not lazily initialized")
	}
}

// A 52-char CronJob name must not overflow the 63-char Job-name
// ceiling: the catch-up suffix is kept whole and only the
// CronJob-name portion is truncated.
func TestCronJobCatchupLongNameTruncated(t *testing.T) {
	longName := strings.Repeat("a", 45) + "-" + strings.Repeat("b", 6) // 52 chars
	cj := ccCronJob("ops", longName, "*/5 * * * *", nil)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchup(cs)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, err := cs.BatchV1().Jobs("ops").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("expected 1 catch-up job, got %d", len(jobs.Items))
	}
	name := jobs.Items[0].Name
	if len(name) > 63 {
		t.Fatalf("job name %q is %d chars — Create would fail Invalid", name, len(name))
	}
	if !strings.Contains(name, "-catchup-") {
		t.Fatalf("job name %q lost the -catchup-<unix> suffix", name)
	}
	// Trailing separators would still violate DNS-1123.
	if strings.HasSuffix(name[:strings.Index(name, "-catchup-")], "-") {
		t.Fatalf("truncated name portion ends on a separator: %q", name)
	}
}

// A weekday-only CronJob idle since Friday must NOT be flagged stale
// over the weekend — its next tick (Monday 09:00) is still in the
// future. The old two-future-ticks period math compared raw
// lastScheduleTime age and fired ~once a day all weekend.
func TestCronJobCatchupWeekdayScheduleWeekendNotStale(t *testing.T) {
	// 2026-01-03 is a Saturday; the last weekday tick ran Friday
	// 2026-01-02 17:00.
	now := time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC)
	if now.Weekday() != time.Saturday {
		t.Fatalf("test premise broken: %v is not a Saturday", now)
	}
	last := metav1.NewTime(time.Date(2026, 1, 2, 17, 0, 0, 0, time.UTC))
	cj := ccCronJob("ops", "weekday", "0 9-17 * * 1-5", &last)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchupAt(cs, now)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 0 {
		t.Fatalf("weekday-only cronjob flagged stale on a Saturday (%d jobs)", n)
	}
}

// The same weekday-only schedule DOES catch up once a real tick is
// missed past its grace: Monday noon with a Friday lastScheduleTime
// means the Monday 09:00 tick never ran (period to the next tick is
// 1h → threshold 2h).
func TestCronJobCatchupWeekdayScheduleMissedTickStale(t *testing.T) {
	now := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC) // Monday noon
	if now.Weekday() != time.Monday {
		t.Fatalf("test premise broken: %v is not a Monday", now)
	}
	last := metav1.NewTime(time.Date(2026, 1, 2, 17, 0, 0, 0, time.UTC)) // Friday 17:00
	cj := ccCronJob("ops", "weekday", "0 9-17 * * 1-5", &last)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchupAt(cs, now)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 1 {
		t.Fatalf("missed weekday tick not caught up (%d jobs)", n)
	}
}

// A missed tick still inside its grace bound is not stale yet — the
// daily job that missed this morning's 03:00 tick gets a full
// 2*period (48h) before a replay is spawned.
func TestCronJobCatchupMissedTickInsideGraceNotStale(t *testing.T) {
	now := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)                 // Monday noon
	last := metav1.NewTime(time.Date(2026, 1, 4, 3, 0, 0, 0, time.UTC)) // Sunday 03:00
	cj := ccCronJob("ops", "daily", "0 3 * * *", &last)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchupAt(cs, now)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 0 {
		t.Fatalf("missed tick inside the grace bound flagged stale (%d jobs)", n)
	}
}

// A daily run missed beyond max(2*period, period+30m) is stale:
// last tick Sunday 03:00, the Monday 03:00 tick is now 57h old —
// past the 48h threshold — so a catch-up fires.
func TestCronJobCatchupMissedDailyRunStale(t *testing.T) {
	now := time.Date(2026, 1, 7, 12, 0, 0, 0, time.UTC)                 // Wednesday noon
	last := metav1.NewTime(time.Date(2026, 1, 4, 3, 0, 0, 0, time.UTC)) // Sunday 03:00
	cj := ccCronJob("ops", "daily", "0 3 * * *", &last)
	cs := fake.NewSimpleClientset(cj)
	c := newCatchupAt(cs, now)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 1 {
		t.Fatalf("missed daily run not caught up (%d jobs)", n)
	}
}

// spec.timeZone shifts where the ticks land: an hourly job in
// Asia/Kathmandu (UTC+5:45) ticks at :15 UTC. The 11:15 UTC tick
// missed 1h55m ago is inside the 2h grace — a UTC interpretation
// would have flagged the 11:00 UTC tick missed 2h10m ago as stale.
func TestCronJobCatchupTimeZoneHonored(t *testing.T) {
	now := time.Date(2026, 1, 5, 13, 10, 0, 0, time.UTC)
	last := metav1.NewTime(time.Date(2026, 1, 5, 10, 15, 0, 0, time.UTC))
	cj := ccCronJob("ops", "tz-hourly", "0 * * * *", &last)
	cj.Spec.TimeZone = ptr.To("Asia/Kathmandu")
	cs := fake.NewSimpleClientset(cj)
	c := newCatchupAt(cs, now)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ccJobCount(t, cs, "ops"); n != 0 {
		t.Fatalf("spec.timeZone ignored — UTC tick math flagged stale (%d jobs)", n)
	}
}

// cronjob-catchup dedupe: the per-sweep cluster-wide Job index that
// proves a catch-up for a CronJob is already covered.
// split from cronjob_catchup.go (see its header for the module contract).
package cronjobcatchup

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// deduped reports whether a catch-up for cj is already covered:
// either a <24h-old Job carrying the missed-catchup label, or any
// Active Job still owned by the CronJob (a scheduled run in flight —
// replaying on top of it double-fires the workload). Both lookups
// run against the sweep's cluster-wide jobDedupeIndex — the per-sweep
// snapshot buildJobDedupeIndex made, so N opted-in CronJobs cost one
// Jobs List, not N.
func (c *cronJobCatchup) deduped(log logr.Logger, cj *batchv1.CronJob,
	idx *jobDedupeIndex) bool {
	key := cj.Namespace + "/" + cj.Name
	now := c.now.Now()
	// Fail CLOSED: an unverifiable dedupe must skip the replay —
	// double-firing the workload is strictly worse than a missed
	// catch-up the next 15m sweep retries.
	if idx.failed {
		log.Info("skip: jobs list failed — dedupe unverifiable (fail closed)",
			"cronjob", key)
		return true
	}
	// The CronJob's own status.active list is proof #0 — the
	// controller's record of runs still in flight counts even when
	// the Jobs snapshot lags behind it.
	if len(cj.Status.Active) > 0 {
		log.Info("skip: cronjob still reports active jobs",
			"cronjob", key, "active", len(cj.Status.Active))
		return true
	}
	// The dedupe window is per-CronJob: max(catchupDedupeAge, period)
	// — a weekly/monthly job's catch-up label must keep deduping for
	// its whole period or the next sweep would spawn a duplicate.
	dedupeWindow := catchupDedupeAge
	if sched, ok := c.parseSchedule(log, cj); ok {
		if next := sched.Next(now); !next.IsZero() {
			if p := sched.Next(next).Sub(next); p > dedupeWindow {
				dedupeWindow = p
			}
		}
	}
	if lj, ok := idx.labeled[key]; ok && now.Sub(lj.created) < dedupeWindow {
		log.Info("skip: a catch-up job already exists",
			"cronjob", key, "job", lj.name)
		return true
	}
	if job, ok := idx.activeOwner[key]; ok {
		log.Info("skip: a scheduled job is still active",
			"cronjob", key, "job", job)
		return true
	}
	return false
}

// labeledJob is one catch-up-labeled Job's dedupe record — the name
// for the skip log and the creation time deduped() windows against.
type labeledJob struct {
	name    string
	created time.Time
}

// jobDedupeIndex is the per-sweep cluster-wide Job snapshot behind
// the catch-up dedupe. Keys are "ns/cronjob-name" — exactly what the
// old per-namespace List could match — so a same-named CronJob in
// another namespace cannot collide and every verdict is unchanged.
type jobDedupeIndex struct {
	// failed: the cluster-wide Jobs list errored — no proof could be
	// collected, so deduped() must fail CLOSED (skip the replay) and
	// the caller retries on the next sweep. The sentinel is non-nil
	// so run()'s lazy build pays the failed list (and its IncError)
	// exactly once per sweep.
	failed bool
	// labeled: the catch-up label's VALUE is the CronJob name —
	// "ns/cronjob" → the NEWEST labeled Job and its creation time
	// (deduped() applies the per-CronJob window to this one's age;
	// an older sibling lingering past the window must not mask it).
	labeled map[string]labeledJob
	// activeOwner: "ns/cronjob" → the name of a Job whose controller
	// ownerRef points at that CronJob and which is still active.
	activeOwner map[string]string
}

// jobStillActive reports whether a CronJob-owned Job counts as an
// active run for dedupe: it has active pods, or it is freshly created
// and simply has not run anything yet — a Job with no
// DeletionTimestamp and no Complete/Failed condition has not finished
// (the status write that would mark it terminal has not happened), so
// a replay on top of it would double-fire the workload.
func jobStillActive(j *batchv1.Job) bool {
	if j.Status.Active > 0 {
		return true
	}
	if j.DeletionTimestamp != nil {
		return false
	}
	for _, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) &&
			c.Status == corev1.ConditionTrue {
			return false
		}
	}
	return true
}

// buildJobDedupeIndex lists Jobs cluster-wide once per sweep and
// indexes the two dedupe proofs. A list failure yields the FAILED
// sentinel — deduped() then fails CLOSED (the old per-namespace List
// failed open, betting one extra idempotent Job against a missed
// catch-up; double-firing a workload is the worse side, and the
// sweep retries in 15m), metered once instead of once per CronJob.
func (c *cronJobCatchup) buildJobDedupeIndex(ctx context.Context,
	log logr.Logger) *jobDedupeIndex {
	jobs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Jobs(c.cs, metav1.NamespaceAll))
	if err != nil {
		metrics.IncError(c.queue)
		log.Info("WARN: list jobs failed — dedupe unverifiable, catch-up deferred (fail closed)",
			"error", err)
		return &jobDedupeIndex{failed: true}
	}
	idx := &jobDedupeIndex{
		labeled:     map[string]labeledJob{},
		activeOwner: map[string]string{},
	}
	for i := range jobs {
		j := &jobs[i]
		if label := j.Labels[catchupLabel]; label != "" {
			key := j.Namespace + "/" + label
			if lj, ok := idx.labeled[key]; !ok || jobNewerThan(j, lj) {
				idx.labeled[key] = labeledJob{
					name:    j.Name,
					created: j.CreationTimestamp.Time,
				}
			}
		}
		if jobStillActive(j) {
			if owner := metav1.GetControllerOf(j); owner != nil &&
				owner.Kind == "CronJob" {
				key := j.Namespace + "/" + owner.Name
				if _, ok := idx.activeOwner[key]; !ok {
					idx.activeOwner[key] = j.Name
				}
			}
		}
	}
	return idx
}

// jobNewerThan reports whether j is newer than the indexed labeled
// job — creationTimestamp first, name descending as the tie-break
// (a same-second spawn keeps the lexicographically newest, i.e. the
// highest unix suffix). typed List order is name ASCENDING, so with
// "<cronjob>-catchup-<unix>" names the FIRST labeled job in list
// order is the OLDEST — indexing it would let an old catch-up past
// the dedupe window mask a fresh one and double-fire the workload.
func jobNewerThan(j *batchv1.Job, lj labeledJob) bool {
	if j.CreationTimestamp.Time.After(lj.created) {
		return true
	}
	return j.CreationTimestamp.Time.Equal(lj.created) && j.Name > lj.name
}

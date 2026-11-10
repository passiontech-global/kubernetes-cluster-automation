// cronjob-catchup — port of hooks/95-cronjob-catchup.sh.
//
// The CronJob controller silently drops a schedule when more than 100
// start times were missed (startingDeadlineSeconds unset): after a
// long apiserver outage, DST gap or suspend window, an hourly CronJob
// can be >4 days behind and Kubernetes just starts counting fresh —
// the missed runs never happen. This sweep detects a stale
// lastScheduleTime on opted-in CronJobs and clones the JobTemplate
// into one catch-up Job, exactly like `kubectl create job
// --from=cronjob/<cj>`.
//
// Opt-in ONLY: a CronJob must carry
// passiontech.dev/catchup: "true" — most jobs are not
// idempotent across a multi-day backlog (report generators, backup
// pruners), so silence means leave it alone.
//
// Dedupe (belt & suspenders, any one vetoes):
//   - a Job in the namespace labeled
//     passiontech.dev/missed-catchup=<cj> younger than 24h
//   - any Active Job still owned by the CronJob
//   - an in-memory 1-catchup-per-cronjob-per-day cap (survives the
//     catch-up Job being deleted)
package cronjobcatchup

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/robfig/cron/v3"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	// catchupAnno is the opt-in annotation — a backlog replay is only
	// safe for jobs whose side effects are idempotent.
	catchupAnno = kube.AnnoCatchup
	// catchupLabel marks Jobs this module created (dedupe).
	catchupLabel = kube.LabelMissedCatchup
	// catchupDedupeAge is how long a previously-created catch-up Job
	// blocks a new one.
	catchupDedupeAge = 24 * time.Hour
	// catchupMinStaleGrace: a missed tick counts as stale once it is
	// older than max(2*period, period+30m), where period is the gap
	// between the missed tick and the FOLLOWING one. The +30m floor
	// keeps a */5-minute job from being flagged during a routine
	// apiserver blip — one missed tick is normal controller behavior.
	catchupMinStaleGrace = 30 * time.Minute
	// catchupJobNameMax is the DNS-1123 subdomain ceiling a Job name
	// must fit — "<cj>-catchup-<unix>" is truncated to stay under it.
	catchupJobNameMax = 63

	// missedStartsLimit mirrors the CronJob controller's hard cap:
	// more than 100 missed start times and kube-controller-manager
	// logs "too many missed start times" and NEVER schedules the
	// CronJob again while spec.startingDeadlineSeconds is unset —
	// the job silently dies (cronjob-catchup).
	missedStartsLimit = 100
	// deadlinePatchSeconds is the startingDeadlineSeconds the
	// auto-unfreezer stamps — 1h of slack lets the controller pick
	// up from the most recent missed tick instead of demanding the
	// full backlog.
	deadlinePatchSeconds = int64(3600)
	// deadlinePatchedAnno records when/that this module repaired the
	// CronJob — operator-visible provenance on an object GitOps did
	// not write the deadline into.
	deadlinePatchedAnno = kube.AnnoStartingDeadlinePatched
)

type cronJobCatchup struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so schedule-relative
	// staleness is deterministic. nil → time.Now.
	now shared.Clock
	// lastCatchup enforces the 1-per-cronjob-per-day cap in memory —
	// keyed "ns/name" -> "2006-01-02" (UTC), pruned each sweep for
	// CronJobs that vanished. An apiserver-restart-clean map only
	// ever re-arms early, and the Job label dedupe still guards the
	// 24h window across restarts.
	lastCatchup map[string]string
	// missedEmitted is the CronJobTooManyMissedStarts ledger
	// ("ns/name") of series currently held at =1 — a CronJob that
	// got its deadline patched, was suspended, or vanished gets its
	// series deleted instead of pinning the alert forever (same
	// seen-set hygiene as the webhook guard's brokenEmitted).
	missedEmitted state.GaugeLedger[string]
}

// Setup registers the 15-minute sweep. The gate rides
// shared.SetupNoConfig like every module: Deps.Disabled registers
// nothing (no knobs to parse — SetupNoConfig is the module's shape).
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		c := &cronJobCatchup{cs: d.CS, queue: d.Name, now: shared.SystemClock,
			lastCatchup: map[string]string{}}
		return shared.AddPeriodic(d.Mgr, c.queue, 15*time.Minute, c.run)
	})
}

func (c *cronJobCatchup) run(ctx context.Context) error {
	c.missedEmitted.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)
	now := c.now.Now()

	cronjobs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.CronJobs(c.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list cronjobs: %w", err) // periodic wrapper IncErrors c.queue
	}

	spawned := 0
	// dedupeIdx is the sweep's lazily-built cluster-wide Job index
	// (nil until the first dedupe check needs it).
	var dedupeIdx *jobDedupeIndex
	for i := range cronjobs {
		cj := &cronjobs[i]
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			continue // deliberately paused — honor the operator's intent
		}
		// cronjob-catchup — the too-many-missed-starts unfreeze runs for EVERY
		// non-suspended CronJob, opt-in or not: unlike a backlog
		// replay, stamping startingDeadlineSeconds has no side
		// effect on the workload — it only un-breaks the controller.
		// Jobs already carrying a deadline are excluded: the >100
		// cap cannot engage while one is set.
		if cj.Spec.StartingDeadlineSeconds == nil {
			if sched, ok := c.parseSchedule(log, cj); ok {
				anchor := cj.CreationTimestamp.Time
				if cj.Status.LastScheduleTime != nil {
					anchor = cj.Status.LastScheduleTime.Time
				}
				if missedOver100(sched, anchor, now) {
					c.missedEmitted.Set(metrics.CronJobTooManyMissedStarts, 1,
						cj.Namespace+"/"+cj.Name, cj.Namespace, cj.Name)
					if c.unfreezeDeadline(ctx, log, cj, now) {
						// The deadline repair hands the CronJob back
						// to the controller, which creates its own
						// recovery Job — spawning our catch-up in
						// the same cycle would double-fire it.
						continue
					}
				}
			}
		}
		if cj.Annotations[catchupAnno] != "true" {
			continue // not opted in — backlog replay may not be idempotent
		}
		stale, ok := c.stale(log, cj)
		if !ok {
			continue // unparseable schedule — already warned
		}
		if !stale {
			continue
		}
		key := cj.Namespace + "/" + cj.Name
		if c.capped(key) {
			log.Info("skip: catch-up already fired today",
				"cronjob", key)
			continue
		}
		// The dedupe index builds lazily — sweeps that never reach a
		// dedupe check (no opted-in stale CronJob) pay no Jobs List.
		if dedupeIdx == nil {
			dedupeIdx = c.buildJobDedupeIndex(ctx, log)
		}
		if c.deduped(log, cj, dedupeIdx) {
			continue
		}
		if c.spawn(ctx, log, cj, key) {
			spawned++
		}
	}
	// Drop daily-cap entries for CronJobs that no longer exist — the
	// map is otherwise append-only per opted-in job ever caught up.
	present := map[string]struct{}{}
	for i := range cronjobs {
		cj := &cronjobs[i]
		present[cj.Namespace+"/"+cj.Name] = struct{}{}
	}
	for key := range c.lastCatchup {
		if _, ok := present[key]; !ok {
			delete(c.lastCatchup, key)
		}
	}
	// Prune TooManyMissedStarts series whose tuple was not re-seen —
	// a patched (deadline now set), suspended or deleted CronJob
	// must not pin the gauge at 1 forever.
	c.missedEmitted.Prune(metrics.CronJobTooManyMissedStarts.DeleteLabelValues)
	log.Info("sweep done", "spawned", spawned)
	return nil
}

// parseSchedule resolves the CronJob's effective schedule — honoring
// spec.timeZone via the CRON_TZ= prefix the parser understands.
// ok=false reports an unparseable schedule (warned, skipped).
func (c *cronJobCatchup) parseSchedule(log logr.Logger, cj *batchv1.CronJob) (cron.Schedule, bool) {
	schedule := cj.Spec.Schedule
	if tz := cj.Spec.TimeZone; tz != nil && *tz != "" {
		// spec.timeZone sets the zone the expression is evaluated in
		// — robfig/cron accepts the CRON_TZ= prefix natively.
		schedule = "CRON_TZ=" + *tz + " " + schedule
	}
	sched, err := cron.ParseStandard(schedule)
	if err != nil {
		log.Info("WARN: unparseable schedule — skip",
			"cronjob", cj.Namespace+"/"+cj.Name,
			"schedule", cj.Spec.Schedule, "error", err)
		return nil, false
	}
	return sched, true
}

// stale decides whether the CronJob genuinely missed a run: the first
// scheduled tick strictly AFTER lastScheduleTime lying in the past
// beyond its grace bound.
// A nil lastScheduleTime means the CronJob NEVER scheduled (or
// status was wiped) — the creation timestamp anchors the same
// missed-tick math, so a brand-new job whose first tick is still in
// the future is NOT stale (the old code treated nil as stale
// unconditionally: a fresh opted-in job got an immediate replay and
// kept re-firing daily until its first real tick landed, because
// lastScheduleTime stays nil that whole time). ok=false reports an
// unparseable schedule.
func (c *cronJobCatchup) stale(log logr.Logger, cj *batchv1.CronJob) (bool, bool) {
	sched, ok := c.parseSchedule(log, cj)
	if !ok {
		return false, false
	}
	// The first tick strictly after lastScheduleTime is the run the
	// controller owed us next. Still in the future means healthy,
	// however long ago the last run was: a weekday-only job idle
	// since Friday 17:00 is NOT stale on Saturday — its next tick is
	// Monday. (The old check derived the period from two FUTURE
	// ticks and compared raw lastScheduleTime age against it, which
	// fired all weekend because the gap since Friday dwarfed the
	// weekday cadence.)
	anchor := cj.CreationTimestamp.Time
	if cj.Status.LastScheduleTime != nil {
		anchor = cj.Status.LastScheduleTime.Time
	}
	missed := sched.Next(anchor)
	now := c.now.Now()
	if missed.IsZero() {
		// An impossible schedule (`0 0 31 2 *` — Feb 31 does not
		// exist) has no next tick at all: nothing is owed, so it can
		// never be stale. Treating the zero time as a missed tick in
		// the past would replay the workload every sweep.
		return false, true
	}
	if !missed.Before(now) {
		return false, true
	}
	// Grace: the period of the MISSED tick — the gap to the tick
	// after it, not the upcoming cadence — so a */5 job gets a tight
	// bound while a sparse schedule is not flagged prematurely.
	period := sched.Next(missed).Sub(missed)
	threshold := period + catchupMinStaleGrace
	if 2*period > threshold {
		threshold = 2 * period
	}
	return now.Sub(missed) > threshold, true
}

// ---------------------------------------------------------------------------
// cronjob-catchup — TooManyMissedStarts detector + auto-unfreezer.
// ---------------------------------------------------------------------------

// missedOver100 reports whether the schedule owes more than 100 ticks
// between anchor (lastScheduleTime, or creationTimestamp when the job
// never ran) and now — the kube-controller-manager hard cap after
// which the CronJob is permanently skipped while
// spec.startingDeadlineSeconds is unset. The loop is self-bounding:
// it returns on the 101st missed tick regardless of the gap's size.
// A zero Next return (an impossible spec like `0 0 31 2 *` — Feb 31
// does not exist) ends the iteration immediately: zero compares
// Before(now) forever, so advancing on it would spin the loop (and
// the periodic sweep's goroutine) indefinitely.
func missedOver100(sched cron.Schedule, anchor, now time.Time) bool {
	missed := 0
	for t := sched.Next(anchor); !t.IsZero() && t.Before(now); t = sched.Next(t) {
		missed++
		if missed > missedStartsLimit {
			return true
		}
	}
	return false
}

// unfreezeDeadline stamps spec.startingDeadlineSeconds=3600 plus the
// provenance annotation onto a CronJob that crossed the >100-missed
// cap — the controller treats the deadline as "count misses only
// inside the window", so the job schedules again instead of being
// skipped forever. Merge patch: the annotation adds a single key and
// the spec field cannot clobber a concurrent writer's spec edits
// (merge preserves every key not named). A patch failure is
// metered+logged but absorbed — the next sweep retries. Reports
// whether the patch landed so the caller can skip its own catch-up
// spawn this cycle (KCM creates the recovery Job itself).
func (c *cronJobCatchup) unfreezeDeadline(ctx context.Context, log logr.Logger, cj *batchv1.CronJob, now time.Time) bool {
	// MergePatchAnnos builds the annotations half; the spec field is
	// grafted onto the same doc so the provenance stamp and the
	// deadline land in ONE merge patch (merge preserves every key
	// not named, so a concurrent spec writer is not clobbered).
	payload, err := kube.MergePatchAnnos(map[string]any{
		deadlinePatchedAnno: now.UTC().Format(time.RFC3339),
	})
	if err == nil {
		var doc map[string]any
		if err = json.Unmarshal(payload, &doc); err == nil {
			doc["spec"] = map[string]any{
				"startingDeadlineSeconds": deadlinePatchSeconds,
			}
			payload, err = json.Marshal(doc)
		}
	}
	if err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "marshal deadline patch",
			"cronjob", cj.Namespace+"/"+cj.Name)
		return false
	}
	if _, err := c.cs.BatchV1().CronJobs(cj.Namespace).Patch(ctx, cj.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "startingDeadlineSeconds patch failed",
			"cronjob", cj.Namespace+"/"+cj.Name)
		return false
	}
	log.Info("PATCH: startingDeadlineSeconds=3600 — CronJob crossed the >100 missed-start cap",
		"cronjob", cj.Namespace+"/"+cj.Name,
		"schedule", cj.Spec.Schedule)
	return true
}

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

// capped enforces the in-memory 1-catchup-per-cronjob-per-day limit.
func (c *cronJobCatchup) capped(key string) bool {
	if c.lastCatchup == nil {
		c.lastCatchup = map[string]string{}
	}
	// The day stamp comes from the clock seam so a pinned now really
	// pins "today" — tests call capped() on a literally-built struct.
	return c.lastCatchup[key] == c.now.Now().UTC().Format("2006-01-02")
}

// spawn clones the CronJob's JobTemplate into a <cj>-catchup-<unix>
// Job in the CronJob's own namespace — the kubectl create job
// --from=cronjob equivalent (labels/annotations cloned, spec
// DeepCopy'd, cronjob.kubernetes.io/instantiate: manual stamped),
// plus the missed-catchup label that powers dedupe. A create failure
// is metered+logged but does not abort the sweep or arm the daily
// cap — the next tick retries. Reports whether the Job was created.
func (c *cronJobCatchup) spawn(ctx context.Context, log logr.Logger, cj *batchv1.CronJob, key string) bool {
	// One read of the clock seam feeds both the Job-name suffix and
	// the daily-cap stamp — a pinned now (tests) must pin both,
	// and on a real clock the two can never straddle midnight.
	now := c.now.Now()
	labels := maps.Clone(cj.Spec.JobTemplate.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[catchupLabel] = cj.Name
	annotations := maps.Clone(cj.Spec.JobTemplate.Annotations)
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["cronjob.kubernetes.io/instantiate"] = "manual"
	// DNS-1123 subdomain caps the Job name at 63 chars but a CronJob
	// name can reach 52 — a naive "<cj>-catchup-<unix>" overflows and
	// Create fails Invalid forever. Truncate the CronJob-name portion
	// so the always-meaningful suffix fits, and drop trailing
	// separators so the name still ends alphanumeric.
	suffix := fmt.Sprintf("-catchup-%d", now.Unix())
	name := cj.Name
	if max := catchupJobNameMax - len(suffix); len(name) > max {
		name = strings.TrimRight(name[:max], "-.")
	}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name + suffix,
			Namespace:   cj.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: *cj.Spec.JobTemplate.Spec.DeepCopy(),
	}
	if _, err := c.cs.BatchV1().Jobs(cj.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "create catch-up job failed",
			"cronjob", cj.Namespace+"/"+cj.Name, "job", job.Name)
		return false
	}
	c.lastCatchup[key] = now.UTC().Format("2006-01-02")
	log.Info("CATCHUP job", "job", job.Name,
		"cronjob", cj.Namespace+"/"+cj.Name,
		"lastSchedule", cj.Status.LastScheduleTime)
	return true
}

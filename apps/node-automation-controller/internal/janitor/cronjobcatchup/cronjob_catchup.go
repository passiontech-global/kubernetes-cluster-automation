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
// node-ops.passiontech.dev/catchup: "true" — most jobs are not
// idempotent across a multi-day backlog (report generators, backup
// pruners), so silence means leave it alone.
//
// Dedupe (belt & suspenders, any one vetoes):
//   - a Job in the namespace labeled
//     node-ops.passiontech.dev/missed-catchup=<cj> younger than 24h
//   - any Active Job still owned by the CronJob
//   - an in-memory 1-catchup-per-cronjob-per-day cap (survives the
//     catch-up Job being deleted)
package cronjobcatchup

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/robfig/cron/v3"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	catchupQueue = "cronjob-catchup"
	// catchupAnno is the opt-in annotation — a backlog replay is only
	// safe for jobs whose side effects are idempotent.
	catchupAnno = "node-ops.passiontech.dev/catchup"
	// catchupLabel marks Jobs this module created (dedupe).
	catchupLabel = "node-ops.passiontech.dev/missed-catchup"
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
)

type cronJobCatchup struct {
	cs kubernetes.Interface
	// nowFn is the clock seam — tests pin it so schedule-relative
	// staleness is deterministic. nil → time.Now.
	nowFn func() time.Time
	// lastCatchup enforces the 1-per-cronjob-per-day cap in memory —
	// keyed "ns/name" -> "2006-01-02" (UTC), pruned each sweep for
	// CronJobs that vanished. An apiserver-restart-clean map only
	// ever re-arms early, and the Job label dedupe still guards the
	// 24h window across restarts.
	mu          sync.Mutex
	lastCatchup map[string]string
}

// Setup registers the 15-minute sweep.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface) error {
	c := &cronJobCatchup{cs: cs, nowFn: time.Now, lastCatchup: map[string]string{}}
	return shared.AddPeriodic(mgr, catchupQueue, 15*time.Minute, c.run)
}

func (c *cronJobCatchup) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazily arm the zero-value struct — unit tests construct the
	// module literally without the Setup path.
	if c.nowFn == nil {
		c.nowFn = time.Now
	}

	cronjobs, err := c.cs.BatchV1().CronJobs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list cronjobs: %w", err) // periodic wrapper IncErrors catchupQueue
	}

	spawned := 0
	for i := range cronjobs.Items {
		cj := &cronjobs.Items[i]
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			continue // deliberately paused — honor the operator's intent
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
		if c.deduped(ctx, log, cj) {
			continue
		}
		if c.spawn(ctx, log, cj, key) {
			spawned++
		}
	}
	// Drop daily-cap entries for CronJobs that no longer exist — the
	// map is otherwise append-only per opted-in job ever caught up.
	present := map[string]struct{}{}
	for i := range cronjobs.Items {
		cj := &cronjobs.Items[i]
		present[cj.Namespace+"/"+cj.Name] = struct{}{}
	}
	c.mu.Lock()
	for key := range c.lastCatchup {
		if _, ok := present[key]; !ok {
			delete(c.lastCatchup, key)
		}
	}
	c.mu.Unlock()
	log.Info("sweep done", "spawned", spawned)
	return nil
}

// stale parses the schedule — honoring spec.timeZone via the
// CRON_TZ= prefix the parser understands — and decides whether the
// CronJob genuinely missed a run: the first scheduled tick strictly
// AFTER lastScheduleTime lying in the past beyond its grace bound.
// A nil lastScheduleTime means the CronJob NEVER scheduled (or
// status was wiped) — the creation timestamp anchors the same
// missed-tick math, so a brand-new job whose first tick is still in
// the future is NOT stale (the old code treated nil as stale
// unconditionally: a fresh opted-in job got an immediate replay and
// kept re-firing daily until its first real tick landed, because
// lastScheduleTime stays nil that whole time). ok=false reports an
// unparseable schedule.
func (c *cronJobCatchup) stale(log logr.Logger, cj *batchv1.CronJob) (bool, bool) {
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
	now := c.nowFn()
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

// deduped reports whether a catch-up for cj is already covered:
// either a <24h-old Job carrying the missed-catchup label, or any
// Active Job still owned by the CronJob (a scheduled run in flight —
// replaying on top of it double-fires the workload).
func (c *cronJobCatchup) deduped(ctx context.Context, log logr.Logger, cj *batchv1.CronJob) bool {
	jobs, err := c.cs.BatchV1().Jobs(cj.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		// List failure = empty dedupe list, still create — a missed
		// catch-up is worse than one extra idempotent Job.
		metrics.IncError(catchupQueue)
		log.Info("WARN: list jobs failed — skipping dedupe",
			"cronjob", cj.Namespace+"/"+cj.Name, "error", err)
		return false
	}
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if j.Labels[catchupLabel] == cj.Name &&
			time.Since(j.CreationTimestamp.Time) < catchupDedupeAge {
			log.Info("skip: a catch-up job already exists",
				"cronjob", cj.Namespace+"/"+cj.Name, "job", j.Name)
			return true
		}
		if j.Status.Active > 0 {
			if owner := metav1.GetControllerOf(j); owner != nil &&
				owner.Kind == "CronJob" && owner.Name == cj.Name {
				log.Info("skip: a scheduled job is still active",
					"cronjob", cj.Namespace+"/"+cj.Name, "job", j.Name)
				return true
			}
		}
	}
	return false
}

// capped enforces the in-memory 1-catchup-per-cronjob-per-day limit.
func (c *cronJobCatchup) capped(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastCatchup == nil {
		c.lastCatchup = map[string]string{}
	}
	// Same lazy arm as run() — tests call capped() on a zero-value
	// struct, and the day stamp must come from the clock seam so a
	// pinned nowFn really pins "today".
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	return c.lastCatchup[key] == c.nowFn().UTC().Format("2006-01-02")
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
	// the daily-cap stamp — a pinned nowFn (tests) must pin both,
	// and on a real clock the two can never straddle midnight.
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	now := c.nowFn()
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
		metrics.IncError(catchupQueue)
		log.Error(err, "create catch-up job failed",
			"cronjob", cj.Namespace+"/"+cj.Name, "job", job.Name)
		return false
	}
	c.mu.Lock()
	c.lastCatchup[key] = now.UTC().Format("2006-01-02")
	c.mu.Unlock()
	log.Info("CATCHUP job", "job", job.Name,
		"cronjob", cj.Namespace+"/"+cj.Name,
		"lastSchedule", cj.Status.LastScheduleTime)
	return true
}

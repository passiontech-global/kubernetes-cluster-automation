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
package controller

import (
	"context"
	"fmt"
	"maps"
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
	// catchupMinStaleGrace: a CronJob is stale when lastScheduleTime is
	// older than max(2*period, period+30m). The +30m floor keeps a
	// */5-minute job from being flagged during a routine apiserver
	// blip — one missed tick is normal controller behavior.
	catchupMinStaleGrace = 30 * time.Minute
)

type cronJobCatchup struct {
	cs kubernetes.Interface
	// lastCatchup enforces the 1-per-cronjob-per-day cap in memory —
	// keyed "ns/name" -> "2006-01-02" (UTC), pruned each sweep for
	// CronJobs that vanished. An apiserver-restart-clean map only
	// ever re-arms early, and the Job label dedupe still guards the
	// 24h window across restarts.
	mu          sync.Mutex
	lastCatchup map[string]string
}

// SetupCronJobCatchup registers the 15-minute sweep.
func SetupCronJobCatchup(mgr ctrl.Manager, cs kubernetes.Interface) error {
	c := &cronJobCatchup{cs: cs, lastCatchup: map[string]string{}}
	return addPeriodic(mgr, catchupQueue, 15*time.Minute, c.run)
}

func (c *cronJobCatchup) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	cronjobs, err := c.cs.BatchV1().CronJobs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err // periodic wrapper IncErrors catchupQueue
	}

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
		c.spawn(ctx, log, cj, key)
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
	log.Info("sweep done")
	return nil
}

// stale parses the schedule and decides whether lastScheduleTime is
// older than max(2*period, period+30m). A nil lastScheduleTime means
// the CronJob NEVER scheduled (or status was wiped) — that is stale
// by definition. ok=false reports an unparseable schedule.
func (c *cronJobCatchup) stale(log logr.Logger, cj *batchv1.CronJob) (bool, bool) {
	sched, err := cron.ParseStandard(cj.Spec.Schedule)
	if err != nil {
		log.Info("WARN: unparseable schedule — skip",
			"cronjob", cj.Namespace+"/"+cj.Name,
			"schedule", cj.Spec.Schedule, "error", err)
		return false, false
	}
	if cj.Status.LastScheduleTime == nil {
		return true, true
	}
	// Derive the period from two successive ticks — works for any
	// cron expression the parser accepts (@daily, */5, ranges, ...).
	next := sched.Next(time.Now())
	period := sched.Next(next).Sub(next)
	threshold := period + catchupMinStaleGrace
	if 2*period > threshold {
		threshold = 2 * period
	}
	return time.Since(cj.Status.LastScheduleTime.Time) > threshold, true
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
	return c.lastCatchup[key] == time.Now().UTC().Format("2006-01-02")
}

// spawn clones the CronJob's JobTemplate into a <cj>-catchup-<unix>
// Job in the CronJob's own namespace — the kubectl create job
// --from=cronjob equivalent (labels/annotations cloned, spec
// DeepCopy'd, cronjob.kubernetes.io/instantiate: manual stamped),
// plus the missed-catchup label that powers dedupe. A create failure
// is metered+logged but does not abort the sweep or arm the daily
// cap — the next tick retries.
func (c *cronJobCatchup) spawn(ctx context.Context, log logr.Logger, cj *batchv1.CronJob, key string) {
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
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("%s-catchup-%d", cj.Name, time.Now().Unix()),
			Namespace:   cj.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: *cj.Spec.JobTemplate.Spec.DeepCopy(),
	}
	if _, err := c.cs.BatchV1().Jobs(cj.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		metrics.IncError(catchupQueue)
		log.Error(err, "ERR: create catch-up job failed",
			"cronjob", cj.Namespace+"/"+cj.Name)
		return
	}
	c.mu.Lock()
	c.lastCatchup[key] = time.Now().UTC().Format("2006-01-02")
	c.mu.Unlock()
	log.Info("CATCHUP job", "job", job.Name,
		"cronjob", cj.Namespace+"/"+cj.Name,
		"lastSchedule", cj.Status.LastScheduleTime)
}

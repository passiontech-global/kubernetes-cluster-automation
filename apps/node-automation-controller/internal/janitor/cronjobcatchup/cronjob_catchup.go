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
//
// File layout: this file holds the module contract, the janitor
// struct, Setup and the run sweep pipeline; cronjob_catchup_schedule.go
// the schedule parsing + staleness math and the >100-missed-ticks
// detector, cronjob_catchup_unfreeze.go the startingDeadlineSeconds
// patch, cronjob_catchup_dedupe.go the Job dedupe index and
// verdicts, cronjob_catchup_spawn.go the catch-up Job creation and
// the daily cap.
package cronjobcatchup

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

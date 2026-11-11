// cronjob-catchup schedule math: parse a CronJob's effective schedule
// and decide whether it genuinely missed a run.
// split from cronjob_catchup.go (see its header for the module contract).
package cronjobcatchup

import (
	"time"

	"github.com/go-logr/logr"
	"github.com/robfig/cron/v3"
	batchv1 "k8s.io/api/batch/v1"
)

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

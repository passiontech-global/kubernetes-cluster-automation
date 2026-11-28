// cronjob_forbid_zombie.go — the cronjob-forbid-zombie check: frees
// concurrencyPolicy=Forbid CronJobs whose Status.Active slot is held
// by a Job that can never finish, and surfaces Jobs running far past
// any sane schedule interval.
//
// Forbid means "skip this schedule while a Job is active" — enforced
// by the cronjob-controller reading status.active. Two failure modes
// pin that slot forever:
//
//   - zombie active refs: the Job was deleted out from under the
//     controller, already reached Complete/Failed, or every pod it
//     owns is terminal / gone / sitting on a node that no longer
//     exists — status.active still lists it, so every subsequent
//     schedule is silently skipped;
//   - runaway active Jobs: a Job whose pods hang (missing
//     activeDeadlineSeconds is the classic cause — the Job controller
//     never times it out) runs for days while the CronJob never fires
//     again.
//
// Zombie refs heal automatically once the evidence holds >= 15m
// (FirstSeenLedger — a Job mid-teardown or a pod-list flap re-arms):
// the check deletes the Job object with UIDDeleteOptions +
// Background propagation, which drops it from status.active and
// unblocks the schedule.
//
// Runaway Jobs ALWAYS emit
// node_automation_cronjob_forbid_stalled{namespace,cronjob,reason};
// the kill half is opt-in per CronJob via
// kube.AnnoCronJobMaxActiveDuration ("4h") or cluster-wide via
// NODE_AUTOMATION_CRONJOB_FORBID_KILL_RUNAWAY=true — an unbounded
// Job on a Forbid schedule is almost always a bug, but killing
// user workloads sight-unseen is not the default.
package watchdogs

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/robfig/cron/v3"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameCronJobForbidZombie is the kuberhealthy_check label
	// and the check's registry Name.
	CheckNameCronJobForbidZombie = "cronjob-forbid-zombie"

	// cjZombieMinAge is the continuous-zombie-evidence window before
	// the Job delete fires.
	cjZombieMinAge = 15 * time.Minute
	// cjRunawayFloor is the minimum runaway threshold — even a
	// minutely schedule gets at least 6h of runtime before the
	// stalled gauge fires.
	cjRunawayFloor = 6 * time.Hour
	// cjRunawayScheduleFactor multiplies the parsed schedule
	// interval for schedules tighter than the floor.
	cjRunawayScheduleFactor = 10
	// cjForbidHealCooldown bounds Job deletes per CronJob.
	cjForbidHealCooldown = 30 * time.Minute

	// stalled reason label values.
	cjStallZombie  = "zombie_active"
	cjStallRunaway = "runaway_active"
)

// cjForbidZombieCheck detects and clears Forbid-CronJob deadlocks.
type cjForbidZombieCheck struct {
	*probefw.Deps

	// killRunaway enables the runaway-Job kill without the per-CronJob
	// annotation (NODE_AUTOMATION_CRONJOB_FORBID_KILL_RUNAWAY,
	// default off — resolved once at construction).
	killRunaway bool

	// zombieSeen tracks "<ns>/<cj>/<job>" first sightings for the
	// 15m zombie window; pruned each complete sweep.
	zombieSeen state.FirstSeenLedger
	// stallEmitted is the gauge ledger for the stalled series.
	stallEmitted state.GaugeLedger[string]
}

// NewCronJobForbidZombieCheck builds the check.
func NewCronJobForbidZombieCheck(d *probefw.Deps) probefw.Check {
	return &cjForbidZombieCheck{
		Deps:        d,
		killRunaway: envx.Gate("NODE_AUTOMATION_CRONJOB_FORBID_KILL_RUNAWAY", false),
	}
}

var (
	// node_automation_cronjob_forbid_stalled — 1 per Forbid CronJob
	// whose active Job is a zombie ref or a runaway.
	cjForbidStalledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cronjob_forbid_stalled",
		Help: "1 while a concurrencyPolicy=Forbid CronJob's active Job is a zombie reference or has run past its max-active threshold — cronjob-forbid-zombie.",
	}, []string{"namespace", "cronjob", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(cjForbidStalledGauge)
}

// Run sweeps Forbid CronJobs for zombie active refs and runaway Jobs.
func (p *cjForbidZombieCheck) Run(ctx context.Context) probefw.Result {
	p.stallEmitted.Begin()
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport

	cjList, err := p.AllCronJobs(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("cronjob forbid zombie: ", "; ")
	}
	jobList, err := p.AllJobs(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("cronjob forbid zombie: ", "; ")
	}
	podList, err := p.AllPods(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("cronjob forbid zombie: ", "; ")
	}
	nodeList, err := p.AllNodes(ctx)
	if err != nil {
		rep.InfraErr(err)
		return rep.Verdict("cronjob forbid zombie: ", "; ")
	}

	liveNodes := map[string]bool{}
	for i := range nodeList {
		liveNodes[nodeList[i].Name] = true
	}
	jobsByKey := map[string]*batchv1.Job{}
	for i := range jobList {
		jobsByKey[jobList[i].Namespace+"/"+jobList[i].Name] = &jobList[i]
	}
	// Pods owned by each Job (controller ref Kind=Job).
	podsByJob := map[string][]*corev1.Pod{}
	for i := range podList {
		pod := &podList[i]
		ref := metav1.GetControllerOf(pod)
		if ref == nil || ref.Kind != "Job" || ref.Name == "" {
			continue
		}
		key := pod.Namespace + "/" + ref.Name
		podsByJob[key] = append(podsByJob[key], pod)
	}

	seen := map[string]bool{}
	for i := range cjList {
		cj := &cjList[i]
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			continue
		}
		if cj.Spec.ConcurrencyPolicy != batchv1.ForbidConcurrent ||
			len(cj.Status.Active) == 0 {
			continue
		}
		for _, ref := range cj.Status.Active {
			if ref.Name == "" {
				continue
			}
			p.sweepActiveJob(ctx, log, now, &rep, cj, ref,
				jobsByKey, podsByJob, liveNodes, seen)
		}
	}

	p.zombieSeen.Prune(func(key string) bool { return seen[key] })
	rep.Close(&p.stallEmitted, cjForbidStalledGauge.DeleteLabelValues)
	return rep.Verdict("cronjob forbid zombie: ", "; ")
}

// sweepActiveJob evaluates one status.active entry: zombie evidence
// first (auto-heal), then the runaway threshold (gauge always, kill
// opt-in).
func (p *cjForbidZombieCheck) sweepActiveJob(ctx context.Context,
	log logr.Logger, now time.Time, rep *probefw.SweepReport,
	cj *batchv1.CronJob, ref corev1.ObjectReference,
	jobsByKey map[string]*batchv1.Job,
	podsByJob map[string][]*corev1.Pod,
	liveNodes map[string]bool, seen map[string]bool) {

	jobName := ref.Name
	jobKey := cj.Namespace + "/" + jobName
	job := jobsByKey[jobKey]
	// Annotation opt-ins are sweep-overlay-aware: a stamp landed
	// earlier in this same sweep must be visible, not the frozen
	// snapshot copy of the CronJob.
	annos := kube.EffectiveAnnos(ctx, cj)
	if job != nil && ref.UID != "" && job.UID != ref.UID {
		// Same-named Job has a different UID: the active ref points to a
		// deleted prior Job instance, never delete the new live Job.
		job = nil
	}

	// --- zombie branch -------------------------------------------------
	// Evidence: the Job object is gone from the census, already
	// Complete/Failed, or every owned pod is terminal / deleted /
	// parked on a vanished node.
	zombie := false
	switch {
	case job == nil:
		zombie = true // status.active outran the object itself
	case jobFinished(job):
		zombie = true
	default:
		pods := podsByJob[jobKey]
		zombie = len(pods) > 0 && jobPodsAllGone(pods, liveNodes)
	}
	if zombie {
		zKey := cj.Namespace + "/" + cj.Name + "/" + jobName
		first, tracked := p.zombieSeen.Observe(zKey, now)
		seen[zKey] = true
		if tracked && now.Sub(first) >= cjZombieMinAge {
			rep.Set(cjForbidStalledGauge, 1,
				cj.Namespace+"/"+cj.Name+"/"+cjStallZombie,
				[]string{cj.Namespace, cj.Name, cjStallZombie})
			rep.Find("cronjob " + cj.Namespace + "/" + cj.Name +
				" active job " + jobName + " is a zombie")
			p.maybeClearActiveRef(ctx, log, now, rep, cj, ref, job)
		}
		return // a zombie ref is not also a runaway — one verdict
	}

	// --- runaway branch -----------------------------------------------
	if job == nil {
		return // nothing to age — the zombie branch covers the gone case
	}
	age := jobRuntimeAge(job, now)
	// The opt-in annotation is read through the sweep overlay — a
	// cooldown/opt-out stamp landed earlier in this same sweep must
	// be visible here instead of the frozen snapshot copy.
	limit := cjRunawayLimit(cj, annos, now)
	if age < limit {
		return
	}
	reason := cjStallRunaway
	rep.Set(cjForbidStalledGauge, 1, cj.Namespace+"/"+cj.Name+"/"+reason,
		[]string{cj.Namespace, cj.Name, reason})
	rep.Find("cronjob " + cj.Namespace + "/" + cj.Name +
		" active job " + jobName + " running " + age.Truncate(time.Minute).String())

	// Kill requires the per-CronJob annotation OR the cluster-wide
	// env opt-in; the annotation always wins over the env default.
	// The annotation must PARSE to a positive duration — a typo'd
	// value must not engage the kill (cjRunawayLimit documents the
	// same rule for the threshold side).
	annoKill := false
	if d, err := time.ParseDuration(
		annos[kube.AnnoCronJobMaxActiveDuration]); err == nil && d > 0 {
		annoKill = true
	}
	if !annoKill && !p.killRunaway {
		return
	}
	p.deleteStalledJob(ctx, log, now, rep, cj, job)
}

// jobFinished reports whether the Job reached a terminal condition.
func jobFinished(job *batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) &&
			c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// jobPodsAllGone reports whether every pod the Job owns is terminal
// (Succeeded/Failed), already deleting, or parked on a node missing
// from the live census — nothing left that could ever finish the
// Job. A Job with zero listed pods is NOT zombie evidence (the pod
// list may just be filtered) — callers require len(pods) > 0.
func jobPodsAllGone(pods []*corev1.Pod, liveNodes map[string]bool) bool {
	for _, pod := range pods {
		if pod.DeletionTimestamp == nil &&
			pod.Status.Phase != corev1.PodSucceeded &&
			pod.Status.Phase != corev1.PodFailed {
			if pod.Spec.NodeName == "" || liveNodes[pod.Spec.NodeName] {
				return false // a live pod on a live node can still finish
			}
		}
	}
	return true
}

// jobRuntimeAge is how long the Job has been running — StartTime
// when the controller stamped it, CreationTimestamp otherwise.
func jobRuntimeAge(job *batchv1.Job, now time.Time) time.Duration {
	start := job.CreationTimestamp.Time
	if job.Status.StartTime != nil && !job.Status.StartTime.IsZero() {
		start = job.Status.StartTime.Time
	}
	return now.Sub(start)
}

// cjRunawayLimit resolves the runaway threshold: the
// AnnoCronJobMaxActiveDuration value when present and parseable,
// otherwise max(6h, 10 × schedule interval). An unparseable
// annotation or schedule falls back to the 6h floor — the gauge
// still fires, the opt-in kill simply never engages on a typo.
func cjRunawayLimit(cj *batchv1.CronJob, annos map[string]string, now time.Time) time.Duration {
	floor := cjRunawayFloor
	if d, err := time.ParseDuration(annos[kube.AnnoCronJobMaxActiveDuration]); err == nil && d > 0 {
		return d
	}
	if sched, err := cron.ParseStandard(cj.Spec.Schedule); err == nil {
		next := sched.Next(now)
		if !next.IsZero() {
			after := sched.Next(next)
			if interval := after.Sub(next); interval > 0 {
				if limit := cjRunawayScheduleFactor * interval; limit > floor {
					return limit
				}
			}
		}
	}
	return floor
}

// maybeClearActiveRef is the zombie branch's actuation: when the Job
// object still exists it is deleted (Background propagation drops it
// from status.active); when the Job is already gone from the census
// the stale status.active ref itself is removed via UpdateStatus —
// otherwise the ghost ref pins the Forbid slot forever with nothing
// left to delete. Both paths share the cluster-wide-only heal gate
// and the per-CronJob cooldown.
func (p *cjForbidZombieCheck) maybeClearActiveRef(ctx context.Context,
	log logr.Logger, now time.Time, rep *probefw.SweepReport,
	cj *batchv1.CronJob, target corev1.ObjectReference, job *batchv1.Job) {

	if job == nil {
		p.clearGhostActiveRef(ctx, log, now, rep, cj, target)
		return
	}
	p.deleteStalledJob(ctx, log, now, rep, cj, job)
}

func (p *cjForbidZombieCheck) clearGhostActiveRef(ctx context.Context,
	log logr.Logger, now time.Time, rep *probefw.SweepReport,
	cj *batchv1.CronJob, target corev1.ObjectReference) {

	jobName := target.Name
	key := cj.Namespace + "/" + cj.Name
	healKey := probefw.SelfHealKey(CheckNameCronJobForbidZombie, key+"/active-ref")
	if p.Heals.CooledDown(healKey, cjForbidHealCooldown, now) {
		return
	}
	proceed, unverifiable := p.HealAllowedUpgradeOnly(ctx, log,
		healKey, now)
	switch {
	case unverifiable:
		metrics.IncError(p.Name)
		return
	case !proceed:
		return
	}
	// Re-verify the target Job instance (matching UID when set) is still absent.
	if liveJob, err := p.CS.BatchV1().Jobs(cj.Namespace).Get(ctx, jobName,
		metav1.GetOptions{}); err == nil {
		if target.UID == "" || liveJob.UID == target.UID {
			return // not a ghost anymore — same Job instance still lives
		}
	} else if !apierrors.IsNotFound(err) {
		if apierrors.IsForbidden(err) {
			log.Info("WARN: cronjob forbid zombie job re-check forbidden (RBAC)",
				"cronjob", key, "job", jobName)
			return
		}
		metrics.IncError(p.Name)
		log.Error(err, "cronjob forbid zombie: job re-check failed",
			"cronjob", key, "job", jobName)
		return
	}
	// Re-read the live CronJob — only drop the ref if matching UID/name is still present.
	live, err := p.CS.BatchV1().CronJobs(cj.Namespace).Get(ctx, cj.Name,
		metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
			return
		}
		metrics.IncError(p.Name)
		log.Error(err, "cronjob forbid zombie: get for status clear failed",
			"cronjob", key)
		return
	}
	kept := live.Status.Active[:0]
	removed := false
	for _, ref := range live.Status.Active {
		match := ref.Name == jobName && (target.UID == "" || ref.UID == "" || ref.UID == target.UID)
		if match {
			removed = true
			continue
		}
		kept = append(kept, ref)
	}
	if !removed {
		return // another actor already cleared it — nothing to do
	}
	live.Status.Active = kept
	if _, err := p.CS.BatchV1().CronJobs(cj.Namespace).UpdateStatus(
		ctx, live, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsForbidden(err) {
			// RBAC is a stable condition — stamp the cooldown so we
			// stop retrying the doomed write every sweep. The audit
			// finding (gauge + FAIL) was already emitted above; this
			// is a tolerated sub-failure, never an aborted audit.
			p.Heals.Stamp(healKey, now)
			log.Info("WARN: cronjob forbid zombie status.active clear forbidden (RBAC) — cooldown stamped",
				"cronjob", key, "job", jobName, "error", err)
			return
		}
		if apierrors.IsConflict(err) {
			log.Info("WARN: cronjob forbid zombie status.active clear deferred (conflict)",
				"cronjob", key, "job", jobName, "error", err)
			return
		}
		metrics.IncError(p.Name)
		log.Error(err, "cronjob forbid zombie: status.active clear failed",
			"cronjob", key, "job", jobName)
		return
	}
	p.Heals.Stamp(healKey, now)
	p.InvalidateCronJobs(ctx)
	rep.Find("healed: cleared ghost active ref " + jobName + " on " + key)
	log.Info("ACTION: cleared ghost status.active ref on Forbid CronJob",
		"cronjob", key, "job", jobName)
}

func (p *cjForbidZombieCheck) deleteStalledJob(ctx context.Context,
	log logr.Logger, now time.Time, rep *probefw.SweepReport,
	cj *batchv1.CronJob, job *batchv1.Job) {

	// A status.active ref names a Job by NAME, not by identity. A
	// same-named Job that is not controlled by THIS CronJob (a later
	// instance from another owner, or a hand-rolled Job with no
	// controller at all) must never be deleted just to free the Forbid
	// slot — that would kill somebody else's workload. Check the
	// controller UID BEFORE the heal gate so no grant is spent.
	if owner := metav1.GetControllerOf(job); owner == nil || owner.UID != cj.UID {
		log.Info("WARN: cronjob forbid zombie job not controlled by this cronjob — skip delete",
			"cronjob", cj.Namespace+"/"+cj.Name,
			"job", job.Namespace+"/"+job.Name)
		return
	}
	key := cj.Namespace + "/" + cj.Name
	healKey := probefw.SelfHealKey(CheckNameCronJobForbidZombie, key)
	proceed, unverifiable := p.HealAllowedClusterWideOnly(ctx, log, &p.Heals,
		healKey, cjForbidHealCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(p.Name)
		return
	case !proceed:
		return
	}
	prop := metav1.DeletePropagationBackground
	err := p.CS.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name,
		kube.UIDDeleteOptions(job.UID, prop))
	switch {
	case apierrors.IsNotFound(err) || apierrors.IsConflict(err):
		heal.RefundGrant(now) // nothing executed — hand the grant back
		return
	case apierrors.IsForbidden(err):
		heal.RefundGrant(now)
		log.Info("WARN: cronjob forbid zombie job delete forbidden (RBAC)",
			"cronjob", key, "job", job.Namespace+"/"+job.Name)
		return
	case err != nil:
		metrics.IncError(p.Name)
		log.Error(err, "cronjob forbid zombie job delete failed",
			"cronjob", key, "job", job.Namespace+"/"+job.Name)
		return
	}
	p.Heals.Stamp(healKey, now)
	p.InvalidateJobs(ctx)
	rep.Find("healed: deleted stalled job " + job.Namespace + "/" +
		job.Name + " on " + key)
	log.Info("ACTION: deleted stalled Job to unblock Forbid CronJob",
		"cronjob", key, "job", job.Namespace+"/"+job.Name)
}

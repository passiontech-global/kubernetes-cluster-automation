// helm_stall_unwedge.go — the stalled-rollout surge-deadlock
// signature of helmrelease-unlocker (opt-in via
// HELM_STALL_UNWEDGE_ENABLED). Sibling to the pending-secret unlock
// in helmrelease_unlocker.go: same HR list, same 30m first-seen
// window, same helm-controller-health gate, same 24h cooldown shape
// (own ledger + passiontech.dev/last-helm-stall-unwedge stamp so the two
// remediations never refund each other).
//
// The wedge (observed 2026-11-04, HelmRelease 1password/connect on
// passiontech-k0s-cicd): a chart bump flipped a Deployment's
// podAntiAffinity from required to preferred and helm retried the
// upgrade — but the OLD ReplicaSet's pods still carry
// requiredDuringSchedulingIgnoredDuringExecution anti-affinity, so
// every schedulable node rejects the new surge pod ("didn't satisfy
// existing pods anti-affinity rules"). With replicas=2 on a 2-node
// cluster the rollout can never make progress: Deployment hits
// ProgressDeadlineExceeded, helm aborts ("failed early due to stalled
// resources"), the remediation rollback succeeds but the next attempt
// deadlocks identically, and after spec.upgrade.remediation.retries
// the HR goes terminal: Stalled=True reason=RetriesExceeded. From
// there `flux reconcile` alone does NOT retry — the controller sees
// no drift and keeps the stale condition; the counter must be reset.
//
// Detection (signature-precise, two layers):
//  1. HR layer: non-suspended HR with a Stalled=True condition OR
//     Ready=False whose message carries the helm stalled-rollout
//     fragment ("stalled resources"/"failed early"), held >30m by the
//     first-seen ledger — a live upgrade legitimately shows the
//     message for minutes while helm waits.
//  2. Workload layer (the shape that makes scaling safe): the named
//     Deployment (parsed from "Deployment/<name>" in the condition
//     message, else the single ProgressDeadlineExceeded Deployment in
//     the release namespace) must have replicas>=2, effective
//     maxUnavailable==0 (the semantic that keeps the old RS pinned
//     up), a new ReplicaSet with unscheduled pods whose PodScheduled=
//     False message mentions anti-affinity, AND old-ReplicaSet pods
//     whose template declares REQUIRED podAntiAffinity terms matching
//     the new pod labels occupying every distinct node the scheduler
//     complained about. Anything else (image pull, quota, plain PDE)
//     is refused — logged and IncError'd once per cooldown window for
//     visibility, never acted on.
//
// Action: scale the OLD ReplicaSet down by the minimum that provably
// frees one node (n blocking pods on d distinct nodes needs n-d+1
// removals — arbitrary survivors still leave at least one node
// pod-free), then merge-patch the HR with
// reconcile.fluxcd.io/{requestedAt,resetAt,forceAt} all set to the
// same token. resetAt zeroes the install/upgrade failure counters —
// the documented way to clear Stalled/RetriesExceeded since
// helm-controller v0.37.0 (flux v2.2) without a suspend/resume cycle;
// forceAt makes the retried reconcile run an install/upgrade even
// when the controller would otherwise see no drift. On a pre-v0.37
// helm-controller the unknown annotations are ignored and only the
// requestedAt nudge lands — a graceful no-op, never a harm.
//
// Guards beyond the shared ones (CrashLoopBackOff, 24h cooldown,
// re-stall → alert):
//   - never touches pods directly and never scales to zero unless
//     that is what the free-one-node math requires — only the
//     minimum ReplicaSet scale-down;
//   - refuses when the Deployment's availability floor would drop:
//     keptOld + min(removals, pendingNew) must stay >=
//     replicas - maxUnavailable;
//   - refuses when any PDB selecting the old pods reports
//     disruptionsAllowed < removals (an unparseable selector fails
//     CLOSED — treated as covering);
//   - refuses when pending new-RS pods are unschedulable for a
//     non-affinity reason or when old pods carry only PREFERRED
//     anti-affinity (preferred never hard-blocks scheduling).
//
// Idempotent + race-safe: the Deployment controller rescaling the old
// ReplicaSet back up is expected — the goal is only a scheduling
// window, and the next sweep re-verifies the whole shape instead of
// fighting the controller.
//
// Layout: this file holds the HR-layer signature, the cooldown /
// retry-cycle bookkeeping and the remediation entry point;
// stalled_deployment.go resolves the workload helm was waiting on,
// stall_plan.go verifies the surge-deadlock shape and computes the
// scale-down.
package helmreleaseunlocker

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// helmLastStallUnwedgeAnno persists the last unwedge moment on
	// the HR — the durable half of the 24h stall-unwedge cooldown,
	// deliberately a different key than passiontech.dev/last-helm-unlock.
	helmLastStallUnwedgeAnno = kube.AnnoLastHelmStallUnwedge
	// fluxResetAnno zeroes helm-controller's failure counters — the
	// documented escape from Stalled=True/RetriesExceeded
	// (helm-controller#823, >= v0.37.0). fluxForceAnno requests a
	// one-off install/upgrade even with no drift. Both are only
	// honored when reconcile.fluxcd.io/requestedAt carries the SAME
	// token value, so all three are stamped in one patch.
	fluxResetAnno = kube.AnnoFluxResetAt
	fluxForceAnno = kube.AnnoFluxForceAt
	// helm-stall-unwedge — the stall-unwedge retry cycle: max 2 attempts per
	// lastAttemptedRevision, each at least 6h apart.
	stallMaxAttemptsPerRevision = 2
	stallAttemptCooldown        = 6 * time.Hour
	// deployRevisionAnno orders ReplicaSets of one Deployment —
	// the newest revision is the surge side of the deadlock.
	deployRevisionAnno = "deployment.kubernetes.io/revision"
)

// stallRolloutMsgs are the helm waiter fragments an HR condition
// carries when an upgrade died on a stalled rollout — "failed early"
// is helm's own prefix for the same waiter abort.
var stallRolloutMsgs = []string{"stalled resources", "failed early"}

// stalledWorkloadRe extracts the stalled workload helm reports in
// "[Deployment/<name> status: 'Failed']" — the optional second group
// covers the "<ns>/<name>" variant.
var stalledWorkloadRe = regexp.MustCompile(
	`\bDeployment/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?:/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?))?`)

// hrStalledRollout is the HR-layer signature: a non-suspended HR
// either parked terminal (Stalled=True — RetriesExceeded parking)
// or Ready=False on the helm stalled-rollout message. The
// workload-layer check in deadlockPlan decides whether it is really
// the surge deadlock — this gate only decides who gets analyzed.
func hrStalledRollout(hr *unstructured.Unstructured) bool {
	if suspended, _ := kube.NestedBool(hr.Object, "spec", "suspend"); suspended {
		return false // parked, not broken — same rule as the artifact healer
	}
	if status, _, _ := hrCondition(hr, "Stalled"); status == "True" {
		return true
	}
	c, _ := kube.ConditionOf(hr.Object, "Ready")
	if c.Status != "False" {
		return false
	}
	lower := strings.ToLower(c.Message)
	for _, frag := range stallRolloutMsgs {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// hrCondition returns a named condition's status/reason/message —
// ("","","") when the condition is absent.
func hrCondition(o *unstructured.Unstructured, condType string) (status, reason, message string) {
	c, _ := kube.ConditionOf(o.Object, condType)
	return c.Status, c.Reason, c.Message
}

// unwedgeDue runs the stall-unwedge pass over the due HRs — cooldown
// check, deadlock analysis, scale-down, retry stamp — and returns how
// many HRs were actually unwedged.
func (u *helmReleaseUnlocker) unwedgeDue(ctx context.Context,
	gvr schema.GroupVersionResource, stalled map[string]*unstructured.Unstructured,
	due []string, now time.Time) int {
	log := logf.FromContext(ctx)
	unwedged := 0
	for _, key := range due {
		hr := stalled[key]
		// Wider of in-RAM ledger and persisted stamp — same cooldown
		// contract as the unlock path (restart must not refund 24h).
		// No ledger fold needed here: unlike the unlock ledger the
		// unwedged set is never pruned (stamps self-expire), so an
		// anno-only cooldown needs no in-RAM mirror.
		if heal.PersistedCooledDown(ctx, &u.stall.unwedged, hr, helmLastStallUnwedgeAnno,
			key, helmUnlockCooldown, now) {
			u.alertStallOnce(ctx, key, now,
				fmt.Sprintf("HR re-stalled inside the %s unwedge cooldown — previous unwedge did not fix it",
					helmUnlockCooldown))
			continue
		}
		// helm-stall-unwedge — cap the retry cycle: at most
		// stallMaxAttemptsPerRevision unwedges for one
		// lastAttemptedRevision, each at least
		// stallAttemptCooldown apart. A revision change re-arms —
		// the new revision has not had its window yet.
		revision, _ := kube.NestedString(
			hr.Object, "status", "lastAttemptedRevision")
		att := u.stall.attempts[key]
		if att == nil || att.revision != revision {
			att = &stallAttempt{revision: revision}
			u.stall.attempts[key] = att
		}
		if att.count >= stallMaxAttemptsPerRevision {
			u.alertStallOnce(ctx, key, now, fmt.Sprintf(
				"HR revision %q already consumed %d unwedge attempts — refusing to retry-loop",
				revision, att.count))
			continue
		}
		if att.count > 0 && now.Sub(att.last) < stallAttemptCooldown {
			continue // inside the 6h attempt gap — let the last unwedge land
		}
		// Read-only analysis BEFORE the gate: stalledDeployment +
		// deadlockPlan are pure LISTs/GETs, and running them first
		// means a stalled HR that is not the surge-deadlock shape
		// never spends a fleet heal grant on a heal that cannot
		// actuate — the grant is only worth buying once a plan
		// exists to execute.
		dep, plan, refuse, err := u.unwedgeAnalyze(ctx, hr)
		if err != nil {
			// Tolerated per-HR failure — absorbed like the
			// actuation error path below; IncError keeps it on
			// the alert path. The attempt budget is spared — an
			// API error is not a verdict on the signature.
			metrics.IncError(u.queue)
			log.Error(err, "helmrelease stall unwedge analysis failed", "hr", key)
			continue
		}
		if plan == nil {
			// Every non-error analysis outcome burns one of the
			// stallMaxAttemptsPerRevision tries: a clean no-op
			// (already-opened window) AND refusals — an
			// uncounted refusal would re-run the full
			// workload-layer analysis every sweep forever and
			// never reach the cap. No gate was consulted, so no
			// grant needs refunding.
			att.count++
			att.last = now
			if refuse != "" {
				u.alertStallOnce(ctx, key, now,
					"stalled HR is not the surge-deadlock shape — refusing to scale: "+refuse)
			}
			continue
		}
		// Fail-closed maintenance mutex — the scale-down below
		// removes live pods' ReplicaSet replicas: during a
		// cordon/drain/upgrade the unwedge would compound the
		// deliberate disruption. Gate AFTER the analysis so a
		// deferral burns neither the persisted cooldown nor one
		// of the per-revision attempts.
		proceed, unverifiable := heal.Gate(ctx, log, &u.verdict,
			u.cs, u.dyn, key, now)
		switch {
		case unverifiable:
			// Tolerated per-HR failure — absorbed like the
			// unwedge error path below; IncError keeps it on
			// the alert path.
			metrics.IncError(u.queue)
			continue
		case !proceed:
			continue
		}
		acted, err := u.unwedgeAct(ctx, gvr, hr, dep, plan)
		if err == nil {
			att.count++
			att.last = now
			if !acted {
				// The Gate grant above bought no heal — hand it
				// back (same contract as heal.EvictPodV's
				// PDB-429 refund). Errors keep the grant — an
				// attempted actuation that failed mid-patch is
				// the documented "spent a cheap token" case.
				heal.RefundGrant(now)
			}
		}
		switch {
		case err != nil:
			// Tolerated per-HR failure: absorbed (log + continue,
			// nil return) — IncError keeps it on the alert path.
			metrics.IncError(u.queue)
			log.Error(err, "helmrelease stall unwedge failed", "hr", key)
		case acted:
			u.stall.unwedged.Stamp(key, now)
			unwedged++
		}
	}
	return unwedged
}

// alertStallOnce fires the visibility page (IncError + warn log) for
// a refused/re-stalled HR at most once per cooldown window — a
// permanently refused signature would otherwise bump the error
// counter every 10-minute sweep.
func (u *helmReleaseUnlocker) alertStallOnce(ctx context.Context, key string, now time.Time, msg string) {
	if u.stall.alerted.CooledDown(key, helmUnlockCooldown, now) {
		return
	}
	metrics.IncError(u.queue)
	u.stall.alerted.Stamp(key, now)
	logf.FromContext(ctx).Info("ALERT: "+msg, "hr", key)
}

// unwedgeAnalyze is the READ-ONLY half of the unwedge: resolve the
// stalled Deployment, verify the surge-deadlock shape, and return
// the scale plan — or a refusal reason. Every refusal is a
// deliberate fail-closed: the HR stays stalled for a human rather
// than risk a wrong-target scale-down. It runs BEFORE heal.Gate so
// a non-deadlock HR never spends a fleet grant; only a non-nil
// plan reaches the gate and the actuation half.
func (u *helmReleaseUnlocker) unwedgeAnalyze(ctx context.Context,
	hr *unstructured.Unstructured) (*appsv1.Deployment, *stallPlan,
	string, error) {

	dep, refuse, err := u.stalledDeployment(ctx, hr)
	if err != nil || dep == nil {
		return nil, nil, refuse, err
	}
	plan, refuse, err := u.deadlockPlan(ctx, dep)
	if err != nil || plan == nil {
		return dep, nil, refuse, err
	}
	return dep, plan, "", nil
}

// unwedgeAct is the MUTATING half: scale the old ReplicaSet down by
// the minimum that provably frees a node, reap the failed hook Jobs,
// stamp the HR retry token. Runs only after heal.Gate granted — the
// caller owns cooldown/attempt accounting. acted=false + err=nil is
// unreachable today (a verified plan always actuates) but keeps the
// RefundGrant pairing honest if a future early-exit lands here.
func (u *helmReleaseUnlocker) unwedgeAct(ctx context.Context,
	gvr schema.GroupVersionResource, hr *unstructured.Unstructured,
	dep *appsv1.Deployment, plan *stallPlan) (bool, error) {
	log := logf.FromContext(ctx)
	key := hr.GetNamespace() + "/" + hr.GetName()

	// Scale the OLD ReplicaSet down by the minimum that provably
	// frees a node. The merge patch pins metadata.resourceVersion —
	// a Deployment-controller rescale between list and patch makes
	// this a conflict (retried next sweep) instead of a blind write.
	desired := plan.targetReplicas - int32(plan.remove)
	if desired < 0 {
		desired = 0 // unreachable: the plan refuses remove > targetReplicas
	}
	log.Info("ACTION: scale old ReplicaSet down to open a scheduling window",
		"hr", key, "rs", dep.Namespace+"/"+plan.target.Name,
		"from", plan.targetReplicas, "to", desired,
		"blockingPods", plan.blocking, "blockedNodes", plan.nodes,
		"pendingNew", plan.pending)
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"resourceVersion": plan.target.ResourceVersion},
		"spec":     map[string]any{"replicas": desired},
	})
	if err != nil {
		return false, err
	}
	if _, err := u.cs.AppsV1().ReplicaSets(dep.Namespace).Patch(ctx, plan.target.Name,
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return false, fmt.Errorf("scale down replicaset %s/%s: %w",
			dep.Namespace, plan.target.Name, err)
	}
	// The destructive half already landed — stamp the 24h cooldown
	// in RAM NOW, before the HR annotation patch: if that patch
	// fails, the next sweep must still see this HR inside its
	// cooldown window instead of re-planning a scale-down that
	// already happened (the persisted half lands with the HR patch
	// below; the RAM half cannot wait for it).
	u.stall.unwedged.Stamp(key, u.now.Now())

	// helm-stall-unwedge: the failed upgrade usually left a Failed helm-hook Job
	// behind in the release namespace — helm refuses to re-run a
	// hook while its Job object still exists, so the retry would
	// wedge identically. Reap it BEFORE the requestedAt cycle; the
	// sweep is best-effort and cannot undo the window we just opened.
	u.cleanFailedHookJobs(ctx, hrReleaseNS(hr), hrReleaseName(hr))

	// Then poke the HR: requestedAt is the reconcile-now hint,
	// resetAt (same token — required pairing) zeroes the failure
	// counters that keep Stalled=True/RetriesExceeded terminal, and
	// forceAt runs the upgrade even with no drift. Without the
	// reset token a stalled HR would consume the freed scheduling
	// window and stay parked.
	token := u.now.Now().UTC().Format(time.RFC3339)
	patch, err = kube.MergePatchAnnos(map[string]any{
		fluxReconcileAnno:        token,
		fluxResetAnno:            token,
		fluxForceAnno:            token,
		helmLastStallUnwedgeAnno: token,
	})
	if err != nil {
		return false, err
	}
	if _, err := u.dyn.Resource(gvr).Namespace(hr.GetNamespace()).Patch(ctx, hr.GetName(),
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return false, fmt.Errorf("annotate helmrelease %s: %w", key, err)
	}
	log.Info("ACTION: requested HR reconcile + failure-counter reset",
		"hr", key, "deployment", dep.Namespace+"/"+dep.Name)
	metrics.HelmStallUnwedgesTotal.
		WithLabelValues(dep.Namespace, dep.Name).Inc()
	return true, nil
}

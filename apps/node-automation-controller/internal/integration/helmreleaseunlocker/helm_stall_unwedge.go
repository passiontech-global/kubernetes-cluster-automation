// helm_stall_unwedge.go — the stalled-rollout surge-deadlock
// signature of helmrelease-unlocker (opt-in via
// HELM_STALL_UNWEDGE_ENABLED). Sibling to the pending-secret unlock
// in helmrelease_unlocker.go: same HR list, same 30m first-seen
// window, same helm-controller-health gate, same 24h cooldown shape
// (own ledger + node.ops/last-helm-stall-unwedge stamp so the two
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
package helmreleaseunlocker

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	// helmLastStallUnwedgeAnno persists the last unwedge moment on
	// the HR — the durable half of the 24h stall-unwedge cooldown,
	// deliberately a different key than node.ops/last-helm-unlock.
	helmLastStallUnwedgeAnno = "node.ops/last-helm-stall-unwedge"
	// fluxResetAnno zeroes helm-controller's failure counters — the
	// documented escape from Stalled=True/RetriesExceeded
	// (helm-controller#823, >= v0.37.0). fluxForceAnno requests a
	// one-off install/upgrade even with no drift. Both are only
	// honored when reconcile.fluxcd.io/requestedAt carries the SAME
	// token value, so all three are stamped in one patch.
	fluxResetAnno = "reconcile.fluxcd.io/resetAt"
	fluxForceAnno = "reconcile.fluxcd.io/forceAt"
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
	if suspended, _, _ := unstructured.NestedBool(hr.Object, "spec", "suspend"); suspended {
		return false // parked, not broken — same rule as the artifact healer
	}
	if status, _, _ := hrCondition(hr, "Stalled"); status == "True" {
		return true
	}
	status, msg := shared.ReadyCond(hr)
	if status != "False" {
		return false
	}
	lower := strings.ToLower(msg)
	for _, frag := range stallRolloutMsgs {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// hrCondition returns a named condition's status/reason/message —
// ReadyConds covers the whole list; ReadyCond only reads "Ready".
func hrCondition(o *unstructured.Unstructured, condType string) (status, reason, message string) {
	for _, c := range shared.ReadyConds(o) {
		if c["type"] != condType {
			continue
		}
		s, _ := c["status"].(string)
		r, _ := c["reason"].(string)
		m, _ := c["message"].(string)
		return s, r, m
	}
	return "", "", ""
}

// helmLastStallUnwedge reads the persisted node.ops/last-helm-stall-
// unwedge stamp — the restart-proof half of the unwedge cooldown.
func helmLastStallUnwedge(hr *unstructured.Unstructured) (time.Time, bool) {
	v := hr.GetAnnotations()[helmLastStallUnwedgeAnno]
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
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
		last, ok := u.unwedged[key]
		if t, hasAnno := helmLastStallUnwedge(hr); hasAnno && t.After(last) {
			last, ok = t, true
		}
		if ok && now.Sub(last) < helmUnlockCooldown {
			u.unwedged[key] = last // fold the persisted stamp into the ledger
			u.alertStallOnce(ctx, key, now,
				fmt.Sprintf("HR re-stalled inside the %s unwedge cooldown — previous unwedge did not fix it",
					helmUnlockCooldown))
			continue
		}
		// W8-GO2 — cap the retry cycle: at most
		// stallMaxAttemptsPerRevision unwedges for one
		// lastAttemptedRevision, each at least
		// stallAttemptCooldown apart. A revision change re-arms —
		// the new revision has not had its window yet.
		revision, _, _ := unstructured.NestedString(
			hr.Object, "status", "lastAttemptedRevision")
		att := u.stallAttempts[key]
		if att == nil || att.revision != revision {
			att = &stallAttempt{revision: revision}
			u.stallAttempts[key] = att
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
		acted, refuse, err := u.unwedge(ctx, gvr, hr)
		if acted || err == nil && refuse == "" {
			// Only a completed cycle (acted, or a clean no-op that
			// needed nothing) and refusals count as attempts —
			// API errors must not burn the 2-try budget.
			att.count++
			att.last = now
		}
		switch {
		case err != nil:
			// Tolerated per-HR failure: absorbed (log + continue,
			// nil return) — IncError keeps it on the alert path.
			metrics.IncError(helmUnlockQueue)
			log.Error(err, "helmrelease stall unwedge failed", "hr", key)
		case refuse != "":
			u.alertStallOnce(ctx, key, now,
				"stalled HR is not the surge-deadlock shape — refusing to scale: "+refuse)
		case acted:
			u.unwedged[key] = now
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
	if u.stallAlerted == nil {
		u.stallAlerted = map[string]time.Time{} // literal-constructed structs (tests)
	}
	if last, ok := u.stallAlerted[key]; ok && now.Sub(last) < helmUnlockCooldown {
		return
	}
	metrics.IncError(helmUnlockQueue)
	u.stallAlerted[key] = now
	logf.FromContext(ctx).Info("ALERT: "+msg, "hr", key)
}

// unwedge evaluates one stalled HR end to end: resolve the stalled
// Deployment, verify the surge-deadlock shape, scale the old
// ReplicaSet down, stamp the HR retry token. refuse != "" means the
// signature matched but the shape or a safety guard did not — the
// caller alerts instead of acting. acted=false + refuse="" means
// nothing needed doing (already opened window).
func (u *helmReleaseUnlocker) unwedge(ctx context.Context,
	gvr schema.GroupVersionResource, hr *unstructured.Unstructured) (bool, string, error) {
	log := logf.FromContext(ctx)
	key := hr.GetNamespace() + "/" + hr.GetName()

	dep, refuse, err := u.stalledDeployment(ctx, hr)
	if err != nil {
		return false, "", err
	}
	if dep == nil {
		return false, refuse, nil
	}

	plan, refuse, err := u.deadlockPlan(ctx, dep)
	if err != nil {
		return false, "", err
	}
	if plan == nil {
		return false, refuse, nil
	}

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
		return false, "", err
	}
	if _, err := u.cs.AppsV1().ReplicaSets(dep.Namespace).Patch(ctx, plan.target.Name,
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return false, "", fmt.Errorf("scale down replicaset %s/%s: %w",
			dep.Namespace, plan.target.Name, err)
	}

	// W8-GO2: the failed upgrade usually left a Failed helm-hook Job
	// behind in the release namespace — helm refuses to re-run a
	// hook while its Job object still exists, so the retry would
	// wedge identically. Reap it BEFORE the requestedAt cycle; the
	// sweep is best-effort and cannot undo the window we just opened.
	u.cleanFailedHookJobs(ctx, hrReleaseNS(hr))

	// Then poke the HR: requestedAt is the reconcile-now hint,
	// resetAt (same token — required pairing) zeroes the failure
	// counters that keep Stalled=True/RetriesExceeded terminal, and
	// forceAt runs the upgrade even with no drift. Without the
	// reset token a stalled HR would consume the freed scheduling
	// window and stay parked.
	token := time.Now().UTC().Format(time.RFC3339)
	patch, err = json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{
			fluxReconcileAnno:        token,
			fluxResetAnno:            token,
			fluxForceAnno:            token,
			helmLastStallUnwedgeAnno: token,
		}},
	})
	if err != nil {
		return false, "", err
	}
	if _, err := u.dyn.Resource(gvr).Namespace(hr.GetNamespace()).Patch(ctx, hr.GetName(),
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return false, "", fmt.Errorf("annotate helmrelease %s: %w", key, err)
	}
	log.Info("ACTION: requested HR reconcile + failure-counter reset",
		"hr", key, "deployment", dep.Namespace+"/"+dep.Name)
	metrics.HelmStallUnwedgesTotal.
		WithLabelValues(dep.Namespace, dep.Name).Inc()
	return true, "", nil
}

// stalledDeployment resolves which Deployment helm was waiting on.
// A "Deployment/<name>" (or "<ns>/<name>") token in ANY condition
// message wins — helm names its stalled resource explicitly; with no
// token the fallback scans the release namespace for a Deployment
// showing Progressing=False/ProgressDeadlineExceeded (refusal when
// zero or several candidates — guessing is not a remediation).
func (u *helmReleaseUnlocker) stalledDeployment(ctx context.Context,
	hr *unstructured.Unstructured) (*appsv1.Deployment, string, error) {
	releaseNS := hrReleaseNS(hr)
	for _, c := range shared.ReadyConds(hr) {
		msg, _ := c["message"].(string)
		m := stalledWorkloadRe.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		ns, name := releaseNS, m[1]
		if m[2] != "" {
			ns, name = m[1], m[2]
		}
		dep, err := u.cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, fmt.Sprintf(
					"stalled workload Deployment/%s reported by the HR is gone from ns %s",
					name, ns), nil
			}
			return nil, "", fmt.Errorf("get deployment %s/%s: %w", ns, name, err)
		}
		return dep, "", nil
	}
	// No explicit workload: scan the release namespace for the one
	// Deployment stuck in ProgressDeadlineExceeded — the condition
	// helm's waiter read when it aborted.
	deps, err := u.cs.AppsV1().Deployments(releaseNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("list deployments in %s: %w", releaseNS, err)
	}
	var candidates []string
	var found *appsv1.Deployment
	for i := range deps.Items {
		d := &deps.Items[i]
		if deploymentProgressDeadlineExceeded(d) {
			candidates = append(candidates, d.Name)
			found = d
		}
	}
	switch len(candidates) {
	case 0:
		return nil, fmt.Sprintf(
			"no Deployment named in the message and none ProgressDeadlineExceeded in ns %s",
			releaseNS), nil
	case 1:
		return found, "", nil
	default:
		sort.Strings(candidates)
		return nil, fmt.Sprintf(
			"ambiguous stalled workload — %d ProgressDeadlineExceeded Deployments in ns %s (%s)",
			len(candidates), releaseNS, strings.Join(candidates, ",")), nil
	}
}

// deploymentProgressDeadlineExceeded reports the rollout-gave-up
// condition — what helm's stalled-resource waiter actually read.
func deploymentProgressDeadlineExceeded(d *appsv1.Deployment) bool {
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing &&
			c.Status == corev1.ConditionFalse &&
			c.Reason == "ProgressDeadlineExceeded" {
			return true
		}
	}
	return false
}

// stallPlan is the verified remediation plan for a surge-deadlocked
// Deployment: which old ReplicaSet to scale and by how much.
type stallPlan struct {
	target         *appsv1.ReplicaSet // old RS holding the blocking pods
	targetReplicas int32              // its current .spec.replicas
	remove         int                // pods to shed — frees >=1 node guaranteed
	blocking       int                // old pods holding nodes via required anti-affinity
	nodes          int                // distinct nodes those pods occupy
	pending        int                // new-RS pods unschedulable on anti-affinity
}

// deadlockPlan verifies the workload-layer signature and returns the
// scale plan, or a refusal reason. Every refusal is a deliberate
// fail-closed: the HR stays stalled for a human rather than risk a
// wrong-target scale-down.
func (u *helmReleaseUnlocker) deadlockPlan(ctx context.Context,
	dep *appsv1.Deployment) (*stallPlan, string, error) {
	replicas := int(ptr.Deref(dep.Spec.Replicas, 1))
	if replicas <= 1 {
		return nil, fmt.Sprintf("deployment %s/%s has replicas=%d — no surge window to open",
			dep.Namespace, dep.Name, replicas), nil
	}
	if dep.Spec.Strategy.Type == appsv1.RecreateDeploymentStrategyType {
		return nil, fmt.Sprintf("deployment %s/%s uses Recreate — no surge pods exist",
			dep.Namespace, dep.Name), nil
	}
	maxUnavailable := deployMaxUnavailable(dep)
	if maxUnavailable > 0 {
		return nil, fmt.Sprintf(
			"deployment %s/%s resolves maxUnavailable=%d — it can drain old pods itself, not this deadlock",
			dep.Namespace, dep.Name, maxUnavailable), nil
	}

	rss, err := u.cs.AppsV1().ReplicaSets(dep.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("list replicasets in %s: %w", dep.Namespace, err)
	}
	pods, err := u.cs.CoreV1().Pods(dep.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("list pods in %s: %w", dep.Namespace, err)
	}

	// ReplicaSets owned by this Deployment, newest revision first.
	var owned []*appsv1.ReplicaSet
	for i := range rss.Items {
		rs := &rss.Items[i]
		if ref := metav1.GetControllerOf(rs); ref != nil &&
			ref.Kind == "Deployment" && ref.Name == dep.Name {
			owned = append(owned, rs)
		}
	}
	if len(owned) < 2 {
		return nil, fmt.Sprintf(
			"deployment %s/%s has %d ReplicaSets — no old/new pair to relieve",
			dep.Namespace, dep.Name, len(owned)), nil
	}
	sort.Slice(owned, func(i, j int) bool {
		return rsRevision(owned[i]) > rsRevision(owned[j])
	})
	newRS := owned[0]
	if ptr.Deref(newRS.Spec.Replicas, 0) <= 0 {
		return nil, fmt.Sprintf(
			"newest ReplicaSet %s has desired replicas 0 — no surge pod is trying to schedule",
			newRS.Name), nil
	}
	newPods := podsOwnedBy(pods.Items, newRS)
	pendingBlocked := 0
	pendingOther := 0
	for _, p := range newPods {
		if p.Spec.NodeName != "" || p.DeletionTimestamp != nil {
			continue // scheduled already — not part of the stall
		}
		if podBlockedByAffinity(p) {
			pendingBlocked++
		} else {
			pendingOther++
		}
	}
	switch {
	case pendingBlocked == 0 && pendingOther > 0:
		return nil, fmt.Sprintf(
			"new ReplicaSet %s pods are Pending for a non-affinity reason — not this deadlock",
			newRS.Name), nil
	case pendingBlocked == 0:
		return nil, fmt.Sprintf(
			"new ReplicaSet %s has no unscheduled pods — the stall is not a scheduling deadlock",
			newRS.Name), nil
	}

	// Old side: pods of every older RS whose TEMPLATE carries
	// required podAntiAffinity matching the new pod labels — only
	// those can reject the surge pod ("didn't satisfy existing pods
	// anti-affinity rules"). Preferred terms never hard-block.
	newLabels := newRS.Spec.Template.Labels
	var target *appsv1.ReplicaSet
	targetBlocking := -1
	blocking := 0
	nodes := map[string]bool{}
	for _, rs := range owned[1:] {
		if !requiredAntiAffinityMatches(&rs.Spec.Template, newLabels) {
			continue
		}
		rsBlocking := 0
		for _, p := range podsOwnedBy(pods.Items, rs) {
			if p.Spec.NodeName == "" || p.DeletionTimestamp != nil {
				continue // unscheduled/dying pods block nothing
			}
			rsBlocking++
			nodes[p.Spec.NodeName] = true
		}
		blocking += rsBlocking
		if rsBlocking > targetBlocking {
			target, targetBlocking = rs, rsBlocking
		}
	}
	if blocking == 0 || target == nil {
		return nil, fmt.Sprintf(
			"no old ReplicaSet pods carry required anti-affinity matching the new pod labels for %s/%s — preferred-only terms do not block",
			dep.Namespace, dep.Name), nil
	}
	if targetBlocking != blocking {
		// Blocking pods spread over several old ReplicaSets — a
		// single scale-down cannot guarantee a freed node, and
		// scaling several RSes is a bigger availability cut than
		// this module is willing to make. Refuse to a human.
		return nil, fmt.Sprintf(
			"blocking pods for %s/%s span multiple old ReplicaSets (%d of %d on %s) — refusing",
			dep.Namespace, dep.Name, targetBlocking, blocking, target.Name), nil
	}

	// Removing k arbitrary pods from `blocking` pods on `nodes`
	// distinct nodes frees >=1 node for sure once survivors <
	// nodes: k = blocking - nodes + 1. The single-RS gate above is
	// what makes this a guarantee — survivors can cover at most
	// min(nodes, blocking-k) = nodes-1 nodes.
	remove := blocking - len(nodes) + 1
	targetReplicas := ptr.Deref(target.Spec.Replicas, 0)
	if int32(remove) > targetReplicas {
		return nil, fmt.Sprintf(
			"freeing a node needs %d removals but old ReplicaSet %s only holds %d desired pods — refusing",
			remove, target.Name, targetReplicas), nil
	}
	// Availability floor: kept old replicas plus the new pods that
	// the freed node(s) can admit must stay >= replicas-maxUnavailable
	// (== replicas here, maxUnavailable is 0 by the gate above).
	kept := int(targetReplicas) - remove
	newSched := min(remove, pendingBlocked)
	if kept+newSched < replicas {
		return nil, fmt.Sprintf(
			"scaling old ReplicaSet %s/%s down by %d violates the availability floor (replicas=%d, maxUnavailable=0, %d pending new pods)",
			dep.Namespace, target.Name, remove, replicas, pendingBlocked), nil
	}
	// PDB gate: every PDB selecting the old pod labels must tolerate
	// the disruption — a covering PDB that would refuse the removal
	// turns the scale-down into a silent availability cut.
	if refuse, err := u.pdbBlocksScaleDown(ctx, dep.Namespace,
		target.Spec.Template.Labels, remove); err != nil {
		return nil, "", err
	} else if refuse != "" {
		return nil, refuse, nil
	}

	return &stallPlan{
		target:         target,
		targetReplicas: targetReplicas,
		remove:         remove,
		blocking:       blocking,
		nodes:          len(nodes),
		pending:        pendingBlocked,
	}, "", nil
}

// pdbBlocksScaleDown returns a refusal reason when any PDB in ns that
// selects the old pods' labels reports fewer disruptions than the
// planned removal — nil selector and unparseable selectors fail
// CLOSED (treated as covering, same convention as
// statefulset-ondelete-roller).
func (u *helmReleaseUnlocker) pdbBlocksScaleDown(ctx context.Context,
	ns string, podLabels map[string]string, remove int) (string, error) {
	pdbs, err := u.cs.PolicyV1().PodDisruptionBudgets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("list poddisruptionbudgets in %s (safety gate): %w", ns, err)
	}
	for i := range pdbs.Items {
		pdb := &pdbs.Items[i]
		sel := labels.Everything()
		if pdb.Spec.Selector != nil {
			parsed, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
			if err != nil {
				// Fail closed — an unreadable selector must not skip
				// the disruption budget check.
				parsed = labels.Everything()
			}
			sel = parsed
		}
		if !sel.Matches(labels.Set(podLabels)) {
			continue
		}
		if int(pdb.Status.DisruptionsAllowed) < remove {
			return fmt.Sprintf(
				"PDB %s/%s covers the old pods and allows %d disruptions, need %d — refusing",
				pdb.Namespace, pdb.Name, pdb.Status.DisruptionsAllowed, remove), nil
		}
	}
	return "", nil
}

// deployMaxUnavailable resolves the effective maxUnavailable for a
// RollingUpdate Deployment — nil strategy fields take the apiserver
// default ("25%", rounded down like the controller does).
func deployMaxUnavailable(dep *appsv1.Deployment) int {
	replicas := int(ptr.Deref(dep.Spec.Replicas, 1))
	maxUnavail := intstr.FromString("25%")
	if ru := dep.Spec.Strategy.RollingUpdate; ru != nil && ru.MaxUnavailable != nil {
		maxUnavail = *ru.MaxUnavailable
	}
	v, err := intstr.GetScaledValueFromIntOrPercent(&maxUnavail, replicas, false)
	if err != nil {
		return 0 // unparseable → 0 (conservative: assume the floor is full)
	}
	return v
}

// rsRevision parses the deployment.kubernetes.io/revision stamp —
// the ordering between a Deployment's ReplicaSets. Unparseable or
// absent reads as revision 0 (oldest).
func rsRevision(rs *appsv1.ReplicaSet) int64 {
	v, err := strconv.ParseInt(rs.Annotations[deployRevisionAnno], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// podsOwnedBy returns the non-terminating pods controlled by rs —
// controller ownerReference kind+name, not UID (fake fixtures rarely
// carry matching UIDs; same convention as ownedPods in
// statefulset-ondelete-roller).
func podsOwnedBy(pods []corev1.Pod, rs *appsv1.ReplicaSet) []*corev1.Pod {
	var out []*corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp != nil {
			continue // dying pods block nothing and stall nothing
		}
		if ref := metav1.GetControllerOf(p); ref != nil &&
			ref.Kind == "ReplicaSet" && ref.Name == rs.Name {
			out = append(out, p)
		}
	}
	return out
}

// podBlockedByAffinity reports whether the pod is stuck unscheduled
// BECAUSE of anti-affinity: PodScheduled=False whose message mentions
// affinity ("didn't satisfy existing pods anti-affinity rules",
// "didn't match pod anti-affinity rules"). Insufficient cpu, taints,
// image pulls and every other scheduling failure read false — the
// caller refuses those.
func podBlockedByAffinity(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type != corev1.PodScheduled || c.Status != corev1.ConditionFalse {
			continue
		}
		return strings.Contains(strings.ToLower(c.Message), "affinity")
	}
	return false
}

// requiredAntiAffinityMatches reports whether the OLD pod template's
// requiredDuringSchedulingIgnoredDuringExecution anti-affinity has at
// least one term whose selector matches the NEW pod labels — that is
// what rejects the surge pod on every occupied node. A nil term
// selector selects all pods (blocking by definition); preferred terms
// never count.
func requiredAntiAffinityMatches(tpl *corev1.PodTemplateSpec, newLabels map[string]string) bool {
	aff := tpl.Spec.Affinity
	if aff == nil || aff.PodAntiAffinity == nil {
		return false
	}
	for _, term := range aff.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
		sel := labels.Everything()
		if term.LabelSelector != nil {
			parsed, err := metav1.LabelSelectorAsSelector(term.LabelSelector)
			if err != nil {
				continue
			}
			sel = parsed
		}
		if sel.Matches(labels.Set(newLabels)) {
			return true
		}
	}
	return false
}

// linkerd_protocol_detection_stall_heal.go — the pod-side heal of
// the linkerd-protocol-detection-stall check (linkerd-protocol-detection-stall): cooldown +
// maintenance gate, then only when the owning workload's template
// took the opaque-ports annotation, delete the pod so the
// replacement proxy starts with the corrected config — and patch
// the pod's own annotation as bookkeeping once the delete is
// delivered.
package linkerd

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// healLinkerdOpaquePorts applies the opaque-ports heal for one
// violating pod: cooldown → maintenance gate → template patch → pod
// annotation patch → pod delete/evict (only when the template took
// the annotation, else the replacement re-inherits the violation).
// pods is the sweep's pod census — the OnDelete StatefulSet guard
// counts Ready siblings off it.
//
// Cooldown stamping contract: p.Heals stamps ONLY when the template
// patch landed (patched) or a pod kill was delivered (inside
// heal.DeletePod/EvictPod). Every refusal — GitOps drift, RBAC,
// unresolved owner, quorum/PDB denial — refunds the budget grant
// and leaves the cooldown unstamped so the NEXT sweep re-evaluates:
// the drift gauge must re-assert every sweep or its ledger prunes
// the series before the alert's `for:` window completes, and a
// stamped refusal used to hide exactly that for 30 minutes.
func (p *linkerdProtocolDetectionStallCheck) healLinkerdOpaquePorts(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time,
	pods []corev1.Pod, rep *probefw.SweepReport, driftNow map[string][]string) {

	// The cooldown keys on the pod's controller (kube.PodControllerKey)
	// — the recreated pod carries a fresh suffix, so a "<ns>/<pod>"
	// key lets the same workload's re-heal fire every sweep.
	ck := probefw.SelfHealKey(CheckNameLinkerdOpaqueStall, kube.PodControllerKey(pod))
	// GitOps-drift detection is READ-ONLY evidence and must run
	// BEFORE every gate below: a stamped controller cooldown, a held
	// maintenance mutex or an exhausted heal budget would otherwise
	// skip the evaluation entirely and driftNow's reconcile would
	// DeleteLabelValues a still-live drift series — Flux/annotation
	// reversion has to be seen the sweep it happens, gated or not.
	// A drifted=true verdict IS the refusal: the probe already
	// emitted the gauge + finding, so the heal stops here — running
	// the gates would burn a budget grant the refund path then hands
	// back, and patchLinkerdTemplate would re-derive the same drift
	// and emit a duplicate rep.Find for the same tuple.
	if p.linkerdTemplateDriftProbe(ctx, log, pod, missing, now, rep, driftNow) {
		return
	}
	// Free in-RAM cooldown first — a stamped controller key defers
	// without touching the mutex verdict or the global heal budget.
	if p.Heals.CooledDown(ck, linkerdOpaqueHealCool, now) {
		return
	}
	proceed, unverifiable := p.HealAllowed(ctx, log,
		&p.Heals, ck, linkerdOpaqueHealCool, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	covered, patched, drift := p.patchLinkerdTemplate(ctx, log, pod, missing, now, rep, driftNow)
	switch {
	case drift:
		// GitOps drift: the gauge + finding already emitted inside
		// patchTemplatePorts. NO cooldown stamp — the next sweep
		// must re-evaluate so the drift series re-asserts (a stamped
		// window skips the check for 30m, the gauge ledger prunes
		// the series, and the alert's `for:` never sees a
		// continuous 1). Refund the grant: a refusal delivered no
		// heal.
		heal.RefundGrant(now)
		return
	case !covered:
		// No pod-side annotation here: writing opaque-ports onto a pod
		// that stays RUNNING (GitOps-reverted template inside the 6h
		// stamp window, RBAC-refused patch, unresolvable owner) makes
		// missingBinaryPorts() read the still-broken pod as covered
		// next sweep — the check would self-blind and clear BOTH
		// linkerd_opaque_port_missing and linkerd_gitops_opaque_drift
		// while the proxy never got the fix.
		//
		// No cooldown stamp either: every !covered cause is a
		// slow-moving refusal that resolves on its own (an RBAC
		// rollout lands, an owner re-links), and the grant refund
		// keeps the retry budget-neutral — an UNSTAMPED refusal no
		// longer burns the shared heal budget, which was the stamp's
		// original job.
		heal.RefundGrant(now)
		log.Info("opaque-ports heal: owning workload template not patched — leaving pod running (annotation alone cannot reach a live proxy)",
			"pod", pod.Namespace+"/"+pod.Name, "ports", missing)
		return
	case patched:
		// Stamp the cooldown the moment the patch lands. HealAllowed
		// already spent this heal's budget token getting here — and
		// heal.DeletePod (the only other Stamp site) never runs on
		// this path, so without the stamp a second stalled pod of the
		// SAME workload resolves to the same controller key this
		// sweep, passes the un-stamped cooldown, spends another token
		// and re-PATCHes the Deployment from the snapshot's stale
		// pre-write copy.
		p.Heals.Stamp(ck, now)
		// The template patch just landed — the workload controller
		// (Deployment/StatefulSet/DaemonSet/Rollout) rolling-update
		// replaces every pod with the corrected config itself.
		// Mass-deleting all matching pods here would duplicate the
		// rollout and churn the whole workload at once; skip the
		// delete AND the pod annotation (a pod-side opaque-ports
		// write would make the next sweep read the still-running
		// pre-rollout pod as covered — the self-blind hazard).
		log.Info("PATCH: linkerd protocol-detection stall — template patched, leaving the rolling update to the workload controller",
			"pod", pod.Namespace+"/"+pod.Name, "ports", missing)
		return
	}
	// Template already covered the ports but the pod is still running
	// the pre-annotation config — the restart is the heal, and the
	// bookkeeping annotation lands only once the delete is delivered
	// (the same self-blind hazard applies to a pod whose delete
	// failed).
	p.restartStalePod(ctx, log, pod, missing, now, pods, ck)
}

// restartStalePod delivers the covered-template pod restart. A
// StatefulSet OnDelete pod gets the manual-roll treatment: the
// delete IS the only roll trigger (the controller never
// auto-updates OnDelete pods), so it requires a Ready sibling to
// absorb the gap and goes through the Eviction API — a raw Delete
// bypasses every PodDisruptionBudget and could take a quorum-
// sensitive replica set to zero. Every other shape keeps the plain
// UID-preconditioned delete.
func (p *linkerdProtocolDetectionStallCheck) restartStalePod(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time,
	pods []corev1.Pod, ck string) {

	if p.podOnDeleteStatefulSet(ctx, log, pod) {
		readyByOwner := probefw.ReadyByOwner(pods)
		if probefw.ReadySiblings(readyByOwner, pod) < 1 {
			// Never take the last Ready replica offline — the
			// restart can wait for a sibling to come up first.
			// Deferral, not a heal: refund the grant.
			heal.RefundGrant(now)
			log.Info("DEFER: ondelete statefulset — no ready sibling to absorb the restart",
				"pod", pod.Namespace+"/"+pod.Name)
			return
		}
		evicted, refused, err := heal.EvictPod(ctx, p.CS, &p.Heals, ck, pod, now)
		if err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "linkerd opaque-ports pod eviction failed",
				"pod", pod.Namespace+"/"+pod.Name)
			return
		}
		if refused {
			// PDB 429 or quorum reservation — a deferral that
			// delivered nothing; hand the grant back.
			heal.RefundGrant(now)
			log.Info("DEFER: ondelete statefulset eviction refused (PDB/quorum)",
				"pod", pod.Namespace+"/"+pod.Name)
			return
		}
		if !evicted {
			return
		}
		p.bookkeepRestart(ctx, log, pod, missing, "evicted")
		return
	}

	didDelete, err := heal.DeletePod(ctx, p.CS, &p.Heals, ck, pod, now)
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "linkerd opaque-ports pod delete failed",
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	if !didDelete {
		// Quorum reservation denied — a sibling check already spent
		// this workload's one-disruption slot this sweep. The pod
		// annotation must NOT land: the pod still runs the stale
		// config and the next sweep re-detects it. Deferral — the
		// grant goes back.
		heal.RefundGrant(now)
		log.Info("DEFER: workload disruption already reserved this sweep",
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	p.bookkeepRestart(ctx, log, pod, missing, "deleted")
}

// bookkeepRestart runs the post-kill bookkeeping shared by the
// delete and eviction paths: the pod annotation lands only once the
// kill is delivered (the self-blind hazard applies to a pod whose
// kill failed), the census tombstones, and the heal counter ticks.
func (p *linkerdProtocolDetectionStallCheck) bookkeepRestart(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, verb string) {

	p.patchLinkerdPodAnno(ctx, log, pod, missing)
	kube.MarkPodDeleted(ctx, pod.UID) // O(1) tombstone — no census reset
	metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameLinkerdOpaqueStall).Inc()
	log.Info("DELETE: linkerd protocol-detection stall — template patched, re-rolling pod",
		"pod", pod.Namespace+"/"+pod.Name, "ports", missing, "verb", verb)
}

// podOnDeleteStatefulSet reports whether pod's controller is a
// StatefulSet whose updateStrategy is OnDelete — the shape where a
// pod delete is a manual roll step, not a redundant kill the
// controller would undo anyway. A missing/unreadable StatefulSet or
// census failure reads false: the guard ADDS protection for a known
// dangerous shape, it does not gate the ordinary delete.
func (p *linkerdProtocolDetectionStallCheck) podOnDeleteStatefulSet(ctx context.Context,
	log logr.Logger, pod *corev1.Pod) bool {

	ref := metav1.GetControllerOf(pod)
	if ref == nil || ref.Kind != "StatefulSet" {
		return false
	}
	stsList, err := p.AllStatefulSets(ctx)
	if err != nil {
		log.Info("WARN: linkerd heal — statefulset census failed for ondelete check",
			"statefulset", pod.Namespace+"/"+ref.Name, "error", err)
		return false
	}
	for i := range stsList {
		sts := &stsList[i]
		if sts.Namespace == pod.Namespace && sts.Name == ref.Name {
			return sts.Spec.UpdateStrategy.Type == appsv1.OnDeleteStatefulSetStrategyType
		}
	}
	return false
}

// patchLinkerdPodAnno merge-patches the pod's own
// opaque-ports annotation — best-effort bookkeeping (a running
// proxy does not re-read it; the template patch + restart is the
// real heal). Failures are logged, never fatal.
func (p *linkerdProtocolDetectionStallCheck) patchLinkerdPodAnno(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int) {

	set := parsePortSet(pod.Annotations[linkerdOpaquePortsAnno])
	changed := false
	for _, pt := range missing {
		if !set[pt] {
			set[pt] = true
			changed = true
		}
	}
	if !changed {
		return
	}
	payload, err := kube.MergePatchAnnos(map[string]any{
		linkerdOpaquePortsAnno: portSetString(set),
	})
	if err != nil {
		return
	}
	if _, err := p.CS.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		// The patch runs after the delete is delivered — a fast
		// teardown can beat it; NotFound is benign there.
		if apierrors.IsNotFound(err) {
			return
		}
		log.Info("WARN: linkerd heal — pod annotation patch failed (RBAC?)",
			"pod", pod.Namespace+"/"+pod.Name, "error", err)
		return
	}
	kube.RecordAnnoPatch(ctx, pod, payload)
}

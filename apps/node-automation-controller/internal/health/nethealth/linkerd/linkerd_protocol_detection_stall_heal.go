// linkerd_protocol_detection_stall_heal.go — the pod-side heal of
// the linkerd-protocol-detection-stall check (W10-NM3): cooldown +
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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// healLinkerdOpaquePorts applies the opaque-ports heal for one
// violating pod: cooldown → maintenance gate → template patch → pod
// annotation patch → pod delete (only when the template took the
// annotation, else the replacement re-inherits the violation).
func (p *linkerdProtocolDetectionStallCheck) healLinkerdOpaquePorts(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time,
	rep *probefw.SweepReport, driftNow map[string][]string) {

	// The cooldown keys on the pod's controller (kube.PodControllerKey)
	// — the recreated pod carries a fresh suffix, so a "<ns>/<pod>"
	// key lets the same workload's re-heal fire every sweep.
	ck := probefw.SelfHealKey(CheckNameLinkerdOpaqueStall, kube.PodControllerKey(pod))
	proceed, unverifiable := p.HealAllowed(ctx, log,
		&p.Heals, ck, linkerdOpaqueHealCool, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	covered, patched := p.patchLinkerdTemplate(ctx, log, pod, missing, now, rep, driftNow)
	if !covered {
		// No pod-side annotation here: writing opaque-ports onto a pod
		// that stays RUNNING (GitOps-reverted template inside the 6h
		// stamp window, RBAC-refused patch) makes missingBinaryPorts()
		// read the still-broken pod as covered next sweep — the check
		// would self-blind and clear BOTH linkerd_opaque_port_missing
		// and linkerd_gitops_opaque_drift while the proxy never got
		// the fix.
		log.Info("opaque-ports heal: owning workload template not patched — leaving pod running (annotation alone cannot reach a live proxy)",
			"pod", pod.Namespace+"/"+pod.Name, "ports", missing)
		return
	}
	if patched {
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
	if _, err := heal.DeletePod(ctx, p.CS, &p.Heals, ck, pod, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "linkerd opaque-ports pod delete failed",
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	// Bookkeeping annotation lands only once the delete is delivered —
	// the same self-blind hazard applies to a pod whose delete failed.
	p.patchLinkerdPodAnno(ctx, log, pod, missing)
	p.InvalidatePods(ctx) // pod gone — drop the census
	metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameLinkerdOpaqueStall).Inc()
	log.Info("DELETE: linkerd protocol-detection stall — template patched, re-rolling pod",
		"pod", pod.Namespace+"/"+pod.Name, "ports", missing)
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
	}
}

// hpa_scaling_guard.go — the hpa-scaling-guard check (P1.8): the
// autoscaling/v2 HorizontalPodAutoscaler twin of
// keda-scaledobject-guard. An HPA holding AbleToScale=False or
// ScalingActive=False past the persistence window means the
// horizontal pod autoscaler cannot evaluate or act on its target —
// missing metrics, a wedged scale subresource, or (the classic
// isolated case) a dead metrics-server pod while its siblings stay
// Ready.
//
// Per unhealthy HPA (conditions persisted >=15m via the
// annotation-backed first-seen window):
//   - gauge node_automation_hpa_scaling_unhealthy + deduped Event,
//   - cold-start rescue: a scale target wedged at spec.replicas==0
//     is patched to max(spec.minReplicas, 1) — 30m cooldown,
//     maintenance-gated, SKIPPED when kube.IsIntentionallyDownscaled
//     proves the zero is the downscaler's doing,
//   - metrics-server bounce: when unhealthy HPAs coincide with a
//     metrics-server pod set that has BOTH a Ready and an unready
//     member, the unready member is deleted (isolated failure —
//     the Ready sibling absorbs; the delete rides SafePodDelete's
//     sibling floor + the shared heal gates, 30m cooldown).
package gitops

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// hpaScalingGuardCheck is the HPA watchdog with the zero-target
// rescue and the metrics-server bounce.
type hpaScalingGuardCheck struct {
	*probefw.Deps

	// seen tracks each unhealthy HPA's first-seen sweep — the 15m
	// persistence window; the annotation-backed variant (stamped
	// on the HPA under kube.AnnoFirstSeenHPA) lets a restarted
	// operator resume a window it never saw in RAM.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger.
	emitted state.GaugeLedger[string]
	// eventHealed dedupes the cluster Event per window.
	eventHealed state.CooldownSet
}

// NewHPAScalingGuardCheck builds the hpa-scaling-guard check.
func NewHPAScalingGuardCheck(d *probefw.Deps) probefw.Check {
	return &hpaScalingGuardCheck{Deps: d}
}

const (
	CheckNameHPAScalingGuard = "hpa-scaling-guard"

	// hpa-scaling-guard knobs.
	hpaUnhealthyMinAge   = 15 * time.Minute
	hpaRescueCooldown    = 30 * time.Minute
	hpaMSBounceCooldown  = 30 * time.Minute
	hpaMSBounceNamespace = "kube-system"
)

// hpaGVR is the autoscaling/v2 HorizontalPodAutoscaler GVR — no
// typed census exists in probefw, so the check rides the
// unstructured path like the KEDA ScaledObject guard.
var hpaGVR = schema.GroupVersionResource{
	Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}

var (
	// hpa-scaling-guard — 1 per unhealthy HPA, labelled by reason.
	hpaScalingUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_hpa_scaling_unhealthy",
		Help: "1 while the HorizontalPodAutoscaler reports AbleToScale=False or ScalingActive=False past the window — hpa-scaling-guard.",
	}, []string{"namespace", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(hpaScalingUnhealthyGauge)
}

// Run audits every autoscaling/v2 HPA for stuck scaling
// conditions, then runs the cold-start rescue and the
// metrics-server bounce for the confirmed set.
func (p *hpaScalingGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	p.eventHealed.PruneExpired(now, hpaUnhealthyMinAge)
	var rep probefw.SweepReport

	hpas, err := p.AllUnstructured(ctx, hpaGVR)
	switch {
	case kube.IsCRDAbsent(err):
		var rep probefw.SweepReport
		p.seen.Prune(func(string) bool { return false })
		return rep.Result(&p.emitted, hpaScalingUnhealthyGauge.DeleteLabelValues,
			"hpas scaling-unhealthy: ", ", ")
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list hpas: %w", err)}
	}

	seenKeep := map[string]bool{}
	var unhealthy []*unstructured.Unstructured
	for i := range hpas {
		hpa := &hpas[i]
		key := hpa.GetNamespace() + "/" + hpa.GetName()
		annoPatch := func(ctx context.Context, data []byte) error {
			_, err := p.Dyn.Resource(hpaGVR).
				Namespace(hpa.GetNamespace()).Patch(ctx, hpa.GetName(),
				types.MergePatchType, data, metav1.PatchOptions{})
			if err == nil {
				kube.RecordAnnoPatch(ctx, hpa, data)
			}
			return err
		}
		var reasons []string
		if c, ok := kube.ConditionOf(hpa.Object, "AbleToScale"); ok && c.Status == "False" {
			reasons = append(reasons, "able_to_scale_false")
		}
		if c, ok := kube.ConditionOf(hpa.Object, "ScalingActive"); ok && c.Status == "False" {
			reasons = append(reasons, "scaling_active_false")
		}
		if len(reasons) == 0 {
			_ = heal.ClearPersistedFirstSeen(ctx, logr.Discard(), &p.seen,
				hpa, kube.AnnoFirstSeenHPA, key, annoPatch)
			continue
		}
		seenKeep[key] = true
		if !heal.FirstSeenPersisted(ctx, logr.Discard(), &p.seen, hpa,
			kube.AnnoFirstSeenHPA, key,
			hpaUnhealthyMinAge, now, annoPatch) {
			continue
		}
		for _, reason := range reasons {
			rep.Flag(hpaScalingUnhealthyGauge, key+"/"+reason,
				[]string{hpa.GetNamespace(), hpa.GetName(), reason})
		}
		rep.Find(key + "(" + strings.Join(reasons, ",") + ")")
		unhealthy = append(unhealthy, hpa)
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })

	for _, hpa := range unhealthy {
		p.rescueZeroTarget(ctx, log, hpa, now)
	}
	if len(unhealthy) > 0 {
		p.maybeBounceMetricsServer(ctx, log, now)
		p.emitHPAEvent(ctx, log, rep.Findings(), now)
	}
	return rep.Result(&p.emitted, hpaScalingUnhealthyGauge.DeleteLabelValues,
		fmt.Sprintf("hpas scaling-unhealthy >=%s: ", hpaUnhealthyMinAge), ", ")
}

// rescueZeroTarget lifts a scale target wedged at spec.replicas==0
// back to max(hpa.spec.minReplicas, 1) — the HPA-side cold-start
// deadlock twin of the KEDA rescue. Deployment/StatefulSet targets
// resolve through the typed censuses; other kinds are skipped
// (unresolvable stays inconclusive, not "not at zero").
func (p *hpaScalingGuardCheck) rescueZeroTarget(ctx context.Context,
	log logr.Logger, hpa *unstructured.Unstructured, now time.Time) {

	ns := hpa.GetNamespace()
	target, ok := kube.NestedString(hpa.Object, "spec", "scaleTargetRef", "name")
	if !ok || target == "" {
		return
	}
	minReplicas, _ := kube.NestedInt64(hpa.Object, "spec", "minReplicas")
	rescue := int32(minReplicas)
	if rescue < 1 {
		rescue = 1
	}

	var annotations map[string]string
	var replicas *int32
	var rv string
	kind := ""
	declared, _ := kube.NestedString(hpa.Object, "spec", "scaleTargetRef", "kind")
	if declared == "" || strings.EqualFold(declared, "Deployment") {
		dep, err := p.Deployment(ctx, ns, target)
		if err != nil {
			return
		}
		if dep != nil {
			kind = "Deployment"
			annotations = kube.EffectiveAnnos(ctx, dep)
			replicas = dep.Spec.Replicas
			rv = dep.ResourceVersion
		}
	}
	if kind == "" && (declared == "" || strings.EqualFold(declared, "StatefulSet")) {
		sts, serr := p.StatefulSet(ctx, ns, target)
		if serr != nil {
			return
		}
		if sts != nil {
			kind = "StatefulSet"
			annotations = kube.EffectiveAnnos(ctx, sts)
			replicas = sts.Spec.Replicas
			rv = sts.ResourceVersion
		}
	}
	if kind == "" {
		return
	}
	if replicas == nil || *replicas != 0 {
		return
	}
	if kube.IsIntentionallyDownscaled(annotations, replicas) {
		return
	}

	ck := probefw.SelfHealKey(CheckNameHPAScalingGuard, "rescue/"+ns+"/"+target)
	proceed, unverifiable := p.HealAllowed(ctx, log,
		&p.Heals, ck, hpaRescueCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	// metadata.resourceVersion pins the write — a legitimate
	// scale-up landing between the census read and this patch
	// becomes a 409 instead of a silent revert to the rescue floor.
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"resourceVersion": rv},
		"spec":     map[string]any{"replicas": rescue},
	})
	if err != nil {
		return
	}
	var patchErr error
	if kind == "Deployment" {
		_, patchErr = p.CS.AppsV1().Deployments(ns).Patch(ctx, target,
			types.MergePatchType, payload, metav1.PatchOptions{})
	} else {
		_, patchErr = p.CS.AppsV1().StatefulSets(ns).Patch(ctx, target,
			types.MergePatchType, payload, metav1.PatchOptions{})
	}
	if patchErr != nil {
		if apierrors.IsConflict(patchErr) || apierrors.IsNotFound(patchErr) {
			heal.RefundGrant(now)
			log.Info("SKIP: hpa cold-start rescue raced (target changed or gone)",
				"target", kind+" "+ns+"/"+target)
			return
		}
		metrics.IncError(p.Name)
		log.Error(patchErr, "hpa cold-start rescue scale patch failed",
			"target", kind+" "+ns+"/"+target, "replicas", rescue)
		return
	}
	switch kind {
	case "Deployment":
		p.InvalidateDeployments(ctx)
	case "StatefulSet":
		p.InvalidateStatefulSets(ctx)
	}
	p.Heals.Stamp(ck, now)
	log.Info("SCALE: hpa cold-start rescue — target wedged at 0 while the HPA is unhealthy",
		"target", kind+" "+ns+"/"+target, "replicas", rescue)
}

// maybeBounceMetricsServer deletes an isolated unready
// metrics-server pod — the classic cause of fleet-wide
// ScalingActive=False: the HPA controller cannot fetch metrics
// from a dead metrics-server while its siblings serve fine. Fires
// only when the pod set has BOTH a Ready and an unready member
// (an all-unready set is an apiserver/network problem a pod
// bounce cannot fix), gated on the shared heal cooldown.
func (p *hpaScalingGuardCheck) maybeBounceMetricsServer(ctx context.Context,
	log logr.Logger, now time.Time) {

	pods, err := p.AllPods(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		return
	}
	var unready []*corev1.Pod
	ready := false
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != hpaMSBounceNamespace ||
			!strings.Contains(pod.Name, "metrics-server") {
			continue
		}
		if pod.DeletionTimestamp != nil {
			continue
		}
		if kube.PodReadyCond(pod) {
			ready = true
			continue
		}
		unready = append(unready, pod)
	}
	if !ready || len(unready) == 0 {
		return
	}
	slices.SortFunc(unready, func(a, b *corev1.Pod) int {
		return strings.Compare(a.Name, b.Name)
	})
	target := unready[0]
	p.DeletePodHeal(ctx, log, CheckNameHPAScalingGuard,
		kube.PodControllerKey(target), target, hpaMSBounceCooldown, now)
}

// emitHPAEvent fires ONE deduped Warning event per window naming
// the stuck HPAs.
func (p *hpaScalingGuardCheck) emitHPAEvent(ctx context.Context,
	log logr.Logger, findings []string, now time.Time) {

	if len(findings) == 0 {
		return
	}
	ck := probefw.SelfHealKey(CheckNameHPAScalingGuard, "event")
	if p.eventHealed.CooledDown(ck, hpaUnhealthyMinAge, now) {
		return
	}
	msg := fmt.Sprintf("hpa scaling guard: %d hpa(s) stuck (%s)",
		len(findings), findings[0])
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      "hpa-scaling-guard-" + now.Format("20060102-150405"),
		Namespace: "kube-system",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       "kube-system",
		},
		Reason:            "HPAScalingStuck",
		Note:              msg,
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: hpa guard event create failed (RBAC?)",
			"error", err)
		return
	}
	p.eventHealed.Stamp(ck, now)
	log.Info("EVENT: HPAScalingStuck", "detail", msg)
}

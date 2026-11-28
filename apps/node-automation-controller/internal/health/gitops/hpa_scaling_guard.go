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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
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

	maxSaturatedSeen    state.FirstSeenLedger
	maxSaturatedEmitted state.GaugeLedger[string]
	maxSaturatedEvents  state.CooldownSet
}

// NewHPAScalingGuardCheck builds the hpa-scaling-guard check.
func NewHPAScalingGuardCheck(d *probefw.Deps) probefw.Check {
	return &hpaScalingGuardCheck{Deps: d}
}

const (
	CheckNameHPAScalingGuard = "hpa-scaling-guard"

	// hpa-scaling-guard knobs.
	hpaUnhealthyMinAge           = 15 * time.Minute
	hpaMaxSaturatedMinAge        = 30 * time.Minute
	hpaMaxSaturatedEventCooldown = 30 * time.Minute
	hpaRescueCooldown            = 30 * time.Minute
	hpaMSBounceCooldown          = 30 * time.Minute
	hpaMSBounceNamespace         = "kube-system"
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

	hpaMaxReplicasSaturatedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_hpa_max_replicas_saturated",
		Help: "1 while the HorizontalPodAutoscaler stays pinned at currentReplicas == maxReplicas with ScalingLimited=True >=30m — hpa-scaling-guard.",
	}, []string{"namespace", "name"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(hpaScalingUnhealthyGauge, hpaMaxReplicasSaturatedGauge)
}

// Run audits every autoscaling/v2 HPA for stuck scaling
// conditions, then runs the cold-start rescue and the
// metrics-server bounce for the confirmed set.
func (p *hpaScalingGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	p.eventHealed.PruneExpired(now, hpaUnhealthyMinAge)
	p.maxSaturatedEvents.PruneExpired(now, hpaMaxSaturatedEventCooldown)
	var rep, maxRep probefw.SweepReport

	hpas, err := p.AllUnstructured(ctx, hpaGVR)
	switch {
	case kube.IsCRDAbsent(err):
		p.seen.Prune(func(string) bool { return false })
		p.maxSaturatedSeen.Prune(func(string) bool { return false })
		maxRep.Close(&p.maxSaturatedEmitted, hpaMaxReplicasSaturatedGauge.DeleteLabelValues)
		return rep.Result(&p.emitted, hpaScalingUnhealthyGauge.DeleteLabelValues,
			"hpas scaling-unhealthy: ", ", ")
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list hpas: %w", err)}
	}

	seenKeep := map[string]bool{}
	maxKeep := map[string]bool{}
	var unhealthy []*unstructured.Unstructured
	for i := range hpas {
		hpa := &hpas[i]
		key := hpa.GetNamespace() + "/" + hpa.GetName()
		if p.checkHPAMaxSaturated(ctx, log, now, hpa, key, &maxRep, &rep, maxKeep) {
			maxKeep[key] = true
		}
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
		if c, ok := kube.ConditionOf(hpa.Object, "AbleToScale"); ok && c.Status == "False" && !isScaleToZeroIdleHPA(hpa, c) {
			reasons = append(reasons, "able_to_scale_false")
		}
		if c, ok := kube.ConditionOf(hpa.Object, "ScalingActive"); ok && c.Status == "False" && !isScaleToZeroIdleHPA(hpa, c) {
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
	p.maxSaturatedSeen.Prune(func(k string) bool { return maxKeep[k] })
	maxRep.Close(&p.maxSaturatedEmitted, hpaMaxReplicasSaturatedGauge.DeleteLabelValues)

	// The fleet heal budget is shared with every other module. One
	// sweep of this check gets at most ONE budgeted action across
	// BOTH heal shapes: a cold-start rescue that consumed a grant
	// defers the remaining rescues and the metrics-server bounce,
	// so a fleet-wide HPA signature cannot drain the whole window
	// in one pass. A cleanly refunded grant did not spend the
	// allowance and leaves the next action free.
	grantSpent := false
	for _, hpa := range unhealthy {
		if grantSpent {
			log.Info("SKIP: heal budget already spent this sweep — cold-start rescues deferred",
				"hpa", hpa.GetNamespace()+"/"+hpa.GetName())
			continue
		}
		if p.rescueZeroTarget(ctx, log, hpa, now) {
			grantSpent = true
		}
	}
	if len(unhealthy) > 0 {
		if grantSpent {
			log.Info("SKIP: heal budget already spent this sweep — metrics-server bounce deferred")
		} else {
			p.maybeBounceMetricsServer(ctx, log, now)
		}
		p.emitHPAEvent(ctx, log, rep.Findings(), now)
	}
	return rep.Result(&p.emitted, hpaScalingUnhealthyGauge.DeleteLabelValues,
		fmt.Sprintf("hpas scaling-unhealthy >=%s: ", hpaUnhealthyMinAge), ", ")
}

// isKEDAManagedHPA reports whether hpa is owned or managed by KEDA.
// KEDA intentionally scales idle targets to 0, causing Kubernetes HPA to
// report Reason=ScalingDisabled; genuine KEDA failures are owned by
// keda-scaledobject-guard.
func isKEDAManagedHPA(hpa *unstructured.Unstructured) bool {
	for _, ref := range hpa.GetOwnerReferences() {
		if ref.Kind == "ScaledObject" || strings.HasPrefix(ref.APIVersion, "keda.sh/") {
			return true
		}
	}
	labels := hpa.GetLabels()
	if labels["app.kubernetes.io/managed-by"] == "keda-operator" ||
		labels["scaledobject.keda.sh/name"] != "" {
		return true
	}
	return strings.HasPrefix(hpa.GetName(), "keda-hpa-")
}

// isScaleToZeroIdleHPA reports whether a False HPA condition reflects an
// intentional scale-to-zero idle state (Reason=ScalingDisabled on an HPA
// with spec.minReplicas==0 or managed by KEDA) rather than a wedged scaler.
// Non-KEDA HPAs with minReplicas>=1 still flag and qualify for cold-start
// rescue.
func isScaleToZeroIdleHPA(hpa *unstructured.Unstructured, c kube.Condition) bool {
	if c.Reason != "ScalingDisabled" {
		return false
	}
	if minRep, found := kube.NestedInt64(hpa.Object, "spec", "minReplicas"); found && minRep == 0 {
		return true
	}
	return isKEDAManagedHPA(hpa)
}

// rescueZeroTarget lifts a scale target wedged at spec.replicas==0
// back to max(hpa.spec.minReplicas, 1) — the HPA-side cold-start
// deadlock twin of the KEDA rescue. Deployment/StatefulSet targets
// resolve through the typed censuses; other kinds are skipped
// (unresolvable stays inconclusive, not "not at zero"). The bool
// return reports whether a heal-budget grant was actually consumed
// and kept (Run uses it to bound this check to one budgeted action
// per sweep).
func (p *hpaScalingGuardCheck) rescueZeroTarget(ctx context.Context,
	log logr.Logger, hpa *unstructured.Unstructured, now time.Time) bool {

	// Never wake up idle KEDA workloads or intentionally scale-to-zero HPAs;
	// keda-scaledobject-guard owns genuine KEDA errors and recovery.
	if isKEDAManagedHPA(hpa) {
		return false
	}
	if minRep, found := kube.NestedInt64(hpa.Object, "spec", "minReplicas"); found && minRep == 0 {
		return false
	}

	ns := hpa.GetNamespace()
	target, ok := kube.NestedString(hpa.Object, "spec", "scaleTargetRef", "name")
	if !ok || target == "" {
		return false
	}
	minReplicas, _ := kube.NestedInt64(hpa.Object, "spec", "minReplicas")
	rescue := max(int32(minReplicas), 1)
	declared, _ := kube.NestedString(hpa.Object, "spec", "scaleTargetRef", "kind")
	return rescueZeroScaleTarget(ctx, p.Deps, log, zeroTargetRescueOpts{
		checkName:    CheckNameHPAScalingGuard,
		sourceLabel:  "hpa",
		ns:           ns,
		declaredKind: declared,
		targetName:   target,
		rescue:       rescue,
		allowRollout: false,
		cooldownKey:  "rescue/" + ns + "/{kind}/" + target,
		cooldown:     hpaRescueCooldown,
	}, now)
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
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning {
			continue // Pending/Succeeded/Failed pods cannot be a
			// metrics-server sibling that should be bounced.
		}
		if kube.PodReadyCond(pod) {
			ready = true
			continue
		}
		// A freshly created or just-flipped pod is still starting —
		// killing it during rollout makes the outage worse. Reuse
		// the same persistence window that gates the HPA finding.
		if unreadyFor, ok := kube.PodUnreadyFor(pod, now); !ok ||
			unreadyFor < hpaUnhealthyMinAge {
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

func (p *hpaScalingGuardCheck) checkHPAMaxSaturated(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	hpa *unstructured.Unstructured,
	key string,
	maxRep, summaryRep *probefw.SweepReport,
	maxKeep map[string]bool,
) bool {
	if hpa.GetDeletionTimestamp() != nil {
		return false
	}
	maxReplicas, hasMax := kube.NestedInt64(hpa.Object, "spec", "maxReplicas")
	currReplicas, hasCurr := kube.NestedInt64(hpa.Object, "status", "currentReplicas")
	if !hasMax || !hasCurr || maxReplicas <= 0 || currReplicas != maxReplicas {
		return false
	}
	sl, ok := kube.ConditionOf(hpa.Object, "ScalingLimited")
	if !ok || sl.Status != "True" {
		return false
	}
	persisted := false
	if !sl.LastTransitionTime.IsZero() {
		persisted = now.Sub(sl.LastTransitionTime) >= hpaMaxSaturatedMinAge
	} else {
		maxKeep[key] = true
		persisted = probefw.Persisted(&p.maxSaturatedSeen, key, now, hpaMaxSaturatedMinAge, log)
	}
	if !persisted {
		return true
	}
	ns, name := hpa.GetNamespace(), hpa.GetName()
	maxRep.Flag(hpaMaxReplicasSaturatedGauge, key, []string{ns, name})
	summaryRep.Find(key + "(max_replicas_saturated)")
	ck := probefw.SelfHealKey(CheckNameHPAScalingGuard, "maxsat/"+key)
	probefw.EmitWarningDeduped(ctx, p.CS, log, &p.maxSaturatedEvents, ck, hpaMaxSaturatedEventCooldown, now, kube.WarningEvent{
		Name:      kube.TruncatedEventName("hpa-max-sat."+name, key, now),
		Namespace: ns,
		Reason:    "HPAMaxReplicasSaturated",
		Note: fmt.Sprintf("HPA %s pinned at currentReplicas == maxReplicas (%d) with ScalingLimited=True >=%s",
			key, maxReplicas, hpaMaxSaturatedMinAge),
		Regarding: corev1.ObjectReference{
			APIVersion: hpa.GetAPIVersion(),
			Kind:       "HorizontalPodAutoscaler",
			Namespace:  ns,
			Name:       name,
			UID:        hpa.GetUID(),
		},
		ReportingInstance: p.Name,
	})
	return true
}

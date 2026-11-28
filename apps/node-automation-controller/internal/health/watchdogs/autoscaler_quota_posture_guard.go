// autoscaler_quota_posture_guard.go — health check "autoscaler-quota-posture-guard":
// read-only auditor detecting two workload scaling/admission posture hazards:
//  1. VPA + HPA / KEDA CPU/Memory scaling conflict: active VerticalPodAutoscaler
//     (updateMode in {"", "Auto", "Recreate", "InPlaceOrRecreate"}) overlapping
//     CPU/Memory control with an autoscaling/v2 HorizontalPodAutoscaler
//     (Resource or ContainerResource metric) or a keda.sh/v1alpha1 ScaledObject
//     (cpu or memory trigger) targeting the same (kind, name) workload.
//  2. ResourceQuota without LimitRange: active non-system namespaces carrying a
//     ResourceQuota with compute hard limits (requests.cpu, limits.cpu,
//     requests.memory, limits.memory, cpu, memory) while having zero LimitRanges
//     defining container/pod default or defaultRequest compute resources.
//
// Zero mutation. Gracefully skips 403 Forbidden and 404/NoMatch without false
// flagging or incrementing error counters.
package watchdogs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameAutoscalerQuotaPostureGuard is the registry check name for VPA+HPA/KEDA & ResourceQuota-without-LimitRange audit.
	CheckNameAutoscalerQuotaPostureGuard = "autoscaler-quota-posture-guard"

	autoscalerPostureEventCooldown       = 6 * time.Hour
	autoscalerPostureEventReasonConflict = "AutoscalerConflict"
	autoscalerPostureEventReasonQuota    = "QuotaWithoutLimitRange"
)

var (
	autoscalerPostureVPAGVR = schema.GroupVersionResource{
		Group: "autoscaling.k8s.io", Version: "v1", Resource: "verticalpodautoscalers"}

	autoscalerPostureConflictGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_vpa_hpa_conflict",
		Help: "1 while an active VPA overlaps CPU/Memory scaling with an HPA or KEDA ScaledObject on the same target.",
	}, []string{"namespace", "vpa", "autoscaler_kind", "autoscaler", "target"})

	autoscalerPostureQuotaNoLimitRangeGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_quota_without_limitrange",
		Help: "1 while an active non-system namespace has a compute ResourceQuota without any LimitRange default/defaultRequest.",
	}, []string{"namespace", "quota"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		autoscalerPostureConflictGauge,
		autoscalerPostureQuotaNoLimitRangeGauge,
	)
}

var autoscalerPostureSystemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"k0s-system":      true,
}

type autoscalerPostureCheck struct {
	*probefw.Deps

	conflictEmitted state.GaugeLedger[string]
	quotaEmitted    state.GaugeLedger[string]
	eventCooldown   state.CooldownSet
}

// NewAutoscalerQuotaPostureGuardCheck constructs the autoscaler-quota-posture-guard check.
func NewAutoscalerQuotaPostureGuardCheck(d *probefw.Deps) probefw.Check {
	return &autoscalerPostureCheck{Deps: d}
}

type autoscalerPostureTargetKey struct {
	namespace string
	kind      string
	name      string
}

type autoscalerPostureResourceMask struct {
	cpu    bool
	memory bool
}

func (m autoscalerPostureResourceMask) overlaps(other autoscalerPostureResourceMask) []string {
	var out []string
	if m.cpu && other.cpu {
		out = append(out, "cpu")
	}
	if m.memory && other.memory {
		out = append(out, "memory")
	}
	return out
}

func (c *autoscalerPostureCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, autoscalerPostureEventCooldown)

	var conflictRep, quotaRep, summaryRep probefw.SweepReport

	c.autoscalerPostureAuditConflicts(ctx, log, now, &conflictRep, &summaryRep)
	c.autoscalerPostureAuditQuotas(ctx, log, now, &quotaRep, &summaryRep)

	conflictRep.Close(&c.conflictEmitted, autoscalerPostureConflictGauge.DeleteLabelValues)
	quotaRep.Close(&c.quotaEmitted, autoscalerPostureQuotaNoLimitRangeGauge.DeleteLabelValues)
	return summaryRep.Verdict("autoscaler/quota posture issues: ", ", ")
}

func (c *autoscalerPostureCheck) autoscalerPostureAuditConflicts(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	conflictRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	if c.Dyn == nil {
		return
	}

	vpas, err := c.AllUnstructured(ctx, autoscalerPostureVPAGVR)
	if err != nil {
		if kube.IsCRDAbsent(err) {
			return
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("VerticalPodAutoscaler list skipped (403)", "error", err)
			for k, lv := range c.conflictEmitted.Last() {
				conflictRep.Carry(k, lv)
			}
			return
		}
		summaryRep.InfraErr(fmt.Errorf("list vpas: %w", err))
		for k, lv := range c.conflictEmitted.Last() {
			conflictRep.Carry(k, lv)
		}
		return
	}

	type activeVPA struct {
		obj       *unstructured.Unstructured
		target    autoscalerPostureTargetKey
		resources autoscalerPostureResourceMask
	}
	var activeVPAs []activeVPA
	for i := range vpas {
		vpa := &vpas[i]
		if vpa.GetDeletionTimestamp() != nil {
			continue
		}
		mode, _ := kube.NestedString(vpa.Object, "spec", "updatePolicy", "updateMode")
		switch mode {
		case "", "Auto", "Recreate", "InPlaceOrRecreate":
		default:
			continue
		}
		targetKind, _ := kube.NestedString(vpa.Object, "spec", "targetRef", "kind")
		targetName, _ := kube.NestedString(vpa.Object, "spec", "targetRef", "name")
		if targetKind == "" || targetName == "" {
			continue
		}
		mask := autoscalerPostureVPAControlledResources(vpa)
		if !mask.cpu && !mask.memory {
			continue
		}
		activeVPAs = append(activeVPAs, activeVPA{
			obj: vpa,
			target: autoscalerPostureTargetKey{
				namespace: vpa.GetNamespace(),
				kind:      targetKind,
				name:      targetName,
			},
			resources: mask,
		})
	}
	if len(activeVPAs) == 0 {
		return
	}

	hpaByTarget := map[autoscalerPostureTargetKey][]struct {
		hpa       *autoscalingv2.HorizontalPodAutoscaler
		resources autoscalerPostureResourceMask
	}{}
	hpaBlocked := false
	hpas, err := kube.ListAll(ctx,
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		},
		autoscalerPostureHPAPage(c.CS))
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("HorizontalPodAutoscaler list skipped", "error", err)
		} else {
			summaryRep.InfraErr(fmt.Errorf("list hpas: %w", err))
		}
		hpaBlocked = true
		autoscalerPostureCarryByKind(conflictRep, &c.conflictEmitted, "HorizontalPodAutoscaler")
	} else {
		for i := range hpas {
			hpa := &hpas[i]
			if hpa.DeletionTimestamp != nil || hpa.Spec.ScaleTargetRef.Kind == "" || hpa.Spec.ScaleTargetRef.Name == "" {
				continue
			}
			mask := autoscalerPostureHPAMetricResources(hpa)
			if !mask.cpu && !mask.memory {
				continue
			}
			tkey := autoscalerPostureTargetKey{
				namespace: hpa.Namespace,
				kind:      hpa.Spec.ScaleTargetRef.Kind,
				name:      hpa.Spec.ScaleTargetRef.Name,
			}
			hpaByTarget[tkey] = append(hpaByTarget[tkey], struct {
				hpa       *autoscalingv2.HorizontalPodAutoscaler
				resources autoscalerPostureResourceMask
			}{hpa: hpa, resources: mask})
		}
	}

	kedaByTarget := map[autoscalerPostureTargetKey][]struct {
		so        *unstructured.Unstructured
		resources autoscalerPostureResourceMask
	}{}
	kedaBlocked := false
	sos, err := c.AllUnstructured(ctx, kube.GVRKedaScaledObject)
	if err != nil {
		if kube.IsCRDAbsent(err) {
			// KEDA not installed on cluster.
		} else if apierrors.IsForbidden(err) {
			log.V(1).Info("ScaledObject list skipped (403)", "error", err)
			kedaBlocked = true
			autoscalerPostureCarryByKind(conflictRep, &c.conflictEmitted, "ScaledObject")
		} else {
			summaryRep.InfraErr(fmt.Errorf("list scaledobjects: %w", err))
			kedaBlocked = true
			autoscalerPostureCarryByKind(conflictRep, &c.conflictEmitted, "ScaledObject")
		}
	} else {
		for i := range sos {
			so := &sos[i]
			if so.GetDeletionTimestamp() != nil {
				continue
			}
			targetKind, _ := kube.NestedString(so.Object, "spec", "scaleTargetRef", "kind")
			if targetKind == "" {
				targetKind = "Deployment"
			}
			targetName, _ := kube.NestedString(so.Object, "spec", "scaleTargetRef", "name")
			if targetName == "" {
				continue
			}
			mask := autoscalerPostureKEDAResources(so)
			if !mask.cpu && !mask.memory {
				continue
			}
			tkey := autoscalerPostureTargetKey{
				namespace: so.GetNamespace(),
				kind:      targetKind,
				name:      targetName,
			}
			kedaByTarget[tkey] = append(kedaByTarget[tkey], struct {
				so        *unstructured.Unstructured
				resources autoscalerPostureResourceMask
			}{so: so, resources: mask})
		}
	}

	for _, vpa := range activeVPAs {
		targetLabel := vpa.target.kind + "/" + vpa.target.name
		if !hpaBlocked {
			for _, match := range hpaByTarget[vpa.target] {
				overlap := vpa.resources.overlaps(match.resources)
				if len(overlap) == 0 {
					continue
				}
				tupleKey := vpa.target.namespace + "/" + vpa.obj.GetName() + "/HPA/" + match.hpa.Name
				conflictRep.Flag(autoscalerPostureConflictGauge, tupleKey,
					[]string{vpa.target.namespace, vpa.obj.GetName(), "HorizontalPodAutoscaler", match.hpa.Name, targetLabel})
				summaryRep.Find(fmt.Sprintf("VPA %s/%s + HPA %s on %s (%s)",
					vpa.target.namespace, vpa.obj.GetName(), match.hpa.Name, targetLabel, strings.Join(overlap, "+")))
				c.autoscalerPostureEmitEvent(ctx, log, now, vpa.target.namespace,
					corev1.ObjectReference{
						APIVersion: "autoscaling.k8s.io/v1",
						Kind:       "VerticalPodAutoscaler",
						Namespace:  vpa.target.namespace,
						Name:       vpa.obj.GetName(),
						UID:        vpa.obj.GetUID(),
					},
					autoscalerPostureEventReasonConflict,
					"autoscaler.vpa.hpa."+vpa.target.namespace+"."+vpa.obj.GetName()+"."+match.hpa.Name,
					fmt.Sprintf("VPA %s/%s conflicts with HPA %s on %s for %s",
						vpa.target.namespace, vpa.obj.GetName(), match.hpa.Name, targetLabel, strings.Join(overlap, "/")))
			}
		}
		if !kedaBlocked {
			for _, match := range kedaByTarget[vpa.target] {
				overlap := vpa.resources.overlaps(match.resources)
				if len(overlap) == 0 {
					continue
				}
				tupleKey := vpa.target.namespace + "/" + vpa.obj.GetName() + "/ScaledObject/" + match.so.GetName()
				conflictRep.Flag(autoscalerPostureConflictGauge, tupleKey,
					[]string{vpa.target.namespace, vpa.obj.GetName(), "ScaledObject", match.so.GetName(), targetLabel})
				summaryRep.Find(fmt.Sprintf("VPA %s/%s + ScaledObject %s on %s (%s)",
					vpa.target.namespace, vpa.obj.GetName(), match.so.GetName(), targetLabel, strings.Join(overlap, "+")))
				c.autoscalerPostureEmitEvent(ctx, log, now, vpa.target.namespace,
					corev1.ObjectReference{
						APIVersion: "autoscaling.k8s.io/v1",
						Kind:       "VerticalPodAutoscaler",
						Namespace:  vpa.target.namespace,
						Name:       vpa.obj.GetName(),
						UID:        vpa.obj.GetUID(),
					},
					autoscalerPostureEventReasonConflict,
					"autoscaler.vpa.keda."+vpa.target.namespace+"."+vpa.obj.GetName()+"."+match.so.GetName(),
					fmt.Sprintf("VPA %s/%s conflicts with KEDA ScaledObject %s on %s for %s",
						vpa.target.namespace, vpa.obj.GetName(), match.so.GetName(), targetLabel, strings.Join(overlap, "/")))
			}
		}
	}
}

func autoscalerPostureCarryByKind(rep *probefw.SweepReport, ledger *state.GaugeLedger[string], kind string) {
	for k, lv := range ledger.Last() {
		if len(lv) >= 3 && lv[2] == kind {
			rep.Carry(k, lv)
		}
	}
}

func autoscalerPostureHPAPage(cs kubernetes.Interface) kube.PageFunc[autoscalingv2.HorizontalPodAutoscaler] {
	return func(ctx context.Context, opts metav1.ListOptions) ([]autoscalingv2.HorizontalPodAutoscaler, string, error) {
		list, err := cs.AutoscalingV2().HorizontalPodAutoscalers(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	}
}

func autoscalerPostureVPAControlledResources(vpa *unstructured.Unstructured) autoscalerPostureResourceMask {
	policies, found := kube.NestedSlice(vpa.Object, "spec", "resourcePolicy", "containerPolicies")
	if !found || len(policies) == 0 {
		return autoscalerPostureResourceMask{cpu: true, memory: true}
	}
	var mask autoscalerPostureResourceMask
	for _, rawPol := range policies {
		pm, ok := rawPol.(map[string]any)
		if !ok {
			continue
		}
		mode, _ := kube.NestedString(pm, "mode")
		if mode == "Off" {
			continue
		}
		resList, hasRes := kube.NestedStringSlice(pm, "controlledResources")
		if !hasRes || len(resList) == 0 {
			return autoscalerPostureResourceMask{cpu: true, memory: true}
		}
		for _, r := range resList {
			switch strings.ToLower(r) {
			case "cpu":
				mask.cpu = true
			case "memory":
				mask.memory = true
			}
		}
	}
	return mask
}

func autoscalerPostureHPAMetricResources(hpa *autoscalingv2.HorizontalPodAutoscaler) autoscalerPostureResourceMask {
	var mask autoscalerPostureResourceMask
	for i := range hpa.Spec.Metrics {
		m := &hpa.Spec.Metrics[i]
		switch m.Type {
		case autoscalingv2.ResourceMetricSourceType:
			if m.Resource != nil {
				switch m.Resource.Name {
				case corev1.ResourceCPU:
					mask.cpu = true
				case corev1.ResourceMemory:
					mask.memory = true
				}
			}
		case autoscalingv2.ContainerResourceMetricSourceType:
			if m.ContainerResource != nil {
				switch m.ContainerResource.Name {
				case corev1.ResourceCPU:
					mask.cpu = true
				case corev1.ResourceMemory:
					mask.memory = true
				}
			}
		}
	}
	return mask
}

func autoscalerPostureKEDAResources(so *unstructured.Unstructured) autoscalerPostureResourceMask {
	var mask autoscalerPostureResourceMask
	triggers, _ := kube.NestedSlice(so.Object, "spec", "triggers")
	for _, rawTrig := range triggers {
		tm, ok := rawTrig.(map[string]any)
		if !ok {
			continue
		}
		t, _ := kube.NestedString(tm, "type")
		switch strings.ToLower(t) {
		case "cpu":
			mask.cpu = true
		case "memory":
			mask.memory = true
		}
	}
	return mask
}

func (c *autoscalerPostureCheck) autoscalerPostureAuditQuotas(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	quotaRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	rqs, err := kube.ListAll(ctx,
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		},
		kube.ResourceQuotas(c.CS, metav1.NamespaceAll))
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("ResourceQuota list skipped", "error", err)
		} else {
			summaryRep.InfraErr(fmt.Errorf("list resourcequotas: %w", err))
		}
		for k, lv := range c.quotaEmitted.Last() {
			quotaRep.Carry(k, lv)
		}
		return
	}
	if len(rqs) == 0 {
		return
	}

	lrs, err := kube.ListAll(ctx,
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		},
		kube.LimitRanges(c.CS, metav1.NamespaceAll))
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("LimitRange list skipped", "error", err)
		} else {
			summaryRep.InfraErr(fmt.Errorf("list limitranges: %w", err))
		}
		for k, lv := range c.quotaEmitted.Last() {
			quotaRep.Carry(k, lv)
		}
		return
	}

	nsActive := map[string]bool{}
	nss, err := c.AllNamespaces(ctx)
	if err != nil {
		if !apierrors.IsForbidden(err) {
			summaryRep.InfraErr(fmt.Errorf("list namespaces: %w", err))
		}
	} else {
		for i := range nss {
			ns := &nss[i]
			nsActive[ns.Name] = ns.DeletionTimestamp == nil && ns.Status.Phase != corev1.NamespaceTerminating
		}
	}

	nsHasComputeDefaults := map[string]bool{}
	for i := range lrs {
		lr := &lrs[i]
		if lr.DeletionTimestamp != nil {
			continue
		}
		if autoscalerPostureLimitRangeHasComputeDefaults(lr) {
			nsHasComputeDefaults[lr.Namespace] = true
		}
	}

	for i := range rqs {
		rq := &rqs[i]
		if rq.DeletionTimestamp != nil || autoscalerPostureSystemNamespaces[rq.Namespace] {
			continue
		}
		if len(nsActive) > 0 {
			if active, known := nsActive[rq.Namespace]; known && !active {
				continue
			}
		}
		if !autoscalerPostureQuotaHasComputeHard(rq) {
			continue
		}
		if nsHasComputeDefaults[rq.Namespace] {
			continue
		}

		key := rq.Namespace + "/" + rq.Name
		quotaRep.Flag(autoscalerPostureQuotaNoLimitRangeGauge, key, []string{rq.Namespace, rq.Name})
		summaryRep.Find(fmt.Sprintf("ResourceQuota %s has compute limits without LimitRange defaults", key))
		c.autoscalerPostureEmitEvent(ctx, log, now, rq.Namespace,
			corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "ResourceQuota",
				Namespace:  rq.Namespace,
				Name:       rq.Name,
				UID:        rq.UID,
			},
			autoscalerPostureEventReasonQuota,
			"quota.nolimitrange."+rq.Namespace+"."+rq.Name,
			fmt.Sprintf("ResourceQuota %s enforces compute limits but namespace %s has no LimitRange defining container/pod default or defaultRequest",
				key, rq.Namespace))
	}
}

func autoscalerPostureQuotaHasComputeHard(rq *corev1.ResourceQuota) bool {
	for _, k := range []corev1.ResourceName{
		corev1.ResourceRequestsCPU,
		corev1.ResourceLimitsCPU,
		corev1.ResourceRequestsMemory,
		corev1.ResourceLimitsMemory,
		corev1.ResourceCPU,
		corev1.ResourceMemory,
	} {
		if _, ok := rq.Spec.Hard[k]; ok {
			return true
		}
	}
	return false
}

func autoscalerPostureLimitRangeHasComputeDefaults(lr *corev1.LimitRange) bool {
	for i := range lr.Spec.Limits {
		item := &lr.Spec.Limits[i]
		if item.Type != "" &&
			item.Type != corev1.LimitTypeContainer &&
			item.Type != corev1.LimitTypePod {
			continue
		}
		if autoscalerPostureResourceListHasCompute(item.Default) ||
			autoscalerPostureResourceListHasCompute(item.DefaultRequest) {
			return true
		}
	}
	return false
}

func autoscalerPostureResourceListHasCompute(rl corev1.ResourceList) bool {
	for _, k := range []corev1.ResourceName{
		corev1.ResourceCPU,
		corev1.ResourceMemory,
		corev1.ResourceRequestsCPU,
		corev1.ResourceLimitsCPU,
		corev1.ResourceRequestsMemory,
		corev1.ResourceLimitsMemory,
	} {
		if _, ok := rl[k]; ok {
			return true
		}
	}
	return false
}

func (c *autoscalerPostureCheck) autoscalerPostureEmitEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	eventNS string,
	regarding corev1.ObjectReference,
	reason string,
	cooldownKey string,
	note string,
) {
	if c.eventCooldown.CooledDown(cooldownKey, autoscalerPostureEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:              kube.TruncatedEventName(cooldownKey, cooldownKey, now),
		Namespace:         eventNS,
		Regarding:         regarding,
		Reason:            reason,
		Note:              note,
		ReportingInstance: c.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: autoscaler/quota event create failed (RBAC?)",
			"reason", reason, "key", cooldownKey, "error", err)
		return
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: "+reason, "key", cooldownKey)
}

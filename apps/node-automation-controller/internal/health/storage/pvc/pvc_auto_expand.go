// pvc_auto_expand.go — health check "pvc-auto-expand": queries Prometheus
// for Bound PVCs with <15% free space sustained >=10m, always emits a
// PVCLowFreeSpace Warning Event + finding, and (when opt-in enabled via
// NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED=true or per-PVC annotation
// passiontech.dev/pvc-auto-expand="true") safely expands
// spec.resources.requests.storage by +25% (min +1Gi), capped at 2x baseline
// (or passiontech.dev/pvc-auto-expand-max), with 6h per-PVC cooldown and
// runaway fill-rate pause protection.
package pvc

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	// CheckNamePVCAutoExpand is the registry check name for pvc-auto-expand.
	CheckNamePVCAutoExpand = "pvc-auto-expand"

	pvcAutoExpandQuery          = `kubelet_volume_stats_available_bytes / kubelet_volume_stats_capacity_bytes < 0.15`
	pvcAutoExpandMinFreeRatio   = 0.15
	pvcAutoExpandMinDuration    = 10 * time.Minute
	pvcAutoExpandCooldown       = 6 * time.Hour
	pvcAutoExpandEventCooldown  = 30 * time.Minute
	pvcAutoExpandRunawayWindow  = 24 * time.Hour
	pvcAutoExpandRunawayMax     = 2
	pvcAutoExpandOneMiB         = int64(1024 * 1024)
	pvcAutoExpandOneGiB         = int64(1024 * 1024 * 1024)
	pvcAutoExpandDefaultCapMult = int64(2)

	annoPVCAutoExpand         = "passiontech.dev/pvc-auto-expand"
	annoPVCAutoExpandBaseline = "passiontech.dev/pvc-auto-expand-baseline"
	annoPVCAutoExpandMax      = "passiontech.dev/pvc-auto-expand-max"

	pvcLowFreeEventReason      = "PVCLowFreeSpace"
	pvcAutoExpandRunawayReason = "PVCAutoExpandRunawayPaused"
	pvcAutoExpandCapReason     = "PVCAutoExpandCapReached"
)

var pvcLowFreeSpaceGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_pvc_low_free_space",
	Help: "1 while a PVC has <15% free space sustained for >=10m.",
}, []string{"namespace", "pvc"})

func init() {
	ctrlmetrics.Registry.MustRegister(pvcLowFreeSpaceGauge)
}

type pvcExpandRecord struct {
	windowStart time.Time
	count       int
	paused      bool
}

type pvcAutoExpandBreach struct {
	ns        string
	name      string
	freeRatio float64
}

type pvcAutoExpandCheck struct {
	*probefw.Deps

	healEnabled bool

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
	expandHistory map[string]*pvcExpandRecord
}

// NewPVCAutoExpandCheck constructs the pvc-auto-expand check, resolving
// NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED once at construction.
func NewPVCAutoExpandCheck(d *probefw.Deps) probefw.Check {
	return &pvcAutoExpandCheck{
		Deps:          d,
		healEnabled:   envx.Gate("NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED", false),
		expandHistory: map[string]*pvcExpandRecord{},
	}
}

func (c *pvcAutoExpandCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, pvcAutoExpandEventCooldown)

	if _, err := c.PromEndpointCtx(ctx); err != nil {
		log.V(1).Info("pvc-auto-expand skipped: prometheus endpoint unavailable", "error", err)
		return c.carryForwardResult()
	}
	samples, err := c.PromQuery(ctx, pvcAutoExpandQuery)
	if err != nil {
		log.V(1).Info("pvc-auto-expand skipped: prometheus query unavailable", "error", err)
		return c.carryForwardResult()
	}

	// Deduplicate by ns/pvc keeping the lowest free ratio reported.
	breachMap := map[string]pvcAutoExpandBreach{}
	for _, s := range samples {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) ||
			s.Value < 0 || s.Value >= pvcAutoExpandMinFreeRatio {
			continue
		}
		ns := s.Label("namespace", "exported_namespace")
		name := s.Label("persistentvolumeclaim", "pvc")
		if ns == "" || name == "" {
			continue
		}
		key := ns + "/" + name
		if prev, ok := breachMap[key]; !ok || s.Value < prev.freeRatio {
			breachMap[key] = pvcAutoExpandBreach{
				ns:        ns,
				name:      name,
				freeRatio: s.Value,
			}
		}
	}

	// Reset runaway tracking for PVCs that recovered above 15% free past the window.
	for k, rec := range c.expandHistory {
		if _, stillLow := breachMap[k]; !stillLow && !rec.paused &&
			now.Sub(rec.windowStart) >= pvcAutoExpandRunawayWindow {
			delete(c.expandHistory, k)
		}
	}

	if len(breachMap) == 0 {
		c.firstSeen.Prune(func(string) bool { return false })
		var rep probefw.SweepReport
		return rep.Result(&c.emitted, pvcLowFreeSpaceGauge.DeleteLabelValues,
			"pvc low free space: ", ", ")
	}

	pvcs, err := c.AllPVCs(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("PVC list skipped (403)", "error", err)
			return c.carryForwardResult()
		}
		return probefw.Result{Infra: fmt.Errorf("list pvcs: %w", err)}
	}
	pvcByKey := make(map[string]*corev1.PersistentVolumeClaim, len(pvcs))
	for i := range pvcs {
		p := &pvcs[i]
		pvcByKey[p.Namespace+"/"+p.Name] = p
	}

	keys := make([]string, 0, len(breachMap))
	for k := range breachMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var rep probefw.SweepReport
	liveFirstSeen := map[string]bool{}
	var expandCandidates []*corev1.PersistentVolumeClaim

	for _, key := range keys {
		b := breachMap[key]
		pvc := pvcByKey[key]
		if pvc == nil || pvc.DeletionTimestamp != nil || pvc.Status.Phase != corev1.ClaimBound {
			continue
		}
		liveFirstSeen[key] = true
		if !probefw.Persisted(&c.firstSeen, key, now, pvcAutoExpandMinDuration, log) {
			continue
		}

		rep.Emit(pvcLowFreeSpaceGauge, key, []string{b.ns, b.name},
			fmt.Sprintf("%s (free=%.1f%%)", key, b.freeRatio*100))

		c.emitLowFreeEvent(ctx, log, pvc, b, now)
		if c.isAutoExpandEligible(ctx, pvc) {
			expandCandidates = append(expandCandidates, pvc)
		}
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })

	if len(expandCandidates) > 0 {
		c.expandCandidates(ctx, log, expandCandidates, now)
	}

	return rep.Result(&c.emitted, pvcLowFreeSpaceGauge.DeleteLabelValues,
		"pvc low free space: ", ", ")
}

func (c *pvcAutoExpandCheck) carryForwardResult() probefw.Result {
	var rep probefw.SweepReport
	for k, lv := range c.emitted.Last() {
		rep.Carry(k, lv)
	}
	rep.Close(&c.emitted, pvcLowFreeSpaceGauge.DeleteLabelValues)
	return probefw.Result{Pass: true}
}

func (c *pvcAutoExpandCheck) isAutoExpandEligible(ctx context.Context, pvc *corev1.PersistentVolumeClaim) bool {
	val := strings.TrimSpace(kube.EffectiveAnno(ctx, pvc, annoPVCAutoExpand))
	if strings.EqualFold(val, "false") {
		return false
	}
	if strings.EqualFold(val, "true") {
		return true
	}
	return c.healEnabled
}

func (c *pvcAutoExpandCheck) emitLowFreeEvent(
	ctx context.Context,
	log logr.Logger,
	pvc *corev1.PersistentVolumeClaim,
	b pvcAutoExpandBreach,
	now time.Time,
) {
	cdKey := "lowspace." + b.ns + "." + b.name
	note := fmt.Sprintf("PVC %s/%s has %.1f%% free space (<15%%) sustained >=%s",
		b.ns, b.name, b.freeRatio*100, pvcAutoExpandMinDuration)
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cdKey, pvcAutoExpandEventCooldown, now, kube.WarningEvent{
		Namespace: b.ns,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "PersistentVolumeClaim",
			Namespace:  b.ns,
			Name:       b.name,
			UID:        pvc.UID,
		},
		Reason:            pvcLowFreeEventReason,
		Note:              note,
		ReportingInstance: c.Name,
	})
}

func (c *pvcAutoExpandCheck) emitPausedEvent(
	ctx context.Context,
	log logr.Logger,
	pvc *corev1.PersistentVolumeClaim,
	reason string,
	note string,
	now time.Time,
) {
	cdKey := "pvc-expand-pause." + reason + "." + pvc.Namespace + "." + pvc.Name
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cdKey, pvcAutoExpandEventCooldown, now, kube.WarningEvent{
		Namespace: pvc.Namespace,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "PersistentVolumeClaim",
			Namespace:  pvc.Namespace,
			Name:       pvc.Name,
			UID:        pvc.UID,
		},
		Reason:            reason,
		Note:              note,
		ReportingInstance: c.Name,
	})
}

func (c *pvcAutoExpandCheck) expandCandidates(
	ctx context.Context,
	log logr.Logger,
	candidates []*corev1.PersistentVolumeClaim,
	now time.Time,
) {
	scMap, defaultSC, ok := c.loadStorageClasses(ctx, log)
	if !ok {
		return
	}

	slices.SortFunc(candidates, func(a, b *corev1.PersistentVolumeClaim) int {
		if d := cmp.Compare(a.Namespace, b.Namespace); d != 0 {
			return d
		}
		return cmp.Compare(a.Name, b.Name)
	})

	for _, pvc := range candidates {
		key := pvc.Namespace + "/" + pvc.Name

		if pvcHasActiveResizeCondition(pvc) {
			log.V(1).Info("skip pvc-auto-expand: resize condition active", "pvc", key)
			continue
		}
		curReq, curCap, sizeOK := pvcCurrentStorage(pvc)
		if !sizeOK {
			continue
		}
		if curCap.Value() > 0 && curReq.Cmp(curCap) > 0 {
			log.V(1).Info("skip pvc-auto-expand: requested > capacity", "pvc", key)
			continue
		}
		if !pvcStorageClassExpandable(pvc, scMap, defaultSC) {
			log.V(1).Info("skip pvc-auto-expand: StorageClass does not allow expansion", "pvc", key)
			continue
		}

		// Compute baseline & cap before consulting cooldown/budget so invalid
		// or already-capped PVCs never consume a fleet budget grant.
		baselineQty, hasBaseline := pvcBaselineQuantity(ctx, pvc, curCap, curReq)
		maxQty, maxOK := pvcMaxAllowedQuantity(ctx, log, pvc, baselineQty)
		if !maxOK {
			continue
		}

		healKey := probefw.SelfHealKey(CheckNamePVCAutoExpand, key)
		if c.Heals.CooledDown(healKey, pvcAutoExpandCooldown, now) {
			log.V(1).Info("skip pvc-auto-expand: inside 6h cooldown", "pvc", key)
			continue
		}

		if c.isRunawayPaused(key, now) {
			c.emitPausedEvent(ctx, log, pvc, pvcAutoExpandRunawayReason,
				fmt.Sprintf("PVC %s auto-expansion paused: >= %d expansions in %s while free space stayed <15%%",
					key, pvcAutoExpandRunawayMax, pvcAutoExpandRunawayWindow),
				now)
			continue
		}

		effectiveCur := curReq
		if curCap.Cmp(effectiveCur) > 0 {
			effectiveCur = curCap
		}
		targetQty := computeExpandedStorage(effectiveCur, maxQty)
		if targetQty.Cmp(effectiveCur) <= 0 {
			c.emitPausedEvent(ctx, log, pvc, pvcAutoExpandCapReason,
				fmt.Sprintf("PVC %s reached max auto-expand cap (%s); manual review required",
					key, maxQty.String()),
				now)
			continue
		}

		proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals, healKey, pvcAutoExpandCooldown, now)
		if unverifiable {
			metrics.IncError(c.Name)
			return
		}
		if !proceed {
			continue
		}

		if !heal.FluxPatchGate("pvc", pvc, CheckNamePVCAutoExpand+":"+key, now) {
			heal.RefundGrant(now)
			log.Info("SKIP: pvc-auto-expand — Flux Heal-Revert Loop", "pvc", key)
			continue
		}

		if allowed, reason := heal.TryAcquireTarget(CheckNamePVCAutoExpand, key, now); !allowed {
			heal.RefundGrant(now)
			log.Info("DEFER: pvc-auto-expand target circuit open", "pvc", key, "reason", reason)
			continue
		}

		if err := c.patchPVCStorage(ctx, pvc, targetQty, baselineQty, !hasBaseline); err != nil {
			if apierrors.IsNotFound(err) {
				heal.RefundTarget(CheckNamePVCAutoExpand, key, now)
				heal.RefundGrant(now)
				continue
			}
			metrics.IncError(c.Name)
			log.Error(err, "pvc-auto-expand patch failed", "pvc", key, "target", targetQty.String())
			continue
		}

		c.Heals.Stamp(healKey, now)
		c.recordExpansion(key, now)
		metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNamePVCAutoExpand).Inc()
		log.Info("ACTION: expanded PVC storage request",
			"pvc", key, "from", curReq.String(), "to", targetQty.String(), "max", maxQty.String())
	}
}

func (c *pvcAutoExpandCheck) loadStorageClasses(ctx context.Context, log logr.Logger) (map[string]*storagev1.StorageClass, *storagev1.StorageClass, bool) {
	scs, err := c.AllStorageClasses(ctx)
	if err != nil {
		log.Info("WARN: storageclass list failed — pvc-auto-expand heal skipped", "error", err)
		return nil, nil, false
	}
	scMap := make(map[string]*storagev1.StorageClass, len(scs))
	var defaultSC *storagev1.StorageClass
	for i := range scs {
		sc := &scs[i]
		scMap[sc.Name] = sc
		if sc.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" ||
			sc.Annotations["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
			defaultSC = sc
		}
	}
	return scMap, defaultSC, true
}

func (c *pvcAutoExpandCheck) isRunawayPaused(key string, now time.Time) bool {
	rec := c.expandHistory[key]
	if rec == nil {
		return false
	}
	if rec.paused {
		return true
	}
	if now.Sub(rec.windowStart) >= pvcAutoExpandRunawayWindow {
		return false
	}
	if rec.count >= pvcAutoExpandRunawayMax {
		rec.paused = true
		return true
	}
	return false
}

func (c *pvcAutoExpandCheck) recordExpansion(key string, now time.Time) {
	rec := c.expandHistory[key]
	if rec == nil || now.Sub(rec.windowStart) >= pvcAutoExpandRunawayWindow {
		c.expandHistory[key] = &pvcExpandRecord{
			windowStart: now,
			count:       1,
		}
		return
	}
	rec.count++
}

func (c *pvcAutoExpandCheck) patchPVCStorage(
	ctx context.Context,
	pvc *corev1.PersistentVolumeClaim,
	targetQty resource.Quantity,
	baselineQty resource.Quantity,
	setBaselineAnno bool,
) error {
	patch := map[string]any{
		"spec": map[string]any{
			"resources": map[string]any{
				"requests": map[string]any{
					string(corev1.ResourceStorage): targetQty.String(),
				},
			},
		},
	}
	var annoPatchBytes []byte
	if setBaselineAnno {
		patch["metadata"] = map[string]any{
			"annotations": map[string]any{
				annoPVCAutoExpandBaseline: baselineQty.String(),
			},
		}
		annoPatchBytes, _ = kube.MergePatchAnnos(map[string]any{
			annoPVCAutoExpandBaseline: baselineQty.String(),
		})
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal pvc expand patch: %w", err)
	}
	if _, err := c.CS.CoreV1().PersistentVolumeClaims(pvc.Namespace).Patch(
		ctx, pvc.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{},
	); err != nil {
		return err
	}
	if len(annoPatchBytes) > 0 {
		kube.RecordAnnoPatch(ctx, pvc, annoPatchBytes)
	}
	return nil
}

func pvcHasActiveResizeCondition(pvc *corev1.PersistentVolumeClaim) bool {
	for _, cond := range pvc.Status.Conditions {
		if cond.Status != corev1.ConditionTrue {
			continue
		}
		if cond.Type == corev1.PersistentVolumeClaimResizing ||
			cond.Type == corev1.PersistentVolumeClaimFileSystemResizePending {
			return true
		}
	}
	return false
}

func pvcCurrentStorage(pvc *corev1.PersistentVolumeClaim) (req, capQty resource.Quantity, ok bool) {
	if pvc.Spec.Resources.Requests != nil {
		req = pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	}
	if pvc.Status.Capacity != nil {
		capQty = pvc.Status.Capacity[corev1.ResourceStorage]
	}
	if req.Value() <= 0 {
		if capQty.Value() <= 0 {
			return req, capQty, false
		}
		req = capQty
	}
	return req, capQty, true
}

func pvcStorageClassExpandable(
	pvc *corev1.PersistentVolumeClaim,
	scMap map[string]*storagev1.StorageClass,
	defaultSC *storagev1.StorageClass,
) bool {
	var sc *storagev1.StorageClass
	if pvc.Spec.StorageClassName == nil {
		sc = defaultSC
	} else if *pvc.Spec.StorageClassName != "" {
		sc = scMap[*pvc.Spec.StorageClassName]
	}
	return sc != nil && sc.AllowVolumeExpansion != nil && *sc.AllowVolumeExpansion
}

func pvcBaselineQuantity(
	ctx context.Context,
	pvc *corev1.PersistentVolumeClaim,
	curCap, curReq resource.Quantity,
) (resource.Quantity, bool) {
	if raw := strings.TrimSpace(kube.EffectiveAnno(ctx, pvc, annoPVCAutoExpandBaseline)); raw != "" {
		if q, err := resource.ParseQuantity(raw); err == nil && q.Value() > 0 {
			return q, true
		}
	}
	if curCap.Value() > 0 {
		return curCap, false
	}
	return curReq, false
}

func pvcMaxAllowedQuantity(
	ctx context.Context,
	log logr.Logger,
	pvc *corev1.PersistentVolumeClaim,
	baseline resource.Quantity,
) (resource.Quantity, bool) {
	if raw := strings.TrimSpace(kube.EffectiveAnno(ctx, pvc, annoPVCAutoExpandMax)); raw != "" {
		q, err := resource.ParseQuantity(raw)
		if err != nil || q.Value() <= 0 {
			log.Info("WARN: invalid pvc-auto-expand-max annotation — skipping expansion",
				"pvc", pvc.Namespace+"/"+pvc.Name, "value", raw)
			return resource.Quantity{}, false
		}
		return q, true
	}
	bVal := baseline.Value()
	if bVal <= 0 {
		return resource.Quantity{}, false
	}
	var maxBytes int64
	if bVal > math.MaxInt64/pvcAutoExpandDefaultCapMult {
		maxBytes = math.MaxInt64
	} else {
		maxBytes = bVal * pvcAutoExpandDefaultCapMult
	}
	return *resource.NewQuantity(maxBytes, resource.BinarySI), true
}

func computeExpandedStorage(cur, maxQty resource.Quantity) resource.Quantity {
	curBytes := cur.Value()
	delta := curBytes / 4
	if delta < pvcAutoExpandOneGiB {
		delta = pvcAutoExpandOneGiB
	}
	var targetBytes int64
	if curBytes > math.MaxInt64-delta {
		targetBytes = math.MaxInt64
	} else {
		targetBytes = curBytes + delta
	}
	// Round up to clean MiB boundary (GiB quantities format cleanly as Gi when exact).
	var roundedBytes int64
	if targetBytes > math.MaxInt64-(pvcAutoExpandOneMiB-1) {
		roundedBytes = (math.MaxInt64 / pvcAutoExpandOneMiB) * pvcAutoExpandOneMiB
	} else {
		roundedBytes = ((targetBytes + pvcAutoExpandOneMiB - 1) / pvcAutoExpandOneMiB) * pvcAutoExpandOneMiB
	}
	if roundedBytes > maxQty.Value() {
		roundedBytes = maxQty.Value()
	}
	return *resource.NewQuantity(roundedBytes, resource.BinarySI)
}

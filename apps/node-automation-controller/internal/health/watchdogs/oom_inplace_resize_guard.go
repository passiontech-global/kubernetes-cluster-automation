// oom_inplace_resize_guard.go — health check "oom-inplace-resize-guard":
// scans Running pods for containers with LastTerminationState.Terminated.Reason
// == "OOMKilled" and >=3 OOM restarts within a 15m window (tracking per-pod/
// container restart baselines cleanly across sweeps). Always emits a Warning
// Event (OOMResizeBurst) + finding. When opt-in enabled
// (NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED=true on curated infra
// allowlist, or per-pod annotation passiontech.dev/oom-inplace-resize="true"),
// bumps container memory.limits by +25% (min +64Mi) up to 2x original limit
// via the K8s 1.33+ pod /resize subresource after checking node Allocatable
// memory headroom, gracefully skipping 403/404/422 with budget refund.
//
// SYMBOL HYGIENE: every package-private symbol in this file uses the
// oomResize* prefix to prevent collisions in package watchdogs.
package watchdogs

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
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
	// CheckNameOOMInplaceResizeGuard is the registry check name for oom-inplace-resize-guard.
	CheckNameOOMInplaceResizeGuard = "oom-inplace-resize-guard"

	oomResizeWindow           = 15 * time.Minute
	oomResizeMinRestarts      = int32(3)
	oomResizeCooldown         = time.Hour
	oomResizeEventCooldown    = 30 * time.Minute
	oomResizeMinBumpBytes     = int64(64 * 1024 * 1024)
	oomResizeOneMiB           = int64(1024 * 1024)
	oomResizeMaxMultiplier    = int64(2)
	oomResizeMaxSkewTolerance = time.Minute

	oomResizeAnnoOptIn     = "passiontech.dev/oom-inplace-resize"
	oomResizeAnnoOrigLimit = "passiontech.dev/oom-resize-orig-limit"
	oomResizeEventReason   = "OOMResizeBurst"
)

var oomResizeBurstGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_oom_inplace_resize_burst",
	Help: "1 while a Running pod container hit >=3 OOMKilled restarts within 15m.",
}, []string{"namespace", "pod", "container"})

func init() {
	ctrlmetrics.Registry.MustRegister(oomResizeBurstGauge)
}

var oomResizeInfraAllowlist = []string{
	"coredns",
	"linkerd-proxy",
	"cilium-operator",
	"cert-manager",
	"flux-system",
}

type oomResizeHit struct {
	at    time.Time
	count int32
}

type oomResizeBaseline struct {
	prevRestartCount int32
	hits             []oomResizeHit
}

type oomResizeCandidate struct {
	pod       *corev1.Pod
	container string
	oomCount  int32
}

type oomResizeGuardCheck struct {
	*probefw.Deps

	healEnabled bool

	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
	baselines     map[string]*oomResizeBaseline
	origLimits    map[string]resource.Quantity
}

// NewOOMInplaceResizeGuardCheck constructs the oom-inplace-resize-guard check,
// resolving NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED once at startup.
func NewOOMInplaceResizeGuardCheck(d *probefw.Deps) probefw.Check {
	return &oomResizeGuardCheck{
		Deps:        d,
		healEnabled: envx.Gate("NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED", false),
		baselines:   map[string]*oomResizeBaseline{},
		origLimits:  map[string]resource.Quantity{},
	}
}

func (c *oomResizeGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, oomResizeEventCooldown)

	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var rep probefw.SweepReport
	liveBaselines := map[string]bool{}
	var candidates []oomResizeCandidate

	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, cs := range pod.Status.ContainerStatuses {
			bKey := oomResizeBaselineKey(pod, cs.Name)
			liveBaselines[bKey] = true

			count := c.observeContainerOOM(pod, cs, bKey, now)
			if count < oomResizeMinRestarts {
				continue
			}

			tupleKey := pod.Namespace + "/" + pod.Name + "/" + cs.Name
			rep.Emit(oomResizeBurstGauge, tupleKey,
				[]string{pod.Namespace, pod.Name, cs.Name},
				fmt.Sprintf("%s/%s[%s] (oom=%d/15m)", pod.Namespace, pod.Name, cs.Name, count))

			c.emitOOMWarningEvent(ctx, log, pod, cs.Name, count, now)
			candidates = append(candidates, oomResizeCandidate{
				pod:       pod,
				container: cs.Name,
				oomCount:  count,
			})
		}
	}

	for k := range c.baselines {
		if !liveBaselines[k] {
			delete(c.baselines, k)
		}
	}

	if len(candidates) > 0 {
		c.applyResizeRelief(ctx, log, pods, candidates, now)
	}

	return rep.Result(&c.emitted, oomResizeBurstGauge.DeleteLabelValues,
		"oom restart burst: ", ", ")
}

func oomResizeBaselineKey(pod *corev1.Pod, container string) string {
	return pod.Namespace + "/" + pod.Name + "/" + string(pod.UID) + "/" + container
}

func oomResizeIsRecentOOM(cs corev1.ContainerStatus, now time.Time) (time.Time, bool) {
	term := cs.LastTerminationState.Terminated
	if term == nil || term.Reason != "OOMKilled" {
		return time.Time{}, false
	}
	finished := term.FinishedAt.Time
	if finished.IsZero() {
		return time.Time{}, false
	}
	if finished.Sub(now) > oomResizeMaxSkewTolerance {
		return time.Time{}, false
	}
	if kube.AgeAtLeast(finished, now, oomResizeWindow) {
		return time.Time{}, false
	}
	return finished, true
}

func (c *oomResizeGuardCheck) observeContainerOOM(
	pod *corev1.Pod,
	cs corev1.ContainerStatus,
	bKey string,
	now time.Time,
) int32 {
	st, exists := c.baselines[bKey]
	finishedAt, recentOOM := oomResizeIsRecentOOM(cs, now)
	isOOMTerm := cs.LastTerminationState.Terminated != nil &&
		cs.LastTerminationState.Terminated.Reason == "OOMKilled"

	if !exists {
		st = &oomResizeBaseline{prevRestartCount: cs.RestartCount}
		if recentOOM && cs.RestartCount > 0 {
			// If pod itself is younger than 15m (non-zero CreationTimestamp),
			// all RestartCount restarts occurred inside the 15m window.
			if !pod.CreationTimestamp.IsZero() &&
				!kube.AgeAtLeast(pod.CreationTimestamp.Time, now, oomResizeWindow) {
				st.hits = append(st.hits, oomResizeHit{at: finishedAt, count: cs.RestartCount})
			} else {
				st.hits = append(st.hits, oomResizeHit{at: finishedAt, count: 1})
			}
		}
		c.baselines[bKey] = st
	} else {
		delta := cs.RestartCount - st.prevRestartCount
		if delta < 0 {
			st.hits = nil
			st.prevRestartCount = cs.RestartCount
		} else if delta > 0 {
			st.prevRestartCount = cs.RestartCount
			if isOOMTerm {
				hitTime := now
				if recentOOM {
					hitTime = finishedAt
				} else if !cs.LastTerminationState.Terminated.FinishedAt.IsZero() &&
					kube.AgeAtLeast(cs.LastTerminationState.Terminated.FinishedAt.Time, now, oomResizeWindow) {
					hitTime = time.Time{}
				}
				if !hitTime.IsZero() {
					st.hits = append(st.hits, oomResizeHit{at: hitTime, count: delta})
				}
			}
		}
	}

	// Prune hits that aged out of the 15m sliding window.
	kept := st.hits[:0]
	var total int32
	for _, h := range st.hits {
		if kube.AgeAtLeast(h.at, now, oomResizeWindow) {
			continue
		}
		kept = append(kept, h)
		total += h.count
	}
	st.hits = kept
	if !isOOMTerm {
		return 0
	}
	return total
}

func (c *oomResizeGuardCheck) emitOOMWarningEvent(
	ctx context.Context,
	log logr.Logger,
	pod *corev1.Pod,
	container string,
	oomCount int32,
	now time.Time,
) {
	cdKey := "oomresize." + pod.Namespace + "." + pod.Name + "." + container
	if c.eventCooldown.CooledDown(cdKey, oomResizeEventCooldown, now) {
		return
	}
	note := fmt.Sprintf("Container %s in Pod %s/%s hit %d OOMKilled restarts inside %s",
		container, pod.Namespace, pod.Name, oomCount, oomResizeWindow)
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName(cdKey, cdKey, now),
		Namespace: pod.Namespace,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
			UID:        pod.UID,
		},
		Reason:            oomResizeEventReason,
		Note:              note,
		ReportingInstance: c.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: OOMResizeBurst event create failed (RBAC?)",
			"pod", pod.Namespace+"/"+pod.Name, "container", container, "error", err)
		return
	}
	c.eventCooldown.Stamp(cdKey, now)
	log.Info("EVENT: OOMResizeBurst",
		"pod", pod.Namespace+"/"+pod.Name, "container", container, "ooms", oomCount)
}

func (c *oomResizeGuardCheck) applyResizeRelief(
	ctx context.Context,
	log logr.Logger,
	allPods []corev1.Pod,
	candidates []oomResizeCandidate,
	now time.Time,
) {
	var eligible []oomResizeCandidate
	for _, cand := range candidates {
		if cand.pod.Annotations["kubernetes.io/config.mirror"] != "" {
			continue
		}
		if oomResizePodEligible(ctx, cand.pod, cand.container, c.healEnabled) {
			eligible = append(eligible, cand)
		}
	}
	if len(eligible) == 0 {
		return
	}

	nodes, err := c.AllNodes(ctx)
	if err != nil {
		log.Info("WARN: list nodes failed — oom inplace resize skipped", "error", err)
		return
	}
	nodeByName := make(map[string]*corev1.Node, len(nodes))
	for i := range nodes {
		nodeByName[nodes[i].Name] = &nodes[i]
	}
	nodeUsedMem := oomResizeNodeAllocatedMem(allPods)

	slices.SortFunc(eligible, func(a, b oomResizeCandidate) int {
		if d := cmp.Compare(a.pod.Namespace, b.pod.Namespace); d != 0 {
			return d
		}
		if d := cmp.Compare(a.pod.Name, b.pod.Name); d != 0 {
			return d
		}
		return cmp.Compare(a.container, b.container)
	})

	for _, cand := range eligible {
		pod := cand.pod
		podKey := pod.Namespace + "/" + pod.Name

		specContainer := oomResizeFindSpecContainer(pod, cand.container)
		if specContainer == nil {
			continue
		}
		curLimit := specContainer.Resources.Limits[corev1.ResourceMemory]
		if curLimit.Value() <= 0 {
			continue
		}
		curReq := specContainer.Resources.Requests[corev1.ResourceMemory]

		origLimit, hasOrigAnno := c.resolveOrigLimit(ctx, pod, cand.container, curLimit)
		newLimit := oomResizeComputeNewLimit(curLimit, origLimit)
		if newLimit.Cmp(curLimit) <= 0 {
			log.V(1).Info("skip oom-inplace-resize: 2x limit cap reached",
				"pod", podKey, "container", cand.container, "limit", curLimit.String())
			continue
		}

		// Node Allocatable memory headroom check before acquiring heal budget.
		neededDelta := newLimit.Value() - curLimit.Value()
		if !oomResizeHasNodeHeadroom(nodeByName[pod.Spec.NodeName], nodeUsedMem[pod.Spec.NodeName], neededDelta) {
			log.Info("SKIP: oom-inplace-resize — insufficient node memory headroom",
				"pod", podKey, "node", pod.Spec.NodeName, "neededBytes", neededDelta)
			continue
		}

		healKey := probefw.SelfHealKey(CheckNameOOMInplaceResizeGuard, podKey)
		proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals, healKey, oomResizeCooldown, now)
		if unverifiable {
			metrics.IncError(c.Name)
			return
		}
		if !proceed {
			continue
		}

		targetKey := kube.PodControllerKey(pod)
		if allowed, reason := heal.TryAcquireTarget(CheckNameOOMInplaceResizeGuard, targetKey, now); !allowed {
			heal.RefundGrant(now)
			log.Info("DEFER: oom-inplace-resize target circuit open",
				"pod", podKey, "target", targetKey, "reason", reason)
			continue
		}

		includeReq := (curReq.Value() > 0 && curReq.Cmp(curLimit) == 0) || curReq.Cmp(newLimit) > 0
		patchBytes, err := oomResizeBuildPatch(cand.container, newLimit, includeReq)
		if err != nil {
			heal.RefundTarget(CheckNameOOMInplaceResizeGuard, targetKey, now)
			heal.RefundGrant(now)
			metrics.IncError(c.Name)
			continue
		}

		_, patchErr := c.CS.CoreV1().Pods(pod.Namespace).Patch(
			ctx, pod.Name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}, "resize",
		)
		if patchErr != nil {
			if oomResizeIsUnsupportedOrGone(patchErr) {
				heal.RefundTarget(CheckNameOOMInplaceResizeGuard, targetKey, now)
				heal.RefundGrant(now)
				log.Info("SKIP: oom-inplace-resize unavailable/rejected on pod",
					"pod", podKey, "container", cand.container, "error", patchErr)
				continue
			}
			metrics.IncError(c.Name)
			log.Error(patchErr, "oom-inplace-resize patch failed",
				"pod", podKey, "container", cand.container)
			continue
		}

		c.Heals.Stamp(healKey, now)
		nodeUsedMem[pod.Spec.NodeName] += neededDelta
		c.recordOrigLimit(ctx, pod, cand.container, origLimit, hasOrigAnno)
		metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameOOMInplaceResizeGuard).Inc()
		log.Info("ACTION: applied in-place OOM memory resize",
			"pod", podKey, "container", cand.container,
			"from", curLimit.String(), "to", newLimit.String(), "orig", origLimit.String())
	}
}

func oomResizePodEligible(ctx context.Context, pod *corev1.Pod, container string, healEnabled bool) bool {
	val := strings.TrimSpace(kube.EffectiveAnno(ctx, pod, oomResizeAnnoOptIn))
	if strings.EqualFold(val, "false") {
		return false
	}
	if strings.EqualFold(val, "true") {
		return true
	}
	if !healEnabled {
		return false
	}
	return oomResizeMatchesAllowlist(pod, container)
}

func oomResizeMatchesAllowlist(pod *corev1.Pod, container string) bool {
	ctrl := metav1.GetControllerOf(pod)
	ctrlName := ""
	if ctrl != nil {
		ctrlName = ctrl.Name
	}
	for _, entry := range oomResizeInfraAllowlist {
		if container == entry || strings.HasPrefix(container, entry+"-") {
			return true
		}
		if pod.Namespace == entry {
			return true
		}
		if pod.Name == entry || strings.HasPrefix(pod.Name, entry+"-") {
			return true
		}
		if ctrlName != "" && (ctrlName == entry || strings.HasPrefix(ctrlName, entry+"-")) {
			return true
		}
	}
	return false
}

func oomResizeFindSpecContainer(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	return nil
}

func oomResizeNodeAllocatedMem(pods []corev1.Pod) map[string]int64 {
	used := map[string]int64{}
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp != nil ||
			p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed ||
			p.Spec.NodeName == "" {
			continue
		}
		for _, c := range p.Spec.Containers {
			reqQty := c.Resources.Requests[corev1.ResourceMemory]
			limQty := c.Resources.Limits[corev1.ResourceMemory]
			if reqQty.Value() > 0 {
				used[p.Spec.NodeName] += reqQty.Value()
			} else if limQty.Value() > 0 {
				used[p.Spec.NodeName] += limQty.Value()
			}
		}
	}
	return used
}

func oomResizeHasNodeHeadroom(node *corev1.Node, usedBytes, neededBytes int64) bool {
	if node == nil {
		return false
	}
	allocQty := node.Status.Allocatable[corev1.ResourceMemory]
	alloc := allocQty.Value()
	if alloc <= 0 {
		return false
	}
	return alloc-usedBytes >= neededBytes
}

func (c *oomResizeGuardCheck) resolveOrigLimit(
	ctx context.Context,
	pod *corev1.Pod,
	container string,
	curLimit resource.Quantity,
) (resource.Quantity, bool) {
	if raw := strings.TrimSpace(kube.EffectiveAnno(ctx, pod, oomResizeAnnoOrigLimit)); raw != "" {
		if q, err := resource.ParseQuantity(raw); err == nil && q.Value() > 0 {
			return q, true
		}
		var m map[string]string
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			if cRaw, ok := m[container]; ok {
				if q, err := resource.ParseQuantity(cRaw); err == nil && q.Value() > 0 {
					return q, true
				}
			}
		}
	}
	memKey := pod.Namespace + "/" + pod.Name + "/" + container
	if q, ok := c.origLimits[memKey]; ok && q.Value() > 0 {
		return q, false
	}
	return curLimit, false
}

func (c *oomResizeGuardCheck) recordOrigLimit(
	ctx context.Context,
	pod *corev1.Pod,
	container string,
	origLimit resource.Quantity,
	hasOrigAnno bool,
) {
	memKey := pod.Namespace + "/" + pod.Name + "/" + container
	if _, ok := c.origLimits[memKey]; !ok {
		c.origLimits[memKey] = origLimit
	}
	if hasOrigAnno {
		return
	}
	m := map[string]string{container: origLimit.String()}
	if raw := strings.TrimSpace(kube.EffectiveAnno(ctx, pod, oomResizeAnnoOrigLimit)); raw != "" {
		var existing map[string]string
		if err := json.Unmarshal([]byte(raw), &existing); err == nil {
			existing[container] = origLimit.String()
			m = existing
		}
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return
	}
	annoPatch, err := kube.MergePatchAnnos(map[string]any{
		oomResizeAnnoOrigLimit: string(encoded),
	})
	if err != nil {
		return
	}
	if _, err := c.CS.CoreV1().Pods(pod.Namespace).Patch(
		ctx, pod.Name, types.MergePatchType, annoPatch, metav1.PatchOptions{},
	); err == nil {
		kube.RecordAnnoPatch(ctx, pod, annoPatch)
	}
}

func oomResizeComputeNewLimit(curLimit, origLimit resource.Quantity) resource.Quantity {
	curBytes := curLimit.Value()
	delta := curBytes / 4
	if delta < oomResizeMinBumpBytes {
		delta = oomResizeMinBumpBytes
	}
	targetBytes := curBytes + delta
	roundedBytes := ((targetBytes + oomResizeOneMiB - 1) / oomResizeOneMiB) * oomResizeOneMiB
	maxBytes := origLimit.Value() * oomResizeMaxMultiplier
	if roundedBytes > maxBytes {
		roundedBytes = maxBytes
	}
	return *resource.NewQuantity(roundedBytes, resource.BinarySI)
}

func oomResizeBuildPatch(container string, newLimit resource.Quantity, includeReq bool) ([]byte, error) {
	resources := map[string]any{
		"limits": map[string]any{
			string(corev1.ResourceMemory): newLimit.String(),
		},
	}
	if includeReq {
		resources["requests"] = map[string]any{
			string(corev1.ResourceMemory): newLimit.String(),
		}
	}
	payload := map[string]any{
		"spec": map[string]any{
			"containers": []map[string]any{
				{
					"name":      container,
					"resources": resources,
				},
			},
		},
	}
	return json.Marshal(payload)
}

func oomResizeIsUnsupportedOrGone(err error) bool {
	if apierrors.IsForbidden(err) ||
		apierrors.IsNotFound(err) ||
		apierrors.IsInvalid(err) ||
		apierrors.IsMethodNotSupported(err) {
		return true
	}
	var se apierrors.APIStatus
	if errors.As(err, &se) {
		code := int(se.Status().Code)
		if code == http.StatusForbidden ||
			code == http.StatusNotFound ||
			code == http.StatusUnprocessableEntity {
			return true
		}
	}
	return false
}

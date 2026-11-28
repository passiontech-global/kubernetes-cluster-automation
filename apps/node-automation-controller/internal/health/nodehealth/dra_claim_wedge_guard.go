// dra_claim_wedge_guard.go — health check "dra-claim-wedge-guard" (R6-K6):
// detects Dynamic Resource Allocation (resource.k8s.io/v1) ResourceClaims
// wedged in terminating_stuck, unallocated_stuck, zombie_reserved (ALL
// reservedFor consumers dead/missing), or dead_node_allocation past min age
// (default 15m via NODE_AUTOMATION_DRA_CLAIM_MIN_AGE).
//
// Emits node_automation_dra_claim_wedged{namespace,claim,reason} and
// cooldown-deduped Warning Events (DRAClaimWedged). When remediation is enabled
// (NODE_AUTOMATION_DRA_CLAIM_REMEDIATE_ENABLED=true, default true), clears
// all-dead status.reservedFor via /status merge patch (after live Pods.Get
// confirmation; NEVER mutates claims with any live or non-Pod consumer) and
// optionally bounces wedged DRA driver DaemonSet pods on pinned live nodes.
// Auto-skips cleanly when resource.k8s.io/v1 is absent.
package nodehealth

import (
	"cmp"
	"context"
	json "encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	// CheckNameDRAClaimWedgeGuard is the registry check name for R6-K6.
	CheckNameDRAClaimWedgeGuard = "dra-claim-wedge-guard"

	draClaimDefaultMinAge            = 15 * time.Minute
	draClaimEventCooldown            = 30 * time.Minute
	draClaimHealCooldown             = 30 * time.Minute
	draClaimEventReason              = "DRAClaimWedged"
	draClaimMaxDriverBouncesPerSweep = 2

	draReasonTerminatingStuck   = "terminating_stuck"
	draReasonUnallocatedStuck   = "unallocated_stuck"
	draReasonZombieReserved     = "zombie_reserved"
	draReasonDeadNodeAllocation = "dead_node_allocation"
)

var (
	draClaimWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_dra_claim_wedged",
		Help: "1 while a DRA ResourceClaim is wedged in terminating_stuck, unallocated_stuck, zombie_reserved, or dead_node_allocation past min age.",
	}, []string{"namespace", "claim", "reason"})

	draClaimHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_dra_claim_heals_total",
		Help: "Total DRA ResourceClaim remediations executed by action.",
	}, []string{"action"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		draClaimWedgedGauge,
		draClaimHealsTotal,
	)
}

type draClaimWedgeGuardCheck struct {
	*probefw.Deps

	minAge           time.Duration
	remediateEnabled bool

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewDRAClaimWedgeGuardCheck constructs the dra-claim-wedge-guard check,
// resolving env knobs once at construction.
func NewDRAClaimWedgeGuardCheck(d *probefw.Deps) probefw.Check {
	minAge := envx.GetenvDuration("NODE_AUTOMATION_DRA_CLAIM_MIN_AGE", draClaimDefaultMinAge)
	if minAge <= 0 {
		minAge = draClaimDefaultMinAge
	}
	return &draClaimWedgeGuardCheck{
		Deps:             d,
		minAge:           minAge,
		remediateEnabled: envx.Gate("NODE_AUTOMATION_DRA_CLAIM_REMEDIATE_ENABLED", true),
	}
}

func (c *draClaimWedgeGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	minAge := c.minAge
	if minAge <= 0 {
		minAge = draClaimDefaultMinAge
	}
	c.eventCooldown.PruneExpired(now, draClaimEventCooldown)

	if r := c.RequireDyn("dra resourceclaim wedge guard"); r != nil {
		return *r
	}

	var rep probefw.SweepReport
	rawClaims, err := c.AllUnstructured(ctx, kube.GVRResourceClaim)
	switch {
	case kube.IsCRDAbsent(err):
		c.firstSeen.Prune(func(string) bool { return false })
		return rep.Result(&c.emitted, draClaimWedgedGauge.DeleteLabelValues,
			"dra resourceclaims wedged: ", ", ")
	case apierrors.IsForbidden(err):
		log.V(1).Info("ResourceClaim list skipped (403)", "error", err)
		for k, lv := range c.emitted.Last() {
			rep.Carry(k, lv)
		}
		return rep.Result(&c.emitted, draClaimWedgedGauge.DeleteLabelValues,
			"dra resourceclaims wedged: ", ", ")
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list resourceclaims: %w", err)}
	}

	if len(rawClaims) == 0 {
		c.firstSeen.Prune(func(string) bool { return false })
		return rep.Result(&c.emitted, draClaimWedgedGauge.DeleteLabelValues,
			"dra resourceclaims wedged: ", ", ")
	}

	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	nodes, nodesErr := c.AllNodes(ctx)
	nodesKnown := nodesErr == nil
	if nodesErr != nil {
		rep.InfraErr(fmt.Errorf("list nodes: %w", nodesErr))
	}

	podByKey := make(map[string]*corev1.Pod, len(pods))
	for i := range pods {
		podByKey[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}
	nodeByName := make(map[string]*corev1.Node, len(nodes))
	if nodesKnown {
		for i := range nodes {
			nodeByName[nodes[i].Name] = &nodes[i]
		}
	}

	liveFirstSeen := map[string]bool{}
	driverBounces := 0

	for i := range rawClaims {
		var claim resourcev1.ResourceClaim
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(rawClaims[i].Object, &claim); err != nil {
			log.Error(err, "decode ResourceClaim failed", "namespace", rawClaims[i].GetNamespace(), "name", rawClaims[i].GetName())
			continue
		}

		claimKey := claim.Namespace + "/" + claim.Name
		var reason string

		switch {
		case claim.DeletionTimestamp != nil:
			if len(claim.Finalizers) == 0 {
				continue
			}
			fsKey := claimKey + "/" + draReasonTerminatingStuck
			if !c.claimPersisted(log, now, minAge, fsKey, claim.DeletionTimestamp.Time, liveFirstSeen) {
				continue
			}
			reason = draReasonTerminatingStuck

		case claim.Status.Allocation == nil:
			fsKey := claimKey + "/" + draReasonUnallocatedStuck
			if !c.claimPersisted(log, now, minAge, fsKey, claim.CreationTimestamp.Time, liveFirstSeen) {
				continue
			}
			reason = draReasonUnallocatedStuck

		case len(claim.Status.ReservedFor) > 0:
			// CRITICAL: if ANY reservedFor entry is live or non-Pod, treat as
			// healthy and NEVER patch or delete.
			if !allReservedConsumersDead(&claim, podByKey, nodeByName, nodesKnown, now, minAge) {
				continue
			}
			refTime := claim.CreationTimestamp.Time
			if claim.Status.Allocation.AllocationTimestamp != nil && !claim.Status.Allocation.AllocationTimestamp.IsZero() {
				refTime = claim.Status.Allocation.AllocationTimestamp.Time
			}
			fsKey := claimKey + "/" + draReasonZombieReserved
			if !c.claimPersisted(log, now, minAge, fsKey, refTime, liveFirstSeen) {
				continue
			}
			reason = draReasonZombieReserved

		default:
			pinned := pinnedNodeName(&claim)
			if pinned == "" || !nodesKnown {
				continue
			}
			node := nodeByName[pinned]
			if node == nil {
				refTime := claim.CreationTimestamp.Time
				if claim.Status.Allocation.AllocationTimestamp != nil && !claim.Status.Allocation.AllocationTimestamp.IsZero() {
					refTime = claim.Status.Allocation.AllocationTimestamp.Time
				}
				fsKey := claimKey + "/" + draReasonDeadNodeAllocation
				if !c.claimPersisted(log, now, minAge, fsKey, refTime, liveFirstSeen) {
					continue
				}
			} else if !nodeDeadPastAge(node, now, minAge) {
				continue
			}
			reason = draReasonDeadNodeAllocation
		}

		tupleKey := claimKey + "/" + reason
		rep.Emit(draClaimWedgedGauge, tupleKey,
			[]string{claim.Namespace, claim.Name, reason},
			fmt.Sprintf("%s (%s)", claimKey, reason))
		c.emitClaimEvent(ctx, log, now, &claim, reason)

		if !c.remediateEnabled {
			continue
		}
		switch reason {
		case draReasonZombieReserved:
			c.clearReservedFor(ctx, log, now, &claim)
		case draReasonTerminatingStuck:
			cleared := false
			if len(claim.Status.ReservedFor) > 0 && allReservedConsumersDead(&claim, podByKey, nodeByName, nodesKnown, now, minAge) {
				cleared = c.clearReservedFor(ctx, log, now, &claim)
			}
			if !cleared && driverBounces < draClaimMaxDriverBouncesPerSweep {
				if pinned := pinnedNodeName(&claim); pinned != "" && (!nodesKnown || (nodeByName[pinned] != nil && !nodeDeadPastAge(nodeByName[pinned], now, minAge))) {
					c.maybeBounceDRADriverPod(ctx, log, now, pods, pinned, &driverBounces)
				}
			}
		}
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })
	return rep.Result(&c.emitted, draClaimWedgedGauge.DeleteLabelValues,
		"dra resourceclaims wedged: ", ", ")
}

func (c *draClaimWedgeGuardCheck) claimPersisted(
	log logr.Logger,
	now time.Time,
	minAge time.Duration,
	fsKey string,
	since time.Time,
	liveFirstSeen map[string]bool,
) bool {
	if !since.IsZero() {
		return now.Sub(since) >= minAge
	}
	liveFirstSeen[fsKey] = true
	return probefw.Persisted(&c.firstSeen, fsKey, now, minAge, log)
}

func allReservedConsumersDead(
	claim *resourcev1.ResourceClaim,
	podByKey map[string]*corev1.Pod,
	nodeByName map[string]*corev1.Node,
	nodesKnown bool,
	now time.Time,
	minAge time.Duration,
) bool {
	if len(claim.Status.ReservedFor) == 0 {
		return false
	}
	for i := range claim.Status.ReservedFor {
		ref := &claim.Status.ReservedFor[i]
		// Non-Pod consumer -> fail closed (assume live).
		if ref.APIGroup != "" || ref.Resource != "pods" {
			return false
		}
		pod := podByKey[claim.Namespace+"/"+ref.Name]
		if podLiveForClaim(pod, ref.UID, nodeByName, nodesKnown, now, minAge) {
			return false
		}
	}
	return true
}

func podLiveForClaim(
	pod *corev1.Pod,
	refUID types.UID,
	nodeByName map[string]*corev1.Node,
	nodesKnown bool,
	now time.Time,
	minAge time.Duration,
) bool {
	if pod == nil {
		return false
	}
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return false
	}
	if refUID != "" && pod.UID != "" && pod.UID != refUID {
		return false
	}
	if pod.Spec.NodeName != "" && nodesKnown && len(nodeByName) > 0 {
		node := nodeByName[pod.Spec.NodeName]
		if node == nil || nodeDeadPastAge(node, now, minAge) {
			return false
		}
	}
	return true
}

func nodeDeadPastAge(node *corev1.Node, now time.Time, minAge time.Duration) bool {
	if node == nil {
		return true
	}
	ready := kube.NodeCondition(node, corev1.NodeReady)
	if ready == nil {
		return !node.CreationTimestamp.IsZero() && now.Sub(node.CreationTimestamp.Time) >= minAge
	}
	if ready.Status == corev1.ConditionTrue {
		return false
	}
	if !ready.LastTransitionTime.IsZero() {
		return now.Sub(ready.LastTransitionTime.Time) >= minAge
	}
	return !node.CreationTimestamp.IsZero() && now.Sub(node.CreationTimestamp.Time) >= minAge
}

func pinnedNodeName(claim *resourcev1.ResourceClaim) string {
	if claim.Status.Allocation == nil || claim.Status.Allocation.NodeSelector == nil {
		return ""
	}
	terms := claim.Status.Allocation.NodeSelector.NodeSelectorTerms
	if len(terms) != 1 {
		return ""
	}
	term := terms[0]
	for _, req := range term.MatchExpressions {
		if req.Key == corev1.LabelHostname && req.Operator == corev1.NodeSelectorOpIn && len(req.Values) == 1 {
			return req.Values[0]
		}
	}
	for _, req := range term.MatchFields {
		if req.Key == "metadata.name" && req.Operator == corev1.NodeSelectorOpIn && len(req.Values) == 1 {
			return req.Values[0]
		}
	}
	return ""
}

func (c *draClaimWedgeGuardCheck) emitClaimEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	claim *resourcev1.ResourceClaim,
	reason string,
) {
	cooldownKey := "draclaim." + claim.Namespace + "." + claim.Name + "." + reason
	if c.eventCooldown.CooledDown(cooldownKey, draClaimEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName(cooldownKey, cooldownKey, now),
		Namespace: claim.Namespace,
		Regarding: corev1.ObjectReference{
			APIVersion: "resource.k8s.io/v1",
			Kind:       "ResourceClaim",
			Namespace:  claim.Namespace,
			Name:       claim.Name,
			UID:        claim.UID,
		},
		Reason:            draClaimEventReason,
		Note:              fmt.Sprintf("ResourceClaim %s/%s wedged (%s)", claim.Namespace, claim.Name, reason),
		ReportingInstance: c.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: DRAClaimWedged event create failed (RBAC?)",
			"claim", claim.Namespace+"/"+claim.Name, "error", err)
		return
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: DRAClaimWedged", "claim", claim.Namespace+"/"+claim.Name, "reason", reason)
}

func (c *draClaimWedgeGuardCheck) clearReservedFor(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	claim *resourcev1.ResourceClaim,
) bool {
	claimKey := claim.Namespace + "/" + claim.Name
	ck := probefw.SelfHealKey(CheckNameDRAClaimWedgeGuard, "status/"+claimKey)
	proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals, ck, draClaimHealCooldown, now)
	if unverifiable {
		metrics.IncError(c.Name)
		return false
	}
	if !proceed {
		return false
	}

	// Live Pods.Get confirmation: abort fail-closed and refund the heal grant
	// if any consumer pod is confirmed live or non-404 unreadable.
	for i := range claim.Status.ReservedFor {
		ref := &claim.Status.ReservedFor[i]
		if ref.APIGroup != "" || ref.Resource != "pods" {
			heal.RefundGrant(now)
			return false
		}
		livePod, err := c.CS.CoreV1().Pods(claim.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
		case err != nil:
			heal.RefundGrant(now)
			log.Info("ABORT: ResourceClaim consumer live Pods.Get failed (fail-closed)",
				"claim", claimKey, "pod", ref.Name, "error", err)
			return false
		default:
			if livePod.Status.Phase != corev1.PodSucceeded &&
				livePod.Status.Phase != corev1.PodFailed &&
				(ref.UID == "" || livePod.UID == "" || livePod.UID == ref.UID) {
				heal.RefundGrant(now)
				log.Info("ABORT: ResourceClaim consumer pod confirmed live via Get",
					"claim", claimKey, "pod", ref.Name)
				return false
			}
		}
	}

	// FluxPatchGate is intentionally omitted: /status subresource writes are
	// outside Flux desired-state management.
	patchDoc := map[string]any{
		"status": map[string]any{
			"reservedFor": []any{},
		},
	}
	if claim.ResourceVersion != "" {
		patchDoc["metadata"] = map[string]any{
			"resourceVersion": claim.ResourceVersion,
		}
	}
	payload, err := json.Marshal(patchDoc)
	if err != nil {
		heal.RefundGrant(now)
		metrics.IncError(c.Name)
		log.Error(err, "marshal ResourceClaim status patch failed", "claim", claimKey)
		return false
	}

	if _, err := c.Dyn.Resource(kube.GVRResourceClaim).Namespace(claim.Namespace).
		Patch(ctx, claim.Name, types.MergePatchType, payload, metav1.PatchOptions{}, "status"); err != nil {
		switch {
		case apierrors.IsNotFound(err), apierrors.IsConflict(err), apierrors.IsForbidden(err):
			heal.RefundGrant(now)
			log.V(1).Info("DEFER: ResourceClaim /status patch skipped",
				"claim", claimKey, "error", err)
		default:
			metrics.IncError(c.Name)
			log.Error(err, "ResourceClaim /status patch failed", "claim", claimKey)
		}
		return false
	}

	c.Heals.Stamp(ck, now)
	draClaimHealsTotal.WithLabelValues("clear_reserved_for").Inc()
	c.InvalidateUnstructuredGVR(ctx, kube.GVRResourceClaim)
	log.Info("PATCH: cleared dead status.reservedFor on wedged ResourceClaim", "claim", claimKey)
	return true
}

func (c *draClaimWedgeGuardCheck) maybeBounceDRADriverPod(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	pods []corev1.Pod,
	nodeName string,
	bounces *int,
) {
	var candidates []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == nodeName && isDRADriverDaemonSetPod(pod) {
			candidates = append(candidates, pod)
		}
	}
	if len(candidates) == 0 {
		return
	}
	slices.SortFunc(candidates, func(a, b *corev1.Pod) int {
		if d := cmp.Compare(a.Namespace, b.Namespace); d != 0 {
			return d
		}
		return cmp.Compare(a.Name, b.Name)
	})

	for _, pod := range candidates {
		if *bounces >= draClaimMaxDriverBouncesPerSweep {
			break
		}
		ctrl := metav1.GetControllerOf(pod)
		targetKey := "driver/" + pod.Namespace + "/" + ctrl.Name + "/" + nodeName
		if c.DeletePodHealOnNode(ctx, log, CheckNameDRAClaimWedgeGuard, targetKey, pod, draClaimHealCooldown, now) {
			*bounces++
		}
	}
}

func isDRADriverDaemonSetPod(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return false
	}
	ctrl := metav1.GetControllerOf(pod)
	if ctrl == nil || ctrl.Kind != "DaemonSet" {
		return false
	}
	if hasDRAToken(pod.Name) || hasDRAToken(ctrl.Name) {
		return true
	}
	for _, lbl := range []string{
		pod.Labels["app.kubernetes.io/name"],
		pod.Labels["app.kubernetes.io/component"],
		pod.Labels["app.kubernetes.io/part-of"],
		pod.Labels["app"],
	} {
		if hasDRAToken(lbl) {
			return true
		}
	}
	for i := range pod.Spec.Containers {
		if hasDRAToken(pod.Spec.Containers[i].Name) || hasDRAToken(pod.Spec.Containers[i].Image) {
			return true
		}
	}
	return false
}

func hasDRAToken(s string) bool {
	if s == "" {
		return false
	}
	for _, seg := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if seg == "dra" {
			return true
		}
	}
	return false
}

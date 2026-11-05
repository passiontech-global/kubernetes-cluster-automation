package clusterhealthprobes

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// localPVStrandedCheck is the W7-C4 local-PV dead-node diagnostic,
// ephemeral-PVC rescue and provisioner watchdog.
type localPVStrandedCheck struct {
	*deps

	// W7-C4 watchdog state (under mu):
	//   - localPVEmitted: "ns/pod/pvc/node/reason" gauge tuples held
	//     at 1 — pruned via DeleteLabelValues when not re-seen (same
	//     hygiene as stsZeroEmitted).
	//   - pvcStalledEmitted: "ns/pvc/storageclass" gauge tuples held
	//     at 1 — same lifecycle.
	//   - localPVHealed: "ns/pvc" → last ephemeral-PVC heal — the
	//     30m cooldown (in-RAM: the PVC is deleted, nothing durable
	//     can carry the stamp).
	//   - pvcProvHealed: provisioner → last provisioner pod delete —
	//     the 1h cooldown.
	localPVEmitted    map[string]bool
	pvcStalledEmitted map[string]bool
	localPVHealed     map[string]time.Time
	pvcProvHealed     map[string]time.Time
}

// ---------------------------------------------------------------------------
// localpv-stranded-pods (W7-C4) — local-PV dead-node diagnostics +
// ephemeral-PVC rescue + provisioner watchdog.
// ---------------------------------------------------------------------------

// W7-C4 — localpv-stranded-pods knobs.
const (
	// localPVStrandedMinAge: a Pending pod must be this old before
	// its bound PV's node gets audited — younger pods may still be
	// pulling images or waiting on the scheduler, not stranded.
	localPVStrandedMinAge = 5 * time.Minute
	// localPVEphemeralHealMinAge: a stranded ephemeral pod must
	// persist this long before the PVC+pod delete fires — longer
	// than the gauge window so a flap cannot reap a volume.
	localPVEphemeralHealMinAge   = 10 * time.Minute
	localPVEphemeralHealCooldown = 30 * time.Minute
	// localPVEphemeralAnno opts any workload into the disposable-
	// volume heal — set on the pod or its PVC.
	localPVEphemeralAnno = "node.ops/ephemeral-localpv"
	// concourseWorkerNS/PodPrefix name the workload whose local
	// workdir is disposable by design — losing it on a dead node is
	// the exact rescue the concourse janitor already performs while
	// the node lives.
	concourseWorkerNS        = "concourse"
	concourseWorkerPodPrefix = "concourse-worker"
	// pvcStalledMinAge is the pending window for the provisioner
	// watchdog: a PVC pending this long on the hostpath class while
	// Ready workers exist means the provisioner wedged.
	pvcStalledMinAge           = 15 * time.Minute
	pvcProvisionerHealCooldown = time.Hour
	openebsHostpathSC          = "openebs-hostpath"
	openebsProvisionerNS       = "openebs"
	openebsProvisionerPrefix   = "openebs-localpv-provisioner"
	openebsProvisionerName     = "openebs-localpv-provisioner"
	// Stranded-reason gauge label values.
	strandedReasonMissingNode  = "missing_node"
	strandedReasonOutOfService = "out_of_service"
	strandedReasonNotReady     = "not_ready"
	strandedReasonCordoned     = "cordoned"
)

// strandedHeal is one pod+PVC pair eligible for the ephemeral-volume
// rescue — carried out of the pod scan so the maintenance mutex is
// evaluated once per sweep.
type strandedHeal struct {
	pod    *corev1.Pod
	pvc    *corev1.PersistentVolumeClaim
	node   string
	reason string
}

// localPVNodeNames extracts the hostnames a PV's required
// nodeAffinity pins it to — the local volume can only ever exist on
// those nodes.
func localPVNodeNames(pv *corev1.PersistentVolume) []string {
	na := pv.Spec.NodeAffinity
	if na == nil || na.Required == nil {
		return nil
	}
	var out []string
	for _, term := range na.Required.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key != corev1.LabelHostname ||
				expr.Operator != corev1.NodeSelectorOpIn {
				continue
			}
			out = append(out, expr.Values...)
		}
	}
	return out
}

// strandedNodeReason classifies a PV-pinned node that can never host
// the pod again — "" when the node is fine (the pod pends for some
// other reason: CPU, scheduling, image).
func strandedNodeReason(nodes map[string]*corev1.Node, name string) string {
	n := nodes[name]
	if n == nil {
		return strandedReasonMissingNode
	}
	if shared.HasTaint(n.Spec.Taints, corev1.TaintNodeOutOfService) {
		return strandedReasonOutOfService
	}
	if !shared.NodeReady(n) {
		return strandedReasonNotReady
	}
	if n.Spec.Unschedulable {
		return strandedReasonCordoned
	}
	return ""
}

// ephemeralLocalPV reports whether the workload's local volume is
// disposable: concourse-worker workdirs (rebuilt by the init
// container on the new node) or anything explicitly annotated
// node.ops/ephemeral-localpv on the pod or the PVC.
func ephemeralLocalPV(pod *corev1.Pod, pvc *corev1.PersistentVolumeClaim) bool {
	if pod.Namespace == concourseWorkerNS &&
		strings.HasPrefix(pod.Name, concourseWorkerPodPrefix) {
		return true
	}
	return pod.Annotations[localPVEphemeralAnno] == "true" ||
		pvc.Annotations[localPVEphemeralAnno] == "true"
}

// checkLocalPVStrandedPods covers the two local-PV failure shapes
// that leave workloads Pending forever with no signal:
//
//	a) STRANDED — a Pending pod's bound PVC points at a PV whose
//	   nodeAffinity pins it to a node that is missing, out-of-
//	   service, NotReady or cordoned. The volume can never follow
//	   the pod to a new node, so the pod pends forever. Every such
//	   pod emits localpv_stranded_pods=1 — and for workloads whose
//	   volume is disposable (concourse-worker, or pod/PVC annotated
//	   node.ops/ephemeral-localpv) stranded on a confirmed-gone
//	   node (missing or out-of-service) the heal deletes PVC+pod so
//	   the StatefulSet rebinds on a live node while the Released PV
//	   gets swept by the node-host-agent. Database volumes are
//	   NEVER touched — alerting only.
//	b) STALLED — a Pending pod waits on a Pending openebs-hostpath
//	   PVC while Ready+schedulable workers exist: the localpv
//	   provisioner wedged. pvc_provisioning_stalled=1 fires and —
//	   outside maintenance, past the 1h cooldown — the provisioner
//	   pod is deleted to force a resync.
func (p *localPVStrandedCheck) run(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.localPVEmitted == nil {
		p.localPVEmitted = map[string]bool{}
	}
	if p.pvcStalledEmitted == nil {
		p.pvcStalledEmitted = map[string]bool{}
	}
	if p.localPVHealed == nil {
		p.localPVHealed = map[string]time.Time{}
	}
	if p.pvcProvHealed == nil {
		p.pvcProvHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	nodesByName := make(map[string]*corev1.Node, len(nodes))
	hasSchedulableWorker := false
	for i := range nodes {
		nodesByName[nodes[i].Name] = &nodes[i]
		if shared.NodeReady(&nodes[i]) && !nodes[i].Spec.Unschedulable &&
			!shared.IsControlPlane(&nodes[i]) {
			hasSchedulableWorker = true
		}
	}

	// Paged cluster-wide reads — the same full-truth posture as the
	// masterless EndpointSlice census: a partial read cannot tell
	// "stranded" from "no data", so a list error aborts the check.
	pvsByName := map[string]*corev1.PersistentVolume{}
	err = shared.ListEach(ctx,
		metav1.ListOptions{Limit: healthListPageSize},
		shared.PersistentVolumes(p.cs),
		func(items []corev1.PersistentVolume) error {
			for i := range items {
				pvsByName[items[i].Name] = &items[i]
			}
			return nil
		})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list persistentvolumes: %w", err)}
	}
	pvcsByKey := map[string]*corev1.PersistentVolumeClaim{}
	err = shared.ListEach(ctx,
		metav1.ListOptions{Limit: healthListPageSize},
		shared.PersistentVolumeClaims(p.cs, metav1.NamespaceAll),
		func(items []corev1.PersistentVolumeClaim) error {
			for i := range items {
				pvcsByKey[items[i].Namespace+"/"+items[i].Name] = &items[i]
			}
			return nil
		})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list persistentvolumeclaims: %w", err)}
	}

	emitted := map[string]bool{} // "ns/pod/pvc/node/reason" this sweep
	stalled := map[string]bool{} // "ns/pvc/storageclass" this sweep
	var heals []strandedHeal

	podOpts := metav1.ListOptions{
		FieldSelector: "status.phase=Pending",
		Limit:         healthListPageSize,
	}
	err = shared.ListEach(ctx, podOpts,
		shared.Pods(p.cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				pod := &items[i]
				if pod.Status.Phase != corev1.PodPending {
					continue // mirrors the FieldSelector for fake clients
				}
				age := now.Sub(pod.CreationTimestamp.Time)
				if age < localPVStrandedMinAge {
					continue
				}
				for _, vol := range pod.Spec.Volumes {
					claim := vol.PersistentVolumeClaim
					if claim == nil {
						continue
					}
					pvc := pvcsByKey[pod.Namespace+"/"+claim.ClaimName]
					if pvc == nil {
						continue
					}
					// Branch A — bound local PV on an unavailable node.
					if pvc.Status.Phase == corev1.ClaimBound &&
						pvc.Spec.VolumeName != "" {
						if pv := pvsByName[pvc.Spec.VolumeName]; pv != nil {
							for _, node := range localPVNodeNames(pv) {
								reason := strandedNodeReason(nodesByName, node)
								if reason == "" {
									continue
								}
								key := pod.Namespace + "/" + pod.Name + "/" +
									pvc.Name + "/" + node + "/" + reason
								emitted[key] = true
								metrics.LocalPVStrandedPods.WithLabelValues(
									pod.Namespace, pod.Name, pvc.Name, node, reason).Set(1)
								// Confirmed-gone nodes only: NotReady/
								// cordoned can come back — a missing or
								// fenced (out-of-service) node cannot.
								if ephemeralLocalPV(pod, pvc) &&
									(reason == strandedReasonMissingNode ||
										reason == strandedReasonOutOfService) &&
									age >= localPVEphemeralHealMinAge {
									heals = append(heals, strandedHeal{
										pod: pod, pvc: pvc, node: node, reason: reason})
								}
							}
						}
					}
					// Branch B — claim still Pending on the hostpath
					// provisioner while schedulable workers exist.
					if pvc.Status.Phase == corev1.ClaimPending &&
						hasSchedulableWorker &&
						pvc.Spec.StorageClassName != nil &&
						*pvc.Spec.StorageClassName == openebsHostpathSC &&
						age >= pvcStalledMinAge {
						key := pod.Namespace + "/" + pvc.Name + "/" + openebsHostpathSC
						stalled[key] = true
						metrics.PVCProvisioningStalled.WithLabelValues(
							pod.Namespace, pvc.Name, openebsHostpathSC).Set(1)
					}
				}
			}
			return nil
		})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}

	// Prune the gauges' series for tuples not re-seen — same
	// DeleteLabelValues hygiene as stsZeroEmitted.
	p.mu.Lock()
	for k := range p.localPVEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 5); len(parts) == 5 {
			metrics.LocalPVStrandedPods.DeleteLabelValues(
				parts[0], parts[1], parts[2], parts[3], parts[4])
		}
		delete(p.localPVEmitted, k)
	}
	maps.Copy(p.localPVEmitted, emitted)
	for k := range p.pvcStalledEmitted {
		if stalled[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.PVCProvisioningStalled.DeleteLabelValues(
				parts[0], parts[1], parts[2])
		}
		delete(p.pvcStalledEmitted, k)
	}
	maps.Copy(p.pvcStalledEmitted, stalled)
	p.mu.Unlock()

	// The maintenance mutex is evaluated once per sweep and only
	// when there is something to delete — pod/PVC kills during a
	// drain are exactly what it exists to prevent; "cannot verify"
	// fails closed.
	var maintHeld bool
	var maintWhy string
	var maintErr error
	if len(heals) > 0 || len(stalled) > 0 {
		maintHeld, maintWhy, maintErr = shared.MaintenanceActive(ctx, p.cs, p.dyn)
		if maintErr != nil {
			metrics.IncError(clusterHealthQueue)
			log.Info("WARN: maintenance check unverifiable — localpv heals deferred (fail closed)",
				"error", maintErr)
		}
	}
	for i := range heals {
		h := &heals[i]
		pvcKey := h.pvc.Namespace + "/" + h.pvc.Name
		if maintErr != nil || maintHeld {
			log.Info("maintenance gate — stranded ephemeral pvc kept",
				"pvc", pvcKey, "why", maintWhy)
			continue
		}
		p.mu.Lock()
		last, ok := p.localPVHealed[pvcKey]
		p.mu.Unlock()
		if ok && now.Sub(last) < localPVEphemeralHealCooldown {
			log.Info("skip heal: ephemeral localpv inside cooldown",
				"pvc", pvcKey, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		// PVC first, then the pod — the claim release flips the PV
		// to Released so the node-host-agent sweeps it, and the pod
		// delete lets the StatefulSet rebind onto a live node. UID
		// preconditions close the list→delete TOCTOU on both.
		pvcUID := h.pvc.UID
		pvcErr := p.cs.CoreV1().PersistentVolumeClaims(h.pvc.Namespace).
			Delete(ctx, h.pvc.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &pvcUID},
			})
		switch {
		case pvcErr == nil || apierrors.IsNotFound(pvcErr):
			// NotFound: the claim vanished between list and heal —
			// the release half is already done, still free the pod.
		case apierrors.IsForbidden(pvcErr):
			// RBAC-denied is permanent (PVC delete is only granted
			// via the concourse Role — an ephemeral-localpv opt-in
			// elsewhere can never succeed). Stamp the cooldown so
			// the check doesn't error-loop every sweep, keep the
			// pod, and surface once.
			metrics.IncError(clusterHealthQueue)
			log.Error(pvcErr, "ephemeral localpv pvc delete forbidden — RBAC scope blocks the heal; stamping cooldown",
				"pvc", pvcKey)
			p.mu.Lock()
			p.localPVHealed[pvcKey] = now
			p.mu.Unlock()
			continue
		default:
			metrics.IncError(clusterHealthQueue)
			log.Error(pvcErr, "ephemeral localpv pvc delete failed", "pvc", pvcKey)
			continue
		}
		podUID := h.pod.UID
		if err := p.cs.CoreV1().Pods(h.pod.Namespace).Delete(ctx, h.pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &podUID},
			}); err != nil && !apierrors.IsNotFound(err) {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "stranded pod delete failed",
				"pod", h.pod.Namespace+"/"+h.pod.Name)
			continue
		}
		p.mu.Lock()
		p.localPVHealed[pvcKey] = now
		p.mu.Unlock()
		metrics.LocalPVEphemeralHealsTotal.
			WithLabelValues(h.pvc.Namespace, h.pvc.Name, h.node).Inc()
		log.Info("DELETE: ephemeral localpv pvc+pod stranded on a confirmed-dead node — StatefulSet rebinds on a live node",
			"pvc", pvcKey, "pod", h.pod.Namespace+"/"+h.pod.Name,
			"node", h.node, "reason", h.reason)
	}
	if len(stalled) > 0 && maintErr == nil && !maintHeld {
		p.healLocalPVProvisioner(ctx, log, now)
	}

	if len(emitted) == 0 && len(stalled) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted)+len(stalled))
	for k := range emitted {
		keys = append(keys, k)
	}
	for k := range stalled {
		keys = append(keys, "stalled:"+k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"localpv-stranded/stalled volumes: %s", strings.Join(keys, ", "))}
}

// healLocalPVProvisioner deletes the openebs-localpv-provisioner
// pod(s) — the same re-sync nudge every operator heal here applies.
// Pending hostpath claims while Ready workers exist mean the
// provisioner missed a watch event; a restart makes it re-list and
// provision. 1h cooldown (in-RAM — the pod itself is the heal
// target, nothing else can carry the stamp).
func (p *localPVStrandedCheck) healLocalPVProvisioner(ctx context.Context,
	log logr.Logger, now time.Time) {

	p.mu.Lock()
	last, ok := p.pvcProvHealed[openebsProvisionerName]
	p.mu.Unlock()
	if ok && now.Sub(last) < pvcProvisionerHealCooldown {
		log.Info("skip heal: localpv provisioner inside cooldown",
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	pods, err := p.cs.CoreV1().Pods(openebsProvisionerNS).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list provisioner pods failed — heal deferred",
			"error", err)
		return
	}
	deleted := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.HasPrefix(pod.Name, openebsProvisionerPrefix) {
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "localpv provisioner delete failed",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		deleted = true
		log.Info("DELETE: wedged localpv provisioner — stalled claims need a resync",
			"pod", pod.Namespace+"/"+pod.Name)
	}
	if !deleted {
		return
	}
	p.mu.Lock()
	p.pvcProvHealed[openebsProvisionerName] = now
	p.mu.Unlock()
	metrics.PVCProvisionerHealsTotal.
		WithLabelValues(openebsProvisionerName).Inc()
}

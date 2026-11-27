// node_overloaded_shed.go — guarded stateless pod shedding for worker nodes
// with sustained NodeOverloaded=True (>=15m, fresh heartbeat).
//
// Pre-cordoning stops NEW pods from landing on an overloaded worker, but
// already-scheduled pods keep pinning CPU/memory/IO until load subsides.
// When NODE_OVERLOADED_EVICT_ENABLED is on (default true) and at least one
// other Ready, uncordoned, non-overloaded worker exists to absorb rescheduled
// pods, this pass evicts AT MOST 1 eligible stateless HA Deployment or
// stateless HA StatefulSet pod (zero PVCs, zero VolumeClaimTemplates) per
// overloaded node per sweep (with a 10m per-node cooldown) via policy/v1
// Eviction (respecting PDBs atomically).
//
// Candidate ordering (incident 2026-11-27 production lanit-02 & nonprod
// worker-02 — alphabetical ordering nibbled 10m pods while 587m vmagent and
// 363m stateless vmselect-1 kept PSI at 42.4%):
//  1. 100%-colocated multi-replica HA workloads on this node first,
//  2. Highest CPU first (live 5m Prometheus rate when available, else sum of
//     container CPU requests),
//  3. Deterministic (namespace, name) tie-break.
package nodehealth

import (
	"cmp"
	"context"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

const (
	nodeOverloadedShedCooldown    = 10 * time.Minute
	overloadPodCPUQuery           = `sum by (namespace, pod) (rate(container_cpu_usage_seconds_total{container!~"POD|"}[5m]))`
	overloadPodCPUQueryTimeout    = 2 * time.Second
	annoSafeToEvict               = "cluster-autoscaler.kubernetes.io/safe-to-evict"
	annoNoOverloadEvict           = "passiontech.dev/no-overload-evict"
	prioritySystemClusterCritical = "system-cluster-critical"
	prioritySystemNodeCritical    = "system-node-critical"
	annoMirrorPod                 = "kubernetes.io/config.mirror"
)

var nodeOverloadedExcludedNamespaces = map[string]bool{
	"kube-system":      true,
	"linkerd":          true,
	"linkerd-viz":      true,
	"cert-manager":     true,
	"external-secrets": true,
	"operators":        true,
	"node-ops":         true,
}

func isNodeOverloadedExcludedNamespace(ns string) bool {
	return nodeOverloadedExcludedNamespaces[ns] || strings.HasPrefix(ns, "cilium")
}

func nodeSustainedOverloaded(n *corev1.Node, now time.Time) bool {
	c := kube.NodeCondition(n, corev1.NodeConditionType(nodecond.NodeOverloaded))
	return c != nil &&
		c.Status == corev1.ConditionTrue &&
		!c.LastTransitionTime.IsZero() &&
		now.Sub(c.LastTransitionTime.Time) >= nodeOverloadedCordonAge &&
		kube.CondHeartbeatLive(c, nodeHangCondHeartbeatMaxAge, now)
}

func nodeIsOverloaded(n *corev1.Node) bool {
	c := kube.NodeCondition(n, corev1.NodeConditionType(nodecond.NodeOverloaded))
	return c != nil && c.Status == corev1.ConditionTrue
}

func nodeIsReady(n *corev1.Node) bool {
	c := kube.NodeCondition(n, corev1.NodeReady)
	return c != nil && c.Status == corev1.ConditionTrue
}

func nodeTaintKeys(n *corev1.Node) []string {
	if len(n.Spec.Taints) == 0 {
		return nil
	}
	keys := make([]string, 0, len(n.Spec.Taints))
	for _, t := range n.Spec.Taints {
		keys = append(keys, t.Key)
	}
	return keys
}

// hasHealthyReceiverWorker reports whether at least one worker other than
// excludeName is Ready, schedulable (uncordoned), and not NodeOverloaded.
func hasHealthyReceiverWorker(nodes []corev1.Node, excludeName string) bool {
	for i := range nodes {
		w := &nodes[i]
		if w.Name == excludeName || kube.IsControlPlane(w) {
			continue
		}
		if nodeIsReady(w) && !w.Spec.Unschedulable && !nodeIsOverloaded(w) {
			return true
		}
	}
	return false
}

// shedOverloadedNodes evicts at most 1 eligible stateless HA Deployment or
// stateless HA StatefulSet pod per sustained-NodeOverloaded worker per sweep
// (10m per-node cooldown) when the cluster has at least one healthy receiver
// worker.
func (p *nodeHangCheck) shedOverloadedNodes(ctx context.Context, log logr.Logger,
	nodes []corev1.Node, now time.Time) {

	if !p.overloadEvictEnabled {
		return
	}
	p.overloadShedCooldown.PruneExpired(now, nodeOverloadedShedCooldown)

	// Fast path: 0 sustained-overloaded workers pays zero extra API reads.
	var overloadedNames []string
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) || !nodeSustainedOverloaded(n, now) {
			continue
		}
		overloadedNames = append(overloadedNames, n.Name)
	}
	if len(overloadedNames) == 0 {
		return
	}
	slices.Sort(overloadedNames)

	// Re-read nodes after uncordonCleared/cordonLatched invalidated the census
	// so the headroom check reflects the live post-cordon unschedulable state.
	freshNodes, err := p.AllNodes(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list nodes for overload shedding failed — shedding deferred", "error", err)
		return
	}

	// Filter overloaded nodes that still qualify (headroom, no L1/kured hold,
	// not in 10m cooldown) before paying pod/workload list calls.
	var activeNodes []*corev1.Node
	for _, name := range overloadedNames {
		n := nodeByName(freshNodes, name)
		if n == nil || !nodeSustainedOverloaded(n, now) {
			continue
		}
		if !n.Spec.Unschedulable {
			continue
		}
		if nodeLocalRemediationActive(ctx, n, now) {
			log.Info("YIELD: node-host-agent local remediation in flight — overload shed deferred",
				"node", name)
			continue
		}
		if nodecond.EvaluateCoord(n.Annotations, nodeTaintKeys(n), now).Active {
			log.Info("DEFER: node under maintenance/kured lock — overload shed deferred",
				"node", name)
			continue
		}
		if p.overloadShedCooldown.CooledDown(name, nodeOverloadedShedCooldown, now) {
			continue
		}
		if !hasHealthyReceiverWorker(freshNodes, name) {
			log.Info("skip overload shed: no other Ready uncordoned non-overloaded worker available",
				"node", name)
			continue
		}
		activeNodes = append(activeNodes, n)
	}
	if len(activeNodes) == 0 {
		return
	}

	pods, err := p.AllPods(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods for overload shedding failed — shedding deferred", "error", err)
		return
	}
	replicaSets, err := p.AllReplicaSets(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list replicasets for overload shedding failed — shedding deferred", "error", err)
		return
	}
	deployments, err := p.AllDeployments(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list deployments for overload shedding failed — shedding deferred", "error", err)
		return
	}
	statefulSets, err := p.AllStatefulSets(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list statefulsets for overload shedding failed — shedding deferred", "error", err)
		return
	}
	pdbs, err := p.AllPDBs(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pdbs for overload shedding failed — shedding deferred", "error", err)
		return
	}

	rsByKey := make(map[string]*metav1.PartialObjectMetadata, len(replicaSets))
	for i := range replicaSets {
		rs := &replicaSets[i]
		rsByKey[rs.Namespace+"/"+rs.Name] = rs
	}
	deployByKey := make(map[string]*appsv1.Deployment, len(deployments))
	for i := range deployments {
		d := &deployments[i]
		deployByKey[d.Namespace+"/"+d.Name] = d
	}
	stsByKey := make(map[string]*appsv1.StatefulSet, len(statefulSets))
	for i := range statefulSets {
		s := &statefulSets[i]
		stsByKey[s.Namespace+"/"+s.Name] = s
	}

	// Best-effort live 5m CPU usage (millicores) per pod; falls back to pod CPU
	// requests when Prometheus is unconfigured, unreachable, or slow.
	liveCPU := p.overloadPodCPUMilli(ctx, log)

	podsByNode := map[string][]*corev1.Pod{}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == "" {
			continue
		}
		podsByNode[pod.Spec.NodeName] = append(podsByNode[pod.Spec.NodeName], pod)
	}

	for _, node := range activeNodes {
		candidates := eligibleOverloadPods(
			podsByNode[node.Name], pods, rsByKey, deployByKey, stsByKey, pdbs, liveCPU)
		if len(candidates) == 0 {
			continue
		}
		for _, pod := range candidates {
			// HealAllowedClusterWideOnly defers on cluster-wide maintenance
			// (autopilot Plan, unscoped kured lock, unresolvable medik8s CR)
			// and enforces the global heal budget + 10m per-node cooldown
			// without deadlocking on the precordon we just placed on this node.
			proceed, unverifiable := p.HealAllowedClusterWideOnly(ctx, log,
				&p.overloadShedCooldown, node.Name, nodeOverloadedShedCooldown, now)
			if unverifiable {
				metrics.IncError(p.Name)
				return
			}
			if !proceed {
				break
			}
			evicted, refused, notFound, err := heal.EvictPodNotFound(ctx, p.CS,
				&p.overloadShedCooldown, node.Name, pod, now)
			switch {
			case err != nil:
				metrics.IncError(p.Name)
				log.Error(err, "overload pod eviction failed",
					"node", node.Name, "pod", pod.Namespace+"/"+pod.Name)
				goto nextNode
			case refused:
				heal.RefundGrant(now)
				if notFound {
					log.V(1).Info("DEFER: overload shed target vanished before eviction",
						"node", node.Name, "pod", pod.Namespace+"/"+pod.Name)
				} else {
					log.Info("DEFER: overload shed eviction refused (PDB/hold/quorum)",
						"node", node.Name, "pod", pod.Namespace+"/"+pod.Name)
				}
				continue
			case evicted:
				metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameNodeHang).Inc()
				log.Info("EVICT: shed stateless workload pod from sustained NodeOverloaded worker",
					"node", node.Name, "pod", pod.Namespace+"/"+pod.Name,
					"cpuMilli", int64(math.Round(podCPUScoreMilli(pod, liveCPU))))
				goto nextNode
			}
		}
	nextNode:
	}
}

// overloadPodCPUMilli queries live 5m CPU usage (in millicores) per
// namespace/pod via one best-effort Prometheus instant query per sweep.
// Any error is absorbed at V(1) so shedding falls back cleanly to pod CPU
// requests without ever failing or stalling on an unreachable Prometheus.
func (p *nodeHangCheck) overloadPodCPUMilli(ctx context.Context, log logr.Logger) map[string]float64 {
	qctx, cancel := context.WithTimeout(ctx, overloadPodCPUQueryTimeout)
	defer cancel()
	samples, err := p.PromQuery(qctx, overloadPodCPUQuery)
	if err != nil {
		log.V(1).Info("overload shed live CPU query unavailable — falling back to pod CPU requests",
			"error", err)
		return nil
	}
	if len(samples) == 0 {
		return nil
	}
	out := make(map[string]float64, len(samples))
	for _, s := range samples {
		ns := s.Label("namespace")
		podName := s.Label("pod")
		if ns == "" || podName == "" || s.Value <= 0 || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			continue
		}
		out[ns+"/"+podName] = s.Value * 1000
	}
	return out
}

// podWorkloadKey returns a canonical workload identifier for pods owned by a
// Deployment ("deploy/<ns>/<name>") or StatefulSet ("sts/<ns>/<name>").
func podWorkloadKey(
	pod *corev1.Pod,
	rsByKey map[string]*metav1.PartialObjectMetadata,
) (string, bool) {
	podCtrl := metav1.GetControllerOf(pod)
	if podCtrl == nil {
		return "", false
	}
	switch podCtrl.Kind {
	case "ReplicaSet":
		rs := rsByKey[pod.Namespace+"/"+podCtrl.Name]
		if rs == nil {
			return "", false
		}
		rsCtrl := metav1.GetControllerOf(rs)
		if rsCtrl == nil || rsCtrl.Kind != "Deployment" {
			return "", false
		}
		return "deploy/" + pod.Namespace + "/" + rsCtrl.Name, true
	case "StatefulSet":
		return "sts/" + pod.Namespace + "/" + podCtrl.Name, true
	default:
		return "", false
	}
}

// colocatedWorkloadsOnNode returns the set of podWorkloadKey identifiers
// whose Running+Ready pods (>= 2) are 100% co-located on nodeName. Evicting
// from these first immediately breaks single-node SPOFs before touching
// already well-spread workloads.
func colocatedWorkloadsOnNode(
	allPods []corev1.Pod,
	rsByKey map[string]*metav1.PartialObjectMetadata,
	nodeName string,
) map[string]bool {
	if nodeName == "" {
		return nil
	}
	type placement struct {
		readyCount int
		nodes      map[string]struct{}
	}
	byWorkload := map[string]*placement{}
	for i := range allPods {
		pod := &allPods[i]
		if !probefw.PodRunningReady(pod) {
			continue
		}
		wlKey, ok := podWorkloadKey(pod, rsByKey)
		if !ok {
			continue
		}
		p := byWorkload[wlKey]
		if p == nil {
			p = &placement{nodes: map[string]struct{}{}}
			byWorkload[wlKey] = p
		}
		p.readyCount++
		p.nodes[pod.Spec.NodeName] = struct{}{}
	}
	colocated := map[string]bool{}
	for wlKey, p := range byWorkload {
		if p.readyCount >= 2 && len(p.nodes) == 1 {
			if _, onNode := p.nodes[nodeName]; onNode {
				colocated[wlKey] = true
			}
		}
	}
	return colocated
}

func podCPURequestMilli(pod *corev1.Pod) int64 {
	var total int64
	for i := range pod.Spec.Containers {
		if q, ok := pod.Spec.Containers[i].Resources.Requests[corev1.ResourceCPU]; ok {
			total += q.MilliValue()
		}
	}
	return total
}

func podCPUScoreMilli(pod *corev1.Pod, liveCPU map[string]float64) float64 {
	if v, ok := liveCPU[pod.Namespace+"/"+pod.Name]; ok && v > 0 {
		return v
	}
	return float64(podCPURequestMilli(pod))
}

func eligibleOverloadPods(
	nodePods []*corev1.Pod,
	allPods []corev1.Pod,
	rsByKey map[string]*metav1.PartialObjectMetadata,
	deployByKey map[string]*appsv1.Deployment,
	stsByKey map[string]*appsv1.StatefulSet,
	pdbs []policyv1.PodDisruptionBudget,
	liveCPU map[string]float64,
) []*corev1.Pod {
	var out []*corev1.Pod
	for _, pod := range nodePods {
		if !podEligibleForOverloadShed(pod, rsByKey, deployByKey, stsByKey, pdbs) {
			continue
		}
		out = append(out, pod)
	}
	if len(out) <= 1 {
		return out
	}
	colocated := colocatedWorkloadsOnNode(allPods, rsByKey, out[0].Spec.NodeName)
	slices.SortFunc(out, func(a, b *corev1.Pod) int {
		aWL, _ := podWorkloadKey(a, rsByKey)
		bWL, _ := podWorkloadKey(b, rsByKey)
		aColoc := colocated[aWL]
		bColoc := colocated[bWL]
		if aColoc != bColoc {
			if aColoc {
				return -1
			}
			return 1
		}
		aCPU := podCPUScoreMilli(a, liveCPU)
		bCPU := podCPUScoreMilli(b, liveCPU)
		if c := cmp.Compare(bCPU, aCPU); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return out
}

func podEligibleForOverloadShed(
	pod *corev1.Pod,
	rsByKey map[string]*metav1.PartialObjectMetadata,
	deployByKey map[string]*appsv1.Deployment,
	stsByKey map[string]*appsv1.StatefulSet,
	pdbs []policyv1.PodDisruptionBudget,
) bool {
	if !probefw.PodRunningReady(pod) {
		return false
	}
	if isNodeOverloadedExcludedNamespace(pod.Namespace) {
		return false
	}
	if pod.Annotations[annoMirrorPod] != "" {
		return false
	}
	if pod.Spec.PriorityClassName == prioritySystemClusterCritical ||
		pod.Spec.PriorityClassName == prioritySystemNodeCritical {
		return false
	}
	if pod.Annotations[annoSafeToEvict] == "false" ||
		pod.Annotations[annoNoOverloadEvict] == "true" {
		return false
	}
	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim != nil {
			return false
		}
	}
	// ONLY HA stateless Deployment or stateless StatefulSet Ready pods:
	//   - ReplicaSet -> Deployment with readyReplicas >= 2, OR
	//   - StatefulSet with readyReplicas >= 2, zero PVC volumes (checked above),
	//     and zero VolumeClaimTemplates (belt-and-suspenders against shedding
	//     stateful data pods such as vmstorage).
	podCtrl := metav1.GetControllerOf(pod)
	if podCtrl == nil {
		return false
	}
	switch podCtrl.Kind {
	case "ReplicaSet":
		rs := rsByKey[pod.Namespace+"/"+podCtrl.Name]
		if rs == nil {
			return false
		}
		rsCtrl := metav1.GetControllerOf(rs)
		if rsCtrl == nil || rsCtrl.Kind != "Deployment" {
			return false
		}
		dep := deployByKey[pod.Namespace+"/"+rsCtrl.Name]
		if dep == nil || dep.Status.ReadyReplicas < 2 {
			return false
		}
	case "StatefulSet":
		sts := stsByKey[pod.Namespace+"/"+podCtrl.Name]
		if sts == nil || sts.Status.ReadyReplicas < 2 || len(sts.Spec.VolumeClaimTemplates) > 0 {
			return false
		}
	default:
		return false
	}
	return overloadPDBAllows(pdbs, pod)
}

func overloadPDBAllows(pdbs []policyv1.PodDisruptionBudget, pod *corev1.Pod) bool {
	for i := range pdbs {
		pdb := &pdbs[i]
		if pdb.Namespace != pod.Namespace {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			sel = labels.Everything() // unparseable selector -> fail closed
		}
		if !sel.Matches(labels.Set(pod.Labels)) {
			continue
		}
		if pdb.Status.DisruptionsAllowed < 1 {
			return false
		}
	}
	return true
}

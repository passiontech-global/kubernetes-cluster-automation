// cluster_health_wave8.go — the Wave-8 checks riding the same
// 5-minute probe plumbing as cluster_health_probes.go:
//
//   - scheduler-watchdog (W8-CP3): Pods Pending >=5m with
//     spec.nodeName=="" and no PodScheduled condition while the
//     cluster has Ready uncordoned workers — the kube-scheduler
//     stopped scheduling (a wedged leader or a starved workqueue).
//     Detect-only: exports node_automation_scheduler_frozen and
//     FAILs the check series.
//   - mesh-controlplane-watchdog (W8-NM2/NM3): a Node carrying
//     CiliumIPAMExhausted=True >=10m gets the cilium-operator pod
//     deleted (1h cooldown) so IPAM state resyncs; linkerd-
//     destination/linkerd-identity pods wedged (unready/crashloop
//     containers or the started-but-never-Ready signature) >=5m
//     while the apiserver is healthy get deleted to re-roll (30m
//     cooldown).
//   - node-hang-precordon (W8-ST2): a worker Node with
//     FilesystemReadOnly or KernelHungTasks True >=2m is patched
//     spec.unschedulable=true before NHC/SNR reboots it — new pods
//     stop landing on a dying node. Gated on fewer than 35% of
//     workers already cordoned so a fleet-wide event cannot unnode
//     the cluster.
//
// The W4 stateful-masterless extension (db operator pod delete for
// mariadb/pxc/psmdb/pg/scylla operators) lives in
// cluster_health_probes.go next to the check it extends.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	// W8-CP3 — scheduler-watchdog knobs.
	checkNameSchedulerWatchdog = "scheduler-watchdog"
	schedulerPendingMinAge     = 5 * time.Minute

	// W8-NM2/NM3 — mesh-controlplane-watchdog knobs.
	checkNameMeshWatchdog  = "mesh-controlplane-watchdog"
	ciliumIPAMMinAge       = 10 * time.Minute
	linkerdWedgedMinAge    = 5 * time.Minute
	ciliumOpHealCooldown   = time.Hour
	linkerdHealCooldown    = 30 * time.Minute
	ciliumOperatorNS       = "kube-system"
	ciliumOperatorPrefix   = "cilium-operator-"
	linkerdNS              = "linkerd"
	linkerdDestinationName = "linkerd-destination"
	linkerdIdentityName    = "linkerd-identity"

	// W8-ST2 — node-hang-precordon knobs.
	checkNameNodeHang        = "node-hang-precordon"
	nodeHangCondMinAge       = 2 * time.Minute
	nodeHangMaxCordonedRatio = 0.35
)

// nodeHangConds are the NPD latches that precede a node reboot —
// patching unschedulable early keeps new pods off the dying node.
var nodeHangConds = []corev1.NodeConditionType{
	"FilesystemReadOnly", "KernelHungTasks",
}

// ---------------------------------------------------------------------------
// W8-CP3 — scheduler-watchdog
// ---------------------------------------------------------------------------

// checkSchedulerFrozen detects a stopped kube-scheduler: unscheduled
// pods accumulate (Pending >=5m, no nodeName, and — the freeze tell —
// no PodScheduled condition at all, because a live scheduler writes a
// PodScheduled=False verdict within seconds) while Ready uncordoned
// workers exist to place them on. Detect-only — restarting the
// scheduler is the platform's job; this check makes the freeze
// visible on node_automation_scheduler_frozen.
func (p *clusterHealthProber) checkSchedulerFrozen(ctx context.Context) probeResult {
	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	schedulable := false
	for i := range nodes {
		if shared.NodeReady(&nodes[i]) && !nodes[i].Spec.Unschedulable &&
			!shared.IsControlPlane(&nodes[i]) {
			schedulable = true
			break
		}
	}
	if !schedulable {
		metrics.SchedulerFrozen.Set(0)
		return probeResult{pass: true} // nowhere to schedule — ambiguous
	}

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{FieldSelector: "status.phase=Pending"})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pending pods: %w", err)}
	}
	now := p.now()
	var stuck []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName != "" ||
			now.Sub(pod.CreationTimestamp.Time) < schedulerPendingMinAge {
			continue
		}
		scheduled := false
		for _, c := range pod.Status.Conditions {
			if c.Type == corev1.PodScheduled {
				scheduled = true
				break
			}
		}
		if !scheduled {
			stuck = append(stuck, pod.Namespace+"/"+pod.Name)
		}
	}
	if len(stuck) == 0 {
		metrics.SchedulerFrozen.Set(0)
		return probeResult{pass: true}
	}
	sort.Strings(stuck)
	metrics.SchedulerFrozen.Set(1)
	return probeResult{why: fmt.Sprintf(
		"%d pods pending >=%s unscheduled with no PodScheduled condition despite Ready workers: %s",
		len(stuck), schedulerPendingMinAge, strings.Join(stuck, ", "))}
}

// ---------------------------------------------------------------------------
// W8-NM2/NM3 — mesh-controlplane-watchdog
// ---------------------------------------------------------------------------

// checkMeshControlPlane heals two control-plane wedge shapes:
//
//	a) W8-NM2 — any Node reporting CiliumIPAMExhausted=True >=10m:
//	   the operator's IPAM bookkeeping wedged; delete a
//	   cilium-operator-* pod (1h cooldown) so the restarted leader
//	   resyncs.
//	b) W8-NM3 — linkerd-destination/linkerd-identity pods in
//	   namespace linkerd stuck >=5m: CrashLoopBackOff or the
//	   started-but-never-Ready wedge while the apiserver is
//	   healthy (our own client calls working proves that). Delete
//	   the pod to re-roll (30m cooldown per component).
//
// Cooldowns live in the in-RAM ledger — the heal target is the pod
// itself, nothing else can carry the stamp.
func (p *clusterHealthProber) checkMeshControlPlane(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.meshHealed == nil {
		p.meshHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	var findings []string

	// (a) CiliumIPAMExhausted latch.
	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	var ipamNodes []string
	for i := range nodes {
		c := shared.NodeCondition(&nodes[i], "CiliumIPAMExhausted")
		if c != nil && c.Status == corev1.ConditionTrue &&
			!c.LastTransitionTime.IsZero() &&
			now.Sub(c.LastTransitionTime.Time) >= ciliumIPAMMinAge {
			ipamNodes = append(ipamNodes, nodes[i].Name)
		}
	}
	if len(ipamNodes) > 0 {
		sort.Strings(ipamNodes)
		findings = append(findings, "cilium_ipam_exhausted:"+strings.Join(ipamNodes, ","))
		p.healComponentPod(ctx, log, "cilium-operator",
			ciliumOperatorNS, ciliumOperatorPrefix, ciliumOpHealCooldown, now)
	}

	// (b) wedged linkerd control-plane pods.
	// linkerd-destination and linkerd-identity are Deployments, so live
	// pod names carry a "<component>-<rs-hash>-<pod-hash>" suffix (or
	// the linkerd.io/control-plane-component label); exact-name match is
	// kept alongside prefix/label match for unit-test fixtures.
	if podList, err := p.cs.CoreV1().Pods(linkerdNS).
		List(ctx, metav1.ListOptions{}); err == nil {
		for _, component := range []string{linkerdDestinationName, linkerdIdentityName} {
			for i := range podList.Items {
				pod := &podList.Items[i]
				if !linkerdPodMatchesComponent(pod, component) || !linkerdPodWedged(pod, now) {
					continue
				}
				findings = append(findings, component+":wedged")
				p.healNamedPod(ctx, log, component, pod.Namespace+"/"+pod.Name,
					pod, linkerdHealCooldown, now)
				break
			}
		}
	}

	if len(findings) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: "mesh control-plane wedge: " + strings.Join(findings, ", ")}
}

// linkerdPodMatchesComponent matches a Pod in the linkerd namespace
// against a control-plane Deployment name ("linkerd-destination" or
// "linkerd-identity") via exact name, Deployment/ReplicaSet prefix, or
// the linkerd.io/control-plane-component label.
func linkerdPodMatchesComponent(pod *corev1.Pod, component string) bool {
	if pod.Name == component || strings.HasPrefix(pod.Name, component+"-") {
		return true
	}
	short := strings.TrimPrefix(component, "linkerd-")
	return short != "" && pod.Labels["linkerd.io/control-plane-component"] == short
}

// linkerdPodWedged reports the wedged-watch / crashloop signature:
// the pod has been Running >= linkerdWedgedMinAge while any container
// sits in CrashLoopBackOff, or every container started but none ever
// went Ready (the ranch-style wedged-watch shape mirrored from the
// rabbitmq suspended-listener detector).
func linkerdPodWedged(pod *corev1.Pod, now time.Time) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return false
	}
	if now.Sub(pod.CreationTimestamp.Time) < linkerdWedgedMinAge {
		return false
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		return false
	}
	allStartedNoneReady := true
	for _, s := range pod.Status.ContainerStatuses {
		if s.State.Waiting != nil && s.State.Waiting.Reason == "CrashLoopBackOff" &&
			s.RestartCount > 2 {
			return true
		}
		if s.Started == nil || !*s.Started || s.Ready {
			allStartedNoneReady = false
		}
	}
	return allStartedNoneReady
}

// healComponentPod deletes one pod matching prefix in ns — the
// generic W8-NM2 shape: same cooldown bookkeeping as every pod-delete
// heal in this package.
func (p *clusterHealthProber) healComponentPod(ctx context.Context, log logr.Logger,
	component, ns, prefix string, cooldown time.Duration, now time.Time) {
	p.mu.Lock()
	last, ok := p.meshHealed[component]
	p.mu.Unlock()
	if ok && now.Sub(last) < cooldown {
		log.Info("skip heal: component inside cooldown", "component", component,
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"component", component, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred", "component", component, "why", why)
		return
	}
	pods, err := p.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list pods failed — heal deferred", "ns", ns, "error", err)
		return
	}
	var target *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if strings.HasPrefix(pod.Name, prefix) && pod.DeletionTimestamp == nil {
			target = pod
			break
		}
	}
	if target == nil {
		return
	}
	p.healNamedPod(ctx, log, component, target.Namespace+"/"+target.Name,
		target, cooldown, now)
}

// healNamedPod deletes the pod after the caller's cooldown decision —
// recording the ledger entry and counting the heal.
func (p *clusterHealthProber) healNamedPod(ctx context.Context, log logr.Logger,
	component, key string, pod *corev1.Pod, cooldown time.Duration, now time.Time) {
	p.mu.Lock()
	last, ok := p.meshHealed[component]
	p.mu.Unlock()
	if ok && now.Sub(last) < cooldown {
		log.Info("skip heal: component inside cooldown", "component", component,
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	uid := pod.UID
	if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "control-plane pod delete failed", "pod", key)
		return
	}
	p.mu.Lock()
	p.meshHealed[component] = now
	p.mu.Unlock()
	metrics.ControlPlanePodHealsTotal.WithLabelValues(component).Inc()
	log.Info("DELETE: wedged control-plane pod — forcing re-roll",
		"component", component, "pod", key)
}

// ---------------------------------------------------------------------------
// W8-ST2 — node-hang-precordon
// ---------------------------------------------------------------------------

// checkNodeHangPreCordon patches spec.unschedulable=true onto worker
// nodes carrying FilesystemReadOnly or KernelHungTasks for >=2m —
// NHC/SNR will reboot the node, but pods keep scheduling onto it
// until then. The 35% cap stops the guard from unnoding the fleet
// during a correlated event (bad kernel rollout, storage backend
// outage).
func (p *clusterHealthProber) checkNodeHangPreCordon(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	workers, cordoned := 0, 0
	var hang []string
	for i := range nodes {
		n := &nodes[i]
		if shared.IsControlPlane(n) {
			continue
		}
		workers++
		if n.Spec.Unschedulable {
			cordoned++
		}
		for _, t := range nodeHangConds {
			c := shared.NodeCondition(n, t)
			if c != nil && c.Status == corev1.ConditionTrue &&
				!c.LastTransitionTime.IsZero() &&
				now.Sub(c.LastTransitionTime.Time) >= nodeHangCondMinAge {
				hang = append(hang, n.Name+":"+string(t))
				break
			}
		}
	}
	if len(hang) == 0 {
		return probeResult{pass: true}
	}
	sort.Strings(hang)
	for _, entry := range hang {
		name, _, _ := strings.Cut(entry, ":")
		var target *corev1.Node
		for i := range nodes {
			if nodes[i].Name == name {
				target = &nodes[i]
				break
			}
		}
		if target == nil || target.Spec.Unschedulable {
			continue
		}
		if workers > 0 && float64(cordoned)/float64(workers) >= nodeHangMaxCordonedRatio {
			log.Info("skip precordon: cordoned-worker ratio at cap — refusing to unnode the fleet",
				"cordoned", cordoned, "workers", workers)
			continue
		}
		payload := []byte(`{"spec":{"unschedulable":true}}`)
		if _, err := p.cs.CoreV1().Nodes().Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "hang precordon patch failed", "node", name)
			continue
		}
		cordoned++
		metrics.NodeHangCordonsTotal.WithLabelValues(name).Inc()
		log.Info("CORDON: node carrying a sustained hang latch — unschedulable before NHC/SNR reboots it",
			"node", name, "condition", entry)
	}
	return probeResult{why: "nodes hanging with a pre-reboot latch: " + strings.Join(hang, ", ")}
}

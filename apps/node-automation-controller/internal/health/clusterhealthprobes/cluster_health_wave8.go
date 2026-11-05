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
//   - node-hang-precordon (W8-ST2/W10-KR6): a worker Node with any
//     nodeHangConds latch (KernelHungTasks, FilesystemReadOnly,
//     KubeletRuntimeStall, KubeletWatchWedge, PodTeardownWedged,
//     InodePressure) True >=2m — or ClockUnsynchronized True >=10m
//     (W9-CP3, long enough for an NTP daemon restart to resync
//     first) — is patched
//     spec.unschedulable=true before NHC/SNR reboots it — new pods
//     stop landing on a dying node. The cordon is stamped with
//     node.ops/precordoned-by=node-hang-precordon and AUTO-UNCORDED
//     once every latch clears (transient recovery, or a post-SNR
//     reboot that preserved spec.unschedulable). Gated on fewer than
//     35% of workers already cordoned so a fleet-wide event cannot
//     unnode the cluster.
//   - linkerd-endpoint-sync (W9-NM2/W10-FIX7): a headless Service in a
//     linkerd-injected namespace whose EndpointSlice stays desynced
//     from its Ready pod IPs >=10m gets
//     node_automation_linkerd_endpoint_desync=1 and a rolling bounce
//     of the oldest linkerd-destination pod (1h per-service cooldown,
//     maintenance-gated) to force a resync — plus deletion of the
//     provably-stale endpointslice-controller-owned EndpointSlices
//     (dead IP retained, or a >3m-Ready pod IP absent from the whole
//     managed set) so KCM rebuilds them instead of the bounce just
//     re-reading the same stale slices.
//   - scylla-cluster-health (W9-ST1): a ScyllaCluster with
//     Degraded=True / Available=False >=15m, a per-member Service
//     whose EndpointSlice lost the live pod IP >=10m, or a member pod
//     whose scylla log tail carries the gossip/raft stall signatures
//     >=10m sets node_automation_scylla_unhealthy{reason}=1.
//
// The W4 stateful-masterless extension (db operator pod delete for
// mariadb/pxc/psmdb/pg/scylla operators) lives in
// cluster_health_probes.go next to the check it extends.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"io"
	"maps"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

	// W9-CP3 — clock-skew pre-cordon: ClockUnsynchronized gets a
	// longer fuse than the hang latches — the NTP daemon needs
	// restart time to resync before the node counts as hanging.
	nodeClockSkewCond      corev1.NodeConditionType = "ClockUnsynchronized"
	nodeClockSkewCordonAge                          = 10 * time.Minute

	// nodeHangPreCordonAnno stamps every cordon this check applies so
	// the auto-uncordon path only ever lifts cordons IT created — a
	// kubectl cordon or an NHC fence carries no stamp and is never
	// touched.
	nodeHangPreCordonAnno  = "node.ops/precordoned-by"
	nodeHangPreCordonValue = "node-hang-precordon"

	// W9-NM2 — linkerd-endpoint-sync knobs.
	checkNameLinkerdEndpointSync = "linkerd-endpoint-sync"
	linkerdEndpointDesyncMinAge  = 10 * time.Minute
	linkerdDestHealCooldown      = time.Hour
	linkerdInjectLabel           = "linkerd.io/inject"
	// linkerdSliceHealMinAge is the fuse on the missing-IP half of
	// the W10-FIX7 stale-slice delete: a Ready pod IP must have been
	// Ready this long before its absence from the service's managed
	// EndpointSlices counts as staleness — younger pods may simply
	// not have been reconciled into the slices yet.
	linkerdSliceHealMinAge = 3 * time.Minute
	// linkerdSliceManagedByESC marks EndpointSlices owned by
	// kube-controller-manager's endpointslice-controller — the only
	// slices the desync heal deletes, since that controller is what
	// recreates them with corrected contents.
	linkerdSliceManagedByESC = "endpointslice-controller.k8s.io"

	// W9-ST1 — scylla-cluster-health knobs.
	checkNameScyllaHealth    = "scylla-cluster-health"
	scyllaDegradedMinAge     = 15 * time.Minute
	scyllaSignatureMinAge    = 10 * time.Minute
	scyllaGossipTailLines    = int64(200)
	scyllaGossipLogMaxBytes  = 256 * 1024
	scyllaPodNameLabel       = "scylla.scylladb.com/pod-name"
	scyllaClusterLabel       = "scylla.scylladb.com/cluster"
	scyllaContainerName      = "scylla"
	scyllaReasonDegraded     = "degraded_condition"
	scyllaReasonMemberDesync = "member_service_desync"
	scyllaReasonGossipStall  = "gossip_or_raft_stall"
)

// scyllaClusterGVR is the ScyllaCluster CR the W9-ST1 auditor reads —
// the same GVR the W5.8 scylla-operator watchdog scans.
var scyllaClusterGVR = schema.GroupVersionResource{
	Group: "scylla.scylladb.com", Version: "v1", Resource: "scyllaclusters"}

// nodeHangConds are the NPD/node-agent latches that precede a node
// reboot — patching unschedulable early keeps new pods off the dying
// node. All are custom NodeConditionTypes written by the node stack
// (FilesystemReadOnly/KernelHungTasks by hostmetrics+workerhygiene,
// KubeletRuntimeStall/KubeletWatchWedge/PodTeardownWedged by
// nodereporter; InodePressure is kubelet-native — nodefs/imagefs
// inode exhaustion, no agent latch involved). There is
// no corev1 constant for any of them — string literals are the
// convention here (same as nodeClockSkewCond below).
// ClockUnsynchronized is deliberately NOT here: it carries its own
// longer fuse (nodeClockSkewCordonAge) and is checked separately.
var nodeHangConds = []corev1.NodeConditionType{
	"KernelHungTasks", "FilesystemReadOnly", "KubeletRuntimeStall",
	"KubeletWatchWedge", "PodTeardownWedged", "InodePressure",
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
// recording the ledger entry and counting the heal. The maintenance
// mutex is re-checked here (not just in healComponentPod) because
// checkMeshControlPlane calls this directly for the wedged linkerd
// pods — every pod-delete heal defers while a drain/upgrade is in
// flight, and "cannot verify" fails closed.
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

// nodeHangLatch reports the first hang latch past its cordon fuse on
// the node — "" when none qualifies. Every nodeHangConds entry fuses
// at nodeHangCondMinAge; ClockUnsynchronized (W9-CP3) gets
// nodeClockSkewCordonAge so an NTP daemon restart has time to resync
// before the node counts as hanging.
func nodeHangLatch(n *corev1.Node, now time.Time) string {
	for _, t := range nodeHangConds {
		c := shared.NodeCondition(n, t)
		if c != nil && c.Status == corev1.ConditionTrue &&
			!c.LastTransitionTime.IsZero() &&
			now.Sub(c.LastTransitionTime.Time) >= nodeHangCondMinAge {
			return string(t)
		}
	}
	if c := shared.NodeCondition(n, nodeClockSkewCond); c != nil &&
		c.Status == corev1.ConditionTrue &&
		!c.LastTransitionTime.IsZero() &&
		now.Sub(c.LastTransitionTime.Time) >= nodeClockSkewCordonAge {
		return string(nodeClockSkewCond)
	}
	return ""
}

// nodeHangLatchActive reports whether ANY hang latch is currently
// True on the node — the auto-uncordon guard. Status only, no age
// floor: a latch that just re-asserted still means the node is
// hanging, so the pre-cordon stays.
func nodeHangLatchActive(n *corev1.Node) bool {
	for _, t := range nodeHangConds {
		if c := shared.NodeCondition(n, t); c != nil &&
			c.Status == corev1.ConditionTrue {
			return true
		}
	}
	if c := shared.NodeCondition(n, nodeClockSkewCond); c != nil &&
		c.Status == corev1.ConditionTrue {
		return true
	}
	return false
}

// checkNodeHangPreCordon patches spec.unschedulable=true onto worker
// nodes carrying a sustained hang latch (any nodeHangConds entry
// >=2m, ClockUnsynchronized >=10m) — NHC/SNR will
// reboot the node, but pods keep scheduling onto it until then. The
// cordon is stamped node.ops/precordoned-by=node-hang-precordon and
// the same sweep AUTO-UNCORDONS a stamped node once every latch has
// cleared — transient recovery, or a post-SNR reboot that came back
// healthy but kept spec.unschedulable. A stale stamp on a schedulable
// node (manual uncordon) is dropped so a later deliberate cordon can
// never inherit the auto-uncordon. The 35% cap stops the guard from
// unnoding the fleet during a correlated event (bad kernel rollout,
// storage backend outage).
func (p *clusterHealthProber) checkNodeHangPreCordon(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	workers, cordoned := 0, 0
	var hang []string
	var uncordon, staleStamp []string
	for i := range nodes {
		n := &nodes[i]
		if shared.IsControlPlane(n) {
			continue
		}
		workers++
		if n.Spec.Unschedulable {
			cordoned++
		}
		// Auto-uncordon / stale-stamp sweep — only nodes THIS check
		// cordoned carry the stamp; everything else is left alone.
		if n.Annotations[nodeHangPreCordonAnno] == nodeHangPreCordonValue {
			switch {
			case n.Spec.Unschedulable && !nodeHangLatchActive(n):
				uncordon = append(uncordon, n.Name)
			case !n.Spec.Unschedulable:
				staleStamp = append(staleStamp, n.Name)
			}
		}
		if latch := nodeHangLatch(n, now); latch != "" {
			hang = append(hang, n.Name+":"+latch)
		}
	}

	// Lift our own cordons first — frees schedulable capacity before
	// the cordon pass re-evaluates the 35% ratio.
	sort.Strings(uncordon)
	for _, name := range uncordon {
		payload := []byte(fmt.Sprintf(
			`{"spec":{"unschedulable":false},"metadata":{"annotations":{"%s":null}}}`,
			nodeHangPreCordonAnno))
		if _, err := p.cs.CoreV1().Nodes().Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "hang precordon uncordon patch failed", "node", name)
			continue
		}
		cordoned--
		metrics.NodeHangUncordonsTotal.WithLabelValues(name).Inc()
		log.Info("UNCORDON: node hang condition cleared",
			"node", name)
	}
	// A stamp left on a schedulable node (manual `kubectl uncordon`)
	// is ours to clean — otherwise a later deliberate cordon would
	// inherit the auto-uncordon.
	sort.Strings(staleStamp)
	for _, name := range staleStamp {
		payload := []byte(fmt.Sprintf(
			`{"metadata":{"annotations":{"%s":null}}}`,
			nodeHangPreCordonAnno))
		if _, err := p.cs.CoreV1().Nodes().Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "hang precordon stale-stamp patch failed", "node", name)
			continue
		}
		log.Info("CORDON STAMP CLEARED: schedulable node carried a stale pre-cordon annotation",
			"node", name)
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
		payload := []byte(fmt.Sprintf(
			`{"spec":{"unschedulable":true},"metadata":{"annotations":{"%s":"%s"}}}`,
			nodeHangPreCordonAnno, nodeHangPreCordonValue))
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

// ---------------------------------------------------------------------------
// W9-NM2 — linkerd-endpoint-sync
// ---------------------------------------------------------------------------

// linkerdEndpointSetsDiverge reports whether a headless Service's
// EndpointSlice view diverged from its pods: a Ready pod IP missing
// from the Ready endpoint addresses (linkerd-destination never learns
// the endpoint exists), or a Ready endpoint address no live selected
// pod owns anymore (a deleted pod's stale IP keeps receiving traffic).
// readyIPs/liveIPs nil-safe: an empty pod set can still flag stale
// endpoint addresses.
func linkerdEndpointSetsDiverge(readyIPs, liveIPs, esReady map[string]bool) bool {
	for ip := range readyIPs {
		if !esReady[ip] {
			return true
		}
	}
	for ip := range esReady {
		if !liveIPs[ip] {
			return true
		}
	}
	return false
}

// linkerdSliceRef is one endpointslice-controller-owned EndpointSlice
// of an audited headless Service — a delete candidate when it
// provably holds stale endpoint data (W10-FIX7). addrs is the set of
// Ready endpoint addresses (nil Ready counts as ready, same
// convention as the aggregate census).
type linkerdSliceRef struct {
	ns, name string
	uid      types.UID
	addrs    map[string]bool
}

// podReadySince returns the pod's PodReady=True LastTransitionTime —
// the clock for the EndpointSlice heal's missing-IP fuse. ok=false
// when the pod is not Ready (mirrors shared.PodReadyCond, which
// returns on the first PodReady-typed condition).
func podReadySince(pod *corev1.Pod) (since time.Time, ok bool) {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			if c.Status != corev1.ConditionTrue {
				return time.Time{}, false
			}
			return c.LastTransitionTime.Time, true
		}
	}
	return time.Time{}, false
}

// staleLinkerdSlices picks the controller-owned EndpointSlices of a
// desynced headless Service that provably hold stale endpoint data
// (W10-FIX7):
//
//   - a slice retaining a Ready address no live selected pod owns
//     (a deleted pod's IP still receiving traffic) is stale on its
//     own — only that slice is returned;
//   - a Ready pod IP past linkerdSliceHealMinAge absent from the
//     UNION of all the service's managed slices means the slice SET
//     is incomplete — no single member is identifiable as the stale
//     one, so every managed slice is returned: deleting them forces
//     endpointslice-controller to rebuild the whole set.
//
// readyAged is the service's pod-IP set filtered to pods Ready past
// the fuse; liveIPs is every live selected pod IP. Both nil-safe.
func staleLinkerdSlices(slices []linkerdSliceRef,
	readyAged, liveIPs map[string]bool) []linkerdSliceRef {
	if len(slices) == 0 {
		return nil
	}
	union := map[string]bool{}
	var stale []linkerdSliceRef
	for _, sl := range slices {
		dead := false
		for a := range sl.addrs {
			union[a] = true
			if !liveIPs[a] {
				dead = true
			}
		}
		if dead {
			stale = append(stale, sl)
		}
	}
	for ip := range readyAged {
		if !union[ip] {
			return slices
		}
	}
	return stale
}

// checkLinkerdEndpointSync audits headless Services (spec.clusterIP
// "None" with a non-empty selector) in namespaces opted into linkerd
// injection: linkerd-destination builds its endpoint table from
// EndpointSlices, so a slice that misses a Ready pod IP — or keeps a
// deleted pod's address — silently blackholes or misroutes traffic
// for exactly the workloads headless services exist for (per-pod DNS,
// StatefulSet members). A divergence must persist
// linkerdEndpointDesyncMinAge before the gauge fires; past the window
// the oldest linkerd-destination pod is bounced (1h per-service
// cooldown, maintenance-gated, UID-preconditioned) to force a full
// resync — the same re-roll shape as the W8-NM3 wedged-pod heal.
// W10-FIX7 adds the other half of the heal: the bounce only re-reads
// EndpointSlices, so when the slices themselves are provably stale
// (a Ready address no live pod owns, or a >3m-Ready pod IP absent
// from the whole endpointslice-controller-owned set) the heal first
// deletes those slices — KCM's endpointslice-controller recreates
// them from current pod state and the bounce then resyncs from
// corrected data. Only managed-by=endpointslice-controller.k8s.io
// slices are delete candidates: mirror/third-party slices are not
// ours to reap.
func (p *clusterHealthProber) checkLinkerdEndpointSync(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.linkerdDesyncSince == nil {
		p.linkerdDesyncSince = map[string]time.Time{}
	}
	if p.linkerdDesyncEmitted == nil {
		p.linkerdDesyncEmitted = map[string]bool{}
	}
	if p.linkerdDesyncHealed == nil {
		p.linkerdDesyncHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	// Namespaces opted into injection — the only places a desynced
	// EndpointSlice actually strands mesh traffic.
	nsList, err := p.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list namespaces: %w", err)}
	}
	injected := map[string]bool{}
	for i := range nsList.Items {
		if nsList.Items[i].Labels[linkerdInjectLabel] == "enabled" {
			injected[nsList.Items[i].Name] = true
		}
	}

	desynced := map[string]bool{} // "ns/name" diverged this sweep
	// staleSlices: "ns/svc" → the provably-stale managed EndpointSlices
	// to delete if the service's desync survives the window (W10-FIX7).
	staleSlices := map[string][]linkerdSliceRef{}
	if len(injected) > 0 {
		svcList, err := p.cs.CoreV1().Services(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			return probeResult{infra: fmt.Errorf("list services: %w", err)}
		}
		podList, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			return probeResult{infra: fmt.Errorf("list pods: %w", err)}
		}
		// Audited services — headless + selector + injected ns, the
		// same filter the per-service loop applies. Only their
		// controller-owned slices are delete candidates (W10-FIX7).
		audited := map[string]bool{}
		for i := range svcList.Items {
			svc := &svcList.Items[i]
			if injected[svc.Namespace] &&
				svc.Spec.ClusterIP == corev1.ClusterIPNone &&
				len(svc.Spec.Selector) > 0 {
				audited[svc.Namespace+"/"+svc.Name] = true
			}
		}
		// Ready endpoint addresses per ns/service — same source and
		// nil-ready-counts-as-ready convention as the masterless
		// census. Paged like every cluster-wide read in this package.
		esReady := map[string]map[string]bool{}
		// managedSlices: "ns/svc" → the service's
		// endpointslice-controller-owned EndpointSlices with their
		// Ready address sets — the W10-FIX7 delete candidates.
		managedSlices := map[string][]linkerdSliceRef{}
		sliceOpts := metav1.ListOptions{Limit: healthListPageSize}
		for {
			page, err := p.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).
				List(ctx, sliceOpts)
			if err != nil {
				return probeResult{infra: fmt.Errorf("list endpointslices: %w", err)}
			}
			for _, s := range page.Items {
				svc := s.Labels[discoveryv1.LabelServiceName]
				if svc == "" {
					continue
				}
				key := s.Namespace + "/" + svc
				managed := audited[key] &&
					s.Labels[discoveryv1.LabelManagedBy] == linkerdSliceManagedByESC &&
					s.DeletionTimestamp == nil
				var sliceAddrs map[string]bool
				if managed {
					sliceAddrs = map[string]bool{}
				}
				set := esReady[key]
				if set == nil {
					set = map[string]bool{}
					esReady[key] = set
				}
				for _, ep := range s.Endpoints {
					if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
						continue
					}
					for _, a := range ep.Addresses {
						set[a] = true
						if managed {
							sliceAddrs[a] = true
						}
					}
				}
				if managed {
					managedSlices[key] = append(managedSlices[key],
						linkerdSliceRef{ns: s.Namespace, name: s.Name,
							uid: s.UID, addrs: sliceAddrs})
				}
			}
			if page.Continue == "" {
				break
			}
			sliceOpts.Continue = page.Continue
		}

		podsByNS := map[string][]*corev1.Pod{}
		for i := range podList.Items {
			pod := &podList.Items[i]
			podsByNS[pod.Namespace] = append(podsByNS[pod.Namespace], pod)
		}
		for i := range svcList.Items {
			svc := &svcList.Items[i]
			if !injected[svc.Namespace] ||
				svc.Spec.ClusterIP != corev1.ClusterIPNone ||
				len(svc.Spec.Selector) == 0 {
				continue
			}
			sel := labels.SelectorFromSet(svc.Spec.Selector)
			readyIPs := map[string]bool{}
			liveIPs := map[string]bool{}
			readyAgedIPs := map[string]bool{}
			for _, pod := range podsByNS[svc.Namespace] {
				if pod.DeletionTimestamp != nil ||
					!sel.Matches(labels.Set(pod.Labels)) ||
					pod.Status.PodIP == "" {
					continue
				}
				liveIPs[pod.Status.PodIP] = true
				if since, ok := podReadySince(pod); ok {
					readyIPs[pod.Status.PodIP] = true
					// W10-FIX7 fuse — only a pod Ready past
					// linkerdSliceHealMinAge counts as "missing"
					// from the slices; a zero LastTransitionTime
					// reads as maximally aged.
					if now.Sub(since) >= linkerdSliceHealMinAge {
						readyAgedIPs[pod.Status.PodIP] = true
					}
				}
			}
			key := svc.Namespace + "/" + svc.Name
			if linkerdEndpointSetsDiverge(readyIPs, liveIPs, esReady[key]) {
				desynced[key] = true
			}
			if stale := staleLinkerdSlices(
				managedSlices[key], readyAgedIPs, liveIPs); len(stale) > 0 {
				staleSlices[key] = stale
			}
		}
	}

	emitted := map[string]bool{} // "ns/name" past the persistence window
	p.mu.Lock()
	for k := range p.linkerdDesyncSince {
		if !desynced[k] {
			delete(p.linkerdDesyncSince, k)
		}
	}
	for k := range desynced {
		first, ok := p.linkerdDesyncSince[k]
		if !ok {
			p.linkerdDesyncSince[k] = now
			log.Info("linkerd endpoint desync — tracking first-seen", "service", k)
			continue
		}
		if now.Sub(first) < linkerdEndpointDesyncMinAge {
			continue
		}
		emitted[k] = true
		parts := strings.SplitN(k, "/", 2)
		metrics.LinkerdEndpointDesync.WithLabelValues(parts[0], parts[1]).Set(1)
	}
	for k := range p.linkerdDesyncEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 2); len(parts) == 2 {
			metrics.LinkerdEndpointDesync.DeleteLabelValues(parts[0], parts[1])
		}
		delete(p.linkerdDesyncEmitted, k)
	}
	maps.Copy(p.linkerdDesyncEmitted, emitted)
	// Prune expired heal-ledger entries — an entry past the cooldown
	// can never block again, so keeping it is pure map growth.
	for k, last := range p.linkerdDesyncHealed {
		if now.Sub(last) >= linkerdDestHealCooldown {
			delete(p.linkerdDesyncHealed, k)
		}
	}
	p.mu.Unlock()

	// Past the window: bounce the oldest linkerd-destination pod so
	// its endpoint table rebuilds from the current EndpointSlices.
	// The 1h cooldown is per desynced SERVICE — two services stuck on
	// the same root cause share one bounce.
	for k := range emitted {
		p.healLinkerdDestination(ctx, log, k, now, staleSlices[k])
	}

	if len(emitted) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"headless services with EndpointSlice desync >=%s: %s",
		linkerdEndpointDesyncMinAge, strings.Join(keys, ", "))}
}

// healLinkerdDestination repairs a desynced headless Service on two
// fronts (W10-FIX7):
//
//  1. DELETE the provably-stale endpointslice-controller-owned
//     EndpointSlices staleLinkerdSlices flagged — a bounce only
//     re-reads the slices, so without this the destination pod would
//     resync from the same stale data. KCM's endpointslice-controller
//     recreates them from current pod state (UID-preconditioned,
//     same delete shape as the orphan-slice cleaner).
//  2. delete the OLDEST linkerd-destination pod — the component that
//     turns EndpointSlices into proxy endpoint state, so restarting
//     it forces a full resync from the (now corrected) slices.
//
// Gates: the 1h in-RAM cooldown keyed on the desynced service (the
// heal targets are the slices + pod — nothing else can carry the
// stamp; one stamp covers BOTH actions so a 5m sweep cannot churn
// slice deletes inside the pod-bounce cooldown) and the maintenance
// mutex, same shape as every pod-delete heal in this package. The
// cooldown stamps when ANY heal action succeeded — a failed delete
// retries next sweep instead of burning the hour.
func (p *clusterHealthProber) healLinkerdDestination(ctx context.Context,
	log logr.Logger, svcKey string, now time.Time, stale []linkerdSliceRef) {

	p.mu.Lock()
	last, ok := p.linkerdDesyncHealed[svcKey]
	p.mu.Unlock()
	if ok && now.Sub(last) < linkerdDestHealCooldown {
		log.Info("skip heal: linkerd-destination inside cooldown",
			"service", svcKey, "ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"service", svcKey, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"service", svcKey, "why", why)
		return
	}

	healed := false
	for _, sl := range stale {
		uid := sl.uid
		err := p.cs.DiscoveryV1().EndpointSlices(sl.ns).Delete(ctx, sl.name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			})
		switch {
		case err == nil:
			healed = true
			log.Info("DELETE: stale EndpointSlice for endpoint desync — endpointslice-controller rebuild forced",
				"endpointslice", sl.ns+"/"+sl.name, "service", svcKey)
		case apierrors.IsNotFound(err):
			// Already gone — another actor or the controller beat
			// us to it; nothing to heal.
		default:
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "stale endpointslice delete failed",
				"endpointslice", sl.ns+"/"+sl.name, "service", svcKey)
		}
	}

	pods, err := p.cs.CoreV1().Pods(linkerdNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list linkerd pods failed — heal deferred",
			"error", err)
		return
	}
	var target *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			!linkerdPodMatchesComponent(pod, linkerdDestinationName) {
			continue
		}
		if target == nil ||
			pod.CreationTimestamp.Before(&target.CreationTimestamp) {
			target = pod
		}
	}
	if target != nil {
		uid := target.UID
		if err := p.cs.CoreV1().Pods(target.Namespace).Delete(ctx, target.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "linkerd-destination delete failed",
				"pod", target.Namespace+"/"+target.Name)
		} else {
			healed = true
			metrics.ControlPlanePodHealsTotal.WithLabelValues(linkerdDestinationName).Inc()
			log.Info("DELETE: linkerd-destination bounce for endpoint desync — forcing endpoint-table resync",
				"pod", target.Namespace+"/"+target.Name, "service", svcKey)
		}
	}
	if healed {
		p.mu.Lock()
		p.linkerdDesyncHealed[svcKey] = now
		p.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// W9-ST1 — scylla-cluster-health
// ---------------------------------------------------------------------------

// scyllaGossipPatterns are the log signatures of the three ScyllaDB
// failure shapes the operator cannot see from the API (per
// docs/scylladb-troubleshooting.md in passiontech-fluxcd):
//
//   - a ghost gossip entry rejecting a rejoining member
//     ("InetAddress ... is already present in gossip" — needs
//     nodetool removenode / replace_address);
//   - replace_address_first_boot — the member is re-bootstrapping
//     against a stale address;
//   - group0/raft timeouts — quorum loss stalls every cluster-wide
//     change (the deadlock the doc's section 3 describes).
var scyllaGossipPatterns = []*regexp.Regexp{
	regexp.MustCompile(`InetAddress .* is already present in gossip`),
	regexp.MustCompile(`replace_address_first_boot`),
	regexp.MustCompile(`group0.*timed out`),
	regexp.MustCompile(`raft_group0`),
}

// unstructuredCondStatus returns a dynamic-client object's named
// status.conditions entry's status and lastTransitionTime — ""
// and the zero time when absent or malformed.
func unstructuredCondStatus(obj *unstructured.Unstructured, typ string) (string, time.Time) {
	for _, c := range shared.ReadyConds(obj) {
		if c["type"] != typ {
			continue
		}
		s, _ := c["status"].(string)
		ts, _ := c["lastTransitionTime"].(string)
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return s, time.Time{}
		}
		return s, t
	}
	return "", time.Time{}
}

// scyllaFinding is one live unhealthy signature resolved to its gauge
// labels.
type scyllaFinding struct {
	ns, cluster, reason string
}

// scyllaPodTroubled selects the member pods worth a log fetch:
// anything not cleanly Running+Ready — Pending/Failed/Unknown phase,
// a pod that never went Ready, or a container in CrashLoopBackOff
// ("unready/restarting" in the W9-ST1 contract). Succeeded pods and
// pods already terminating are skipped — their logs describe a dead
// end, not a live stall.
func scyllaPodTroubled(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded {
		return false
	}
	if pod.Status.Phase != corev1.PodRunning {
		return true
	}
	if !shared.PodReadyCond(pod) {
		return true
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			return true
		}
	}
	return false
}

// scyllaGossipLogHit fetches the last scyllaGossipTailLines of the
// pod's "scylla" container and reports whether any line matches a
// gossip/raft stall signature. Bounded to 8s / scyllaGossipLogMaxBytes
// (same posture as the coredns watchdog's log probe); a stream/read
// failure is inconclusive — returned as an error so the caller logs
// it rather than reading "no match" as "healthy".
func (p *clusterHealthProber) scyllaGossipLogHit(ctx context.Context, pod *corev1.Pod) (bool, error) {
	lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tail := scyllaGossipTailLines
	stream, err := p.cs.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name,
		&corev1.PodLogOptions{
			Container: scyllaContainerName,
			TailLines: &tail,
		}).Stream(lctx)
	if err != nil {
		return false, err
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, scyllaGossipLogMaxBytes))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, re := range scyllaGossipPatterns {
			if re.MatchString(line) {
				return true, nil
			}
		}
	}
	return false, nil
}

// checkScyllaHealth audits the ScyllaDB operand stack on the three
// failure shapes that leave the cluster degraded without the operator
// noticing (W9-ST1):
//
//	a) degraded_condition — the ScyllaCluster CR itself reports
//	   Degraded=True or Available=False for >=15m (the condition's
//	   own lastTransitionTime is the persistence clock);
//	b) member_service_desync — a per-member Service
//	   (scylla.scylladb.com/pod-name=<pod>) whose EndpointSlice does
//	   not carry the live pod's status.podIP — or carries no endpoint
//	   at all while the pod is Running — for >=10m;
//	c) gossip_or_raft_stall — an unready/restarting member pod
//	   (scylla.scylladb.com/cluster=<name>) whose scylla log tail
//	   matches the ghost-gossip / replace_address_first_boot /
//	   group0-raft-timeout signatures for >=10m.
//
// Every signature must persist its window before
// node_automation_scylla_unhealthy{reason}=1 fires; a resolved tuple
// is DeleteLabelValues'd, never left stale at 1.
func (p *clusterHealthProber) checkScyllaHealth(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	// The CR scan needs dyn — a missing client is a wiring bug, not
	// "no signal" (same posture as the OLM check).
	if p.dyn == nil {
		return probeResult{infra: fmt.Errorf(
			"no dynamic client — scylla health check unverifiable")}
	}
	now := p.now()
	p.mu.Lock()
	if p.scyllaFirstSeen == nil {
		p.scyllaFirstSeen = map[string]time.Time{}
	}
	if p.scyllaEmitted == nil {
		p.scyllaEmitted = map[string]bool{}
	}
	p.mu.Unlock()

	// pending: signatures still inside their persistence window,
	// keyed for first-seen tracking. emittedKeys collect the gauge
	// tuples already past their evidence window.
	pending := map[string]scyllaFinding{}
	emitted := map[string]scyllaFinding{} // "ns/cluster/reason" -> finding

	// (a) degraded_condition — the CR's own condition clock.
	crs, err := p.dyn.Resource(scyllaClusterGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// ScyllaDB stack not installed on this cluster — (b)/(c)
		// still run: member services/pods could outlive the CRD.
	case err != nil:
		return probeResult{infra: fmt.Errorf("list scyllaclusters: %w", err)}
	default:
		for i := range crs.Items {
			cr := &crs.Items[i]
			for _, probe := range []struct{ typ, status string }{
				{"Degraded", "True"},
				{"Available", "False"},
			} {
				status, since := unstructuredCondStatus(cr, probe.typ)
				if status != probe.status || since.IsZero() ||
					now.Sub(since) < scyllaDegradedMinAge {
					continue
				}
				f := scyllaFinding{
					ns: cr.GetNamespace(), cluster: cr.GetName(),
					reason: scyllaReasonDegraded,
				}
				emitted[f.ns+"/"+f.cluster+"/"+f.reason] = f
			}
		}
	}

	// Shared reads for (b) and (c) — one pod/service/EndpointSlice
	// census per sweep.
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	svcs, err := p.cs.CoreV1().Services(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list services: %w", err)}
	}
	esAddrs := map[string]map[string]bool{} // "ns/svc" -> endpoint addresses
	sliceOpts := metav1.ListOptions{Limit: healthListPageSize}
	for {
		page, err := p.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).
			List(ctx, sliceOpts)
		if err != nil {
			return probeResult{infra: fmt.Errorf("list endpointslices: %w", err)}
		}
		for _, s := range page.Items {
			svc := s.Labels[discoveryv1.LabelServiceName]
			if svc == "" {
				continue
			}
			key := s.Namespace + "/" + svc
			set := esAddrs[key]
			if set == nil {
				set = map[string]bool{}
				esAddrs[key] = set
			}
			for _, ep := range s.Endpoints {
				// Ready-only — a slice holding the pod IP but
				// marked unready is still a desync for traffic.
				// nil Ready counts as ready (k8s convention).
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				for _, a := range ep.Addresses {
					set[a] = true
				}
			}
		}
		if page.Continue == "" {
			break
		}
		sliceOpts.Continue = page.Continue
	}

	podsByKey := map[string]*corev1.Pod{}
	for i := range pods.Items {
		podsByKey[pods.Items[i].Namespace+"/"+pods.Items[i].Name] = &pods.Items[i]
	}

	// (b) member_service_desync — the per-member Service must route
	// to the live pod's IP.
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		podName := svc.Labels[scyllaPodNameLabel]
		if podName == "" {
			continue
		}
		pod := podsByKey[svc.Namespace+"/"+podName]
		if pod == nil || pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			pod.Status.PodIP == "" {
			continue
		}
		if esAddrs[svc.Namespace+"/"+svc.Name][pod.Status.PodIP] {
			continue // EndpointSlice carries the live IP — synced
		}
		cluster := pod.Labels[scyllaClusterLabel]
		if cluster == "" {
			cluster = svc.Name // unlabeled member pod — key the gauge on the service
		}
		pending["member/"+svc.Namespace+"/"+svc.Name] = scyllaFinding{
			ns: svc.Namespace, cluster: cluster,
			reason: scyllaReasonMemberDesync,
		}
	}

	// (c) gossip_or_raft_stall — troubled member pods whose scylla
	// log tail carries a stall signature.
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Labels[scyllaClusterLabel] == "" || !scyllaPodTroubled(pod) {
			continue
		}
		hit, err := p.scyllaGossipLogHit(ctx, pod)
		if err != nil {
			// Inconclusive, not clean — a broken pod-log path must
			// not silently read as "no stall".
			log.Info("WARN: scylla log fetch failed — stall signature inconclusive",
				"pod", pod.Namespace+"/"+pod.Name, "error", err)
			continue
		}
		if !hit {
			continue
		}
		pending["gossip/"+pod.Namespace+"/"+pod.Name+"/"+string(pod.UID)] =
			scyllaFinding{
				ns: pod.Namespace, cluster: pod.Labels[scyllaClusterLabel],
				reason: scyllaReasonGossipStall,
			}
	}

	// Persistence window + gauge emission — same first-seen /
	// DeleteLabelValues hygiene as the OLM and masterless checks.
	p.mu.Lock()
	for k := range p.scyllaFirstSeen {
		if _, ok := pending[k]; !ok {
			delete(p.scyllaFirstSeen, k)
		}
	}
	for k, f := range pending {
		first, ok := p.scyllaFirstSeen[k]
		if !ok {
			p.scyllaFirstSeen[k] = now
			log.Info("scylla unhealthy signature — tracking first-seen",
				"signature", k)
			continue
		}
		if now.Sub(first) < scyllaSignatureMinAge {
			continue
		}
		emitted[f.ns+"/"+f.cluster+"/"+f.reason] = f
	}
	for k := range p.scyllaEmitted {
		if _, ok := emitted[k]; ok {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.ScyllaClusterUnhealthy.DeleteLabelValues(
				parts[0], parts[1], parts[2])
		}
		delete(p.scyllaEmitted, k)
	}
	emittedKeys := make(map[string]bool, len(emitted))
	for k := range emitted {
		emittedKeys[k] = true
	}
	maps.Copy(p.scyllaEmitted, emittedKeys)
	p.mu.Unlock()

	for _, f := range emitted {
		metrics.ScyllaClusterUnhealthy.
			WithLabelValues(f.ns, f.cluster, f.reason).Set(1)
	}

	if len(emitted) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"scylla unhealthy signatures: %s", strings.Join(keys, ", "))}
}

// dead-node-sweeper — port of hooks/90-dead-node-sweeper.sh.
//
// Force-evicts pods stuck in Terminating on a dead node. A pod whose
// kubelet stopped answering stays "Terminating" forever (grace-period
// timers run on the kubelet, not the apiserver): PVCs stay attached,
// Deployments/StatefulSets can't reschedule, and `kubectl delete pod
// --force` is a foot-gun because it can produce two writers on one
// volume if the node is only partitioned (incident 2026-11-02: 40+
// Terminating pods on a power-failed worker, DBs pending for hours).
//
// The fix is NOT force-delete — it is the out-of-service taint
// (node.kubernetes.io/out-of-service=nodeshutdown:NoExecute). On that
// taint the node-controller itself force-deletes the node's pods and
// the attach-detach controller force-detaches its volumes — the same
// code path kubectl-node-shell / medik8s SNR use, so failover is
// atomic with no split-brain window.
//
// SAFETY — fail closed, always. The taint is applied only when there
// is independent evidence the node is fenced:
//
//	(a) a medik8s remediation CR exists for the node
//	    (selfnoderemediations.self-node-remediation.medik8s.io or
//	    fenceagentsremediations.fence-agents-remediation.medik8s.io, any namespace,
//	    named after the node) — a fencer already declared it dead; or
//	(b) Ready=Unknown for >30m AND the kubelet /healthz probe through
//	    the apiserver proxy fails — kubelet is unreachable AND the
//	    node-controller gave up on its lease long ago.
//
// A node that is merely NotReady (Ready=False) with no remediation CR
// and a fresh-enough heartbeat window is left alone — that is the
// host-watchdog / NHC layer's job. Pods on Ready nodes are skipped
// entirely. At most one node is tainted per cycle, so even a wrong
// verdict bounds the blast radius. Pods are never deleted directly.
//
// Recovery: a node that comes back Ready=True while still carrying
// the out-of-service taint gets untainted so it rejoins scheduling.
package controller

import (
	"context"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	deadNodeSweeperQueue = "dead-node-sweeper"
	// deadNodeStuckPodAge: how long a pod may sit in Terminating
	// before its node is suspected. Longer than any legitimate
	// graceful shutdown (default grace 30s, worst-case preStop +
	// 5-10m drains) so normal deletes are never touched.
	deadNodeStuckPodAge = 15 * time.Minute
	// deadNodeUnknownAge: Ready=Unknown must persist this long
	// before path (b) is even considered — covers monitor-grace
	// (40s), lease retry storms and short network partitions.
	deadNodeUnknownAge = 30 * time.Minute
	// deadNodeProbeTimeout: per-probe apiserver timeout, same as
	// the kubelet reaper's.
	deadNodeProbeTimeout = 8 * time.Second
	// deadNodeCap: nodes tainted per cycle — wrong verdicts must
	// never take more than one node at a time.
	deadNodeCap = 1
	// outOfServiceTaint*: the Kubernetes-native "node is fenced"
	// signal — node lifecycle controller force-deletes the pods,
	// attach-detach controller force-detaches the volumes.
	outOfServiceTaintKey   = "node.kubernetes.io/out-of-service"
	outOfServiceTaintValue = "nodeshutdown"
)

// medik8s remediation CRs — a fencer naming a node is the strongest
// death certificate available in-cluster.
var (
	selfNodeRemediationGVR = schema.GroupVersionResource{
		Group:    "self-node-remediation.medik8s.io",
		Version:  "v1alpha1",
		Resource: "selfnoderemediations",
	}
	fenceAgentsRemediationGVR = schema.GroupVersionResource{
		Group:    "fence-agents-remediation.medik8s.io",
		Version:  "v1alpha1",
		Resource: "fenceagentsremediations",
	}
)

type deadNodeSweeper struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// Probe seam — same trick as kubeletReaper: the node/proxy REST
	// path cannot be served by the fake clientset, so tests stub the
	// healthz outcome per node.
	probeFn func(ctx context.Context, nodeName string) (bool, error)
}

// SetupDeadNodeSweeper registers the 5-minute sweep.
func SetupDeadNodeSweeper(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface) error {
	s := &deadNodeSweeper{cs: cs, dyn: dyn}
	s.probeFn = s.probe
	return addPeriodic(mgr, deadNodeSweeperQueue, 5*time.Minute, s.run)
}

func (s *deadNodeSweeper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	nodes, err := listNodes(ctx, s.cs)
	if err != nil {
		return err
	}
	nodeByName := make(map[string]*corev1.Node, len(nodes))
	hasNotReady := false
	untainted := 0
	for i := range nodes {
		n := &nodes[i]
		nodeByName[n.Name] = n
		if !nodeReady(n) {
			hasNotReady = true
		}

		// Recovery first: a node back to Ready=True must not keep
		// the out-of-service taint or it stays unschedulable.
		if hasTaint(n.Spec.Taints, outOfServiceTaintKey) && nodeReady(n) {
			if err := untaintNode(ctx, s.cs, n.Name, outOfServiceTaintKey); err != nil {
				log.Error(err, "untaint failed", "node", n.Name)
				metrics.IncError(deadNodeSweeperQueue)
				continue
			}
			untainted++
			log.Info("UNTAINT: node Ready again -> out-of-service removed", "node", n.Name)
		}
	}
	// nodeByName holds all the node data the rest of the sweep needs —
	// the slice copy stays reachable through it, so only the redundant
	// slice header is dropped here (keeps the diff honest about which
	// references are actually dead).
	nodes = nil

	// Every node Ready = nothing can be fenced this cycle, so skip
	// the cluster-wide pod list entirely: it is by far the biggest
	// read this module makes (every pod in the cluster, deserialized)
	// and the all-Ready happy path never consumes it. A stuck pod on
	// a since-deleted node could only produce a skip-log anyway.
	if !hasNotReady {
		log.Info("sweep done", "untainted", untainted)
		return nil
	}

	// Server-side phase filter: terminal pods can never be "stuck
	// Terminating" evidence, so they are dead weight in the biggest
	// read this module makes. The in-code phase check stays — fake
	// clientsets ignore field selectors and the belt costs nothing.
	pods, err := s.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
	})
	if err != nil {
		return err
	}

	// Count pods stuck in Terminating past the grace age, per node.
	stuck := map[string]int{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue // mirrors the FieldSelector for fake clients
		}
		if p.DeletionTimestamp == nil || p.Spec.NodeName == "" {
			continue
		}
		if time.Since(p.DeletionTimestamp.Time) <= deadNodeStuckPodAge {
			continue // still inside a legitimate graceful shutdown
		}
		stuck[p.Spec.NodeName]++
	}
	// The probes/lists/taints below only need the per-node counts —
	// release the full PodList before they run.
	pods = nil
	if len(stuck) == 0 {
		log.Info("sweep done", "untainted", untainted)
		return nil
	}

	// Deterministic order so the per-cycle cap picks the same node.
	names := make([]string, 0, len(stuck))
	for name := range stuck {
		names = append(names, name)
	}
	sort.Strings(names)

	tainted := 0
	for _, nodeName := range names {
		count := stuck[nodeName]

		n := nodeByName[nodeName]
		if n == nil {
			log.Info("SKIP: node object gone — apiserver already force-removed it?",
				"node", nodeName, "stuckPods", count)
			continue
		}
		if nodeReady(n) {
			// Node is alive: Terminating pods there are a wedged
			// runtime/finalizer problem — the host watchdog's job,
			// not a fencing decision.
			log.Info("SKIP: node still Ready", "node", nodeName, "stuckPods", count)
			continue
		}
		if hasTaint(n.Spec.Taints, outOfServiceTaintKey) {
			// Already fenced — the node controller is working on
			// the force-deletes; does not consume the cap.
			log.Info("KEEP-TAINT: already out-of-service", "node", nodeName, "stuckPods", count)
			continue
		}
		if tainted >= deadNodeCap {
			log.Info("SKIP rest: cap reached", "cap", deadNodeCap, "node", nodeName, "stuckPods", count)
			continue
		}

		dead, err := s.confirmedDead(ctx, n)
		if err != nil {
			log.Error(err, "death check failed — node skipped (fail closed)",
				"node", nodeName, "stuckPods", count)
			metrics.IncError(deadNodeSweeperQueue)
			continue
		}
		if !dead {
			log.Info("SKIP: no fencing evidence — fail closed",
				"node", nodeName, "stuckPods", count)
			continue
		}

		// Signal only: which volumes will the taint force-detach.
		// Failure here must not veto the taint decision.
		s.logVolumeAttachments(ctx, nodeName)

		if err := taintNode(ctx, s.cs, nodeName, outOfServiceTaintKey,
			outOfServiceTaintValue, corev1.TaintEffectNoExecute); err != nil {
			log.Error(err, "out-of-service taint failed", "node", nodeName)
			metrics.IncError(deadNodeSweeperQueue)
			continue
		}
		tainted++
		log.Info("TAINT: node confirmed dead -> out-of-service=nodeshutdown:NoExecute "+
			"(pods force-deleted, volumes detached by node controller)",
			"node", nodeName, "stuckPods", count)
	}
	log.Info("sweep done", "tainted", tainted, "untainted", untainted,
		"stuckNodes", len(stuck))
	return nil
}

// confirmedDead is the safety gate — true only with independent
// fencing evidence (medik8s CR, or Ready=Unknown>30m + dead probe).
func (s *deadNodeSweeper) confirmedDead(ctx context.Context, n *corev1.Node) (bool, error) {
	log := logf.FromContext(ctx)

	// Path (a): a fencer CR exists for the node.
	fenced, err := s.hasRemediationCR(ctx, n.Name)
	if err != nil {
		return false, err
	}
	if fenced {
		log.Info("fencing evidence: medik8s remediation CR", "node", n.Name)
		return true, nil
	}

	// Path (b): Ready=Unknown held for >30m (the node controller
	// stopped getting heartbeats long ago) AND the kubelet does not
	// answer /healthz through the apiserver proxy.
	c := nodeCondition(n, corev1.NodeReady)
	if c == nil || c.Status != corev1.ConditionUnknown {
		return false, nil // NotReady/False alone is not a death certificate
	}
	if c.LastTransitionTime.IsZero() ||
		time.Since(c.LastTransitionTime.Time) <= deadNodeUnknownAge {
		return false, nil
	}
	ok, err := s.probeFn(ctx, n.Name)
	if err != nil {
		// A probe that errors out IS a failed probe — the kubelet
		// did not serve healthz (same meaning as kubelet reaper's
		// DoRaw error). Logged for forensics, not counted as a
		// module failure.
		log.Error(err, "kubelet healthz probe errored — counts as failed", "node", n.Name)
		return true, nil
	}
	if !ok {
		log.Info("fencing evidence: Ready=Unknown>30m + kubelet probe failed", "node", n.Name)
		return true, nil
	}
	return false, nil
}

// hasRemediationCR reports whether any medik8s remediation object is
// named after the node (CR name == node name in both CRDs). A missing
// CRD is "no evidence", not an error — other list failures are real.
func (s *deadNodeSweeper) hasRemediationCR(ctx context.Context, nodeName string) (bool, error) {
	for _, gvr := range []schema.GroupVersionResource{
		selfNodeRemediationGVR, fenceAgentsRemediationGVR,
	} {
		list, err := s.dyn.Resource(gvr).Namespace(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
				continue // CRD not installed on this cluster
			}
			return false, err
		}
		for i := range list.Items {
			if list.Items[i].GetName() == nodeName {
				return true, nil
			}
		}
	}
	return false, nil
}

// probe GETs /api/v1/nodes/<node>/proxy/healthz through the apiserver
// (the konnectivity tunnel path, same as the kubelet reaper): a body
// starting with "ok" is healthy. 8s timeout, single attempt — the
// 30m Unknown window already absorbed transient wobble.
func (s *deadNodeSweeper) probe(ctx context.Context, nodeName string) (bool, error) {
	body, err := s.cs.CoreV1().RESTClient().Get().
		Resource("nodes").Name(nodeName).SubResource("proxy").
		Suffix("healthz").
		Timeout(deadNodeProbeTimeout).
		DoRaw(ctx)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(strings.TrimSpace(string(body)), "ok"), nil
}

// logVolumeAttachments lists VolumeAttachments bound to the node as a
// forensics signal (these are what the taint will force-detach).
// Never fatal, never vetoes a decision.
func (s *deadNodeSweeper) logVolumeAttachments(ctx context.Context, nodeName string) {
	log := logf.FromContext(ctx)
	vas, err := s.cs.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Error(err, "volumeattachment list failed — signal only", "node", nodeName)
		metrics.IncError(deadNodeSweeperQueue)
		return
	}
	var names []string
	for i := range vas.Items {
		if vas.Items[i].Spec.NodeName == nodeName {
			names = append(names, vas.Items[i].Name)
		}
	}
	if len(names) > 0 {
		log.Info("node holds volumeattachments — taint will force-detach",
			"node", nodeName, "attachments", names)
	}
}

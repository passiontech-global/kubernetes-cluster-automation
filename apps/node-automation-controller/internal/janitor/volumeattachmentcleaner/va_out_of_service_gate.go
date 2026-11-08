// va_out_of_service_gate.go — gate 2 of the volumeattachment-cleaner:
// the out-of-service reaping proof (metric reason
// "out_of_service_node"). The node carries
// node.kubernetes.io/out-of-service, the fencing signal CSI respects
// (dead-node-sweeper and medik8s SNR set it once a node is confirmed
// dead); on that taint attach-detach force-detaches by deleting the
// VAs itself, so a VA still pointing at a fenced node is a straggler.
// The gate only ever takes over a WEDGED cleanup: the node must have
// been continuously not-Ready past vaOutOfServiceDownFor (the
// nodeNotReadySince first-seen ledger, fed by trackNodeNotReady — a
// Ready node re-arms the window) AND a live pod List must confirm
// zero non-terminal pods: a pod still in Pending/Running on that
// node may still hold the mount, and only the node controller —
// never us — force-deletes those. Split out of
// volumeattachment_cleaner.go — see that file for the sweep that
// consumes these verdicts.
package volumeattachmentcleaner

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// trackNodeNotReady feeds the gate's not-Ready ledger from the node
// census. Recovery re-arms the window — a node that flapped back to
// life must prove another full 15m of death before its VAs are
// touched again.
func (c *volumeAttachmentCleaner) trackNodeNotReady(n *corev1.Node, now time.Time) {
	if !kube.NodeReady(n) {
		c.nodeNotReadySince.Observe(n.Name, now)
	} else {
		c.nodeNotReadySince.Forget(n.Name)
	}
}

// pruneVanishedNodes re-arms the not-Ready window for nodes that
// vanished between cycles — their clock was measuring a node that no
// longer exists.
func (c *volumeAttachmentCleaner) pruneVanishedNodes(nodeByName map[string]*corev1.Node) {
	c.nodeNotReadySince.Prune(func(name string) bool {
		_, ok := nodeByName[name]
		return ok
	})
}

// nodeFencedDead is the out-of-service gate: true only when the node
// carries the fencing taint AND has been not-Ready past the window
// AND provably hosts zero non-terminal pods. Any failed check keeps
// the VA — the volume may still be mounted by something real.
// podProbe caches one node's live-pod verdict for the cycle: a
// successful count, or the list error (fail closed either way on
// retry within the same sweep). reported marks that err already
// bumped IncError — N VAs sharing one fenced node must not fire N
// error bumps off the single cached failure.
type podProbe struct {
	count    int
	err      error
	reported bool
}

func (c *volumeAttachmentCleaner) nodeFencedDead(ctx context.Context,
	node *corev1.Node, livePods map[string]podProbe, now time.Time) bool {
	log := logf.FromContext(ctx)
	if !kube.HasTaint(node.Spec.Taints, vaOutOfServiceTaint) {
		return false // not fenced — NotReady alone is never a verdict
	}
	if kube.NodeReady(node) {
		return false // fenced but alive — the taint is stale, VAs stay
	}
	notReadyFor, ok := c.nodeNotReadySince.Seen(node.Name, now)
	if !ok {
		return false // node not in the not-Ready ledger — no verdict
	}
	if notReadyFor < vaOutOfServiceDownFor {
		log.Info("KEEP: fenced node still inside not-Ready window",
			"node", node.Name,
			"notReadyFor", notReadyFor.Truncate(time.Minute),
			"required", vaOutOfServiceDownFor)
		return false // not-Ready window still running
	}
	live, err := c.livePodCount(ctx, livePods, node.Name)
	if err != nil {
		// Cannot prove the node is empty → cannot prove the mount
		// is dead. Fail closed: keep the VA, flag the API failure —
		// once per node, not once per VA: every VA on this node
		// re-reads the same cached error, so the once-flag rides on
		// the probe itself.
		if pr := livePods[node.Name]; !pr.reported {
			pr.reported = true
			livePods[node.Name] = pr
			metrics.IncError(c.queue)
		}
		log.Error(err, "pod list failed — keeping node VAs (fail closed)",
			"node", node.Name)
		return false
	}
	if live > 0 {
		log.Info("KEEP: fenced node still hosts non-terminal pods",
			"node", node.Name, "pods", live)
		return false
	}
	return true
}

// livePodCount lists pods bound to node and returns how many
// WORKLOAD pods are non-terminal (not Succeeded/Failed) — the "is
// anyone still potentially writing" check. DaemonSet and static
// mirror pods don't count: they run on every node, hold no PVC
// mounts, and on a fenced node are force-deleted + recreated as
// Pending by the controller — counting them would keep this gate
// permanently closed and the feature dead. Terminating workload
// pods count as live: a pod wedged in Terminating on a fenced node
// is the node controller's force-delete problem, and until it
// finishes the mount may still exist. Counts are cached per cycle.
func (c *volumeAttachmentCleaner) livePodCount(ctx context.Context,
	cache map[string]podProbe, node string) (int, error) {
	if pr, ok := cache[node]; ok {
		return pr.count, pr.err
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(c.cs, metav1.NamespaceAll))
	if err != nil {
		err = fmt.Errorf("list pods on %s: %w", node, err)
		cache[node] = podProbe{err: err}
		return 0, err
	}
	live := 0
	for i := range pods {
		p := &pods[i]
		// Fake clientsets ignore field selectors — the spec.nodeName
		// filter is applied in code too, same convention as the
		// phase filters elsewhere in this codebase.
		if p.Spec.NodeName != node {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue // terminal — nobody is writing through it
		}
		if _, mirror := p.Annotations["kubernetes.io/config.mirror"]; mirror {
			continue // static pod mirror — the kubelet owns the real pod
		}
		ds := false
		for _, o := range p.OwnerReferences {
			if o.Kind == "DaemonSet" {
				ds = true
				break
			}
		}
		if ds {
			continue // infra agent — never holds a workload mount
		}
		live++
	}
	cache[node] = podProbe{count: live}
	return live, nil
}

// Port of hooks/60-partition-pod-evictor.sh.
//
// Evicts non-HA infra pods off network-partitioned nodes: a node can stay
// Ready (kubelet posts status over a healthy path) while its pod IPs are
// unreachable from other sites — a single-replica source-controller
// stuck there blocked every Flux fetch for hours (incident 2026-09-28).
// NHC deliberately ignores pure partitions, so this sweep fills the gap.
//
// Flow (faithful to bash):
//   - flag a node when any NWPD network condition (plural or singular
//     spelling) is True continuously for >10m;
//   - untaint recovered nodes first;
//   - abort when >= half (or all) nodes are flagged — that's a mesh-wide
//     partition where eviction only makes churn;
//   - taint flagged nodes node.ops/network-partitioned=true:NoSchedule so
//     evicted pods don't get rescheduled onto the same broken node;
//   - delete pods in the configured namespaces (PARTITION_EVICT_NAMESPACES,
//     default flux-system) plus any pod carrying the
//     node.ops/evict-on-partition=true opt-in annotation — in ANY
//     namespace — off flagged nodes, capped at 8/run.
//
// Three pod classes are never evicted no matter the namespace or the
// annotation: terminal pods (nothing left to move), DaemonSet pods
// (the daemon re-creates them in place — they are usually hostNetwork
// and unaffected by the pod-net partition anyway), and static mirror
// pods (the kubelet owns the real pod; the API object is a mirror).
package node

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	partitionEvictorQueue = "partition-pod-evictor"
	partitionTaintKey     = "node.ops/network-partitioned"
	partitionMinAge       = 600 * time.Second // condition True >10m before evicting
	partitionPodNS        = "flux-system"     // default for partitionNSsEnv
	partitionEvictCap     = 8                 // bound churn per run
	// partitionNSsEnv is the comma-separated namespace allow-list the
	// sweep evicts from; unset/whitespace keeps the bash default
	// (partitionPodNS) so a misconfigured flag degrades to the
	// original behavior instead of silently evicting nothing.
	partitionNSsEnv = "PARTITION_EVICT_NAMESPACES"
	// partitionEvictAnno opts an individual pod into partition
	// eviction from ANY namespace — the escape hatch for
	// single-replica infra living outside the allow-list (a
	// cert-manager webhook or a database proxy wedged on a
	// blackholed node is just as stuck as source-controller was).
	partitionEvictAnno = "node.ops/evict-on-partition"
	// mirrorPodAnno is the kubelet's static-pod marker — the API
	// object is only a mirror, the kubelet owns (and recreates) the
	// real pod, so deleting it buys nothing.
	mirrorPodAnno = "kubernetes.io/config.mirror"
)

// partitionCondTypes covers upstream NWPD K8sExporter plurals and the
// singular spellings some builds emit.
var partitionCondTypes = []corev1.NodeConditionType{
	"HostNetworkProblems",
	"ClusterNetworkProblems",
	"HostNetworkProblem",
	"ClusterNetworkProblem",
}

type partitionEvictor struct {
	cs kubernetes.Interface
}

// SetupPartitionEvictor registers the 5-minute sweep (was crontab */5).
func SetupPartitionEvictor(mgr ctrl.Manager, cs kubernetes.Interface) error {
	e := &partitionEvictor{cs: cs}
	return shared.AddPeriodic(mgr, partitionEvictorQueue, 5*time.Minute, e.run)
}

// nodePartitioned reports whether any NWPD network condition has been
// True for longer than partitionMinAge. A missing/empty timestamp
// (bash's `[ -n "$ts" ]` guard) does NOT flag the node.
func nodePartitioned(n *corev1.Node) bool {
	for _, t := range partitionCondTypes {
		c := shared.NodeCondition(n, t)
		if c != nil && c.Status == corev1.ConditionTrue &&
			!c.LastTransitionTime.IsZero() &&
			time.Since(c.LastTransitionTime.Time) > partitionMinAge {
			return true
		}
	}
	return false
}

// partitionEvictNamespaces parses PARTITION_EVICT_NAMESPACES into the
// namespace set the sweep evicts from: comma-separated, entries
// trimmed, blanks dropped (so "a, ,b" and trailing commas produce no
// phantom namespace). Unset or all-empty falls back to partitionPodNS.
func partitionEvictNamespaces() map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv(partitionNSsEnv))
	if raw == "" {
		raw = partitionPodNS
	}
	out := make(map[string]struct{})
	for _, ns := range strings.Split(raw, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			out[ns] = struct{}{}
		}
	}
	return out
}

// partitionEvictable reports whether pod p is a candidate for
// partition eviction. Membership is by the configured namespace set
// OR the node.ops/evict-on-partition=true opt-in annotation, but
// three classes are always skipped no matter where they live:
//   - terminal pods (Succeeded/Failed): dead weight, nothing to move;
//   - DaemonSet pods: the daemon re-creates them in place — and DS
//     pods are usually hostNetwork, so the pod-net partition does not
//     strand them anyway;
//   - static mirror pods: the kubelet owns the real pod — deleting
//     the mirror only produces a new mirror.
func partitionEvictable(p *corev1.Pod, namespaces map[string]struct{}) bool {
	if p.Status.Phase == corev1.PodSucceeded ||
		p.Status.Phase == corev1.PodFailed {
		return false
	}
	if p.DeletionTimestamp != nil {
		// Already terminating — a re-delete changes nothing but the
		// attempt still counts against partitionEvictCap, so enough
		// wedged pods would starve the real victims.
		return false
	}
	if _, mirror := p.Annotations[mirrorPodAnno]; mirror {
		return false
	}
	for _, o := range p.OwnerReferences {
		if o.Kind == "DaemonSet" {
			return false
		}
	}
	if _, ok := namespaces[p.Namespace]; ok {
		return true
	}
	return p.Annotations[partitionEvictAnno] == "true"
}

func (e *partitionEvictor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	nodes, err := shared.ListNodes(ctx, e.cs)
	if err != nil {
		return err
	}
	byName := make(map[string]*corev1.Node, len(nodes))
	flagged := map[string]bool{}
	for i := range nodes {
		byName[nodes[i].Name] = &nodes[i]
		if nodePartitioned(&nodes[i]) {
			flagged[nodes[i].Name] = true
		}
	}

	// Lift the taint on nodes that recovered — before the early exits,
	// exactly like bash.
	for i := range nodes {
		n := &nodes[i]
		if shared.HasTaint(n.Spec.Taints, partitionTaintKey) && !flagged[n.Name] {
			if err := shared.UntaintNode(ctx, e.cs, n.Name, partitionTaintKey); err != nil {
				metrics.IncError(partitionEvictorQueue)
				log.Error(err, "untaint failed", "node", n.Name)
				continue
			}
			log.Info(fmt.Sprintf("UNTAINT %s: network partition cleared", n.Name))
		}
	}

	nFlagged := len(flagged)
	if nFlagged == 0 {
		log.Info("OK: no partitioned nodes")
		return nil
	}
	// Mesh-wide guard: >50% flagged (or all) means the partition is not
	// node-local — evicting just churns pods between broken nodes.
	total := len(nodes)
	if nFlagged*2 > total || nFlagged >= total {
		log.Info(fmt.Sprintf("ABORT: %d/%d nodes flagged — mesh-wide partition, no evict", nFlagged, total))
		return nil
	}

	names := make([]string, 0, nFlagged)
	for name := range flagged {
		names = append(names, name)
	}
	sort.Strings(names)

	// Resolve the eviction set once per run: the env allow-list plus
	// the annotation opt-in (checked per pod inside the loop). One
	// node-scoped cluster-wide list per flagged node beats
	// 1+len(namespaces) namespaced lists — RBAC already grants
	// cluster-wide pod list (dead-node-sweeper reads the same way).
	namespaces := partitionEvictNamespaces()

	evicted := 0
loop:
	for _, name := range names {
		node := byName[name]
		if !shared.HasTaint(node.Spec.Taints, partitionTaintKey) {
			if err := shared.TaintNode(ctx, e.cs, name, partitionTaintKey, "true", corev1.TaintEffectNoSchedule); err != nil {
				metrics.IncError(partitionEvictorQueue)
				log.Error(err, "taint failed", "node", name)
			} else {
				log.Info(fmt.Sprintf("TAINT %s: network partitioned -> NoSchedule", name))
			}
		}
		pods, err := e.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + name,
		})
		if err != nil {
			metrics.IncError(partitionEvictorQueue)
			log.Error(err, "list pods failed", "node", name)
			continue
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			if evicted >= partitionEvictCap {
				log.Info(fmt.Sprintf("SKIP rest: cap=%d reached", partitionEvictCap))
				break loop
			}
			// Belt: the spec.nodeName field selector scopes the
			// server-side list, but fake clientsets ignore field
			// selectors — and a dropped/broken selector must never
			// turn a node-local sweep into a cluster-wide eviction.
			if p.Spec.NodeName != name {
				continue
			}
			if !partitionEvictable(p, namespaces) {
				continue
			}
			log.Info(fmt.Sprintf("EVICT %s/%s off %s (partitioned)", p.Namespace, p.Name, name))
			if err := e.cs.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil {
				metrics.IncError(partitionEvictorQueue)
				log.Error(err, "evict failed", "pod", p.Namespace+"/"+p.Name)
			}
			evicted++ // bash counts the attempt against the cap too
		}
	}
	log.Info(fmt.Sprintf("sweep done: evicted %d pod(s) off %d flagged node(s)", evicted, nFlagged))
	return nil
}

// sweep_phases.go — the two per-cycle read phases the run() driver
// calls before its verdict loop: the recovered-node reconciliation
// (untaint + node census) and the paged stuck-Terminating pod census.
// Pure extraction from dead_node_sweeper.go — the safety story lives
// in doc.go.
package deadnodesweeper

import (
	"context"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// deadNodeStuckPodAge: how long a pod may sit in Terminating
	// before its node is suspected. Longer than any legitimate
	// graceful shutdown (default grace 30s, worst-case preStop +
	// 5-10m drains) so normal deletes are never touched.
	deadNodeStuckPodAge = 15 * time.Minute
)

// reconcileRecoveredNodes builds the sweep's node census and untaints
// every node that came back Ready=True while still carrying the
// out-of-service taint — it must not keep the taint or it stays
// unschedulable. The cached census decides WHO looks recovered, but
// the untaint confirms on the LIVE API first — the same discipline as
// the evictor's untaintRecovered: within informer lag a node that
// flipped Ready→Unknown still reads Ready here, and stripping its
// fence then would let new pods schedule onto a dead node for a whole
// lag window. A node that vanished, is not Ready live, or fails to
// confirm keeps its fence this cycle. An untaint failure is tolerated
// (log + IncError + skip that node): the next cycle retries.
func (s *deadNodeSweeper) reconcileRecoveredNodes(ctx context.Context,
	nodes []corev1.Node) (nodeByName map[string]*corev1.Node,
	nodeNames map[string]bool, hasNotReady bool, untainted int) {
	log := logf.FromContext(ctx)

	nodeByName = make(map[string]*corev1.Node, len(nodes))
	nodeNames = make(map[string]bool, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		nodeByName[n.Name] = n
		nodeNames[n.Name] = true
		if !kube.NodeReady(n) {
			hasNotReady = true
		}

		// Recovery first: a node back to Ready=True must not keep
		// the out-of-service taint or it stays unschedulable.
		if !kube.HasTaint(n.Spec.Taints, kube.TaintNodeOutOfService) || !kube.NodeReady(n) {
			continue
		}
		live, err := s.cs.CoreV1().Nodes().Get(ctx, n.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// Node deleted since the census — its fence died
			// with it; nothing to lift.
			continue
		}
		if err != nil {
			// Fail closed: unconfirmable means the fence stays up
			// this cycle — the next cycle retries.
			log.Error(err, "live node get failed — untaint skipped this cycle", "node", n.Name)
			metrics.IncError(s.queue)
			continue
		}
		if !kube.NodeReady(live) {
			// Live truth overrides the cache: the Ready flip is
			// stale — the node is dead again. Keep the fence.
			log.Info("node not Ready live — untaint skipped", "node", n.Name)
			continue
		}
		if err := kube.UntaintNode(ctx, s.cs, n.Name, kube.TaintNodeOutOfService); err != nil {
			log.Error(err, "untaint failed", "node", n.Name)
			metrics.IncError(s.queue)
			continue
		}
		untainted++
		// A recovered node's stale skip flag reads as
		// an unfenced dead node forever; clear it with the taint.
		metrics.DeadNodeUnfencedStatefulSkipped.DeleteLabelValues(n.Name)
		log.Info("UNTAINT: node Ready again -> out-of-service removed", "node", n.Name)
	}
	return nodeByName, nodeNames, hasNotReady, untainted
}

// stuckTerminatingCensus counts, per node, the pods stuck in
// Terminating for longer than deadNodeStuckPodAge, returning the
// counts plus the node names in deterministic order so the per-cycle
// cap picks the same node.
//
// Server-side phase filter: terminal pods can never be "stuck
// Terminating" evidence, so they are dead weight in the biggest
// read this module makes. The in-code phase check stays — fake
// clientsets ignore field selectors and the belt costs nothing.
// Paged: one unbounded List forces the apiserver to serialize
// every pod in the cluster into a single response — a multi-MB
// heap burst both server- and client-side; 500-per-page flattens
// it while keeping only the per-node Terminating counts.
// The stuck-pod count is folded INTO the pagination loop — each
// page is tallied and dropped, so peak client heap is one page,
// not every pod in the cluster (which is the same footprint the
// unbounded List had).
// `now` is the caller's pinned sweep clock — a stuck verdict measured
// against a drifting wall clock inside a thousands-pod page loop
// could straddle the threshold mid-pass.
func (s *deadNodeSweeper) stuckTerminatingCensus(ctx context.Context,
	now time.Time) (stuck map[string]int, names []string, err error) {
	stuck = map[string]int{}
	err = kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(s.cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Status.Phase == corev1.PodSucceeded ||
					p.Status.Phase == corev1.PodFailed {
					continue // mirrors the FieldSelector for fake clients
				}
				if p.DeletionTimestamp == nil || p.Spec.NodeName == "" {
					continue
				}
				if now.Sub(p.DeletionTimestamp.Time) <= deadNodeStuckPodAge {
					continue // still inside a legitimate graceful shutdown
				}
				stuck[p.Spec.NodeName]++
			}
			return nil
		})
	if err != nil {
		return nil, nil, err
	}

	for name := range stuck {
		names = append(names, name)
	}
	slices.Sort(names)
	return stuck, names, nil
}

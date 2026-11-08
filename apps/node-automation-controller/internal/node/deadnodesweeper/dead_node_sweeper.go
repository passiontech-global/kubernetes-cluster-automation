// dead-node-sweeper — port of hooks/90-dead-node-sweeper.sh.
//
// This file holds the sweep driver: the per-cycle run() and its
// verdict loop. The safety story (why the out-of-service taint, the
// fail-closed evidence ladder, the stateful split-brain gate) lives in
// doc.go — read it before touching any of this. Wiring is setup.go,
// the verdict is verdict.go, the stateful holder checks and the fence
// application are stateful_holders.go, and the two per-cycle read
// phases are sweep_phases.go.
package deadnodesweeper

import (
	"context"
	"fmt"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// deadNodeCap: nodes tainted per cycle — wrong verdicts must
	// never take more than one node at a time.
	deadNodeCap = 1
	// outOfServiceTaint*: the Kubernetes-native "node is fenced"
	// signal — node lifecycle controller force-deletes the pods,
	// attach-detach controller force-detaches the volumes.
	outOfServiceTaintKey   = "node.kubernetes.io/out-of-service"
	outOfServiceTaintValue = "nodeshutdown"
)

func (s *deadNodeSweeper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Drop any aborted sweep's leftover emissions so this sweep's
	// ledger state reflects only what THIS run measured.
	s.statefulSkipEmitted.Begin()

	nodes, err := kube.ListNodesCached(ctx, s.nodeReader, s.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	nodeByName, nodeNames, hasNotReady, untainted :=
		s.reconcileRecoveredNodes(ctx, nodes)

	// Every node Ready = nothing can be fenced this cycle, so skip
	// the cluster-wide pod list entirely: it is by far the biggest
	// read this module makes (every pod in the cluster, deserialized)
	// and the all-Ready happy path never consumes it. A stuck pod on
	// a since-deleted node could only produce a skip-log anyway.
	if !hasNotReady {
		log.Info("sweep done — all nodes Ready", "untainted", untainted)
		s.statefulSkipEmitted.Prune(metrics.DeadNodeUnfencedStatefulSkipped.DeleteLabelValues)
		return nil
	}

	// One "now" pins the whole sweep — a stuck verdict measured
	// against a drifting wall clock inside a thousands-pod page loop
	// could straddle the threshold mid-pass.
	now := s.now.Now()
	stuck, names, err := s.stuckTerminatingCensus(ctx, now)
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	if len(stuck) == 0 {
		log.Info("sweep done — no stuck Terminating pods", "untainted", untainted)
		s.statefulSkipEmitted.Prune(metrics.DeadNodeUnfencedStatefulSkipped.DeleteLabelValues)
		return nil
	}

	// The two medik8s remediation CRD lists are fetched once per
	// sweep — lazily on the first death check — and shared by every
	// suspect node (previously one List pair PER node).
	remCache := &remediationCache{}
	tainted := 0
	for _, nodeName := range names {
		count := stuck[nodeName]

		n := nodeByName[nodeName]
		if n == nil {
			log.Info("SKIP: node object gone — apiserver already force-removed it?",
				"node", nodeName, "stuckPods", count)
			continue
		}
		if kube.NodeReady(n) {
			// Node is alive: Terminating pods there are a wedged
			// runtime/finalizer problem — the host watchdog's job,
			// not a fencing decision.
			log.Info("SKIP: node still Ready", "node", nodeName, "stuckPods", count)
			continue
		}
		if kube.HasTaint(n.Spec.Taints, outOfServiceTaintKey) {
			// Already fenced — the node controller is working on
			// the force-deletes; does not consume the cap.
			log.Info("KEEP-TAINT: already out-of-service", "node", nodeName, "stuckPods", count)
			continue
		}
		if tainted >= deadNodeCap {
			log.Info("SKIP rest: cap reached", "cap", deadNodeCap, "node", nodeName, "stuckPods", count)
			continue
		}

		dead, viaSNR, reason, err := s.confirmedDead(ctx, n, remCache, nodeNames)
		if err != nil {
			log.Error(err, "death check failed — node skipped (fail closed)",
				"node", nodeName, "stuckPods", count)
			metrics.IncError(s.queue)
			continue
		}
		if !dead {
			log.Info("SKIP: no fencing evidence — fail closed",
				"node", nodeName, "stuckPods", count)
			continue
		}

		// Branch (b) (dead without a medik8s SNR CR): the
		// evidence is one-sided — we cannot hear the node, but the
		// node may simply not hear US. A node holding an RWO
		// VolumeAttachment or a StatefulSet pod could come back and
		// write over its re-bound volumes: exactly the split-brain a
		// fencer CR exists to rule out. Fail closed and leave the
		// decision to medik8s unless the operator's override says
		// otherwise.
		hasVolumes := false
		if !viaSNR {
			holds, holdsErr := s.nodeHasStatefulHolders(ctx, nodeName)
			if holdsErr != nil {
				log.Error(holdsErr, "stateful-holder check failed — node skipped (fail closed)",
					"node", nodeName, "stuckPods", count)
				metrics.IncError(s.queue)
				continue
			}
			hasVolumes = holds
			if holds && !fenceUnfencedStateful() {
				s.statefulSkipEmitted.Set(metrics.DeadNodeUnfencedStatefulSkipped, 1,
					nodeName, nodeName)
				log.Info("SKIP: dead node holds stateful volumes/pods without medik8s SNR CR — fail closed against split-brain",
					"node", nodeName, "stuckPods", count)
				continue
			}
		}

		if err := s.fenceNode(ctx, nodeName, count, viaSNR, hasVolumes, reason); err != nil {
			continue // logged + IncError'd inside
		}
		tainted++
	}
	log.Info("sweep done", "tainted", tainted, "untainted", untainted,
		"stuckNodes", len(stuck))
	// Full sweep, every suspect evaluated — stale skip tuples that no
	// node re-asserted are resolved, not carried.
	s.statefulSkipEmitted.Prune(metrics.DeadNodeUnfencedStatefulSkipped.DeleteLabelValues)
	return nil
}

// fenceUnfencedStateful reads the split-brain override EVERY cycle —
// the same hot-reload ops-lever convention as the webhookguard gates.
// Opt-in (exactly "true"), default off: it authorizes fencing a
// branch-(b) node that holds stateful volumes/pods without a medik8s
// SNR CR, an operator's explicit "I know the node is really dead".
func fenceUnfencedStateful() bool {
	return envx.Gate("DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL", false)
}

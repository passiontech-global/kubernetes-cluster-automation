// descheduler_storm_signals.go — the evidence half of the
// descheduler-storm-gate reconcile: the node census (Ready /
// storm conditions / storm taints / active cordons), the
// preemption-cascade event count, and the image-pull stall census,
// all folded into one stormEvidence the verdict reads. Split out
// of descheduler_storm_gate.go — see that file for the gate
// contract.
package deschedulerstormgate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// stormEvidence bundles one reconcile's storm signals — every
// non-empty slice is storm evidence; all empty means "clear".
type stormEvidence struct {
	notReady    []string
	bad         []string
	tainted     []string
	cordoned    []string
	maintenance []string
	preempted   []string
	imagePull   []string
}

// storming reports whether any collected signal is storm evidence.
func (e *stormEvidence) storming() bool {
	return len(e.notReady) > 0 || len(e.bad) > 0 || len(e.tainted) > 0 ||
		len(e.cordoned) > 0 || len(e.maintenance) > 0 ||
		len(e.preempted) > 0 || len(e.imagePull) > 0
}

// nodeStormSignals scans the cached node list for the four
// node-local storm signals: not-Ready nodes, True storm conditions
// (NPD watchdog latches, kubelet pressure — zombie agent heartbeats
// excluded), storm remediation taints, and actively-cordoned nodes.
func (r *deschedulerStormGate) nodeStormSignals(ctx context.Context,
	now time.Time) (*stormEvidence, error) {
	nodes, err := kube.ListNodesCached(ctx, r.nodeReader, r.cs)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	if len(nodes) == 0 {
		// An empty-but-successful node list is an apiserver/RBAC
		// flap, never a real cluster — without this gate the scan
		// below yields a "clear" verdict and scales the descheduler
		// back up on blind data (same fail-closed posture as the
		// statefulset-ondelete-roller's nodesSafe check).
		return nil, errors.New("empty node list (API flap) — refusing to compute a verdict")
	}

	ev := &stormEvidence{}
	for i := range nodes {
		n := &nodes[i]
		if !kube.NodeReady(n) {
			ev.notReady = append(ev.notReady, n.Name)
		}
		// Only an ACTIVE cordon is a storm signal — a node statically
		// cordoned past the cordon window is deliberate state, and
		// counting it would pin the descheduler at 0 forever.
		if kube.NodeActivelyCordoned(n, now) {
			ev.cordoned = append(ev.cordoned, n.Name)
		}
		for _, c := range n.Status.Conditions {
			if c.Status != corev1.ConditionTrue ||
				!slices.Contains(stormConds, c.Type) {
				continue
			}
			// A nodereporter-owned True with a frozen or absent
			// heartbeat is a zombie — the wedged reporter cannot
			// vouch for the condition anymore, so it must not hold
			// the descheduler at 0 forever. Kubelet-native storm
			// conditions (MemoryPressure/DiskPressure/
			// NetworkUnavailable/InodePressure) and the foreign
			// CiliumLRPDegraded spelling are not agent-managed and
			// keep gating on status alone.
			if nodecond.AgentHeartbeatManaged(string(c.Type)) &&
				!kube.CondHeartbeatLive(&c, stormCondHeartbeatMaxAge, now) {
				continue
			}
			ev.bad = append(ev.bad, n.Name+" "+string(c.Type))
		}
		for _, t := range n.Spec.Taints {
			if slices.Contains(stormTaints, t.Key) {
				ev.tainted = append(ev.tainted, n.Name+" "+t.Key)
			}
		}
	}
	return ev, nil
}

// clusterStormSignals runs the two cluster-wide storm reads into
// ev: the preemption-cascade event count and the image-pull stall
// census. Both fail closed — a list error aborts the reconcile,
// never a "clear" verdict on blind data. Callers run this AFTER
// the deployment-exists skip so a cluster without descheduler
// never pays for (or fails on) either scan.
func (r *deschedulerStormGate) clusterStormSignals(ctx context.Context,
	now time.Time, ev *stormEvidence) error {
	// preemption-cascade-signal storm signal (d): a PriorityClass preemption cascade
	// — a domino wave of reason=Preempted events — gates the
	// descheduler so its own evictions do not amplify the storm.
	preemptedCount, err := kube.CountRecentEvents(ctx, r.cs,
		kube.PreemptedEventReason, stormPreemptionWindow, now)
	if err != nil {
		return fmt.Errorf("list preempted events: %w", err)
	}
	if preemptedCount > stormPreemptionMax {
		ev.preempted = append(ev.preempted, fmt.Sprintf(
			"%d Preempted events in %s (>%d)",
			preemptedCount, stormPreemptionWindow, stormPreemptionMax))
	}

	// image-pull-storm-gate storm signal (e): a cluster-wide image-pull storm —
	// enough pods stuck in ImagePullBackOff/ErrImagePull that
	// rescheduling would just spread unrunnable pods onto more
	// nodes. Same fail-closed posture as the events scan above: a
	// pod-list error aborts the reconcile, never a "clear" verdict
	// on blind data.
	stallPods, stallNamespaces, err := kube.CountImagePullStalledPods(ctx, r.cs)
	if err != nil {
		return fmt.Errorf(
			"list pods (image-pull storm census): %w", err)
	}
	if stallPods >= stormImagePullMinPods ||
		stallNamespaces >= stormImagePullMinNamespaces {
		ev.imagePull = append(ev.imagePull, fmt.Sprintf(
			"image-pull-stall: %d pods in %d namespaces stuck on ImagePullBackOff/ErrImagePull",
			stallPods, stallNamespaces))
	}
	return nil
}

// pin.go — ReplicaPin: the proportional replica-pin machinery the
// Deployment patchers share. It replaces the standalone
// cluster-proportional-autoscaler: the {min, nodesPerReplica} knob
// pair, the wantReplicas computation off the live node count, and
// the conditional Node watch that re-reconciles on node add/remove.
package pinnedworkload

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// ReplicaPin carries the CPA-linear replica pin knobs
// (COREDNS_MIN_REPLICAS/COREDNS_NODES_PER_REPLICA and the
// METRICS_SERVER_* twins). MinReplicas<=0 disables the pin entirely —
// the Deployment keeps its own .spec.replicas so a cluster can
// re-enable the standalone CPA without being fought.
type ReplicaPin struct {
	MinReplicas     int
	NodesPerReplica int
}

// Enabled reports whether the pin is on — MinReplicas<=0 means the
// reconciler never reads the node count and the patch body never
// sends spec.replicas.
func (p ReplicaPin) Enabled() bool { return p.MinReplicas > 0 }

// Want computes the pinned replica count for the live cluster: 0 when
// the pin is disabled (callers must then keep spec.replicas out of
// the patch body), else the CPA "linear" formula max(MinReplicas,
// ceil(totalNodes/NodesPerReplica)) — see kube.ProportionalReplicas.
// A node list error surfaces so the count is never computed from a
// partial picture.
func (p ReplicaPin) Want(ctx context.Context, cs kubernetes.Interface) (int32, error) {
	if !p.Enabled() {
		return 0, nil
	}
	nodes, err := kube.ListNodes(ctx, cs)
	if err != nil {
		return 0, err
	}
	return kube.ProportionalReplicas(len(nodes), p.MinReplicas, p.NodesPerReplica), nil
}

// WatchNodes adds the Node watch that re-reconciles on every node
// add/remove to b — only when the pin is enabled: with the pin off
// the node count is never read, so no watch is registered at all.
// Every event collapses to the fixed sweepKey (the reconciler ignores
// the request name anyway), letting the workqueue set-collapse
// duplicate enqueues and leaving a single RequeueAfter timer; see
// NodeCountChanges for why only create/delete fire.
func (p ReplicaPin) WatchNodes(b *builder.Builder, sweepKey string) *builder.Builder {
	if !p.Enabled() {
		return b
	}
	return b.Watches(&corev1.Node{},
		handler.EnqueueRequestsFromMapFunc(shared.SweepRequests(sweepKey)),
		builder.WithPredicates(NodeCountChanges))
}

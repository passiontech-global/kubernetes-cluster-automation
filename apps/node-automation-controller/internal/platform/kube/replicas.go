// replicas.go — replica math: the cluster-proportional-autoscaler
// "linear" formula the proportional-replica pin modules (coredns,
// metrics-server) share.
package kube

// ---------------------------------------------------------------------------
// Replica math.
// ---------------------------------------------------------------------------

// ProportionalReplicas is the cluster-proportional-autoscaler
// "linear" formula with includeUnschedulableNodes=true — every Node
// object counts, cordoned or not:
//
//	replicas = max(minReplicas, ceil(totalNodes / nodesPerReplica))
//
// nodesPerReplica<=0 is clamped to 1 — a 0 divisor would otherwise
// mean "one replica per node" anyway under the CPA semantics.
func ProportionalReplicas(totalNodes, minReplicas, nodesPerReplica int) int32 {
	if nodesPerReplica <= 0 {
		nodesPerReplica = 1
	}
	n := (totalNodes + nodesPerReplica - 1) / nodesPerReplica
	if n < minReplicas {
		n = minReplicas
	}
	return int32(n)
}

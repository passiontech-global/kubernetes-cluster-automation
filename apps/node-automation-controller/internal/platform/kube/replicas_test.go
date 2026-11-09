// replicas_test.go — coverage for ProportionalReplicas, the
// cluster-proportional-autoscaler "linear" formula the coredns /
// metrics-server pin modules share: ceil division, the minReplicas
// floor, and the nodesPerReplica<=0 clamp.
package kube

import "testing"

func TestProportionalReplicas(t *testing.T) {
	for _, tc := range []struct {
		name            string
		totalNodes      int
		minReplicas     int
		nodesPerReplica int
		want            int32
	}{
		{"exact division", 10, 1, 5, 2},
		{"rounds up", 11, 1, 5, 3},
		{"min floor wins", 3, 2, 5, 2},
		{"zero nodes still floors", 0, 2, 5, 2},
		{"zero divisor clamps to one-per-node", 4, 1, 0, 4},
		{"negative divisor clamps to one-per-node", 4, 1, -3, 4},
		{"single node", 1, 1, 100, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProportionalReplicas(tc.totalNodes, tc.minReplicas,
				tc.nodesPerReplica); got != tc.want {
				t.Fatalf("ProportionalReplicas(%d,%d,%d) = %d, want %d",
					tc.totalNodes, tc.minReplicas, tc.nodesPerReplica, got, tc.want)
			}
		})
	}
}

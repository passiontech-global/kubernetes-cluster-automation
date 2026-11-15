package criticalns

import (
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
)

func TestHeartbeatScopeAllows(t *testing.T) {
	all := admissionv1.AllScopes
	cluster := admissionv1.ClusterScope
	namespaced := admissionv1.NamespacedScope

	cases := []struct {
		name  string
		scope *admissionv1.ScopeType
		res   string
		want  bool
	}{
		{"nil_scope", nil, "leases", true},
		{"all_scopes", &all, "nodes/status", true},
		{"cluster_allows_nodes_status", &cluster, "nodes/status", true},
		{"cluster_blocks_leases", &cluster, "leases", false},
		{"namespaced_allows_leases", &namespaced, "leases", true},
		{"namespaced_blocks_nodes_status", &namespaced, "nodes/status", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := heartbeatScopeAllows(tc.scope, tc.res); got != tc.want {
				t.Fatalf("heartbeatScopeAllows(%v, %q) = %v, want %v", tc.scope, tc.res, got, tc.want)
			}
		})
	}
}

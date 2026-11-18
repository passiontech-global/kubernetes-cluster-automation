package criticalns

import (
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
)

// APIGroups ["*"] matches the core group and coordination.k8s.io
// server-side, so a wildcard group with an explicit heartbeat resource
// is a real exposure (wave3.2/api-groups-wildcard). A specific foreign
// group behind the same literal is still a CRD lookalike, not a
// heartbeat path.
func TestHeartbeatRuleHitsAPIGroupWildcard(t *testing.T) {
	rule := func(groups []string, res string) admissionv1.RuleWithOperations {
		return admissionv1.RuleWithOperations{
			Rule: admissionv1.Rule{
				APIGroups: groups, APIVersions: []string{"v1"},
				Resources: []string{res},
			},
		}
	}
	for _, tc := range []struct {
		name   string
		groups []string
		res    string
		want   bool
	}{
		{"wildcard leases", []string{"*"}, "leases", true},
		{"wildcard nodes/status", []string{"*"}, "nodes/status", true},
		{"wildcard pods/status", []string{"*"}, "pods/status", true},
		{"wildcard pods/eviction", []string{"*"}, "pods/eviction", true},
		{"wildcard nodes/*", []string{"*"}, "nodes/*", true},
		{"wildcard among foreign groups", []string{"example.com", "*"}, "pods/status", true},
		{"core group still matches", []string{""}, "pods/status", true},
		{"coordination group still matches", []string{"coordination.k8s.io"}, "leases", true},
		{"foreign group does not match core literal", []string{"example.com"}, "nodes/status", false},
		{"foreign group does not match leases", []string{"example.com"}, "leases", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := heartbeatRuleHits(rule(tc.groups, tc.res))
			got := len(hits) == 1 && hits[0] == tc.res
			if got != tc.want {
				t.Fatalf("heartbeatRuleHits(groups=%v, res=%q) = %v, want hit=%v",
					tc.groups, tc.res, hits, tc.want)
			}
		})
	}
}

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

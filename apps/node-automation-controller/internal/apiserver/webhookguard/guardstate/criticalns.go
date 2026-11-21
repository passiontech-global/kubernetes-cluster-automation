// criticalns.go — shared critical-namespace and heartbeat-resource
// matching and exclusion-patch helpers used by both criticalns (MWC/VWC)
// and celpolicy (ValidatingAdmissionPolicy/MutatingAdmissionPolicy).
package guardstate

import (
	"maps"
	"slices"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// CriticalSelfHealingNamespaces are the namespaces that run CNI,
// DNS, the kubelet heartbeat, the OLM operator stack, and the node
// self-healing stack itself — a fail-closed admission webhook or CEL
// policy that matches any of them can deadlock recovery when its own
// backend or parameter resource dies.
var CriticalSelfHealingNamespaces = []string{
	"kube-system", "kube-node-lease", "node-ops", "medik8s", "operators",
}

// WebhookHeartbeatResources is the rule-resource set on the node/pod
// lifecycle heartbeat path. A fail-closed webhook or CEL policy
// intercepting any of these turns its own outage into cluster-wide
// wedging.
var WebhookHeartbeatResources = map[string]bool{
	"nodes/status":  true,
	"pods/status":   true,
	"pods/eviction": true,
	"leases":        true,
	"pods/*":        true,
	"nodes/*":       true,
	"*":             true,
	"*/*":           true,
}

// HeartbeatClusterScopedResources are the heartbeat hits a
// namespaceSelector can never exclude: nodes/status is cluster-scoped,
// pods/eviction wedges every drain in every namespace, and wildcards
// cover both by definition.
var HeartbeatClusterScopedResources = map[string]bool{
	"nodes/status":  true,
	"pods/eviction": true,
	"pods/*":        true,
	"nodes/*":       true,
	"*":             true,
	"*/*":           true,
}

// HeartbeatNamespacedResources are the heartbeat literals whose
// underlying resources are namespaced — a Cluster-scoped rule can never
// intercept them.
var HeartbeatNamespacedResources = map[string]bool{
	"pods/status":   true,
	"pods/eviction": true,
	"leases":        true,
	"pods/*":        true,
}

// HeartbeatClusterResources are the cluster-scoped heartbeat literals
// — a Namespaced-scoped rule can never intercept them.
var HeartbeatClusterResources = map[string]bool{
	"nodes/status": true,
	"nodes/*":      true,
}

// RuleGroupMatches reports whether an admission rule's APIGroups
// includes want (either literally or via the "*" wildcard).
func RuleGroupMatches(groups []string, want string) bool {
	return slices.Contains(groups, want) || slices.Contains(groups, "*")
}

// HeartbeatScopeAllows reports whether a rule carrying the given
// Scope can actually intercept the heartbeat literal res.
func HeartbeatScopeAllows(scope *admissionv1.ScopeType, res string) bool {
	if scope == nil || *scope == admissionv1.AllScopes {
		return true
	}
	switch *scope {
	case admissionv1.ClusterScope:
		return !HeartbeatNamespacedResources[res]
	case admissionv1.NamespacedScope:
		return !HeartbeatClusterResources[res]
	}
	return true
}

// AllClusterScopedRules reports whether every admission rule is
// cluster-scoped — such a policy/webhook's namespaceSelector is never
// consulted, so a missing critical-namespace exclusion is not a
// finding and patching the selector would be a no-op.
func AllClusterScopedRules(rules []admissionv1.RuleWithOperations) bool {
	if len(rules) == 0 {
		return false
	}
	for _, r := range rules {
		if r.Scope == nil || *r.Scope != admissionv1.ClusterScope {
			return false
		}
	}
	return true
}

// HeartbeatRuleHits returns the rule's resource literals that land on
// the heartbeat path, checked group-aware and scope-aware.
func HeartbeatRuleHits(rule admissionv1.RuleWithOperations) []string {
	var hits []string
	for _, res := range rule.Resources {
		if !WebhookHeartbeatResources[res] {
			continue
		}
		if !HeartbeatScopeAllows(rule.Scope, res) {
			continue
		}
		switch {
		case res == "leases":
			if !RuleGroupMatches(rule.APIGroups, "coordination.k8s.io") {
				continue
			}
		case res == "*" || res == "*/*":
			// Wildcard resources cover every group by definition.
		default:
			if !RuleGroupMatches(rule.APIGroups, "") {
				continue
			}
		}
		hits = append(hits, res)
	}
	return hits
}

// MatchedCriticalNamespaces returns a function returning which of
// CriticalSelfHealingNamespaces match a given namespaceSelector (nil or
// malformed selectors match all critical namespaces). Returns ok=false
// when the namespace census failed or snap is nil.
func MatchedCriticalNamespaces(snap *Snapshot) (matched func(*metav1.LabelSelector) []string, ok bool) {
	if snap == nil || snap.NSErr != nil {
		return nil, false
	}
	critLabels := make(map[string]labels.Set, len(CriticalSelfHealingNamespaces))
	for _, ns := range CriticalSelfHealingNamespaces {
		critLabels[ns] = labels.Set{"kubernetes.io/metadata.name": ns}
	}
	if snap.NS != nil {
		for i := range snap.NS.Items {
			ns := &snap.NS.Items[i]
			if _, exists := critLabels[ns.Name]; !exists {
				continue
			}
			merged := make(labels.Set, len(ns.Labels)+1)
			maps.Copy(merged, ns.Labels)
			merged["kubernetes.io/metadata.name"] = ns.Name
			critLabels[ns.Name] = merged
		}
	}
	return func(ls *metav1.LabelSelector) []string {
		if ls == nil {
			return slices.Clone(CriticalSelfHealingNamespaces)
		}
		sel, err := metav1.LabelSelectorAsSelector(ls)
		if err != nil {
			return slices.Clone(CriticalSelfHealingNamespaces)
		}
		var out []string
		for _, ns := range CriticalSelfHealingNamespaces {
			if sel.Matches(critLabels[ns]) {
				out = append(out, ns)
			}
		}
		return out
	}, true
}

// CriticalNSMatcher builds the namespaceSelector predicate from the
// snapshot's namespace census: true when the selector still matches any
// of CriticalSelfHealingNamespaces.
func CriticalNSMatcher(snap *Snapshot) (matches func(*metav1.LabelSelector) bool, ok bool) {
	matched, ok := MatchedCriticalNamespaces(snap)
	if !ok {
		return nil, false
	}
	return func(ls *metav1.LabelSelector) bool {
		return len(matched(ls)) > 0
	}, true
}

// MergeCriticalNSExclusion builds a namespaceSelector map merging the
// kubernetes.io/metadata.name NotIn CriticalSelfHealingNamespaces
// exclusion into sel while preserving existing MatchLabels and
// MatchExpressions.
func MergeCriticalNSExclusion(sel *metav1.LabelSelector) map[string]any {
	var cur metav1.LabelSelector
	if sel != nil {
		cur = *sel
	}
	const nameKey = "kubernetes.io/metadata.name"
	patch := map[string]any{}
	if len(cur.MatchLabels) > 0 {
		ml := make(map[string]string, len(cur.MatchLabels))
		maps.Copy(ml, cur.MatchLabels)
		patch["matchLabels"] = ml
	}
	exprs := make([]map[string]any, 0, len(cur.MatchExpressions)+1)
	merged := false
	for _, e := range cur.MatchExpressions {
		vals := slices.Clone(e.Values)
		if e.Key == nameKey && e.Operator == metav1.LabelSelectorOpNotIn {
			for _, ns := range CriticalSelfHealingNamespaces {
				if !slices.Contains(vals, ns) {
					vals = append(vals, ns)
				}
			}
			merged = true
		}
		expr := map[string]any{
			"key": e.Key, "operator": string(e.Operator),
		}
		if len(vals) > 0 {
			expr["values"] = vals
		}
		exprs = append(exprs, expr)
	}
	if !merged {
		exprs = append(exprs, map[string]any{
			"key":      nameKey,
			"operator": string(metav1.LabelSelectorOpNotIn),
			"values":   slices.Clone(CriticalSelfHealingNamespaces),
		})
	}
	patch["matchExpressions"] = exprs
	return patch
}

// netpol.go — shared NetworkPolicy and CiliumNetworkPolicy /
// CiliumClusterwideNetworkPolicy spec parsing and endpointSelector
// matching helpers used across health watchdogs and nethealth checks.
package kube

import (
	"slices"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

// NetworkPolicyAffectsIngress reports whether np governs ingress traffic.
func NetworkPolicyAffectsIngress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return true
	}
	return slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
}

// NetworkPolicyAffectsEgress reports whether np governs egress traffic.
func NetworkPolicyAffectsEgress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return len(np.Spec.Egress) > 0
	}
	return slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
}

// ExtractCiliumSpecs returns every spec rule block from a
// CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy unstructured CR
// (covering both singular .spec and plural .specs).
func ExtractCiliumSpecs(u *unstructured.Unstructured) []map[string]any {
	var out []map[string]any
	if sp, ok := NestedMap(u.Object, "spec"); ok {
		out = append(out, sp)
	}
	if specs, ok := NestedSlice(u.Object, "specs"); ok {
		for _, item := range specs {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// CiliumSpecHasAnyField reports whether any of fields is present and
// non-nil on a Cilium policy spec map (e.g. "ingress"/"ingressDeny"
// or "egress"/"egressDeny").
func CiliumSpecHasAnyField(sp map[string]any, fields ...string) bool {
	for _, f := range fields {
		if v, ok := sp[f]; ok && v != nil {
			return true
		}
	}
	return false
}

// CiliumEndpointSelectorToK8s translates a Cilium endpointSelector
// object into a standard Kubernetes LabelSelector scoped to targetNS,
// returning (nil, false) when the selector targets a different
// namespace, reserved Cilium identities, or malformed fields.
func CiliumEndpointSelectorToK8s(raw map[string]any, targetNS string) (*metav1.LabelSelector, bool) {
	ls := &metav1.LabelSelector{}
	if mlRaw, ok := raw["matchLabels"].(map[string]any); ok {
		ml := make(map[string]string, len(mlRaw))
		for k, v := range mlRaw {
			vs, ok := v.(string)
			if !ok {
				return nil, false
			}
			cleanKey := strings.TrimPrefix(k, "k8s:")
			if cleanKey == "io.kubernetes.pod.namespace" {
				if vs != targetNS {
					return nil, false
				}
				continue
			}
			if strings.HasPrefix(cleanKey, "reserved:") {
				return nil, false
			}
			ml[cleanKey] = vs
		}
		if len(ml) > 0 {
			ls.MatchLabels = ml
		}
	}
	if exprsRaw, ok := raw["matchExpressions"].([]any); ok {
		for _, item := range exprsRaw {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			key, _ := m["key"].(string)
			op, _ := m["operator"].(string)
			key = strings.TrimPrefix(key, "k8s:")
			if strings.HasPrefix(key, "reserved:") {
				return nil, false
			}
			var vals []string
			switch vs := m["values"].(type) {
			case []any:
				for _, v := range vs {
					if s, ok := v.(string); ok {
						vals = append(vals, s)
					}
				}
			case []string:
				vals = append(vals, vs...)
			}
			if key == "io.kubernetes.pod.namespace" {
				if !ciliumNamespaceMatchesExpr(targetNS, metav1.LabelSelectorOperator(op), vals) {
					return nil, false
				}
				continue
			}
			ls.MatchExpressions = append(ls.MatchExpressions, metav1.LabelSelectorRequirement{
				Key:      key,
				Operator: metav1.LabelSelectorOperator(op),
				Values:   vals,
			})
		}
	}
	return ls, true
}

func ciliumNamespaceMatchesExpr(targetNS string, op metav1.LabelSelectorOperator, vals []string) bool {
	switch op {
	case metav1.LabelSelectorOpIn:
		return slices.Contains(vals, targetNS)
	case metav1.LabelSelectorOpNotIn:
		return !slices.Contains(vals, targetNS)
	case metav1.LabelSelectorOpExists:
		return targetNS != ""
	case metav1.LabelSelectorOpDoesNotExist:
		return false
	default:
		return false
	}
}

// CiliumSpecMatchesPod reports whether one parsed Cilium spec rule
// selects pods in ns with podLabels. Clusterwide policies with an
// explicit nodeSelector and no endpointSelector match nodes, not pods.
func CiliumSpecMatchesPod(sp map[string]any, ns string, podLabels labels.Set, clusterwide bool) bool {
	if clusterwide && sp["nodeSelector"] != nil && sp["endpointSelector"] == nil {
		return false
	}
	epRaw, hasEP := sp["endpointSelector"].(map[string]any)
	if !hasEP {
		return sp["nodeSelector"] == nil
	}
	ls, ok := CiliumEndpointSelectorToK8s(epRaw, ns)
	if !ok {
		return false
	}
	sel, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return false
	}
	return sel.Matches(podLabels)
}

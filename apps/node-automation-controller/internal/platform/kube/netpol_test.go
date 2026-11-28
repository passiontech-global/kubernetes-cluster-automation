// netpol_test.go — unit tests for shared NetworkPolicy / Cilium policy
// helpers in kube/netpol.go.
package kube

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

func TestNetworkPolicyAffectsIngressAndEgress(t *testing.T) {
	defaultNP := &networkingv1.NetworkPolicy{}
	if !NetworkPolicyAffectsIngress(defaultNP) {
		t.Fatal("empty PolicyTypes should affect Ingress by default")
	}
	if NetworkPolicyAffectsEgress(defaultNP) {
		t.Fatal("empty PolicyTypes without Egress rules should not affect Egress")
	}

	egressOnly := &networkingv1.NetworkPolicy{
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
	if NetworkPolicyAffectsIngress(egressOnly) {
		t.Fatal("Egress-only PolicyTypes should not affect Ingress")
	}
	if !NetworkPolicyAffectsEgress(egressOnly) {
		t.Fatal("Egress-only PolicyTypes should affect Egress")
	}
}

func TestCiliumHelpersAndEndpointSelector(t *testing.T) {
	u := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchLabels": map[string]any{
						"k8s:app":                         "web",
						"k8s:io.kubernetes.pod.namespace": "apps",
					},
				},
				"egress": []any{},
			},
			"specs": []any{
				map[string]any{"ingress": []any{}},
			},
		},
	}
	specs := ExtractCiliumSpecs(u)
	if len(specs) != 2 {
		t.Fatalf("ExtractCiliumSpecs = %d, want 2", len(specs))
	}
	if !CiliumSpecHasAnyField(specs[0], "egress", "egressDeny") {
		t.Fatal("expected egress field detected on spec[0]")
	}
	if CiliumSpecHasAnyField(specs[0], "ingress", "ingressDeny") {
		t.Fatal("unexpected ingress field detected on spec[0]")
	}
	if !CiliumSpecMatchesPod(specs[0], "apps", labels.Set{"app": "web"}, false) {
		t.Fatal("expected CiliumSpecMatchesPod=true for matching namespace+label")
	}
	if CiliumSpecMatchesPod(specs[0], "other", labels.Set{"app": "web"}, false) {
		t.Fatal("expected CiliumSpecMatchesPod=false for mismatched namespace")
	}
}

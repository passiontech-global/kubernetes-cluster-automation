package celpolicy

import (
	"sync/atomic"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

type countingDiscovery struct {
	discovery.DiscoveryInterfaces
	calls *atomic.Int32
}

func (c *countingDiscovery) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	c.calls.Add(1)
	return c.DiscoveryInterfaces.ServerResourcesForGroupVersion(groupVersion)
}

type countingDiscoveryClientset struct {
	kubernetes.Interface
	disc discovery.DiscoveryInterfaces
}

func (c *countingDiscoveryClientset) Discovery() discovery.DiscoveryInterfaces {
	return c.disc
}

func TestSweepCircuitBreakerMemoizesParamDiscovery(t *testing.T) {
	pk := &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "ClusterPolicyParam"}
	vap1 := testVAP("vap-param-1", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	vap1.Spec.ParamKind = pk
	vapb1 := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-param-1"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-param-1",
			ParamRef:   &admissionv1.ParamRef{Name: "missing-1"},
		},
	}
	vap2 := testVAP("vap-param-2", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	vap2.Spec.ParamKind = pk
	vapb2 := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-param-2"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-param-2",
			ParamRef:   &admissionv1.ParamRef{Name: "missing-2"},
		},
	}

	cs := fake.NewSimpleClientset(vap1, vapb1, vap2, vapb2)
	cs.Resources = []*metav1.APIResourceList{{
		GroupVersion: "example.com/v1",
		APIResources: []metav1.APIResource{{
			Name:       "clusterpolicyparams",
			Namespaced: false,
			Kind:       "ClusterPolicyParam",
		}},
	}}
	s, g, _ := newTestSweeperAndGuard(t, cs)
	var discCalls atomic.Int32
	g.CS = &countingDiscoveryClientset{
		Interface: cs,
		disc: &countingDiscovery{
			DiscoveryInterfaces: cs.Discovery(),
			calls:               &discCalls,
		},
	}

	ctx := t.Context()
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := discCalls.Load(); got != 1 {
		t.Fatalf("ServerResourcesForGroupVersion calls = %d, want 1 across 2 policies", got)
	}
}

// endpoints_test.go — coverage for ReadyEndpointsByService, the
// EndpointSlice → "namespace/service" rollup every endpoint census
// shares: service-name binding, the nil-Ready-counts-as-ready
// convention, explicit-false demotion, and the zone/node/podKey
// placement detail.
package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// slice builds an EndpointSlice bound to svc (via the
// kubernetes.io/service-name label) carrying the given endpoints.
func slice(ns, name, svc string, eps ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	labels := map[string]string{}
	if svc != "" {
		labels[discoveryv1.LabelServiceName] = svc
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Endpoints:  eps,
	}
}

func ep(addrs ...string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{Addresses: addrs}
}

func TestReadyEndpointsByService(t *testing.T) {
	zone := "zone-a"
	node := "w1"
	slices := []discoveryv1.EndpointSlice{
		// Two slices for the same service merge under one key.
		*slice("apps", "svc-1", "web",
			discoveryv1.Endpoint{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
				Zone:       &zone, NodeName: &node,
				TargetRef: &corev1.ObjectReference{
					Kind: "Pod", Namespace: "apps", Name: "web-1"},
			},
			discoveryv1.Endpoint{
				Addresses:  []string{"10.0.0.2"},
				Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
			},
		),
		*slice("apps", "svc-2", "web",
			ep("10.0.0.3"), // nil Ready counts as ready
		),
		// A label-less slice has no owning Service — skipped.
		*slice("apps", "orphan", "",
			ep("10.9.9.9"),
		),
		// Same service name in another namespace is a different key.
		*slice("other", "svc-3", "web", ep("10.0.1.1")),
	}

	got := ReadyEndpointsByService(slices)
	if len(got) != 2 {
		t.Fatalf("rollup keys = %v, want apps/web + other/web", got)
	}
	web := got["apps/web"]
	if len(web) != 2 {
		t.Fatalf("apps/web endpoints = %d, want 2 (explicit-false dropped)", len(web))
	}
	if web[0].Zone != "zone-a" || web[0].Node != "w1" ||
		web[0].PodKey != "apps/web-1" {
		t.Fatalf("placement detail = %+v", web[0])
	}
	if len(web[0].Addresses) != 1 || web[0].Addresses[0] != "10.0.0.1" {
		t.Fatalf("addresses = %v", web[0].Addresses)
	}
	// The nil-Ready endpoint carries no placement hints — all empty.
	if web[1].Zone != "" || web[1].Node != "" || web[1].PodKey != "" {
		t.Fatalf("bare endpoint placement = %+v, want empty", web[1])
	}
	if len(got["other/web"]) != 1 {
		t.Fatalf("other/web endpoints = %d, want 1", len(got["other/web"]))
	}
}

package apiserverendpointguard

import (
	"context"
	"errors"
	"strings"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ctx is the sweep context every test in the package shares.
var ctx = context.Background()

// ---------------------------------------------------------------------------
// apiserver-endpoint-guard
// ---------------------------------------------------------------------------

// kubeEndpoints builds the default/kubernetes Endpoints object the way
// the apiserver's own reconciler writes it: one subset, port 443 —
// unstructured, the shape the dynamic client returns on the wire.
func kubeEndpoints(active, notReady, quarantined []string) *unstructured.Unstructured {
	sub := map[string]any{
		"ports": []any{map[string]any{
			"name": "https", "port": int64(443), "protocol": "TCP"}},
	}
	if len(active) > 0 {
		addrs := make([]any, 0, len(active))
		for _, ip := range active {
			addrs = append(addrs, map[string]any{"ip": ip})
		}
		sub["addresses"] = addrs
	}
	if len(notReady) > 0 {
		nr := make([]any, 0, len(notReady))
		for _, ip := range notReady {
			nr = append(nr, map[string]any{"ip": ip})
		}
		sub["notReadyAddresses"] = nr
	}
	ep := testutil.Unstructured(
		schema.GroupVersionKind{Version: "v1", Kind: "Endpoints"},
		endpointGuardNS, endpointGuardName,
		map[string]any{"subsets": []any{sub}})
	annos := map[string]string{}
	if len(quarantined) > 0 {
		annos[endpointGuardAnno] = strings.Join(quarantined, ",")
	}
	ep.SetAnnotations(annos)
	return ep
}

// subsetAddrs decodes subset[i]'s map-typed list field for assertions.
func subsetAddrs(ep *unstructured.Unstructured, i int, field string) []map[string]any {
	subs := endpointSubsets(ep)
	if i >= len(subs) {
		return nil
	}
	return nestedMaps(subs[i], field)
}

// appendSubset appends a raw subset map to the fixture — the
// unstructured equivalent of ep.Subsets = append(ep.Subsets, ...).
func appendSubset(ep *unstructured.Unstructured, subset map[string]any) {
	subs, _, _ := unstructured.NestedSlice(ep.Object, "subsets")
	subs = append(subs, subset)
	if err := unstructured.SetNestedSlice(ep.Object, subs, "subsets"); err != nil {
		panic(err)
	}
}

// appendAddr appends {"ip": ip} to subset[i]'s field — the test-time
// "reconciler re-added a live IP" mutation.
func appendAddr(ep *unstructured.Unstructured, i int, field, ip string) {
	subs, _, _ := unstructured.NestedSlice(ep.Object, "subsets")
	m, _ := subs[i].(map[string]any)
	addrs, _, _ := unstructured.NestedSlice(m, field)
	addrs = append(addrs, map[string]any{"ip": ip})
	_ = unstructured.SetNestedSlice(m, addrs, field)
	_ = unstructured.SetNestedSlice(ep.Object, subs, "subsets")
}

// kubeEndpointSlice mirrors the discovery.k8s.io/v1 slice the apiserver
// maintains for the kubernetes service on a self-hosted control plane —
// fixed name, apiserver-managed (not a mirror).
func kubeEndpointSlice(ips []string) *discoveryv1.EndpointSlice {
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: endpointGuardNS, Name: endpointGuardName,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: endpointGuardName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	ready := true
	for _, ip := range ips {
		eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{ip},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		})
	}
	return eps
}

// kubeMirrorSlice builds the generated-name slice the
// endpointslicemirroring controller projects from Endpoints/kubernetes
// on hosted control planes — never the SSOT.
func kubeMirrorSlice(name string, ips []string) *discoveryv1.EndpointSlice {
	eps := kubeEndpointSlice(ips)
	eps.Name = name
	eps.Labels[discoveryv1.LabelManagedBy] = endpointSliceMirrorValue
	owner := true
	eps.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "v1", Kind: "Endpoints", Name: endpointGuardName,
		Controller: &owner,
	}}
	return eps
}

// probeTable is the test seam for g.probeFn — per-IP results the test
// mutates between runs to script multi-cycle wedge/recovery scenarios.
type probeTable map[string]*apiProbeResult

func (pt probeTable) fn(_ context.Context, ip string) apiProbeResult {
	if r, ok := pt[ip]; ok && r != nil {
		return *r
	}
	return apiProbeResult{err: errors.New("no probe result scripted for " + ip)}
}

func newEndpointGuard(cs kubernetes.Interface, dyn dynamic.Interface, probes probeTable) *apiServerEndpointGuard {
	return &apiServerEndpointGuard{
		cs:       cs,
		dyn:      dyn,
		probeFn:  probes.fn,
		backends: map[string]*backendProbeState{},
	}
}

func getKubeEndpoints(t *testing.T, dyn dynamic.Interface) *unstructured.Unstructured {
	t.Helper()
	ep, err := dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).
		Get(ctx, endpointGuardName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get endpoints: %v", err)
	}
	return ep
}

func getKubeSlice(t *testing.T, cs *fake.Clientset) *discoveryv1.EndpointSlice {
	t.Helper()
	eps, err := cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
		Get(ctx, endpointGuardName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get endpointslice: %v", err)
	}
	return eps
}

func endpointAddrSet(ep *unstructured.Unstructured) map[string]bool {
	set := map[string]bool{}
	for _, sub := range endpointSubsets(ep) {
		for _, a := range nestedMaps(sub, "addresses") {
			if ip, _ := a["ip"].(string); ip != "" {
				set[ip] = true
			}
		}
	}
	return set
}

func sliceAddrSet(eps *discoveryv1.EndpointSlice) map[string]bool {
	set := map[string]bool{}
	for _, e := range eps.Endpoints {
		for _, a := range e.Addresses {
			set[a] = true
		}
	}
	return set
}

func apiHealthyProbe(rv int64) *apiProbeResult {
	return &apiProbeResult{liveRV: rv, cacheRV: rv}
}

// quarantine_mutation_test.go — coverage for the quarantine
// bookkeeping's pure helpers: the unstructured scalar reader, the
// Endpoints/EndpointSlice IP navigation and mutation helpers, and the
// annotation read/write pair.
package apiserverendpointguard

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func TestNum64(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    any
		want int64
	}{
		{"int64", int64(42), 42},
		{"int", int(7), 7},
		{"float64", float64(6.0), 6},
		{"string reads as 0", "6", 0},
		{"nil reads as 0", nil, 0},
		{"bool reads as 0", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := num64(tc.v); got != tc.want {
				t.Fatalf("num64(%v) = %d, want %d", tc.v, got, tc.want)
			}
		})
	}
}

// qmEndpoints builds an unstructured core/v1 Endpoints object from
// subset maps — the shape the dynamic client decodes.
func qmEndpoints(subsets ...any) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Endpoints",
		"metadata": map[string]any{"name": "kubernetes", "namespace": "default"},
	}}
	if subsets != nil {
		lst := make([]any, 0, len(subsets))
		for _, s := range subsets {
			lst = append(lst, s)
		}
		o.Object["subsets"] = lst
	}
	return o
}

func addr(ip string) map[string]any { return map[string]any{"ip": ip} }

func TestEndpointIPs(t *testing.T) {
	ep := qmEndpoints(
		map[string]any{
			"addresses":         []any{addr("10.0.0.2"), addr("10.0.0.1")},
			"notReadyAddresses": []any{addr("10.0.0.3")},
			"ports":             []any{map[string]any{"port": int64(6443), "name": "https"}},
		},
		// garbage-shaped subset entry is skipped, not fatal
		"not-a-map",
		map[string]any{"addresses": []any{"garbage", addr("10.0.0.2")}},
	)
	got := endpointIPs(ep)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("endpointIPs = %v, want %v (sorted, deduped, notReady counts)", got, want)
	}
	if got := endpointIPs(qmEndpoints()); len(got) != 0 {
		t.Fatalf("endpoints without subsets must read as no IPs, got %v", got)
	}
}

func TestRoutableEndpointIPs(t *testing.T) {
	ep := qmEndpoints(map[string]any{
		"addresses":         []any{addr("10.0.0.1"), addr("10.0.0.2")},
		"notReadyAddresses": []any{addr("10.0.0.3")},
	})
	got := routableEndpointIPs(ep)
	if len(got) != 2 || !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("routableEndpointIPs = %v, want exactly the addresses set", got)
	}
}

func TestQuarantineAnnotationRoundTrip(t *testing.T) {
	ep := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "n"}}
	if got := parseQuarantineAnnotation(ep); len(got) != 0 {
		t.Fatalf("absent annotation = %v, want empty set", got)
	}
	writeQuarantineAnnotation(ep, map[string]bool{"10.0.0.2": true, "10.0.0.1": true})
	got := parseQuarantineAnnotation(ep)
	if len(got) != 2 || !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("round-trip = %v, want both IPs", got)
	}
	if v := ep.GetAnnotations()[endpointGuardAnno]; v != "10.0.0.1,10.0.0.2" {
		t.Fatalf("annotation value = %q, want sorted join", v)
	}
	// Clearing removes the key entirely.
	writeQuarantineAnnotation(ep, map[string]bool{})
	if _, ok := ep.GetAnnotations()[endpointGuardAnno]; ok {
		t.Fatal("empty set must delete the annotation")
	}
	// Clearing an absent annotation is a no-op (and must not re-add the key).
	writeQuarantineAnnotation(ep, map[string]bool{})
	if _, ok := ep.GetAnnotations()[endpointGuardAnno]; ok {
		t.Fatalf("no-op write must not re-create the annotation, got %v", ep.GetAnnotations())
	}
}

// TestUnionIPs already lives in apiserver_endpoint_guard_test.go.

func TestRemoveEndpointIP(t *testing.T) {
	ep := qmEndpoints(
		map[string]any{
			"addresses":         []any{addr("10.0.0.1"), addr("10.0.0.2")},
			"notReadyAddresses": []any{addr("10.0.0.1")},
		},
		map[string]any{"addresses": []any{addr("10.0.0.1")}}, // empties out — dropped
		"garbage-kept",
	)
	removeEndpointIP(ep, "10.0.0.1")
	got := endpointIPs(ep)
	if !reflect.DeepEqual(got, []string{"10.0.0.2"}) {
		t.Fatalf("endpointIPs after removal = %v, want [10.0.0.2]", got)
	}
	subs, _ := kube.NestedSlice(ep.Object, "subsets")
	if len(subs) != 2 {
		t.Fatalf("emptied subset must be dropped and garbage kept, subsets = %v", subs)
	}
	// Absent subsets: no-op.
	empty := qmEndpoints()
	removeEndpointIP(empty, "10.0.0.1")
	if _, found := kube.NestedSlice(empty.Object, "subsets"); found {
		t.Fatal("removeEndpointIP on subset-less object must not write subsets")
	}
}

func TestAddEndpointIP(t *testing.T) {
	port := func(p int64, name string) map[string]any {
		return map[string]any{"port": p, "name": name, "protocol": "TCP"}
	}
	// Prefers the :443-https subset.
	ep := qmEndpoints(
		map[string]any{"addresses": []any{addr("10.9.9.9")},
			"ports": []any{port(8080, "http")}},
		map[string]any{"addresses": []any{addr("10.9.9.8")},
			"ports": []any{port(6443, "https")}},
	)
	addEndpointIP(ep, "10.0.0.1")
	subs, _ := kube.NestedSlice(ep.Object, "subsets")
	second := subs[1].(map[string]any)
	addrs, _ := kube.NestedSlice(second, "addresses")
	if len(addrs) != 2 || addrs[1].(map[string]any)["ip"] != "10.0.0.1" {
		t.Fatalf("IP must land in the https/6443 subset, subsets = %v", subs)
	}
	// Re-adding is a no-op (reconciler already restored it).
	addEndpointIP(ep, "10.0.0.1")
	subs, _ = kube.NestedSlice(ep.Object, "subsets")
	second = subs[1].(map[string]any)
	addrs, _ = kube.NestedSlice(second, "addresses")
	if len(addrs) != 2 {
		t.Fatalf("duplicate add must be skipped, addresses = %v", addrs)
	}
	// Object without subsets seeds a fresh well-formed subset.
	fresh := qmEndpoints()
	addEndpointIP(fresh, "10.0.0.7")
	subs, _ = kube.NestedSlice(fresh.Object, "subsets")
	if len(subs) != 1 {
		t.Fatalf("fresh subset not seeded: %v", subs)
	}
	if ips := endpointIPs(fresh); !reflect.DeepEqual(ips, []string{"10.0.0.7"}) {
		t.Fatalf("seeded subset IPs = %v", ips)
	}
	// Garbage-shaped subset entry: append a fresh subset, keep the blob.
	messy := qmEndpoints("garbage")
	addEndpointIP(messy, "10.0.0.8")
	subs, _ = kube.NestedSlice(messy.Object, "subsets")
	if len(subs) != 2 {
		t.Fatalf("garbage subset must be kept alongside the fresh one: %v", subs)
	}
	if ips := endpointIPs(messy); !reflect.DeepEqual(ips, []string{"10.0.0.8"}) {
		t.Fatalf("garbage-path IPs = %v", ips)
	}
}

func qmSlice(eps ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes-x"},
		Endpoints:  eps,
	}
}

func TestSliceIPs(t *testing.T) {
	up, down := true, false
	eps := qmSlice(
		discoveryv1.Endpoint{Addresses: []string{"10.0.0.2", "10.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{Ready: &up}},
		discoveryv1.Endpoint{Addresses: []string{"10.0.0.1", "10.0.0.3"},
			Conditions: discoveryv1.EndpointConditions{Ready: &down}},
	)
	got := sliceIPs(eps)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sliceIPs = %v, want %v (notReady counts too)", got, want)
	}
}

func TestRoutableSliceIPs(t *testing.T) {
	up, down := true, false
	eps := qmSlice(
		discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{Ready: &up}},
		discoveryv1.Endpoint{Addresses: []string{"10.0.0.2"},
			Conditions: discoveryv1.EndpointConditions{Ready: &down}},
		discoveryv1.Endpoint{Addresses: []string{"10.0.0.3"}}, // nil Ready → ready
	)
	got := routableSliceIPs([]*discoveryv1.EndpointSlice{eps})
	if len(got) != 2 || !got["10.0.0.1"] || !got["10.0.0.3"] {
		t.Fatalf("routableSliceIPs = %v, want ready + nil-Ready addresses only", got)
	}
}

func TestRemoveSliceIP(t *testing.T) {
	up, down := true, false
	eps := qmSlice(
		discoveryv1.Endpoint{Addresses: []string{"10.0.0.1", "10.0.0.2"},
			Conditions: discoveryv1.EndpointConditions{Ready: &up}},
		discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{Ready: &down}},
	)
	if !removeSliceIP(eps, "10.0.0.1") {
		t.Fatal("removal must report a change")
	}
	if got := sliceIPs(eps); !reflect.DeepEqual(got, []string{"10.0.0.2"}) {
		t.Fatalf("sliceIPs after removal = %v", got)
	}
	if len(eps.Endpoints) != 1 {
		t.Fatalf("emptied endpoint must be dropped, endpoints = %d", len(eps.Endpoints))
	}
	// Removing an absent IP reports no change.
	if removeSliceIP(eps, "10.9.9.9") {
		t.Fatal("no-op removal must report unchanged")
	}
}

func TestAddSliceIP(t *testing.T) {
	up := true
	eps := qmSlice(discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"},
		Conditions: discoveryv1.EndpointConditions{Ready: &up}})
	if !addSliceIP(eps, "10.0.0.2") {
		t.Fatal("adding a new IP must report a change")
	}
	if got := sliceIPs(eps); !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("sliceIPs after add = %v", got)
	}
	if addSliceIP(eps, "10.0.0.1") {
		t.Fatal("re-adding an existing IP must report no change")
	}
	if got := sliceIPs(eps); !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("re-add mutated the slice: %v", got)
	}
}

// guard_ipset_test.go — pure subset/annotation/union IP-math units
// over the Endpoints/EndpointSlice fixtures.
package apiserverendpointguard

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ---------------------------------------------------------------------------
// Pure helper coverage — subset/annotation/union mutations.
// ---------------------------------------------------------------------------

// endpointIPs merges addresses + notReadyAddresses, deduped and sorted.
func TestEndpointIPSet(t *testing.T) {
	ep := kubeEndpoints([]string{"10.0.0.3", "10.0.0.1"}, []string{"10.0.0.2"}, nil)
	// Duplicate the IP across subsets to prove dedupe.
	appendSubset(ep, map[string]any{
		"addresses": []any{map[string]any{"ip": "10.0.0.1"}},
	})
	got := endpointIPs(ep)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("endpointIPs = %v, want %v", got, want)
	}
}

// The quarantine annotation tolerates whitespace and empty segments.
func TestParseQuarantineAnnotation(t *testing.T) {
	ep := kubeEndpoints(nil, nil, nil)
	if got := parseQuarantineAnnotation(ep); len(got) != 0 {
		t.Fatalf("absent annotation = %v", got)
	}
	ep.SetAnnotations(map[string]string{endpointGuardAnno: ""})
	if got := parseQuarantineAnnotation(ep); len(got) != 0 {
		t.Fatalf("empty annotation = %v", got)
	}
	ep.SetAnnotations(map[string]string{endpointGuardAnno: " 10.0.0.1 , ,10.0.0.2 "})
	got := parseQuarantineAnnotation(ep)
	if len(got) != 2 || !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("parseQuarantineAnnotation = %v", got)
	}
}

// writeQuarantineAnnotation writes a sorted join and removes the key
// entirely when the set drains.
func TestWriteQuarantineAnnotation(t *testing.T) {
	ep := kubeEndpoints(nil, nil, nil)
	writeQuarantineAnnotation(ep, map[string]bool{"10.0.0.2": true, "10.0.0.1": true})
	if got := ep.GetAnnotations()[endpointGuardAnno]; got != "10.0.0.1,10.0.0.2" {
		t.Fatalf("annotation = %q, want sorted join", got)
	}
	writeQuarantineAnnotation(ep, map[string]bool{})
	if _, ok := ep.GetAnnotations()[endpointGuardAnno]; ok {
		t.Fatal("empty quarantine set left the annotation behind")
	}
}

// unionIPs merges active + quarantined sources, deduped and sorted.
func TestUnionIPs(t *testing.T) {
	got := unionIPs([]string{"10.0.0.2", "10.0.0.1"},
		map[string]bool{"10.0.0.3": true, "10.0.0.1": true})
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unionIPs = %v, want %v", got, want)
	}
}

// A subset emptied by the removal drops its empty address lists and
// keeps its PORT shell: addEndpointIP must be able to restore the
// recovered backend onto the ORIGINAL ports (kube-proxy reads the
// endpoint port back; the object's ports may be 443 on one plane and
// 6443 on another). A subset with neither addresses nor ports left
// drops entirely.
func TestRemoveEndpointIPDropsEmptySubset(t *testing.T) {
	ep := kubeEndpoints([]string{"10.0.0.1"}, nil, nil) // ports + address
	appendSubset(ep, map[string]any{
		"addresses": []any{map[string]any{"ip": "10.0.0.2"}}, // no ports
	})
	removeEndpointIP(ep, "10.0.0.1")
	subs := endpointSubsets(ep)
	// subs[0] is the surviving port shell; subs[1] is the untouched
	// ports-less subset still carrying 10.0.0.2.
	if len(subs) != 2 {
		t.Fatalf("want the port shell plus the untouched subset: %+v", subs)
	}
	if _, found := subs[0]["addresses"]; found {
		t.Fatal("emptied subset must not serialize an empty addresses list")
	}
	if _, found := subs[0]["notReadyAddresses"]; found {
		t.Fatal("emptied subset must not serialize an empty notReadyAddresses list")
	}
	ports := nestedMaps(subs[0], "ports")
	if len(ports) != 1 || num64(ports[0]["port"]) != 443 {
		t.Fatalf("port shell lost by the removal: %+v", ports)
	}
	if got := subsetAddrs(ep, 1, "addresses"); len(got) != 1 || got[0]["ip"] != "10.0.0.2" {
		t.Fatalf("untouched subset changed: %+v", got)
	}
	// The restore lands the recovered IP back onto the shell's ports.
	addEndpointIP(ep, "10.0.0.1")
	subs = endpointSubsets(ep)
	if len(subs) != 2 || len(subsetAddrs(ep, 0, "addresses")) != 1 {
		t.Fatalf("re-add must land in the surviving port shell: %+v", subs)
	}
}

// addEndpointIP placement: existing -> no-op; empty -> fresh subset on
// :6443; named "https" port wins; otherwise the first subset.
func TestAddEndpointIPPlacement(t *testing.T) {
	// Already present — no-op.
	ep := kubeEndpoints([]string{"10.0.0.1"}, nil, nil)
	addEndpointIP(ep, "10.0.0.1")
	if n := len(subsetAddrs(ep, 0, "addresses")); n != 1 {
		t.Fatalf("duplicate address appended: %d addresses", n)
	}

	// No subsets at all — a fresh subset is seeded with port 6443/https.
	bare := kubeEndpoints(nil, nil, nil)
	unstructured.RemoveNestedField(bare.Object, "subsets")
	addEndpointIP(bare, "10.0.0.9")
	bareAddrs := subsetAddrs(bare, 0, "addresses")
	if len(endpointSubsets(bare)) != 1 || len(bareAddrs) != 1 ||
		bareAddrs[0]["ip"] != "10.0.0.9" {
		t.Fatalf("empty endpoints not re-seeded: %+v", endpointSubsets(bare))
	}
	if p := nestedMaps(endpointSubsets(bare)[0], "ports")[0]; num64(p["port"]) != 6443 || p["name"] != "https" {
		t.Fatalf("seeded subset port = %+v, want 6443/https", p)
	}

	// A subset carrying an "https" port (any number) is the target.
	named := &unstructured.Unstructured{Object: map[string]any{
		"subsets": []any{
			map[string]any{
				"addresses": []any{map[string]any{"ip": "10.0.0.1"}},
				"ports":     []any{map[string]any{"name": "https", "port": int64(443)}},
			},
			map[string]any{
				"addresses": []any{map[string]any{"ip": "10.0.0.2"}},
				"ports":     []any{map[string]any{"name": "other", "port": int64(1234)}},
			},
		},
	}}
	addEndpointIP(named, "10.0.0.7")
	if n := len(subsetAddrs(named, 0, "addresses")); n != 2 {
		t.Fatalf("IP not appended to the https subset: %+v", endpointSubsets(named))
	}

	// No https/6443 port anywhere — fall back to subset[0].
	fallback := &unstructured.Unstructured{Object: map[string]any{
		"subsets": []any{
			map[string]any{
				"addresses": []any{map[string]any{"ip": "10.0.0.1"}},
				"ports":     []any{map[string]any{"name": "dns", "port": int64(53)}},
			},
		},
	}}
	addEndpointIP(fallback, "10.0.0.8")
	if n := len(subsetAddrs(fallback, 0, "addresses")); n != 2 {
		t.Fatalf("IP not appended to subset[0]: %+v", endpointSubsets(fallback))
	}
}

// removeSliceIP reports whether anything changed; addSliceIP refuses
// duplicates.
func TestSliceIPHelpers(t *testing.T) {
	eps := kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"})

	if removeSliceIP(eps, "10.0.0.9") {
		t.Fatal("removeSliceIP reported a change for an absent IP")
	}
	if !removeSliceIP(eps, "10.0.0.1") {
		t.Fatal("removeSliceIP reported no change for a present IP")
	}
	if got := sliceAddrSet(eps); got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("slice after removal = %v", got)
	}

	if addSliceIP(eps, "10.0.0.2") {
		t.Fatal("addSliceIP duplicated an existing IP")
	}
	if !addSliceIP(eps, "10.0.0.3") {
		t.Fatal("addSliceIP refused a new IP")
	}
	if !sliceAddrSet(eps)["10.0.0.3"] {
		t.Fatal("new IP not appended to the slice")
	}
}

// An endpoint whose only address is removed is dropped from the slice.
func TestRemoveSliceIPDropsEmptyEndpoint(t *testing.T) {
	eps := kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"})
	removeSliceIP(eps, "10.0.0.1")
	if len(eps.Endpoints) != 1 {
		t.Fatalf("emptied endpoint kept in slice: %+v", eps.Endpoints)
	}
}

// quarantine_mutation.go — the quarantine bookkeeping + write path
// of apiserver-endpoint-guard: reading/writing the
// passiontech.dev/quarantined-endpoints annotation (the persisted half of
// the quarantine set, mirrored in memory by g.memQuarantine) and the
// pure Endpoints/EndpointSlice mutation helpers run() applies to the
// SSOT object's deep copy before Update.
//
// The deprecated core/v1 Endpoints object stays the writable SSOT on
// hosted planes where EndpointSlice mirroring does not apply — it is
// reached as unstructured maps (dynamic client) so the deprecated
// type is never named in code.
package apiserverendpointguard

import (
	"maps"
	"slices"
	"strings"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// Endpoints (unstructured) navigation.
//
// Nested* accessors deep-copy, so read helpers can consume them
// directly while mutators build a fresh subsets slice and write it
// back through unstructured.SetNestedSlice.
// ---------------------------------------------------------------------------

// endpointSubsets decodes subsets[] into maps — absent/garbage-shaped
// entries are skipped rather than panicking on a hand-edited object.
func endpointSubsets(ep *unstructured.Unstructured) []map[string]any {
	subs, _ := kube.NestedSlice(ep.Object, "subsets")
	out := make([]map[string]any, 0, len(subs))
	for _, s := range subs {
		if m, ok := s.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// nestedMaps decodes a map-typed list field (addresses,
// notReadyAddresses, ports) into maps — same skip-garbage contract.
func nestedMaps(m map[string]any, field string) []map[string]any {
	l, _ := kube.NestedSlice(m, field)
	out := make([]map[string]any, 0, len(l))
	for _, e := range l {
		if em, ok := e.(map[string]any); ok {
			out = append(out, em)
		}
	}
	return out
}

// num64 reads an unstructured scalar as int64 — JSON ints decode as
// int64, but hand-built fixtures (or JSONNumber decoders) can carry
// other numeric shapes.
func num64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}

// ---------------------------------------------------------------------------
// Endpoints mutation helpers.
// ---------------------------------------------------------------------------

// endpointIPs returns the sorted deduped controller IPs currently in
// the Endpoints subsets — notReadyAddresses count too: a not-ready
// backend is still a controller IP (and a wedge suspect).
func endpointIPs(ep *unstructured.Unstructured) []string {
	set := map[string]bool{}
	for _, sub := range endpointSubsets(ep) {
		for _, field := range []string{"addresses", "notReadyAddresses"} {
			for _, a := range nestedMaps(sub, field) {
				if ip, _ := a["ip"].(string); ip != "" {
					set[ip] = true
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// routableEndpointIPs returns the IPs kube-proxy actually routes to:
// subsets[].Addresses ONLY — a notReadyAddresses entry is probed and
// quarantined like any backend, but it can never serve traffic, so it
// must not count as a healthy peer when deciding removals.
func routableEndpointIPs(ep *unstructured.Unstructured) map[string]bool {
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

// parseQuarantineAnnotation reads passiontech.dev/quarantined-endpoints off
// whichever object is the SSOT this cluster (Endpoints <1.33,
// EndpointSlice >=1.33).
func parseQuarantineAnnotation(obj metav1.Object) map[string]bool {
	set := map[string]bool{}
	for _, ip := range strings.Split(obj.GetAnnotations()[endpointGuardAnno], ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			set[ip] = true
		}
	}
	return set
}

func writeQuarantineAnnotation(obj metav1.Object, set map[string]bool) {
	a := obj.GetAnnotations()
	if len(set) == 0 {
		if _, ok := a[endpointGuardAnno]; !ok {
			return
		}
		delete(a, endpointGuardAnno)
	} else {
		if a == nil {
			a = map[string]string{}
		}
		a[endpointGuardAnno] = strings.Join(slices.Sorted(maps.Keys(set)), ",")
	}
	// GetAnnotations returns a COPY for unstructured objects — always
	// write the map back (harmless on typed objects where it is live).
	obj.SetAnnotations(a)
}

func unionIPs(a []string, b map[string]bool) []string {
	set := map[string]bool{}
	for _, ip := range a {
		set[ip] = true
	}
	for ip := range b {
		set[ip] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// removeEndpointIP drops ip from every subset's Addresses AND
// NotReadyAddresses; a subset left with zero addresses is dropped so
// the object never serializes an empty-addresses subset.
func removeEndpointIP(ep *unstructured.Unstructured, ip string) {
	subs, found := kube.NestedSlice(ep.Object, "subsets")
	if !found {
		return
	}
	out := make([]any, 0, len(subs))
	for _, s := range subs {
		m, ok := s.(map[string]any)
		if !ok {
			out = append(out, s)
			continue
		}
		empty := true
		for _, f := range []string{"addresses", "notReadyAddresses"} {
			if kept := dropAddrField(m, f, ip); len(kept) > 0 {
				empty = false
			}
		}
		if !empty {
			out = append(out, m)
		}
	}
	_ = unstructured.SetNestedSlice(ep.Object, out, "subsets")
}

// dropAddrField filters ip out of m[field] in place and returns the
// kept entries — an absent field is already empty.
func dropAddrField(m map[string]any, field, ip string) []any {
	addrs, found := kube.NestedSlice(m, field)
	if !found {
		return nil
	}
	kept := addrs[:0]
	for _, a := range addrs {
		if am, ok := a.(map[string]any); !ok || am["ip"] != ip {
			kept = append(kept, a)
		}
	}
	clear(addrs[len(kept):])
	_ = unstructured.SetNestedSlice(m, kept, field)
	return kept
}

// addEndpointIP appends ip to the subset serving :443 (the kubernetes
// API port — falls back to the first subset, then to a fresh subset so
// a cluster whose object was emptied can still be re-seeded).
func addEndpointIP(ep *unstructured.Unstructured, ip string) {
	subs, _ := kube.NestedSlice(ep.Object, "subsets")
	for _, sub := range subs {
		if m, ok := sub.(map[string]any); ok {
			for _, a := range nestedMaps(m, "addresses") {
				if a["ip"] == ip {
					return // already back — reconciler beat us to it
				}
			}
		}
	}
	idx := -1
	for i, s := range subs {
		m, _ := s.(map[string]any)
		for _, p := range nestedMaps(m, "ports") {
			if num64(p["port"]) == 6443 || p["name"] == "https" {
				idx = i
				break
			}
		}
		if idx >= 0 {
			break
		}
	}
	if idx < 0 && len(subs) > 0 {
		idx = 0
	}
	if idx < 0 {
		subs = []any{map[string]any{
			"addresses": []any{map[string]any{"ip": ip}},
			"ports": []any{map[string]any{
				"name": "https", "port": int64(6443), "protocol": "TCP"},
			},
		}}
	} else if m, ok := subs[idx].(map[string]any); ok {
		addrs, _ := kube.NestedSlice(m, "addresses")
		addrs = append(addrs, map[string]any{"ip": ip})
		_ = unstructured.SetNestedSlice(m, addrs, "addresses")
		subs[idx] = m
	} else {
		// Garbage-shaped subset entry: append a fresh well-formed
		// subset rather than dropping the unknown blob.
		subs = append(subs, map[string]any{
			"addresses": []any{map[string]any{"ip": ip}},
			"ports": []any{map[string]any{
				"name": "https", "port": int64(6443), "protocol": "TCP"},
			},
		})
	}
	_ = unstructured.SetNestedSlice(ep.Object, subs, "subsets")
}

// sliceIPs returns the sorted deduped backend IPs across all
// EndpointSlice endpoints — Ready=false/absent entries count too (same
// convention as Endpoints notReadyAddresses: still a controller IP,
// still a wedge suspect).
func sliceIPs(eps *discoveryv1.EndpointSlice) []string {
	set := map[string]bool{}
	for _, e := range eps.Endpoints {
		for _, a := range e.Addresses {
			set[a] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// routableSliceIPs unions the addresses of READY endpoints across the
// resolved slices — the slice-side routable set (a nil
// conditions.ready counts as ready: the field defaults to true
// server-side). Ready=false endpoints stay in activeIPs for probing
// and quarantine but never vouch as a healthy peer.
func routableSliceIPs(list []*discoveryv1.EndpointSlice) map[string]bool {
	set := map[string]bool{}
	for _, s := range list {
		for _, e := range s.Endpoints {
			if e.Conditions.Ready == nil || *e.Conditions.Ready {
				for _, a := range e.Addresses {
					set[a] = true
				}
			}
		}
	}
	return set
}

// removeSliceIP drops ip from every endpoint's addresses in the slice;
// an endpoint left with zero addresses is dropped. Returns whether the
// slice actually changed.
func removeSliceIP(eps *discoveryv1.EndpointSlice, ip string) bool {
	changed := false
	endpoints := eps.Endpoints[:0]
	for _, e := range eps.Endpoints {
		out := e.Addresses[:0]
		for _, a := range e.Addresses {
			if a == ip {
				changed = true
			} else {
				out = append(out, a)
			}
		}
		clear(e.Addresses[len(out):])
		e.Addresses = out
		if len(e.Addresses) > 0 {
			endpoints = append(endpoints, e)
		}
	}
	clear(eps.Endpoints[len(endpoints):])
	eps.Endpoints = endpoints
	return changed
}

// addSliceIP appends a ready endpoint carrying ip unless the slice
// already lists it (the apiserver's own endpoints reconciler may have
// re-added it first — never duplicate).
func addSliceIP(eps *discoveryv1.EndpointSlice, ip string) bool {
	for _, e := range eps.Endpoints {
		if slices.Contains(e.Addresses, ip) {
			return false
		}
	}
	ready := true
	eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
		Addresses:  []string{ip},
		Conditions: discoveryv1.EndpointConditions{Ready: &ready},
	})
	return true
}

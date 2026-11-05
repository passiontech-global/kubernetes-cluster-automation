// quarantine_mutation.go — the quarantine bookkeeping + write path
// of apiserver-endpoint-guard: reading/writing the
// node.ops/quarantined-endpoints annotation (the persisted half of
// the quarantine set, mirrored in memory by g.memQuarantine) and the
// pure Endpoints/EndpointSlice mutation helpers run() applies to the
// SSOT object's deep copy before Update.
package apiserverendpointguard

import (
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Endpoint / EndpointSlice mutation helpers.
// ---------------------------------------------------------------------------

// endpointIPs returns the sorted deduped controller IPs currently in
// the Endpoints subsets — notReadyAddresses count too: a not-ready
// backend is still a controller IP (and a wedge suspect).
func endpointIPs(ep *corev1.Endpoints) []string {
	set := map[string]bool{}
	for _, sub := range ep.Subsets {
		for _, a := range sub.Addresses {
			set[a.IP] = true
		}
		for _, a := range sub.NotReadyAddresses {
			set[a.IP] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// routableEndpointIPs returns the IPs kube-proxy actually routes to:
// subsets[].Addresses ONLY — a notReadyAddresses entry is probed and
// quarantined like any backend, but it can never serve traffic, so it
// must not count as a healthy peer when deciding removals.
func routableEndpointIPs(ep *corev1.Endpoints) map[string]bool {
	set := map[string]bool{}
	for _, sub := range ep.Subsets {
		for _, a := range sub.Addresses {
			set[a.IP] = true
		}
	}
	return set
}

// parseQuarantineAnnotation reads node.ops/quarantined-endpoints off
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
		delete(a, endpointGuardAnno)
		return
	}
	if a == nil {
		a = map[string]string{}
		obj.SetAnnotations(a)
	}
	a[endpointGuardAnno] = strings.Join(slices.Sorted(maps.Keys(set)), ",")
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
func removeEndpointIP(ep *corev1.Endpoints, ip string) {
	subsets := ep.Subsets[:0]
	for _, sub := range ep.Subsets {
		sub.Addresses = dropAddr(sub.Addresses, ip)
		sub.NotReadyAddresses = dropAddr(sub.NotReadyAddresses, ip)
		if len(sub.Addresses) > 0 || len(sub.NotReadyAddresses) > 0 {
			subsets = append(subsets, sub)
		}
	}
	// Zero the tail — stale subset copies would otherwise keep the
	// dropped address strings reachable through the backing array.
	clear(ep.Subsets[len(subsets):])
	ep.Subsets = subsets
}

func dropAddr(addrs []corev1.EndpointAddress, ip string) []corev1.EndpointAddress {
	out := addrs[:0]
	for _, a := range addrs {
		if a.IP != ip {
			out = append(out, a)
		}
	}
	clear(addrs[len(out):])
	return out
}

// addEndpointIP appends ip to the subset serving :443 (the kubernetes
// API port — falls back to the first subset, then to a fresh subset so
// a cluster whose object was emptied can still be re-seeded).
func addEndpointIP(ep *corev1.Endpoints, ip string) {
	for _, sub := range ep.Subsets {
		for _, a := range sub.Addresses {
			if a.IP == ip {
				return // already back — reconciler beat us to it
			}
		}
	}
	idx := -1
	for i, sub := range ep.Subsets {
		for _, p := range sub.Ports {
			if p.Port == 6443 || p.Name == "https" {
				idx = i
				break
			}
		}
		if idx >= 0 {
			break
		}
	}
	if idx < 0 && len(ep.Subsets) > 0 {
		idx = 0
	}
	if idx < 0 {
		ep.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{IP: ip}},
			Ports: []corev1.EndpointPort{
				{Name: "https", Port: 6443, Protocol: corev1.ProtocolTCP},
			},
		}}
		return
	}
	ep.Subsets[idx].Addresses = append(ep.Subsets[idx].Addresses,
		corev1.EndpointAddress{IP: ip})
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

// endpoints.go — the EndpointSlice → Service rollup every endpoint
// census in this binary converged on. Before this, the webhook
// guard's census, the stateful-masterless check, the linkerd
// endpoint-sync/H2-stream guards, the scylla member desync and the
// gateway-route check each hand-rolled the same "group Ready
// endpoints by kubernetes.io/service-name" loop — same label
// binding, same nil-Ready-counts-as-ready convention — and a couple
// drifted into private endpoint structs to keep the zone/node/
// targetRef placement detail. ReadyEndpointsByService is the one
// rollup; ReadyEndpoint carries the fields the converged consumers
// actually read.
package kube

import (
	discoveryv1 "k8s.io/api/discovery/v1"
)

// ReadyEndpoint is the placement detail one Ready slice endpoint
// carries — distilled to the fields the converged consumers use:
//   - Zone: the endpoint's own zone hint (ep.Zone; "" when unset —
//     the endpointslice controller copies the node's zone label,
//     but custom producers may never fill it).
//   - Node: the endpoint's nodeName ("" for off-cluster targets or
//     endpoints not yet bound — an absent nodeName must read the
//     same as an unresolvable one).
//   - PodKey: "<ns>/<name>" of the targetRef, only when Kind=="Pod"
//     — the fallback the zone resolvers walk when Zone/Node are
//     empty ("" otherwise; a namespace-less ref still joins as
//     "/name", byte-identical to the original inline loops).
//   - Addresses: the endpoint's IPs verbatim — dual-stack targets
//     legitimately carry several, and the desync/brownout censuses
//     compare them against live pod IPs.
type ReadyEndpoint struct {
	Zone      string
	Node      string
	PodKey    string
	Addresses []string
}

// ReadyEndpointsByService rolls a cluster EndpointSlice census up to
// "namespace/service" → its Ready endpoints: the
// kubernetes.io/service-name label binds each slice to its Service
// (label-less slices carry no owning Service and are skipped), and a
// nil conditions.ready counts as ready — the field defaults to true
// server-side, so every hand-rolled census treated unset as serving.
// The returned map is freshly allocated per call and read-only in
// spirit: consumers keep it whole or not at all, never feed mutated
// entries back into a shared structure.
func ReadyEndpointsByService(slices []discoveryv1.EndpointSlice) map[string][]ReadyEndpoint {
	out := map[string][]ReadyEndpoint{}
	for _, s := range slices {
		svc := s.Labels[discoveryv1.LabelServiceName]
		if svc == "" {
			continue // no owning Service — nothing to group under
		}
		key := s.Namespace + "/" + svc
		for _, ep := range s.Endpoints {
			// nil Ready counts as ready — k8s defaults the field
			// true server-side; only an explicit false demotes the
			// endpoint (the convention every census in this binary
			// hand-rolled identically).
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			e := ReadyEndpoint{Addresses: ep.Addresses}
			if ep.Zone != nil {
				e.Zone = *ep.Zone
			}
			if ep.NodeName != nil {
				e.Node = *ep.NodeName
			}
			if ref := ep.TargetRef; ref != nil && ref.Kind == "Pod" {
				e.PodKey = ref.Namespace + "/" + ref.Name
			}
			out[key] = append(out[key], e)
		}
	}
	return out
}

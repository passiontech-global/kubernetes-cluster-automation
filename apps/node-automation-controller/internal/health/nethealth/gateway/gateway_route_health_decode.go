// gateway_route_health_decode.go — the route-decode helpers of the
// gateway-route-health check: the unstructured shapes the sweep reads
// (Service backendRefs off spec.rules, the ReferenceGrant from/to
// tuples and their permits verdict, parent-condition→reason
// reduction) plus gatewayRouteCensus, the lazily-built cluster view
// the backend verdicts share.
package gateway

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// route decode — the unstructured shapes the check reads
// ---------------------------------------------------------------------------

// routeBackendRef is one Service-typed backendRef decoded off a
// route's spec.rules — non-Service backends are filtered out before
// this struct exists. crossNS records whether the ref names a
// different namespace than the route's (the ReferenceGrant gate —
// negative-cache-guard): an unset namespace resolves to same-ns by default.
type routeBackendRef struct {
	ns, name string
	port     int64
	hasPort  bool
	crossNS  bool
}

// routeWorkloads is one Deployment/StatefulSet's downscaler verdict
// inputs: the pod-template labels a service selector matches against
// and the object annotations + replica count IsIntentionallyDownscaled
// reads.
type routeWorkload struct {
	templateLabels map[string]string
	annotations    map[string]string
	replicas       *int32
}

// gatewayRouteCensus is the lazily-built cluster view the backend
// checks share: Services fetched on demand and cached by "ns/name"
// (nil + miss flag for 404s, err flag for inconclusive lookups), the
// Ready-endpoint census loaded on the first valid backend, and the
// per-namespace workload list loaded on the first zero-endpoint
// candidate — a cluster with no flagged routes pays nothing.
type gatewayRouteCensus struct {
	services  map[string]*corev1.Service
	svcMiss   map[string]bool
	svcErr    map[string]bool
	esReady   map[string]map[string]bool
	esLoaded  bool
	workloads map[string][]routeWorkload
	wlLoaded  map[string]bool
	// grants/grantsTried/grantsErr lazily load the ReferenceGrant
	// census on the first cross-namespace backendRef — decoded
	// from/to entries, a load attempted flag so one error does not
	// re-list per ref, and an inconclusive flag so a list failure
	// flags nothing ("can't tell" is not "not permitted").
	grants      []routeGrant
	grantsTried bool
	grantsErr   bool
}

func newGatewayRouteCensus() *gatewayRouteCensus {
	return &gatewayRouteCensus{
		services:  map[string]*corev1.Service{},
		svcMiss:   map[string]bool{},
		svcErr:    map[string]bool{},
		esReady:   map[string]map[string]bool{},
		workloads: map[string][]routeWorkload{},
		wlLoaded:  map[string]bool{},
	}
}

// routeGrant is one decoded ReferenceGrant: the namespace it lives
// in (the TO side's home — a grant in the backend's namespace is the
// only thing that may permit the ref) plus the raw from/to tuples.
type routeGrant struct {
	ns   string
	from []routeGrantFrom
	to   []routeGrantTo
}

// routeGrantFrom is one spec.from entry — group/kind/namespace of
// what may reference INTO the grant's namespace.
type routeGrantFrom struct{ group, kind, namespace string }

// routeGrantTo is one spec.to entry — group/kind/(optional)name of
// what may be referenced.
type routeGrantTo struct{ group, kind, name string }

// permits reports whether the grant lets a route of kind routeKind in
// routeNS reference the Service svcName in the grant's own namespace —
// the ReferenceGrant contract: from must name the route's group/kind/
// namespace, to must name core Service (name absent = any Service).
func (g routeGrant) permits(routeKind, routeNS, svcName string) bool {
	fromOK := false
	for _, f := range g.from {
		if f.group == "gateway.networking.k8s.io" && f.kind == routeKind &&
			f.namespace == routeNS {
			fromOK = true
		}
	}
	if !fromOK {
		return false
	}
	for _, t := range g.to {
		if t.group == "" && t.kind == "Service" &&
			(t.name == "" || t.name == svcName) {
			return true
		}
	}
	return false
}

// decodeRouteGrant reduces one ReferenceGrant unstructured to the
// from/to tuples permits reads.
func decodeRouteGrant(u *unstructured.Unstructured) routeGrant {
	g := routeGrant{ns: u.GetNamespace()}
	if froms, ok := kube.NestedSlice(u.Object, "spec", "from"); ok {
		for _, f := range froms {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			g.from = append(g.from, routeGrantFrom{
				group:     mustNestedString(fm, "group"),
				kind:      mustNestedString(fm, "kind"),
				namespace: mustNestedString(fm, "namespace")})
		}
	}
	if tos, ok := kube.NestedSlice(u.Object, "spec", "to"); ok {
		for _, t := range tos {
			tm, ok := t.(map[string]any)
			if !ok {
				continue
			}
			g.to = append(g.to, routeGrantTo{
				group: mustNestedString(tm, "group"),
				kind:  mustNestedString(tm, "kind"),
				name:  mustNestedString(tm, "name")})
		}
	}
	return g
}

// mustNestedString reads a string field, tolerating absence.
func mustNestedString(m map[string]any, field string) string {
	v, _ := kube.NestedString(m, field)
	return v
}

// routeServiceBackendRef reports whether a backendRef points at a
// core Service: empty group ("" = core) and absent-or-"Service" kind.
// Non-Service backends (implementation-specific kinds, cross-group
// refs) are outside this check's verdict.
func routeServiceBackendRef(bm map[string]any) bool {
	group, _ := kube.NestedString(bm, "group")
	kind, _ := kube.NestedString(bm, "kind")
	return (group == "" || group == "core") &&
		(kind == "" || kind == "Service")
}

// routeBackendRefs decodes every Service backendRef off a route's
// spec.rules — ref namespace defaults to the route's own.
func routeBackendRefs(route *unstructured.Unstructured) []routeBackendRef {
	rules, found := kube.NestedSlice(route.Object, "spec", "rules")
	if !found {
		return nil
	}
	var out []routeBackendRef
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		refs, _ := kube.NestedSlice(rm, "backendRefs")
		for _, b := range refs {
			bm, ok := b.(map[string]any)
			if !ok || !routeServiceBackendRef(bm) {
				continue
			}
			name, _ := kube.NestedString(bm, "name")
			if name == "" {
				continue
			}
			ns, _ := kube.NestedString(bm, "namespace")
			crossNS := ns != "" && ns != route.GetNamespace()
			if ns == "" {
				ns = route.GetNamespace()
			}
			port, hasPort := kube.NestedNumber(bm, "port")
			out = append(out, routeBackendRef{
				ns: ns, name: name, port: port, hasPort: hasPort, crossNS: crossNS})
		}
	}
	return out
}

// routeParentConditionReasons reduces a route's status.parents
// conditions to the failure reasons they prove: any parent reporting
// Accepted=False or ResolvedRefs=False flags the matching reason —
// one stuck attachment is enough to blackhole that parent.
// ResolvedRefs carries the more precise ref_not_permitted reason
// when the controller names it (negative-cache-guard) so alerting can tell a
// ReferenceGrant problem apart from a plain unresolved ref.
func routeParentConditionReasons(route *unstructured.Unstructured) map[string]bool {
	reasons := map[string]bool{}
	parents, found := kube.NestedSlice(route.Object, "status", "parents")
	if !found {
		return reasons
	}
	for _, pr := range parents {
		pm, ok := pr.(map[string]any)
		if !ok {
			continue
		}
		for _, c := range kube.Conditions(pm, "conditions") {
			switch {
			case c.Type == "Accepted" && c.Status == "False":
				reasons[routeReasonAcceptedFalse] = true
			case c.Type == "ResolvedRefs" && c.Reason == "RefNotPermitted":
				reasons[routeReasonRefNotPermitted] = true
			case c.Type == "ResolvedRefs" && c.Status == "False":
				reasons[routeReasonResolvedRefsFalse] = true
			}
		}
	}
	return reasons
}

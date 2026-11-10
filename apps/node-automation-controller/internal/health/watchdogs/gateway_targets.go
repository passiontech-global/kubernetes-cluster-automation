// gateway_targets.go — the gateway-API stuck signatures and
// ownership filters of the operator-workqueue-watchdog check (operator-workqueue-watchdog):
// the parent/listener/Accepted-condition staleness predicates for
// the GatewayClass, Gateway and route kinds (their status has no
// top-level observedGeneration), the cached GatewayClass →
// controllerName resolution, and the ciliumOwns* filters that keep
// gateway-API resources shared by several controllers attributed to
// the right operator. Split out of operator_watchdog_targets.go —
// see that file for the watched-operator table.
package watchdogs

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// condMaxObservedGeneration returns the largest observedGeneration
// carried inside a conditions list. Gateway-API resources report the
// generation their controller last processed inside each condition —
// there is no top-level status.observedGeneration on
// Gateway/HTTPRoute/GRPCRoute — so 0 means the attached controller
// has never reported a spec generation.
func condMaxObservedGeneration(conds []kube.Condition) int64 {
	var max int64
	for _, c := range conds {
		if c.ObservedGeneration > max {
			max = c.ObservedGeneration
		}
	}
	return max
}

// gatewayStatusStuck is the cilium-operator signature on the
// gateway-API route resources its gateway controller reconciles: an
// object reporting no status.parents (the controller attaches a
// parent status when it programs the route), or one whose parents'
// conditions still report only older observedGenerations — the
// controller attached once but never saw the last spec write.
func gatewayStatusStuck(o *unstructured.Unstructured) bool {
	parents, found := kube.NestedSlice(o.Object, "status", "parents")
	if !found || len(parents) == 0 {
		return true
	}
	var maxOG int64
	for _, pr := range parents {
		m, ok := pr.(map[string]any)
		if !ok {
			continue
		}
		if og := condMaxObservedGeneration(
			kube.Conditions(m, "conditions")); og > maxOG {
			maxOG = og
		}
	}
	return maxOG < o.GetGeneration()
}

// gatewayObjectStuck is the same signature for the Gateway kind
// itself: Gateways carry status.listeners, not status.parents — the
// route predicate would flag every healthy Gateway forever. A
// programmed Gateway reports one status.listeners entry per
// spec.listeners entry; a spec with listeners but an empty/absent
// status.listeners means the controller never programmed it.
// Generation lag is judged from the conditions' observedGeneration
// (top-level status.conditions plus per-listener conditions) —
// Gateway status has no top-level observedGeneration field.
func gatewayObjectStuck(o *unstructured.Unstructured) bool {
	spec, found := kube.NestedSlice(o.Object, "spec", "listeners")
	if !found || len(spec) == 0 {
		return false
	}
	status, found := kube.NestedSlice(o.Object, "status", "listeners")
	if !found || len(status) == 0 {
		return true
	}
	var maxOG int64
	maxOG = condMaxObservedGeneration(
		kube.Conditions(o.Object, "status", "conditions"))
	for _, l := range status {
		m, ok := l.(map[string]any)
		if !ok {
			continue
		}
		if og := condMaxObservedGeneration(
			kube.Conditions(m, "conditions")); og > maxOG {
			maxOG = og
		}
	}
	return maxOG < o.GetGeneration()
}

// gatewayClassStuck is the signature for the GatewayClass kind
// itself: the class carries no top-level status.observedGeneration —
// the serving controller reports the last reconciled generation only
// inside status.conditions[type=Accepted].observedGeneration. No
// conditions, or none of them an Accepted entry, means the class was
// never picked up; an Accepted observedGeneration lagging
// metadata.generation means the last spec write was never seen. The
// Accepted status value (True/False) is irrelevant — a fresh
// rejection still proves the controller read the object.
func gatewayClassStuck(o *unstructured.Unstructured) bool {
	conds := kube.Conditions(o.Object, "status", "conditions")
	if len(conds) == 0 {
		return true
	}
	c, ok := kube.FindCondition(conds, "Accepted")
	if !ok {
		return true
	}
	return c.ObservedGeneration < o.GetGeneration()
}

// gatewayClassCensus returns the class-name → controllerName map,
// refreshing it at most once a minute. ok=false means the LIST
// itself failed — the caller cannot disprove ownership and must
// keep the object. ok=true with a missing key is different: the
// class set was successfully listed and does NOT contain the name,
// so a Gateway referencing it is provably orphaned (same shape as
// bug #11's deleted-parent route — no controller will ever own it).
func (p *operatorWorkqueueCheck) gatewayClassCensus(ctx context.Context) (map[string]string, bool) {
	cached, at := p.gwClassCtlr, p.gwClassAt
	if cached == nil || p.Now().Sub(at) > time.Minute {
		list, err := p.AllUnstructured(ctx, kube.GVRGatewayClass)
		if err != nil {
			return nil, false
		}
		m := map[string]string{}
		for i := range list {
			ctlr, _ := kube.NestedString(list[i].Object, "spec", "controllerName")
			m[list[i].GetName()] = ctlr
		}
		p.gwClassCtlr, p.gwClassAt = m, p.Now()
		cached = m
	}
	return cached, true
}

// gatewayClassController resolves a GatewayClass name to its
// spec.controllerName through the shared census. ok=false means the
// class set is unavailable OR the class is unknown — callers treat
// that as "cannot disprove ownership" and keep the object.
func (p *operatorWorkqueueCheck) gatewayClassController(ctx context.Context, class string) (string, bool) {
	m, ok := p.gatewayClassCensus(ctx)
	if !ok {
		return "", false
	}
	ctlr, ok := m[class]
	return ctlr, ok
}

// ciliumOwnsGatewayObject is the ownership filter for the Gateways
// resource: only a Gateway whose class is served by cilium's gateway
// controller belongs in cilium-operator's stuck set. Unresolvable
// class data keeps the object — a Gateway whose class cannot be
// attributed is still worth flagging under the cluster's gateway-API
// watcher.
func ciliumOwnsGatewayObject(ctx context.Context, p *operatorWorkqueueCheck,
	o *unstructured.Unstructured) bool {
	class, _ := kube.NestedString(o.Object, "spec", "gatewayClassName")
	if class == "" {
		return true // malformed — cannot disprove ownership
	}
	m, listed := p.gatewayClassCensus(ctx)
	if !listed {
		return true // API flap — cannot disprove ownership
	}
	ctlr, known := m[class]
	if !known {
		// The class census succeeded and the class is absent — the
		// Gateway is orphaned (its GatewayClass was deleted or never
		// created), so NO gateway controller will ever own it. Keeping
		// it in cilium-operator's stuck set gets the leader pod
		// bounced on every cooldown for an object nobody can fix —
		// the same false-positive bug #11 fixed for orphan routes.
		return false
	}
	return ctlr == ciliumGatewayController
}

// ciliumOwnsGatewayClass attributes a GatewayClass to cilium
// directly — spec.controllerName sits on the object itself, so no
// lookup is needed. An absent controllerName keeps the object (a
// malformed class cannot disprove ownership, same rule as the other
// gateway-API filters); a PROVEN foreign controller drops it.
func ciliumOwnsGatewayClass(_ context.Context, _ *operatorWorkqueueCheck,
	o *unstructured.Unstructured) bool {
	ctlr, _ := kube.NestedString(o.Object, "spec", "controllerName")
	return ctlr == "" || ctlr == ciliumGatewayController
}

// lookupGateway resolves one Gateway by namespace/name through the
// sweep-wide snapshot (Deps.AllUnstructured) — client-side pick from
// the memoized cluster-wide LIST instead of a per-parent GET. ok=false
// when the Gateway doesn't resolve (absent or a memoized read error).
func lookupGateway(ctx context.Context, p *operatorWorkqueueCheck,
	ns, name string) (*unstructured.Unstructured, bool) {
	gws, err := p.AllUnstructured(ctx, kube.GVRGateway)
	if err != nil {
		return nil, false
	}
	for i := range gws {
		if gws[i].GetNamespace() == ns && gws[i].GetName() == name {
			return &gws[i], true
		}
	}
	return nil, false
}

// ciliumOwnsRouteParent is the same filter for the route kinds: it
// resolves each spec.parentRefs[] entry to its Gateway and reports
// whether any parent's class is cilium's. Objects with no Gateway
// parents, or parents that fail to resolve, stay in the stuck set —
// an unattributable route is still a gateway-API-plane problem —
// while a route provably owned by another gateway controller is
// that controller's problem, not cilium-operator's.
func ciliumOwnsRouteParent(ctx context.Context, p *operatorWorkqueueCheck,
	o *unstructured.Unstructured) bool {
	refs, found := kube.NestedSlice(o.Object, "spec", "parentRefs")
	if !found || len(refs) == 0 {
		return true
	}
	resolved := false
	sawGatewayRef := false
	gatewayFound := false
	for _, ref := range refs {
		m, ok := ref.(map[string]any)
		if !ok {
			continue
		}
		if k, _ := kube.NestedString(m, "kind"); k != "" && k != "Gateway" {
			continue
		}
		if g, _ := kube.NestedString(m, "group"); g != "" && g != "gateway.networking.k8s.io" {
			continue
		}
		name, _ := kube.NestedString(m, "name")
		if name == "" {
			continue
		}
		ns, _ := kube.NestedString(m, "namespace")
		if ns == "" {
			ns = o.GetNamespace()
		}
		sawGatewayRef = true
		gw, ok := lookupGateway(ctx, p, ns, name)
		if !ok {
			continue
		}
		gatewayFound = true
		class, _ := kube.NestedString(gw.Object, "spec", "gatewayClassName")
		ctlr, ok := p.gatewayClassController(ctx, class)
		if !ok {
			continue
		}
		resolved = true
		if ctlr == ciliumGatewayController {
			return true
		}
	}
	// A route whose every Gateway parent fails to resolve is an
	// orphan — the Gateway was deleted or never created, so NO
	// gateway controller will ever write status.parents. Keeping it
	// in every operator's stuck set gets each leader pod killed on
	// every cooldown for a route nobody owns.
	if sawGatewayRef && !gatewayFound {
		return false
	}
	return !resolved
}

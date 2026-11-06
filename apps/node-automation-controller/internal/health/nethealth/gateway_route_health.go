// gateway_route_health.go — the gateway-route-health check: audits
// every HTTPRoute and GRPCRoute (gateway.networking.k8s.io) for
// attachment and backend-health failures — a parent Accepted=False
// or ResolvedRefs=False condition, a cross-namespace backendRef the
// ReferenceGrants do not permit (W12-NM4b — resolved_refs_false's
// RefNotPermitted reason plus the static grant cross-check for
// controllers that never write status), a backendRef pointing at a
// missing Service or a port the Service does not carry, and a
// backendRef whose live Service has zero Ready endpoints. Each
// signature must persist >= 10m before it reports — a gateway
// controller reconciling an attachment or a Service mid-rollout
// flaps through these states routinely, so only a stuck condition
// is a page. The dedicated zero-endpoints gauge fires at 5m — the
// earlier, less noisy edge of the same blackhole signal.
package nethealth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// gatewayRouteHealthCheck is the route-attachment/backend watchdog.
type gatewayRouteHealthCheck struct {
	*probefw.Deps

	// since: "kind/ns/name/reason" → first sweep the signature held;
	// pruned when the route heals so a later flap re-arms the window.
	// emitted: gauge tuples held at 1 — a tuple not re-seen gets
	// DeleteLabelValues, not a stale 1.
	since   state.FirstSeenLedger
	emitted state.GaugeLedger[string]
	// zeroSince/zeroEmitted are the dedicated zero-endpoints gauge's
	// own ledgers (5m window, separate vec — one GaugeLedger per
	// vec). zeroLast keeps last sweep's live zero candidates for the
	// endpoint-census carry-forward ("can't tell" is not "resolved").
	zeroSince   state.FirstSeenLedger
	zeroEmitted state.GaugeLedger[string]
	zeroLast    map[string][]string
}

// NewGatewayRouteHealthCheck builds the check — both ledgers are
// zero-value ready, so the constructor carries no initialization.
func NewGatewayRouteHealthCheck(d *probefw.Deps) probefw.Check {
	return &gatewayRouteHealthCheck{Deps: d}
}

const (
	CheckNameGatewayRouteHealth = "gateway-route-health"

	// gatewayRouteUnhealthyMinAge is the persistence window every
	// signature must survive — attachment/endpoint churn settles in
	// seconds on a healthy gateway controller; ten minutes means
	// "stuck", not "reconciling".
	gatewayRouteUnhealthyMinAge = 10 * time.Minute
	// gatewayRouteZeroEndpointsMinAge is the earlier window for the
	// dedicated node_automation_gateway_route_zero_endpoints gauge —
	// a routed Service that reads zero Ready endpoints for five
	// minutes is already a blackhole worth alerting on.
	gatewayRouteZeroEndpointsMinAge = 5 * time.Minute
)

// The reason values node_automation_gateway_route_unhealthy carries —
// one per failure class the check flags.
const (
	routeReasonAcceptedFalse     = "accepted_false"
	routeReasonResolvedRefsFalse = "resolved_refs_false"
	routeReasonRefNotPermitted   = "ref_not_permitted"
	routeReasonBackendUnresolved = "backend_unresolved"
	routeReasonZeroEndpoints     = "backend_zero_endpoints"
)

// referenceGrantGVRs are the served ReferenceGrant versions — v1beta1
// on the current gateway-api channel, v1alpha2 on older installs —
// probed in order like the ExternalSecret version ladder (declared
// local to the check, the endpointsGVR precedent: a CRD the kube
// GVR registry does not cover).
var referenceGrantGVRs = []schema.GroupVersionResource{
	{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "referencegrants"},
	{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "referencegrants"},
}

var (
	// One series per (route kind, route, failure reason) persisting
	// past the window — a resolved signature deletes its tuple.
	gatewayRouteUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_gateway_route_unhealthy",
		Help: "1 while the HTTPRoute/GRPCRoute carries an unhealthy signature (accepted_false, resolved_refs_false, backend_unresolved, backend_zero_endpoints) past the persistence window.",
	}, []string{"kind", "namespace", "name", "reason"})
	// W12-NM4b — one series per (route, backend Service) whose
	// backendRef has zero Ready endpoints past the earlier 5m
	// window: the Envoy/cloudflared blackhole signal without the
	// unhealthy-reason split.
	gatewayRouteZeroEndpointsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_gateway_route_zero_endpoints",
		Help: "1 while a route backendRef Service has zero Ready endpoints past the 5m window (W12-NM4b).",
	}, []string{"kind", "namespace", "name", "service_namespace", "service"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		gatewayRouteUnhealthyGauge, gatewayRouteZeroEndpointsGauge)
}

// ---------------------------------------------------------------------------
// route decode — the unstructured shapes the check reads
// ---------------------------------------------------------------------------

// routeBackendRef is one Service-typed backendRef decoded off a
// route's spec.rules — non-Service backends are filtered out before
// this struct exists. crossNS records whether the ref names a
// different namespace than the route's (the ReferenceGrant gate —
// W12-NM4b): an unset namespace resolves to same-ns by default.
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
// when the controller names it (W12-NM4b) so alerting can tell a
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

// ---------------------------------------------------------------------------
// backend verdicts — unresolved vs zero-endpoints
// ---------------------------------------------------------------------------

// serviceBackendUnresolved reports whether a resolvable-looking
// backendRef cannot actually terminate traffic: the Service is gone,
// or the ref pins a port the Service's spec.ports does not carry.
// found=false distinguishes a hard verdict from an inconclusive
// lookup (API flap — the caller flags nothing on it).
func (p *gatewayRouteHealthCheck) serviceBackendUnresolved(ctx context.Context,
	log logr.Logger, c *gatewayRouteCensus, b routeBackendRef) (unresolved, found bool) {

	key := b.ns + "/" + b.name
	svc, ok := c.services[key]
	if !ok && !c.svcMiss[key] && !c.svcErr[key] {
		got, err := p.CS.CoreV1().Services(b.ns).
			Get(ctx, b.name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			c.svcMiss[key] = true
		case err != nil:
			c.svcErr[key] = true
			metrics.IncError(p.Name)
			log.Info("WARN: gateway route backend service get failed — verdict inconclusive",
				"service", key, "error", err)
		default:
			svc = got
			c.services[key] = svc
		}
	}
	switch {
	case c.svcMiss[key]:
		return true, true
	case c.svcErr[key]:
		return false, false
	}
	if svc == nil {
		return false, false // paranoia — cache said neither hit nor miss
	}
	if !b.hasPort {
		return false, true // no pinned port — the Service existing is resolution enough
	}
	for _, sp := range svc.Spec.Ports {
		if int64(sp.Port) == b.port {
			return false, true
		}
	}
	return true, true // pinned port not carried by the Service
}

// loadGrants lazily lists ReferenceGrants across every served
// version, merging both lists (a cluster may serve only one — each
// absent version is tolerated like the route kinds). A non-NoMatch
// list error marks the census inconclusive (grantsErr): flagging
// ref_not_permitted on a partial grant picture would false-positive
// every cross-namespace backend in the cluster.
func (p *gatewayRouteHealthCheck) loadGrants(ctx context.Context,
	log logr.Logger, c *gatewayRouteCensus) {

	if c.grantsTried {
		return
	}
	c.grantsTried = true
	for _, gvr := range referenceGrantGVRs {
		l, err := p.Dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // this version is not served on the cluster
		case err != nil:
			c.grantsErr = true
			metrics.IncError(p.Name)
			log.Info("WARN: gateway route health — referencegrant list failed, grant verdicts inconclusive",
				"resource", gvr.Resource, "error", err)
			return
		}
		for i := range l.Items {
			c.grants = append(c.grants, decodeRouteGrant(&l.Items[i]))
		}
	}
}

// backendRefGranted reports whether a cross-namespace backendRef is
// permitted by some ReferenceGrant in the backend's own namespace —
// the runtime mirror of the ResolvedRefs/RefNotPermitted status, kept
// for gateway controllers that never write parents status (and to
// catch the grant-vs-route drift a stale condition misses).
// conclusive=false means the grant census failed this sweep — the
// caller flags nothing (API flap, not a verdict).
func (p *gatewayRouteHealthCheck) backendRefGranted(ctx context.Context,
	log logr.Logger, c *gatewayRouteCensus, routeKind, routeNS string,
	b routeBackendRef) (granted, conclusive bool) {

	p.loadGrants(ctx, log, c)
	if c.grantsErr {
		return false, false
	}
	for _, g := range c.grants {
		if g.ns == b.ns && g.permits(routeKind, routeNS, b.name) {
			return true, true
		}
	}
	return false, true
}

// loadEndpointCensus builds the per-service Ready-endpoint address
// sets — paged like every cluster-wide EndpointSlice read in this
// package, nil-Ready-counts-as-ready like the endpoint-sync census.
// Only slices bound to a Service via kubernetes.io/service-name
// contribute.
func (p *gatewayRouteHealthCheck) loadEndpointCensus(ctx context.Context,
	c *gatewayRouteCensus) error {

	if c.esLoaded {
		return nil
	}
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.EndpointSlices(p.CS, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for _, s := range items {
				svc := s.Labels[discoveryv1.LabelServiceName]
				if svc == "" {
					continue
				}
				set := c.esReady[s.Namespace+"/"+svc]
				if set == nil {
					set = map[string]bool{}
					c.esReady[s.Namespace+"/"+svc] = set
				}
				for _, ep := range s.Endpoints {
					if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
						continue
					}
					for _, a := range ep.Addresses {
						set[a] = true
					}
				}
			}
			return nil
		})
	if err != nil {
		// A mid-walk failure leaves a partial census — do NOT mark it
		// loaded or later backendRefs would judge 0-endpoints against
		// incomplete data (false backend_zero_endpoints + wrongly
		// pruned persistence/series).
		return err
	}
	c.esLoaded = true
	return nil
}

// loadNamespaceWorkloads caches the ns's Deployments/StatefulSets as
// downscaler verdict inputs. A list failure is a tolerated
// sub-failure — logged, IncError'd, and the verdict falls through to
// "not provably downscaled" so the suspicious zero still reports.
func (p *gatewayRouteHealthCheck) loadNamespaceWorkloads(ctx context.Context,
	log logr.Logger, c *gatewayRouteCensus, ns string) {

	if c.wlLoaded[ns] {
		return
	}
	c.wlLoaded[ns] = true
	deps, err := p.CS.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: gateway route health — deployment list failed, downscaler verdict off",
			"namespace", ns, "error", err)
	} else {
		for i := range deps.Items {
			d := &deps.Items[i]
			c.workloads[ns] = append(c.workloads[ns], routeWorkload{
				templateLabels: d.Spec.Template.Labels,
				annotations:    d.Annotations,
				replicas:       d.Spec.Replicas})
		}
	}
	stss, err := p.CS.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: gateway route health — statefulset list failed, downscaler verdict off",
			"namespace", ns, "error", err)
	} else {
		for i := range stss.Items {
			s := &stss.Items[i]
			c.workloads[ns] = append(c.workloads[ns], routeWorkload{
				templateLabels: s.Spec.Template.Labels,
				annotations:    s.Annotations,
				replicas:       s.Spec.Replicas})
		}
	}
}

// serviceDownscaled reports whether the workload feeding svc's
// selector is a Deployment/StatefulSet the go-kube-downscaler parked
// at replicas:0 — a routed backend asleep ON PURPOSE reads as zero
// endpoints without being a failure.
func (p *gatewayRouteHealthCheck) serviceDownscaled(ctx context.Context,
	log logr.Logger, c *gatewayRouteCensus, svc *corev1.Service) bool {

	p.loadNamespaceWorkloads(ctx, log, c, svc.Namespace)
	sel := labels.SelectorFromSet(svc.Spec.Selector)
	for _, w := range c.workloads[svc.Namespace] {
		if sel.Matches(labels.Set(w.templateLabels)) &&
			kube.IsIntentionallyDownscaled(w.annotations, w.replicas) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// the sweep
// ---------------------------------------------------------------------------

// checkGatewayRouteHealth scans every HTTPRoute and GRPCRoute for the
// four unhealthy signatures. A route kind absent from the cluster
// (no CRD) is skipped — the fake-ready posture of every dyn-reading
// sibling check. Each flag lands in live keyed "kind/ns/name/reason"
// and must persist gatewayRouteUnhealthyMinAge before the gauge and
// the FAIL verdict fire.
func (p *gatewayRouteHealthCheck) Run(ctx context.Context) probefw.Result {
	if r := p.RequireDyn("gateway route health check"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()

	routeKinds := []struct {
		gvr  schema.GroupVersionResource
		kind string
	}{
		{kube.GVRHTTPRoute, "HTTPRoute"},
		{kube.GVRGRPCRoute, "GRPCRoute"},
	}
	census := newGatewayRouteCensus()
	live := map[string][]string{}    // "kind/ns/name/reason" → label tuple
	zeroNow := map[string][]string{} // "kind/ns/name/svcns/svc" → zero gauge tuple
	for _, rk := range routeKinds {
		routes, err := p.Dyn.Resource(rk.gvr).List(ctx, metav1.ListOptions{})
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // gateway-api flavor not installed on this cluster
		case err != nil:
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", rk.gvr.Resource, err)}
		}
		for i := range routes.Items {
			p.scanRoute(ctx, log, census, &routes.Items[i], rk.kind, live, zeroNow)
		}
	}

	p.since.Prune(func(k string) bool { _, ok := live[k]; return ok })
	p.zeroSince.Prune(func(k string) bool { _, ok := zeroNow[k]; return ok })
	p.zeroLast = zeroNow

	// The dedicated 5m zero-endpoints gauge — the earlier edge of the
	// backend_zero_endpoints signal (gauge only; the FAIL verdict
	// still belongs to the 10m unhealthy signature below).
	liveZero := map[string][]string{}
	for k, lv := range zeroNow {
		if !probefw.Persisted(&p.zeroSince, k, now,
			gatewayRouteZeroEndpointsMinAge, log) {
			continue
		}
		gatewayRouteZeroEndpointsGauge.WithLabelValues(lv...).Set(1)
		liveZero[k] = lv
	}
	p.zeroEmitted.Reconcile(liveZero, gatewayRouteZeroEndpointsGauge.DeleteLabelValues)

	var rep probefw.SweepReport
	for k, lv := range live {
		if !probefw.Persisted(&p.since, k, now,
			gatewayRouteUnhealthyMinAge, log) {
			continue
		}
		rep.Emit(gatewayRouteUnhealthyGauge, k, lv, k)
	}
	return rep.Result(&p.emitted, gatewayRouteUnhealthyGauge.DeleteLabelValues,
		fmt.Sprintf("gateway routes unhealthy >=%s: ",
			gatewayRouteUnhealthyMinAge), ", ")
}

// scanRoute evaluates one route and adds every live signature to
// live — parent-condition reasons first, then the per-backendRef
// verdicts (a route can carry several reasons at once).
func (p *gatewayRouteHealthCheck) scanRoute(ctx context.Context,
	log logr.Logger, census *gatewayRouteCensus,
	route *unstructured.Unstructured, kind string,
	live, zeroNow map[string][]string) {

	ns, name := route.GetNamespace(), route.GetName()
	flag := func(reason string) {
		live[kind+"/"+ns+"/"+name+"/"+reason] =
			[]string{kind, ns, name, reason}
	}
	for reason := range routeParentConditionReasons(route) {
		flag(reason)
	}
	for _, b := range routeBackendRefs(route) {
		// W12-NM4b ReferenceGrant gate: a cross-namespace ref without
		// a permitting grant is RefNotPermitted — the gateway
		// controller silently drops it, so the route blackholes even
		// while ResolvedRefs still reads True (status lag, or a
		// controller that never writes status).
		if b.crossNS {
			granted, conclusive := p.backendRefGranted(ctx, log, census, kind, ns, b)
			if !conclusive {
				// Carry-forward: same "can't tell" posture as the
				// endpoint-census failure below — keep last sweep's
				// ref_not_permitted verdict for THIS route live.
				key := kind + "/" + ns + "/" + name + "/" + routeReasonRefNotPermitted
				if lv, ok := p.emitted.Last()[key]; ok {
					live[key] = lv
				}
				continue
			}
			if !granted {
				flag(routeReasonRefNotPermitted)
				continue // an unpermitted ref resolves to nothing — skip the svc checks
			}
		}
		unresolved, found := p.serviceBackendUnresolved(ctx, log, census, b)
		if !found {
			continue // inconclusive lookup — flag nothing on an API flap
		}
		if unresolved {
			flag(routeReasonBackendUnresolved)
			continue
		}
		svc := census.services[b.ns+"/"+b.name]
		if svc == nil || len(svc.Spec.Selector) == 0 {
			// Selectorless Services keep hand-managed endpoints —
			// zero Ready addresses there is user intent, not a
			// failure this check can score.
			continue
		}
		if err := p.loadEndpointCensus(ctx, census); err != nil {
			metrics.IncError(p.Name)
			log.Info("WARN: gateway route health — endpointslice list failed, zero-endpoint verdict skipped",
				"error", err)
			// Carry-forward: the census is unverifiable this sweep
			// ("can't tell", not "clean") — keep last sweep's
			// zero-endpoints verdict for THIS route live so a
			// transient list failure doesn't flap the alert off.
			key := kind + "/" + ns + "/" + name + "/" + routeReasonZeroEndpoints
			if lv, ok := p.emitted.Last()[key]; ok {
				live[key] = lv
			}
			// Same carry-forward for the dedicated 5m gauge's live
			// candidates so its first-seen window keeps counting.
			prefix := kind + "/" + ns + "/" + name + "/"
			for zk, zv := range p.zeroLast {
				if strings.HasPrefix(zk, prefix) {
					zeroNow[zk] = zv
				}
			}
			continue
		}
		if len(census.esReady[b.ns+"/"+b.name]) > 0 {
			continue // backend has Ready endpoints
		}
		if p.serviceDownscaled(ctx, log, census, svc) {
			continue // backend asleep on purpose — downscaler owns the zero
		}
		flag(routeReasonZeroEndpoints)
		zeroNow[kind+"/"+ns+"/"+name+"/"+b.ns+"/"+b.name] =
			[]string{kind, ns, name, b.ns, b.name}
	}
}

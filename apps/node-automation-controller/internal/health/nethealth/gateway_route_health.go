// gateway_route_health.go — the gateway-route-health check: audits
// every HTTPRoute and GRPCRoute (gateway.networking.k8s.io) for
// attachment and backend-health failures — a parent Accepted=False
// or ResolvedRefs=False condition, a backendRef pointing at a
// missing Service or a port the Service does not carry, and a
// backendRef whose live Service has zero Ready endpoints. Each
// signature must persist >= 10m before it reports — a gateway
// controller reconciling an attachment or a Service mid-rollout
// flaps through these states routinely, so only a stuck condition
// is a page.
package nethealth

import (
	"context"
	"fmt"
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
)

// The reason values node_automation_gateway_route_unhealthy carries —
// one per failure class the check flags.
const (
	routeReasonAcceptedFalse     = "accepted_false"
	routeReasonResolvedRefsFalse = "resolved_refs_false"
	routeReasonBackendUnresolved = "backend_unresolved"
	routeReasonZeroEndpoints     = "backend_zero_endpoints"
)

var (
	// One series per (route kind, route, failure reason) persisting
	// past the window — a resolved signature deletes its tuple.
	gatewayRouteUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_gateway_route_unhealthy",
		Help: "1 while the HTTPRoute/GRPCRoute carries an unhealthy signature (accepted_false, resolved_refs_false, backend_unresolved, backend_zero_endpoints) past the persistence window.",
	}, []string{"kind", "namespace", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		gatewayRouteUnhealthyGauge)
}

// ---------------------------------------------------------------------------
// route decode — the unstructured shapes the check reads
// ---------------------------------------------------------------------------

// routeBackendRef is one Service-typed backendRef decoded off a
// route's spec.rules — non-Service backends are filtered out before
// this struct exists.
type routeBackendRef struct {
	ns, name string
	port     int64
	hasPort  bool
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
			if ns == "" {
				ns = route.GetNamespace()
			}
			port, hasPort := kube.NestedNumber(bm, "port")
			out = append(out, routeBackendRef{
				ns: ns, name: name, port: port, hasPort: hasPort})
		}
	}
	return out
}

// routeParentConditionReasons reduces a route's status.parents
// conditions to the failure reasons they prove: any parent reporting
// Accepted=False or ResolvedRefs=False flags the matching reason —
// one stuck attachment is enough to blackhole that parent.
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
	live := map[string][]string{} // "kind/ns/name/reason" → label tuple
	for _, rk := range routeKinds {
		routes, err := p.Dyn.Resource(rk.gvr).List(ctx, metav1.ListOptions{})
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // gateway-api flavor not installed on this cluster
		case err != nil:
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", rk.gvr.Resource, err)}
		}
		for i := range routes.Items {
			p.scanRoute(ctx, log, census, &routes.Items[i], rk.kind, live)
		}
	}

	p.since.Prune(func(k string) bool { _, ok := live[k]; return ok })
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
	live map[string][]string) {

	ns, name := route.GetNamespace(), route.GetName()
	flag := func(reason string) {
		live[kind+"/"+ns+"/"+name+"/"+reason] =
			[]string{kind, ns, name, reason}
	}
	for reason := range routeParentConditionReasons(route) {
		flag(reason)
	}
	for _, b := range routeBackendRefs(route) {
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
			continue
		}
		if len(census.esReady[b.ns+"/"+b.name]) > 0 {
			continue // backend has Ready endpoints
		}
		if p.serviceDownscaled(ctx, log, census, svc) {
			continue // backend asleep on purpose — downscaler owns the zero
		}
		flag(routeReasonZeroEndpoints)
	}
}

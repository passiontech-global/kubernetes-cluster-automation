// gateway_route_health.go — the gateway-route-health check: audits
// every HTTPRoute and GRPCRoute (gateway.networking.k8s.io) for
// attachment and backend-health failures — a parent Accepted=False
// or ResolvedRefs=False condition, a cross-namespace backendRef the
// ReferenceGrants do not permit (negative-cache-guard — resolved_refs_false's
// RefNotPermitted reason plus the static grant cross-check for
// controllers that never write status), a backendRef pointing at a
// missing Service or a port the Service does not carry, and a
// backendRef whose live Service has zero Ready endpoints. Each
// signature must persist >= 10m before it reports — a gateway
// controller reconciling an attachment or a Service mid-rollout
// flaps through these states routinely, so only a stuck condition
// is a page. The dedicated zero-endpoints gauge fires at 5m — the
// earlier, less noisy edge of the same blackhole signal. When the
// blackhole is VIP-wide (every backend of an L2-announced Service
// dark at once), cilium-l2-lease-guard (cilium-l2-lease-guard) watches the other
// end: a stale cilium-l2announce Lease holder announcing the VIP
// from a node that cannot answer ARP.
package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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
	// liveLast is last sweep's full live-signature map
	// ("kind/ns/name/reason" → label tuple) — the carry source for
	// inconclusive verdicts. emitted.Last() only covers tuples past
	// the 10m window; liveLast also holds the inside-window keys
	// whose first-seen stamps must survive a transient read failure.
	liveLast map[string][]string
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

var (
	// One series per (route kind, route, failure reason) persisting
	// past the window — a resolved signature deletes its tuple.
	gatewayRouteUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_gateway_route_unhealthy",
		Help: "1 while the HTTPRoute/GRPCRoute carries an unhealthy signature (accepted_false, resolved_refs_false, backend_unresolved, backend_zero_endpoints) past the persistence window.",
	}, []string{"kind", "namespace", "name", "reason"})
	// negative-cache-guard — one series per (route, backend Service) whose
	// backendRef has zero Ready endpoints past the earlier 5m
	// window: the Envoy/cloudflared blackhole signal without the
	// unhealthy-reason split.
	gatewayRouteZeroEndpointsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_gateway_route_zero_endpoints",
		Help: "1 while a route backendRef Service has zero Ready endpoints past the 5m window (negative-cache-guard).",
	}, []string{"kind", "namespace", "name", "service_namespace", "service"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		gatewayRouteUnhealthyGauge, gatewayRouteZeroEndpointsGauge)
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
		// The per-sweep unstructured snapshot memoizes one LIST per
		// GVR; the raw error keeps the NoMatch/NotFound = "gateway-api
		// flavor not installed" interpretation.
		routes, err := p.AllUnstructured(ctx, rk.gvr)
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // gateway-api flavor not installed on this cluster
		case err != nil:
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", rk.gvr.Resource, err)}
		}
		for i := range routes {
			p.scanRoute(ctx, log, census, &routes[i], rk.kind, live, zeroNow)
		}
	}
	p.liveLast = live

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
		// negative-cache-guard ReferenceGrant gate: a cross-namespace ref without
		// a permitting grant is RefNotPermitted — the gateway
		// controller silently drops it, so the route blackholes even
		// while ResolvedRefs still reads True (status lag, or a
		// controller that never writes status).
		if b.crossNS {
			granted, conclusive := p.backendRefGranted(ctx, log, census, kind, ns, b)
			if !conclusive {
				// Carry-forward: the grant census failed, so EVERY
				// backend verdict behind it is unverifiable this
				// sweep — keep last sweep's tuples live ("can't
				// tell" is not "resolved") or one API flap would
				// prune live series and reset their windows.
				p.carryRouteSignature(kind, ns, name, routeReasonRefNotPermitted, live, zeroNow)
				p.carryRouteSignature(kind, ns, name, routeReasonBackendUnresolved, live, zeroNow)
				p.carryRouteSignature(kind, ns, name, routeReasonZeroEndpoints, live, zeroNow)
				continue
			}
			if !granted {
				flag(routeReasonRefNotPermitted)
				continue // an unpermitted ref resolves to nothing — skip the svc checks
			}
		}
		unresolved, found := p.serviceBackendUnresolved(ctx, log, census, b)
		if !found {
			// AllServices census failed — the backend resolution AND
			// the zero-endpoints verdict behind it are unverifiable:
			// carry last sweep's tuples instead of reading the flap
			// as resolved (flag nothing fresh either way).
			p.carryRouteSignature(kind, ns, name, routeReasonBackendUnresolved, live, zeroNow)
			p.carryRouteSignature(kind, ns, name, routeReasonZeroEndpoints, live, zeroNow)
			continue
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
			// The census load counts ONE run_error per sweep (its
			// first LIST failure); this per-ref branch only logs and
			// carries the verdict forward.
			log.Info("WARN: gateway route health — endpointslice list failed, zero-endpoint verdict skipped",
				"error", err)
			// Carry-forward: the census is unverifiable this sweep
			// ("can't tell", not "clean") — keep last sweep's
			// zero-endpoints verdict for THIS route live so a
			// transient list failure doesn't flap the alert off.
			p.carryRouteSignature(kind, ns, name, routeReasonZeroEndpoints, live, zeroNow)
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

// carryRouteSignature re-asserts last sweep's live tuple for one
// (route, reason) into this sweep's live/zeroNow sets — "can't tell"
// is not "resolved": an inconclusive verdict must not prune the
// series or reset the first-seen window. liveLast covers the
// inside-window keys emitted.Last() never saw; for
// backend_zero_endpoints the dedicated 5m gauge's candidates carry
// through zeroLast the same way.
func (p *gatewayRouteHealthCheck) carryRouteSignature(kind, ns, name,
	reason string, live, zeroNow map[string][]string) {

	key := kind + "/" + ns + "/" + name + "/" + reason
	if lv, ok := p.liveLast[key]; ok {
		live[key] = lv
	}
	if reason != routeReasonZeroEndpoints {
		return
	}
	prefix := kind + "/" + ns + "/" + name + "/"
	for zk, zv := range p.zeroLast {
		if strings.HasPrefix(zk, prefix) {
			zeroNow[zk] = zv
		}
	}
}

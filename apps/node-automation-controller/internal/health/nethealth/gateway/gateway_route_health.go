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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
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
	liveLast      map[string][]string
	immediateLast map[string]bool
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

	// gwControllerHealCooldown / gwControllerPodMinAge bound the
	// hung Gateway controller pod eviction.
	gwControllerHealCooldown = time.Hour
	gwControllerPodMinAge    = 10 * time.Minute
)

// The reason values node_automation_gateway_route_unhealthy carries —
// one per failure class the check flags.
const (
	routeReasonAcceptedFalse     = "accepted_false"
	routeReasonResolvedRefsFalse = "resolved_refs_false"
	routeReasonRefNotPermitted   = "ref_not_permitted"
	routeReasonBackendUnresolved = "backend_unresolved"
	routeReasonZeroEndpoints     = "backend_zero_endpoints"
	gwReasonProgrammedFalse      = "programmed_false"
	gwReasonClassMissing         = "gateway_class_missing"
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

	census := newGatewayRouteCensus()
	live := map[string][]string{}    // "kind/ns/name/reason" → label tuple
	immediate := map[string]bool{}   // keys whose age is already >= 10m from condition/creation timestamp
	zeroNow := map[string][]string{} // "kind/ns/name/svcns/svc" → zero gauge tuple
	unhealthyGatewayRefs := map[string]bool{}
	routeCensusFailed := false
	var rep probefw.SweepReport

	carryKind := func(kind string) {
		prefix := kind + "/"
		for k, lv := range p.liveLast {
			if strings.HasPrefix(k, prefix) {
				live[k] = lv
				if p.immediateLast[k] {
					immediate[k] = true
				}
			}
		}
		if kind == "HTTPRoute" || kind == "GRPCRoute" || kind == "TLSRoute" {
			for zk, zv := range p.zeroLast {
				if strings.HasPrefix(zk, prefix) {
					zeroNow[zk] = zv
				}
			}
		}
	}

	// 1. Audit GatewayClass (validates class Accepted=False and builds
	// class -> controllerName index for Gateway audits).
	gcKnown := false
	gcInconclusive := false
	gcControllers := map[string]string{}
	gcAcceptedFalse := map[string]bool{}
	gcs, gcErr := p.AllUnstructured(ctx, kube.GVRGatewayClass)
	switch {
	case kube.IsCRDAbsent(gcErr) || apierrors.IsForbidden(gcErr):
		// GatewayClass CRD absent or RBAC-restricted; skip gracefully.
	case gcErr != nil:
		gcInconclusive = true
		rep.InfraErr(fmt.Errorf("list gatewayclasses: %w", gcErr))
		carryKind("GatewayClass")
	default:
		gcKnown = true
		for i := range gcs {
			gc := &gcs[i]
			gcName := gc.GetName()
			ctrlName, _ := kube.NestedString(gc.Object, "spec", "controllerName")
			gcControllers[gcName] = ctrlName
			for _, c := range kube.Conditions(gc.Object, "status", "conditions") {
				if c.Type == "Accepted" && c.Status == "False" {
					gcAcceptedFalse[gcName] = true
					k := "GatewayClass//" + gcName + "/" + routeReasonAcceptedFalse
					live[k] = []string{"GatewayClass", "", gcName, routeReasonAcceptedFalse}
					if !c.LastTransitionTime.IsZero() && now.Sub(c.LastTransitionTime) >= gatewayRouteUnhealthyMinAge {
						immediate[k] = true
					}
				}
			}
		}
	}

	// 2. Audit HTTPRoute, GRPCRoute, and TLSRoute.
	routeKinds := []struct {
		gvr  schema.GroupVersionResource
		kind string
	}{
		{kube.GVRHTTPRoute, "HTTPRoute"},
		{kube.GVRGRPCRoute, "GRPCRoute"},
	}
	for _, rk := range routeKinds {
		routes, err := p.AllUnstructured(ctx, rk.gvr)
		switch {
		case kube.IsCRDAbsent(err) || apierrors.IsForbidden(err):
			continue
		case err != nil:
			routeCensusFailed = true
			rep.InfraErr(fmt.Errorf("list %s: %w", rk.gvr.Resource, err))
			carryKind(rk.kind)
			continue
		}
		for i := range routes {
			p.scanRoute(ctx, log, census, &routes[i], rk.kind, live, zeroNow, unhealthyGatewayRefs)
		}
	}

	tlsRoutes, _, tlsErr := p.AllUnstructuredFirst(ctx, kube.TLSRouteGVRs)
	switch {
	case kube.IsCRDAbsent(tlsErr) || apierrors.IsForbidden(tlsErr):
		// TLSRoute CRD absent or RBAC-restricted; skip gracefully.
	case tlsErr != nil:
		routeCensusFailed = true
		rep.InfraErr(fmt.Errorf("list tlsroutes: %w", tlsErr))
		carryKind("TLSRoute")
	default:
		for i := range tlsRoutes {
			p.scanRoute(ctx, log, census, &tlsRoutes[i], "TLSRoute", live, zeroNow, unhealthyGatewayRefs)
		}
	}

	// 3. Audit Gateways (missing/unknown GatewayClass, Accepted/Programmed/
	// ResolvedRefs conditions, cross-NS TLS Secret ReferenceGrants, and
	// hung Gateway controller pod bounce).
	var bounceCandidates []gwBounceCandidate
	gws, gwErr := p.AllUnstructured(ctx, kube.GVRGateway)
	switch {
	case kube.IsCRDAbsent(gwErr) || apierrors.IsForbidden(gwErr):
		// Gateway CRD absent or RBAC-restricted; skip gracefully.
	case gwErr != nil:
		rep.InfraErr(fmt.Errorf("list gateways: %w", gwErr))
		carryKind("Gateway")
	default:
		for i := range gws {
			cand, ok := p.scanGateway(ctx, log, census, &gws[i],
				gcKnown, gcInconclusive, gcControllers, gcAcceptedFalse,
				live, immediate, now)
			if ok {
				bounceCandidates = append(bounceCandidates, cand)
			}
		}
	}

	p.liveLast = live
	p.immediateLast = immediate

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

	persisted := make(map[string]bool, len(live))
	for k := range live {
		persisted[k] = immediate[k] || probefw.Persisted(&p.since, k, now,
			gatewayRouteUnhealthyMinAge, log)
	}

	// Bounce hung Gateway controller pod only when the cluster/backend
	// census is clean and the Gateway itself has Programmed=False >= 10m
	// with Accepted=True and no config/grant/class/route errors.
	if !routeCensusFailed && !census.svcErr && !census.esErr && !census.grantsErr {
		for _, cand := range bounceCandidates {
			if !persisted[cand.programmedKey] {
				continue
			}
			if unhealthyGatewayRefs[cand.gwKey] {
				continue
			}
			p.maybeBounceGatewayController(ctx, log, cand, now)
		}
	}

	for k, lv := range live {
		if !persisted[k] {
			continue
		}
		rep.Emit(gatewayRouteUnhealthyGauge, k, lv, k)
	}
	return rep.Result(&p.emitted, gatewayRouteUnhealthyGauge.DeleteLabelValues,
		fmt.Sprintf("gateway routes unhealthy >=%s: ",
			gatewayRouteUnhealthyMinAge), ", ")
}

type gwBounceCandidate struct {
	gw             *unstructured.Unstructured
	gwKey          string
	className      string
	controllerName string
	programmedKey  string
}

func (p *gatewayRouteHealthCheck) scanGateway(ctx context.Context,
	log logr.Logger, census *gatewayRouteCensus,
	gw *unstructured.Unstructured,
	gcKnown, gcInconclusive bool,
	gcControllers map[string]string, gcAcceptedFalse map[string]bool,
	live map[string][]string, immediate map[string]bool,
	now time.Time) (gwBounceCandidate, bool) {

	ns, name := gw.GetNamespace(), gw.GetName()
	flagGW := func(reason string, persistedNow bool) {
		k := "Gateway/" + ns + "/" + name + "/" + reason
		live[k] = []string{"Gateway", ns, name, reason}
		if persistedNow {
			immediate[k] = true
		}
	}

	className, _ := kube.NestedString(gw.Object, "spec", "gatewayClassName")
	classInvalid := false
	if gcKnown {
		if _, exists := gcControllers[className]; className == "" || !exists {
			classInvalid = true
			ct := gw.GetCreationTimestamp()
			persistedNow := !ct.IsZero() && now.Sub(ct.Time) >= gatewayRouteUnhealthyMinAge
			flagGW(gwReasonClassMissing, persistedNow)
		}
	} else if gcInconclusive {
		k := "Gateway/" + ns + "/" + name + "/" + gwReasonClassMissing
		if lv, ok := p.liveLast[k]; ok {
			live[k] = lv
			if p.immediateLast[k] {
				immediate[k] = true
			}
		}
		classInvalid = true
	}

	topConds := kube.Conditions(gw.Object, "status", "conditions")
	acceptedTrue := false
	for _, c := range topConds {
		if c.Type == "Accepted" && c.Status == "True" {
			acceptedTrue = true
		}
	}
	allConds := make([]kube.Condition, 0, len(topConds)+4)
	allConds = append(allConds, topConds...)
	allConds = append(allConds, gatewayListenerConditions(gw)...)

	acceptedFalse := false
	programmedFalse := false
	refErr := false
	for _, c := range allConds {
		persistedNow := !c.LastTransitionTime.IsZero() && now.Sub(c.LastTransitionTime) >= gatewayRouteUnhealthyMinAge
		switch {
		case c.Type == "Accepted" && c.Status == "False":
			acceptedFalse = true
			flagGW(routeReasonAcceptedFalse, persistedNow)
		case c.Type == "Programmed" && c.Status == "False":
			programmedFalse = true
			flagGW(gwReasonProgrammedFalse, persistedNow)
		case c.Type == "ResolvedRefs" && c.Reason == "RefNotPermitted":
			refErr = true
			flagGW(routeReasonRefNotPermitted, persistedNow)
		case c.Type == "ResolvedRefs" && c.Status == "False":
			refErr = true
			flagGW(routeReasonResolvedRefsFalse, persistedNow)
		}
	}

	for _, ref := range gatewayCrossNSCertSecretRefs(gw) {
		granted, conclusive := p.refGranted(ctx, log, census, "Gateway", ns, ref.ns, "", "Secret", ref.name)
		if !conclusive {
			k := "Gateway/" + ns + "/" + name + "/" + routeReasonRefNotPermitted
			if lv, ok := p.liveLast[k]; ok {
				live[k] = lv
				if p.immediateLast[k] {
					immediate[k] = true
				}
			}
			refErr = true
			continue
		}
		if !granted {
			refErr = true
			flagGW(routeReasonRefNotPermitted, false)
		}
	}

	eligible := programmedFalse &&
		acceptedTrue && !acceptedFalse &&
		gcKnown && !classInvalid && !gcAcceptedFalse[className] &&
		!refErr
	return gwBounceCandidate{
		gw:             gw,
		gwKey:          ns + "/" + name,
		className:      className,
		controllerName: gcControllers[className],
		programmedKey:  "Gateway/" + ns + "/" + name + "/" + gwReasonProgrammedFalse,
	}, eligible
}

func (p *gatewayRouteHealthCheck) maybeBounceGatewayController(ctx context.Context,
	log logr.Logger, cand gwBounceCandidate, now time.Time) {

	target := p.findGatewayControllerPod(ctx, cand.gw, cand.controllerName, cand.className, now)
	if target == nil {
		return
	}
	ck := probefw.SelfHealKey(CheckNameGatewayRouteHealth, "gw-controller/"+kube.PodControllerKey(target))
	proceed, unverifiable, evicted, refused, err := heal.EvictPodV(
		ctx, log, p.Maintenance, p.CS, p.Dyn, &p.Heals, ck, gwControllerHealCooldown, target, now)
	if !proceed {
		if unverifiable {
			metrics.IncError(p.Name)
		}
		return
	}
	if refused {
		log.Info("DEFER: hung gateway controller pod eviction refused",
			"gateway", cand.gwKey, "pod", target.Namespace+"/"+target.Name)
		return
	}
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "hung gateway controller pod eviction failed",
			"gateway", cand.gwKey, "pod", target.Namespace+"/"+target.Name)
		return
	}
	if evicted {
		metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameGatewayRouteHealth).Inc()
		log.Info("EVICT: hung gateway controller pod — forcing reconcile",
			"gateway", cand.gwKey, "pod", target.Namespace+"/"+target.Name)
	}
}

func (p *gatewayRouteHealthCheck) findGatewayControllerPod(ctx context.Context,
	gw *unstructured.Unstructured, controllerName, className string, now time.Time) *corev1.Pod {

	pods, err := p.AllPods(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		return nil
	}
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		return nil
	}
	nodesByName := make(map[string]*corev1.Node, len(nodes))
	for i := range nodes {
		nodesByName[nodes[i].Name] = &nodes[i]
	}

	eligible := func(pod *corev1.Pod) bool {
		if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
			return false
		}
		if metav1.GetControllerOf(pod) == nil {
			return false
		}
		if pod.CreationTimestamp.IsZero() || now.Sub(pod.CreationTimestamp.Time) < gwControllerPodMinAge {
			return false
		}
		if pod.Spec.NodeName == "" {
			return false
		}
		n := nodesByName[pod.Spec.NodeName]
		return n != nil && kube.NodeReady(n)
	}

	pickOldest := func(match func(*corev1.Pod) bool) *corev1.Pod {
		var oldest *corev1.Pod
		for i := range pods {
			pod := &pods[i]
			if !match(pod) || !eligible(pod) {
				continue
			}
			if oldest == nil || pod.CreationTimestamp.Before(&oldest.CreationTimestamp) ||
				(pod.CreationTimestamp.Equal(&oldest.CreationTimestamp) &&
					pod.Namespace+"/"+pod.Name < oldest.Namespace+"/"+oldest.Name) {
				oldest = pod
			}
		}
		return oldest
	}

	// 1. Per-Gateway pod label in the Gateway's namespace.
	gwNS, gwName := gw.GetNamespace(), gw.GetName()
	if pod := pickOldest(func(pod *corev1.Pod) bool {
		return pod.Namespace == gwNS && pod.Labels["gateway.networking.k8s.io/gateway-name"] == gwName
	}); pod != nil {
		return pod
	}

	// 2. Fallback to known controller Deployment/Pod selectors.
	switch {
	case controllerName == "io.cilium/gateway-controller":
		return pickOldest(func(pod *corev1.Pod) bool {
			return pod.Namespace == "kube-system" && pod.Labels["io.cilium/app"] == "operator"
		})
	case className == "cloudflare-tunnel" || strings.Contains(controllerName, "cloudflare"):
		return pickOldest(func(pod *corev1.Pod) bool {
			return pod.Namespace == "cloudflare-tunnel-system" &&
				pod.Labels["app.kubernetes.io/name"] == "cloudflare-tunnel-gateway-controller"
		})
	case controllerName == "gateway.envoyproxy.io/gatewayclass-controller":
		return pickOldest(func(pod *corev1.Pod) bool {
			return pod.Namespace == "envoy-gateway-system" &&
				(pod.Labels["control-plane"] == "envoy-gateway" ||
					pod.Labels["app.kubernetes.io/name"] == "envoy-gateway")
		})
	case controllerName == "gateway.nginx.org/nginx-gateway-controller":
		return pickOldest(func(pod *corev1.Pod) bool {
			return pod.Namespace == "nginx-gateway" &&
				pod.Labels["app.kubernetes.io/name"] == "nginx-gateway-fabric"
		})
	case controllerName == "istio.io/gateway-controller":
		return pickOldest(func(pod *corev1.Pod) bool {
			return pod.Namespace == "istio-system" && pod.Labels["app"] == "istiod"
		})
	default:
		return nil
	}
}

// scanRoute evaluates one route and adds every live signature to
// live — parent-condition reasons first, then the per-backendRef
// verdicts (a route can carry several reasons at once).
func (p *gatewayRouteHealthCheck) scanRoute(ctx context.Context,
	log logr.Logger, census *gatewayRouteCensus,
	route *unstructured.Unstructured, kind string,
	live, zeroNow map[string][]string,
	unhealthyGatewayRefs map[string]bool) {

	ns, name := route.GetNamespace(), route.GetName()
	routeBad := false
	flag := func(reason string) {
		routeBad = true
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
				routeBad = true
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
			routeBad = true
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
			routeBad = true
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
	if routeBad && unhealthyGatewayRefs != nil {
		for _, gwKey := range routeParentGatewayRefs(route) {
			unhealthyGatewayRefs[gwKey] = true
		}
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

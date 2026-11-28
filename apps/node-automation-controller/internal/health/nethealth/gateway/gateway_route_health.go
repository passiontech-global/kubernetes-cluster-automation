// gateway_route_health.go — the gateway-route-health check: audits
// every HTTPRoute, GRPCRoute, and TLSRoute (gateway.networking.k8s.io)
// plus Gateway and GatewayClass objects for attachment, ReferenceGrant,
// and backend-health failures.
//
// File layout: this file owns the check struct, constants, gauges, and Run
// sweep pipeline; gateway_route_health_eval.go holds Gateway/route scanning
// and hung controller pod eviction; gateway_route_health_verdicts.go holds
// backend/ReferenceGrant/downscaler verdicts; gateway_route_health_decode.go
// holds Gateway API unstructured decoders.
package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

type gatewayRouteHealthCheck struct {
	*probefw.Deps

	since         state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	zeroSince     state.FirstSeenLedger
	zeroEmitted   state.GaugeLedger[string]
	zeroLast      map[string][]string
	liveLast      map[string][]string
	immediateLast map[string]bool
}

// NewGatewayRouteHealthCheck builds the gateway-route-health check.
func NewGatewayRouteHealthCheck(d *probefw.Deps) probefw.Check {
	return &gatewayRouteHealthCheck{Deps: d}
}

const (
	CheckNameGatewayRouteHealth = "gateway-route-health"

	gatewayRouteUnhealthyMinAge     = 10 * time.Minute
	gatewayRouteZeroEndpointsMinAge = 5 * time.Minute

	gwControllerHealCooldown = time.Hour
	gwControllerPodMinAge    = 10 * time.Minute
)

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
	gatewayRouteUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_gateway_route_unhealthy",
		Help: "1 while the HTTPRoute/GRPCRoute carries an unhealthy signature (accepted_false, resolved_refs_false, backend_unresolved, backend_zero_endpoints) past the persistence window.",
	}, []string{"kind", "namespace", "name", "reason"})
	gatewayRouteZeroEndpointsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_gateway_route_zero_endpoints",
		Help: "1 while a route backendRef Service has zero Ready endpoints past the 5m window (negative-cache-guard).",
	}, []string{"kind", "namespace", "name", "service_namespace", "service"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		gatewayRouteUnhealthyGauge, gatewayRouteZeroEndpointsGauge)
}

func (p *gatewayRouteHealthCheck) Run(ctx context.Context) probefw.Result {
	if r := p.RequireDyn("gateway route health check"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()

	census := newGatewayRouteCensus()
	live := map[string][]string{}
	immediate := map[string]bool{}
	zeroNow := map[string][]string{}
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

	gcKnown := false
	gcInconclusive := false
	gcControllers := map[string]string{}
	gcAcceptedFalse := map[string]bool{}
	gcs, gcErr := p.AllUnstructured(ctx, kube.GVRGatewayClass)
	switch {
	case kube.IsCRDAbsent(gcErr) || apierrors.IsForbidden(gcErr):
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
	case tlsErr != nil:
		routeCensusFailed = true
		rep.InfraErr(fmt.Errorf("list tlsroutes: %w", tlsErr))
		carryKind("TLSRoute")
	default:
		for i := range tlsRoutes {
			p.scanRoute(ctx, log, census, &tlsRoutes[i], "TLSRoute", live, zeroNow, unhealthyGatewayRefs)
		}
	}

	var bounceCandidates []gwBounceCandidate
	gws, gwErr := p.AllUnstructured(ctx, kube.GVRGateway)
	switch {
	case kube.IsCRDAbsent(gwErr) || apierrors.IsForbidden(gwErr):
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

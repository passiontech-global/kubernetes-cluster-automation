// gateway_route_health_eval.go — Gateway, HTTPRoute/GRPCRoute/TLSRoute
// condition & backend scanning, carry-forward bookkeeping, and hung Gateway
// controller pod bounce actuation for gateway-route-health.
// Split from gateway_route_health.go.
package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

type gwBounceCandidate struct {
	gw             *unstructured.Unstructured
	gwKey          string
	className      string
	controllerName string
	programmedKey  string
}

func isNonWedgeProgrammedReason(reason string) bool {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "addressnotassigned", "addressnotusable", "noresources",
		"invalid", "invalidparameters", "listenersnotvalid",
		"unsupportedaddress":
		return true
	default:
		return false
	}
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
	nonWedgeProgrammed := false
	refErr := false
	for _, c := range allConds {
		persistedNow := !c.LastTransitionTime.IsZero() && now.Sub(c.LastTransitionTime) >= gatewayRouteUnhealthyMinAge
		switch {
		case c.Type == "Accepted" && c.Status == "False":
			acceptedFalse = true
			flagGW(routeReasonAcceptedFalse, persistedNow)
		case c.Type == "Programmed" && c.Status == "False":
			programmedFalse = true
			if isNonWedgeProgrammedReason(c.Reason) {
				nonWedgeProgrammed = true
			}
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

	eligible := programmedFalse && !nonWedgeProgrammed &&
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
	proceed, unverifiable, evicted, refused, err := p.EvictPodV(
		ctx, log, &p.Heals, ck, gwControllerHealCooldown, target, now)
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

	gwNS, gwName := gw.GetNamespace(), gw.GetName()
	if pod := pickOldest(func(pod *corev1.Pod) bool {
		return pod.Namespace == gwNS && pod.Labels["gateway.networking.k8s.io/gateway-name"] == gwName
	}); pod != nil {
		return pod
	}

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
		if b.crossNS {
			granted, conclusive := p.backendRefGranted(ctx, log, census, kind, ns, b)
			if !conclusive {
				routeBad = true
				p.carryRouteSignature(kind, ns, name, routeReasonRefNotPermitted, live, zeroNow)
				p.carryRouteSignature(kind, ns, name, routeReasonBackendUnresolved, live, zeroNow)
				p.carryRouteSignature(kind, ns, name, routeReasonZeroEndpoints, live, zeroNow)
				continue
			}
			if !granted {
				flag(routeReasonRefNotPermitted)
				continue
			}
		}
		unresolved, found := p.serviceBackendUnresolved(ctx, log, census, b)
		if !found {
			routeBad = true
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
			continue
		}
		if err := p.loadEndpointCensus(ctx, census); err != nil {
			routeBad = true
			log.Info("WARN: gateway route health — endpointslice list failed, zero-endpoint verdict skipped",
				"error", err)
			p.carryRouteSignature(kind, ns, name, routeReasonZeroEndpoints, live, zeroNow)
			continue
		}
		if len(census.esReady[b.ns+"/"+b.name]) > 0 {
			continue
		}
		if p.serviceDownscaled(ctx, log, census, svc) {
			continue
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

// gateway_route_health_verdicts.go — the backend-verdict helpers of
// the gateway-route-health check: unresolved vs zero-endpoints — the
// lazy Service lookup + pinned-port match, the ReferenceGrant census
// and permit check (W12-NM4b), the Ready-endpoint census, and the
// go-kube-downscaler "asleep on purpose" exemption.
package nethealth

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
		// The per-sweep unstructured snapshot memoizes one LIST per
		// GVR; the raw error keeps the NoMatch/NotFound = "this
		// version is not served" interpretation.
		l, err := p.AllUnstructured(ctx, gvr)
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
		for i := range l {
			c.grants = append(c.grants, decodeRouteGrant(&l[i]))
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
// sets on the shared ReadyEndpointsByService rollup — paged like
// every cluster-wide EndpointSlice read in this package,
// nil-Ready-counts-as-ready like the endpoint-sync census. Only
// slices bound to a Service via kubernetes.io/service-name
// contribute.
func (p *gatewayRouteHealthCheck) loadEndpointCensus(ctx context.Context,
	c *gatewayRouteCensus) error {

	if c.esLoaded {
		return nil
	}
	slices, err := p.AllEndpointSlices(ctx)
	if err != nil {
		return err
	}
	for key, eps := range kube.ReadyEndpointsByService(slices) {
		set := c.esReady[key]
		if set == nil {
			set = map[string]bool{}
			c.esReady[key] = set
		}
		for _, e := range eps {
			for _, a := range e.Addresses {
				set[a] = true
			}
		}
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
	// The Deployments/StatefulSets ride the per-sweep snapshot LISTs,
	// filtered client-side to ns (a failed census is the same
	// tolerated sub-failure the per-namespace lists were).
	deps, err := p.AllDeployments(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: gateway route health — deployment census failed, downscaler verdict off",
			"namespace", ns, "error", err)
	} else {
		for i := range deps {
			d := &deps[i]
			if d.Namespace != ns {
				continue
			}
			c.workloads[ns] = append(c.workloads[ns], routeWorkload{
				templateLabels: d.Spec.Template.Labels,
				annotations:    d.Annotations,
				replicas:       d.Spec.Replicas})
		}
	}
	stss, err := p.AllStatefulSets(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: gateway route health — statefulset census failed, downscaler verdict off",
			"namespace", ns, "error", err)
	} else {
		for i := range stss {
			s := &stss[i]
			if s.Namespace != ns {
				continue
			}
			c.workloads[ns] = append(c.workloads[ns], routeWorkload{
				templateLabels: s.Spec.Template.Labels,
				annotations:    s.Annotations,
				replicas:       s.Spec.Replicas})
		}
	}
	// argoproj.io Rollouts are first-class workload backends too
	// (W18-5): a Rollout the downscaler parked at zero reads the same
	// asleep-on-purpose exemption. Unstructured CR — template labels,
	// annotations and spec.replicas come off the unstructured object
	// through the per-sweep snapshot census; a failed census is the
	// same tolerated sub-failure (verdict stays "not provably
	// downscaled", fail closed).
	ros, err := p.AllUnstructured(ctx, kube.GVRArgoRollout)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: gateway route health — rollout census failed, downscaler verdict off",
			"namespace", ns, "error", err)
		return
	}
	for i := range ros {
		r := &ros[i]
		if r.GetNamespace() != ns {
			continue
		}
		tl, _, _ := unstructured.NestedStringMap(r.Object,
			"spec", "template", "metadata", "labels")
		var replicas *int32
		if reps, found, _ := unstructured.NestedInt64(r.Object, "spec", "replicas"); found {
			v := int32(reps)
			replicas = &v
		}
		c.workloads[ns] = append(c.workloads[ns], routeWorkload{
			templateLabels: tl,
			annotations:    r.GetAnnotations(),
			replicas:       replicas})
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

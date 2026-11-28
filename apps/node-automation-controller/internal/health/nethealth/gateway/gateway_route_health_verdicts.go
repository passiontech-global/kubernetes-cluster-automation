// gateway_route_health_verdicts.go — the backend-verdict helpers of
// the gateway-route-health check: unresolved vs zero-endpoints — the
// lazy Service lookup + pinned-port match, the ReferenceGrant census
// and permit check (negative-cache-guard), the Ready-endpoint census, and the
// go-kube-downscaler "asleep on purpose" exemption.
package gateway

import (
	"context"
	"errors"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

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
	if !c.svcTried {
		// The sweep-memoized Services census loads ONCE per sweep —
		// the first backend miss builds the ns/name index every later
		// ref shares, replacing the per-miss linear scan over
		// p.AllServices (and the per-ref IncError a failed list used
		// to multiply across backend refs).
		c.svcTried = true
		svcs, err := p.AllServices(ctx)
		if err != nil {
			c.svcErr = true
			metrics.IncError(p.Name)
			log.Info("WARN: gateway route backend service list failed — verdict inconclusive",
				"error", err)
		} else {
			c.services = make(map[string]*corev1.Service, len(svcs))
			for i := range svcs {
				c.services[svcs[i].Namespace+"/"+svcs[i].Name] = &svcs[i]
			}
		}
	}
	if c.svcErr {
		return false, false
	}
	svc := c.services[key]
	if svc == nil {
		return true, true // absent from a healthy census = the Service is gone
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
	loadedAny := false
	forbiddenAny := false
	for _, gvr := range kube.ReferenceGrantGVRs {
		// The per-sweep unstructured snapshot memoizes one LIST per
		// GVR; absent versions (NoMatch/NotFound) are tolerated, while
		// 403 Forbidden is tracked separately so an RBAC-restricted
		// cluster cannot silently read as "zero grants exist" and
		// false-flag every cross-namespace route as ref_not_permitted.
		l, err := p.AllUnstructured(ctx, gvr)
		switch {
		case kube.IsCRDAbsent(err):
			continue // this version is not served on the cluster
		case apierrors.IsForbidden(err):
			forbiddenAny = true
			continue
		case err != nil:
			c.grantsErr = true
			metrics.IncError(p.Name)
			log.Info("WARN: gateway route health — referencegrant list failed, grant verdicts inconclusive",
				"resource", gvr.Resource, "error", err)
			return
		}
		loadedAny = true
		for i := range l {
			c.grants = append(c.grants, decodeRouteGrant(&l[i]))
		}
	}
	if forbiddenAny && !loadedAny {
		// RBAC denied every served ReferenceGrant version — treat the
		// grant census as inconclusive (without bumping run_errors on
		// intentionally restricted clusters) rather than false-flagging
		// valid cross-namespace routes as ref_not_permitted.
		c.grantsErr = true
		log.V(1).Info("gateway route health — referencegrant list forbidden (403), grant verdicts inconclusive")
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

	return p.refGranted(ctx, log, c, routeKind, routeNS, b.ns, "", "Service", b.name)
}

// refGranted reports whether any ReferenceGrant in toNS permits a
// reference from (gateway.networking.k8s.io, fromKind, fromNS) to
// (toGroup, toKind, toName).
func (p *gatewayRouteHealthCheck) refGranted(ctx context.Context,
	log logr.Logger, c *gatewayRouteCensus, fromKind, fromNS, toNS,
	toGroup, toKind, toName string) (granted, conclusive bool) {

	p.loadGrants(ctx, log, c)
	if c.grantsErr {
		return false, false
	}
	for _, g := range c.grants {
		if g.ns == toNS && g.permitsRef("gateway.networking.k8s.io", fromKind, fromNS, toGroup, toKind, toName) {
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
//
// Like svcTried/svcErr, the census attempts ONCE per sweep: the
// first failure counts ONE run_error and leaves esErr set, and every
// later backend ref in the sweep short-circuits on esTried with the
// sentinel — one bad LIST is one incident, not one per backendRef.
func (p *gatewayRouteHealthCheck) loadEndpointCensus(ctx context.Context,
	c *gatewayRouteCensus) error {

	if c.esLoaded {
		return nil
	}
	if c.esTried {
		return errEndpointCensusInconclusive
	}
	c.esTried = true
	slices, err := p.AllEndpointSlices(ctx)
	if err != nil {
		c.esErr = true
		metrics.IncError(p.Name)
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

// errEndpointCensusInconclusive is what retry callers of
// loadEndpointCensus see after the census already failed this sweep —
// the real error was counted and logged on the first attempt.
var errEndpointCensusInconclusive = errors.New("endpointslice census failed earlier this sweep")

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
				annotations:    kube.EffectiveAnnos(ctx, d),
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
				annotations:    kube.EffectiveAnnos(ctx, s),
				replicas:       s.Spec.Replicas})
		}
	}
	// argoproj.io Rollouts are first-class workload backends too
	// (argo-rollout-gates): a Rollout the downscaler parked at zero reads the same
	// asleep-on-purpose exemption. Unstructured CR — template labels,
	// annotations and spec.replicas come off the unstructured object
	// through the per-sweep snapshot census; a failed census is the
	// same tolerated sub-failure (verdict stays "not provably
	// downscaled", fail closed).
	ros, err := p.AllUnstructured(ctx, kube.GVRArgoRollout)
	if err != nil {
		// NoMatch = the cluster has no Argo Rollouts CRD — there are
		// simply no rollout workloads to exempt, the same verdict a
		// successful empty list produces. Not an infra failure.
		// IsCRDAbsent (not meta.IsNoMatchError) also covers the
		// fake-dynamic-client "no kind registered" shape the
		// CRD-aware test client produces.
		if !kube.IsCRDAbsent(err) && !c.rolloutErrLogged {
			c.rolloutErrLogged = true
			metrics.IncError(p.Name)
			log.Info("WARN: gateway route health — rollout census failed, downscaler verdict off",
				"namespace", ns, "error", err)
		}
		return
	}
	for i := range ros {
		r := &ros[i]
		if r.GetNamespace() != ns {
			continue
		}
		tl, _ := kube.NestedStringMap(r.Object,
			"spec", "template", "metadata", "labels")
		var replicas *int32
		if reps, found := kube.NestedInt64(r.Object, "spec", "replicas"); found {
			v := int32(reps)
			replicas = &v
		}
		c.workloads[ns] = append(c.workloads[ns], routeWorkload{
			templateLabels: tl,
			annotations:    kube.EffectiveAnnos(ctx, r),
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
	// A selectorless Service (ExternalName, manually managed
	// EndpointSlices) has NO workload binding — SelectorFromSet(nil)
	// is labels.Everything(), which would match every workload in
	// the namespace and let any unrelated downscaled Deployment
	// suppress a real zero_endpoints alert. "Can't prove the
	// backend is asleep" must fail closed.
	if len(svc.Spec.Selector) == 0 {
		return false
	}
	sel := labels.SelectorFromSet(svc.Spec.Selector)
	matched := false
	for _, w := range c.workloads[svc.Namespace] {
		if !sel.Matches(labels.Set(w.templateLabels)) {
			continue
		}
		matched = true
		// A Service can be backed by several workloads (a blue/
		// green pair, two ReplicaSets with the same labels). It is
		// "asleep on purpose" only if ALL of them are parked at
		// zero — one live replica must keep the zero-endpoints
		// verdict live instead of being excused by a sibling at
		// zero. An explicit spec.replicas=0 is intent in its own
		// right (GitOps-parked backend), even without a
		// downscaler/* schedule annotation; nil replicas means the
		// apiserver default of 1 and stays a real finding.
		if w.replicas == nil || *w.replicas != 0 {
			return false
		}
	}
	return matched
}

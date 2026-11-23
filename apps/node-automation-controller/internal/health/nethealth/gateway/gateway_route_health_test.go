// gateway_route_health_test.go — coverage for the gateway-route-health
// check: the four flagged reasons, the 10m persistence window, the
// downscaler/selectorless exemptions and resolved routes staying clean.
package gateway

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// routeFixture builds a bare HTTPRoute/GRPCRoute unstructured —
// spec.rules and status.parents are layered on by the helpers below.
func routeFixture(kind, ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       kind,
		"metadata":   map[string]any{"namespace": ns, "name": name},
	}}
}

// setRouteParents stamps a single status.parents entry carrying the
// given conditions (the shape every gateway controller writes).
func setRouteParents(u *unstructured.Unstructured, conds ...map[string]any) {
	anyConds := make([]any, 0, len(conds))
	for _, c := range conds {
		anyConds = append(anyConds, c)
	}
	parents := []any{map[string]any{"conditions": anyConds}}
	if err := unstructured.SetNestedSlice(u.Object, parents, "status", "parents"); err != nil {
		panic(err)
	}
}

// routeCond is one typed status condition entry.
func routeCond(condType, status string) map[string]any {
	return map[string]any{"type": condType, "status": status}
}

// routeCondReason is one status condition entry carrying a reason —
// ResolvedRefs/RefNotPermitted is the negative-cache-guard signature.
func routeCondReason(condType, status, reason string) map[string]any {
	return map[string]any{"type": condType, "status": status, "reason": reason}
}

// referenceGrantFixture builds a ReferenceGrant in ns permitting
// `fromKind` routes from fromNS to reach kind/name targets — empty
// toName means any object of the kind.
func referenceGrantFixture(ns, name, fromKind, fromNS, toKind, toName string) *unstructured.Unstructured {
	to := map[string]any{"group": "", "kind": toKind}
	if toName != "" {
		to["name"] = toName
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1beta1",
		"kind":       "ReferenceGrant",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"from": []any{map[string]any{
				"group": "gateway.networking.k8s.io",
				"kind":  fromKind, "namespace": fromNS}},
			"to": []any{to},
		},
	}}
}

// setRouteBackends stamps one spec.rules entry carrying the given
// backendRefs (name/namespace/port/kind/group fields).
func setRouteBackends(u *unstructured.Unstructured, refs ...map[string]any) {
	anyRefs := make([]any, 0, len(refs))
	for _, b := range refs {
		anyRefs = append(anyRefs, b)
	}
	rules := []any{map[string]any{"backendRefs": anyRefs}}
	if err := unstructured.SetNestedSlice(u.Object, rules, "spec", "rules"); err != nil {
		panic(err)
	}
}

// unreadyEndpointSlice builds an EndpointSlice whose only endpoint is
// NOT Ready — the backend-zero-endpoints fixture.
func unreadyEndpointSlice(ns, svc, addr string) *discoveryv1.EndpointSlice {
	s := probetest.EndpointSliceForService(ns, svc)
	s.Endpoints = []discoveryv1.Endpoint{{
		Addresses:  []string{addr},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
	}}
	return s
}

// downscaledDeployment builds a Deployment the go-kube-downscaler
// parked at replicas:0 whose pod template the service selector
// matches — the "asleep on purpose" verdict inputs.
func downscaledDeployment(ns, name string, tplLabels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: map[string]string{"downscaler/downtime-replicas": "0"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(0)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: tplLabels},
			},
		},
	}
}

// driveRouteCheck runs the check at base, +5m (inside the window) and
// +gatewayRouteUnhealthyMinAge (past it) — the three-sweep shape the
// persistence window requires — and returns the final Result.
func driveRouteCheck(t *testing.T, p *probetest.Prober, base time.Time) probefw.Result {
	t.Helper()
	chk := probetest.MustCheck[*gatewayRouteHealthCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	r0 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(5*time.Minute))
	r1 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(gatewayRouteUnhealthyMinAge+time.Minute))
	r2 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !r0.Pass || !r1.Pass {
		t.Fatalf("signature must not flag inside the persistence window: r0=%+v r1=%+v", r0, r1)
	}
	return r2
}

// ---------------------------------------------------------------------------
// The four reasons
// ---------------------------------------------------------------------------

// Accepted=False under status.parents flags accepted_false — only
// after the 10m window, and the gauge carries the route's kind tuple.
func TestGatewayRouteHealthAcceptedFalse(t *testing.T) {
	route := routeFixture("HTTPRoute", "apps", "accepted-route")
	setRouteParents(route, routeCond("Accepted", "False"))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(route))
	res := driveRouteCheck(t, p, time.Now())
	if res.Pass {
		t.Fatal("Accepted=False route did not fail past the window")
	}
	m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "accepted-route", "reason": "accepted_false"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("unhealthy gauge = %v, want 1", m)
	}
}

// ResolvedRefs=False flags resolved_refs_false — same window, GRPCRoute
// kind tuple.
func TestGatewayRouteHealthResolvedRefsFalse(t *testing.T) {
	route := routeFixture("GRPCRoute", "apps", "grpc-route")
	setRouteParents(route,
		routeCond("Accepted", "True"),
		routeCond("ResolvedRefs", "False"))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(route))
	res := driveRouteCheck(t, p, time.Now())
	if res.Pass {
		t.Fatal("ResolvedRefs=False route did not fail past the window")
	}
	m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "GRPCRoute", "namespace": "apps",
			"name": "grpc-route", "reason": "resolved_refs_false"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("unhealthy gauge = %v, want 1", m)
	}
}

// A cross-namespace backendRef with NO permitting ReferenceGrant in
// the backend's namespace flags ref_not_permitted — the controller
// drops the ref silently, so the static grant cross-check is the
// only way to see it before ResolvedRefs catches up (negative-cache-guard).
func TestGatewayRouteHealthCrossNSRefNotPermitted(t *testing.T) {
	t.Run("no grant", func(t *testing.T) {
		route := routeFixture("HTTPRoute", "apps", "xns-route")
		setRouteBackends(route, map[string]any{
			"name": "web-svc", "namespace": "backend", "port": int64(80)})
		setRouteParents(route, routeCond("Accepted", "True"),
			routeCond("ResolvedRefs", "True"))
		cs := fake.NewSimpleClientset(
			clusterIPService("backend", "web-svc", map[string]string{"app": "x"}))
		// A grant in an unrelated namespace keeps the GVR served on
		// the fake while proving it does not permit this ref.
		dyn := probetest.OpDyn(route,
			referenceGrantFixture("other", "g1", "HTTPRoute", "apps", "Service", ""))
		p := testProberDyn(cs, dyn)
		res := driveRouteCheck(t, p, time.Now())
		if res.Pass {
			t.Fatal("unpermitted cross-ns backendRef did not fail")
		}
		m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
			map[string]string{"kind": "HTTPRoute", "namespace": "apps",
				"name": "xns-route", "reason": "ref_not_permitted"})
		if m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("ref_not_permitted gauge = %v, want 1", m)
		}
	})

	t.Run("grant permits", func(t *testing.T) {
		route := routeFixture("HTTPRoute", "apps", "xns-ok-route")
		setRouteBackends(route, map[string]any{
			"name": "web-svc", "namespace": "backend", "port": int64(80)})
		setRouteParents(route, routeCond("Accepted", "True"),
			routeCond("ResolvedRefs", "True"))
		cs := fake.NewSimpleClientset(
			clusterIPService("backend", "web-svc", map[string]string{"app": "x"}),
			probetest.EndpointSliceForService("backend", "web-svc", "10.244.0.5"))
		dyn := probetest.OpDyn(route,
			referenceGrantFixture("backend", "g1", "HTTPRoute", "apps", "Service", "web-svc"))
		p := testProberDyn(cs, dyn)
		res := driveRouteCheck(t, p, time.Now())
		if !res.Pass {
			t.Fatalf("permitted cross-ns backendRef must pass: %s", res.Why)
		}
	})

	t.Run("wrong grant shape does not permit", func(t *testing.T) {
		route := routeFixture("HTTPRoute", "apps", "xns-wrong-route")
		setRouteBackends(route, map[string]any{
			"name": "web-svc", "namespace": "backend", "port": int64(80)})
		setRouteParents(route, routeCond("Accepted", "True"))
		cs := fake.NewSimpleClientset(
			clusterIPService("backend", "web-svc", map[string]string{"app": "x"}))
		// Grant names a different Service — not this ref's backend.
		dyn := probetest.OpDyn(route,
			referenceGrantFixture("backend", "g1", "HTTPRoute", "apps", "Service", "other-svc"))
		p := testProberDyn(cs, dyn)
		res := driveRouteCheck(t, p, time.Now())
		if res.Pass {
			t.Fatal("grant naming another service must not permit this ref")
		}
	})
}

// ResolvedRefs=False with reason RefNotPermitted lands the precise
// ref_not_permitted reason (not generic resolved_refs_false).
func TestGatewayRouteHealthRefNotPermittedReason(t *testing.T) {
	route := routeFixture("GRPCRoute", "apps", "rnp-route")
	setRouteParents(route,
		routeCond("Accepted", "True"),
		routeCondReason("ResolvedRefs", "False", "RefNotPermitted"))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(route))
	res := driveRouteCheck(t, p, time.Now())
	if res.Pass {
		t.Fatal("RefNotPermitted route did not fail")
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "GRPCRoute", "namespace": "apps",
			"name": "rnp-route", "reason": "ref_not_permitted"}); m == nil {
		t.Fatal("ref_not_permitted gauge missing")
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "GRPCRoute", "namespace": "apps",
			"name": "rnp-route", "reason": "resolved_refs_false"}); m != nil {
		t.Fatal("RefNotPermitted also flagged generic resolved_refs_false")
	}
}

// The dedicated 5m zero-endpoints gauge fires BEFORE the 10m
// unhealthy signature — same blackhole, earlier edge (negative-cache-guard).
func TestGatewayRouteHealthZeroEndpointsGaugeAt5m(t *testing.T) {
	base := time.Now()
	route := routeFixture("HTTPRoute", "apps", "zero5m-route")
	setRouteBackends(route, map[string]any{"name": "web-svc", "port": int64(80)})
	setRouteParents(route, routeCond("Accepted", "True"))
	cs := fake.NewSimpleClientset(
		clusterIPService("apps", "web-svc", map[string]string{"app": "x"}))
	p := testProberDyn(cs, probetest.OpDyn(route))
	chk := probetest.MustCheck[*gatewayRouteHealthCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	if r := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !r.Pass {
		t.Fatalf("fresh zero-endpoints must not flag: %+v", r)
	}
	// Inside the 10m unhealthy window but PAST the 5m zero window —
	// the dedicated gauge is live while the check still passes.
	probetest.FreezeNow(p.Deps, base.Add(gatewayRouteZeroEndpointsMinAge+time.Minute))
	r := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !r.Pass {
		t.Fatalf("zero gauge must not fail the check before 10m: %+v", r)
	}
	m := probetest.FindMetric(t, "node_automation_gateway_route_zero_endpoints",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "zero5m-route", "service_namespace": "apps", "service": "web-svc"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("zero-endpoints gauge = %v, want 1 at 5m", m)
	}
	// Past 10m the unhealthy reason lands too.
	probetest.FreezeNow(p.Deps, base.Add(gatewayRouteUnhealthyMinAge+time.Minute))
	if r := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); r.Pass {
		t.Fatal("persisted zero-endpoints did not fail at 10m")
	}
	// Endpoints appear — both gauges must drain on the next sweep.
	cs2 := probetest.EndpointSliceForService("apps", "web-svc", "10.244.0.7")
	if _, err := cs.DiscoveryV1().EndpointSlices("apps").Create(ctx, cs2, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(2*gatewayRouteUnhealthyMinAge+time.Minute))
	if r := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !r.Pass {
		t.Fatalf("healed backend must pass: %+v", r)
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_zero_endpoints",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "zero5m-route", "service_namespace": "apps", "service": "web-svc"}); m != nil {
		t.Fatal("zero-endpoints gauge not cleared after endpoints returned")
	}
}

// A backendRef whose Service does not exist flags backend_unresolved;
// so does a pinned port the Service does not carry.
func TestGatewayRouteHealthBackendUnresolved(t *testing.T) {
	t.Run("missing service", func(t *testing.T) {
		route := routeFixture("HTTPRoute", "apps", "missing-be-route")
		setRouteBackends(route, map[string]any{"name": "ghost-svc"})
		setRouteParents(route, routeCond("Accepted", "True"))
		p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(route))
		res := driveRouteCheck(t, p, time.Now())
		if res.Pass {
			t.Fatal("missing-backend route did not fail")
		}
		if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
			map[string]string{"kind": "HTTPRoute", "namespace": "apps",
				"name": "missing-be-route", "reason": "backend_unresolved"}); m == nil {
			t.Fatal("backend_unresolved gauge missing")
		}
	})

	t.Run("port not on service", func(t *testing.T) {
		route := routeFixture("HTTPRoute", "apps", "port-be-route")
		setRouteBackends(route, map[string]any{"name": "web-svc", "port": int64(8443)})
		setRouteParents(route, routeCond("Accepted", "True"))
		cs := fake.NewSimpleClientset(
			clusterIPService("apps", "web-svc", map[string]string{"app": "x"}))
		p := testProberDyn(cs, probetest.OpDyn(route))
		res := driveRouteCheck(t, p, time.Now())
		if res.Pass {
			t.Fatal("port-mismatched backend did not fail")
		}
		if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
			map[string]string{"kind": "HTTPRoute", "namespace": "apps",
				"name": "port-be-route", "reason": "backend_unresolved"}); m == nil {
			t.Fatal("backend_unresolved gauge missing for port mismatch")
		}
	})
}

// A backendRef to a valid Service with zero Ready endpoints flags
// backend_zero_endpoints — a routed blackhole.
func TestGatewayRouteHealthBackendZeroEndpoints(t *testing.T) {
	t.Run("no endpointslice at all", func(t *testing.T) {
		route := routeFixture("HTTPRoute", "apps", "zero-be-route")
		setRouteBackends(route, map[string]any{"name": "web-svc", "port": int64(80)})
		setRouteParents(route, routeCond("Accepted", "True"))
		cs := fake.NewSimpleClientset(
			clusterIPService("apps", "web-svc", map[string]string{"app": "x"}))
		p := testProberDyn(cs, probetest.OpDyn(route))
		res := driveRouteCheck(t, p, time.Now())
		if res.Pass {
			t.Fatal("zero-endpoint backend did not fail")
		}
		if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
			map[string]string{"kind": "HTTPRoute", "namespace": "apps",
				"name": "zero-be-route", "reason": "backend_zero_endpoints"}); m == nil {
			t.Fatal("backend_zero_endpoints gauge missing")
		}
	})

	t.Run("only not-ready endpoints", func(t *testing.T) {
		route := routeFixture("HTTPRoute", "apps", "nr-be-route")
		setRouteBackends(route, map[string]any{"name": "web-svc"})
		setRouteParents(route, routeCond("Accepted", "True"))
		cs := fake.NewSimpleClientset(
			clusterIPService("apps", "web-svc", map[string]string{"app": "x"}),
			unreadyEndpointSlice("apps", "web-svc", "10.244.0.9"))
		p := testProberDyn(cs, probetest.OpDyn(route))
		res := driveRouteCheck(t, p, time.Now())
		if res.Pass {
			t.Fatal("all-not-ready backend did not fail")
		}
		if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
			map[string]string{"kind": "HTTPRoute", "namespace": "apps",
				"name": "nr-be-route", "reason": "backend_zero_endpoints"}); m == nil {
			t.Fatal("backend_zero_endpoints gauge missing for not-ready endpoints")
		}
	})
}

// ---------------------------------------------------------------------------
// Exemptions and healthy routes
// ---------------------------------------------------------------------------

// A zero-endpoint backend the go-kube-downscaler parked at replicas:0
// is asleep on purpose — never flagged.
func TestGatewayRouteHealthSkipsDownscaledBackend(t *testing.T) {
	route := routeFixture("HTTPRoute", "apps", "downscaled-route")
	setRouteBackends(route, map[string]any{"name": "web-svc"})
	setRouteParents(route, routeCond("Accepted", "True"))
	cs := fake.NewSimpleClientset(
		clusterIPService("apps", "web-svc", map[string]string{"app": "x"}),
		downscaledDeployment("apps", "web", map[string]string{"app": "x"}))
	p := testProberDyn(cs, probetest.OpDyn(route))
	res := driveRouteCheck(t, p, time.Now())
	if !res.Pass {
		t.Fatalf("downscaler-owned zero must pass: %s", res.Why)
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "downscaled-route", "reason": "backend_zero_endpoints"}); m != nil {
		t.Fatal("gauge emitted for an intentionally downscaled backend")
	}
}

// downscaledRollout builds an argoproj.io Rollout (argo-rollout-gates) the
// go-kube-downscaler parked at replicas:0 whose pod template the
// service selector matches — the unstructured twin of
// downscaledDeployment.
func downscaledRollout(ns, name string, tplLabels map[string]string) *unstructured.Unstructured {
	labels := map[string]any{}
	for k, v := range tplLabels {
		labels[k] = v
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata": map[string]any{
			"namespace":   ns,
			"name":        name,
			"annotations": map[string]any{"downscaler/downtime-replicas": "0"},
		},
		"spec": map[string]any{
			"replicas": int64(0),
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels}},
		},
	}}
}

// A zero-endpoint backend served by an intentionally downscaled
// argoproj.io Rollout is asleep on purpose too — never flagged.
func TestGatewayRouteHealthSkipsDownscaledRolloutBackend(t *testing.T) {
	route := routeFixture("HTTPRoute", "apps", "downscaled-ro-route")
	setRouteBackends(route, map[string]any{"name": "web-svc", "port": int64(80)})
	setRouteParents(route, routeCond("Accepted", "True"))
	cs := fake.NewSimpleClientset(
		clusterIPService("apps", "web-svc", map[string]string{"app": "x"}))
	dyn := probetest.OpDyn(route, downscaledRollout("apps", "web", map[string]string{"app": "x"}))
	p := testProberDyn(cs, dyn)
	res := driveRouteCheck(t, p, time.Now())
	if !res.Pass {
		t.Fatalf("downscaler-owned Rollout zero must pass: %s", res.Why)
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "downscaled-ro-route", "reason": "backend_zero_endpoints"}); m != nil {
		t.Fatal("gauge emitted for an intentionally downscaled Rollout backend")
	}
}

// An explicit spec.replicas=0 is intent even without a downscaler
// annotation (GitOps-parked backend) — the zero-endpoints verdict
// must stay quiet, just as it does for a downscaled Rollout.
func TestGatewayRouteHealthSkipsExplicitZeroReplicaRolloutBackend(t *testing.T) {
	route := routeFixture("HTTPRoute", "apps", "zero-ro-route")
	setRouteBackends(route, map[string]any{"name": "web-svc", "port": int64(80)})
	setRouteParents(route, routeCond("Accepted", "True"))
	ro := downscaledRollout("apps", "web", map[string]string{"app": "x"})
	delete(ro.Object["metadata"].(map[string]any), "annotations")
	cs := fake.NewSimpleClientset(
		clusterIPService("apps", "web-svc", map[string]string{"app": "x"}))
	p := testProberDyn(cs, probetest.OpDyn(route, ro))
	res := driveRouteCheck(t, p, time.Now())
	if !res.Pass {
		t.Fatalf("explicit zero-replica backend must not flag: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "zero-ro-route", "reason": "backend_zero_endpoints"}); m != nil {
		t.Fatal("gauge emitted for an explicitly zero-replica Rollout backend")
	}
}

// A selectorless Service's endpoints are user-managed — zero Ready
// addresses is never this check's verdict.
func TestGatewayRouteHealthSkipsSelectorlessBackend(t *testing.T) {
	route := routeFixture("HTTPRoute", "apps", "selless-route")
	setRouteBackends(route, map[string]any{"name": "no-sel-svc"})
	setRouteParents(route, routeCond("Accepted", "True"))
	cs := fake.NewSimpleClientset(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "no-sel-svc"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.30"},
	})
	p := testProberDyn(cs, probetest.OpDyn(route))
	res := driveRouteCheck(t, p, time.Now())
	if !res.Pass {
		t.Fatalf("selectorless backend must pass: %s", res.Why)
	}
}

// A fully healthy route — Accepted/ResolvedRefs True, backend Service
// resolvable with a Ready endpoint — passes and emits nothing.
func TestGatewayRouteHealthHealthyRoutePasses(t *testing.T) {
	route := routeFixture("HTTPRoute", "apps", "healthy-route")
	setRouteBackends(route, map[string]any{"name": "web-svc", "port": int64(80)})
	setRouteParents(route,
		routeCond("Accepted", "True"),
		routeCond("ResolvedRefs", "True"))
	cs := fake.NewSimpleClientset(
		clusterIPService("apps", "web-svc", map[string]string{"app": "x"}),
		probetest.EndpointSliceForService("apps", "web-svc", "10.244.0.5"))
	p := testProberDyn(cs, probetest.OpDyn(route))
	res := driveRouteCheck(t, p, time.Now())
	if !res.Pass {
		t.Fatalf("healthy route must pass: %s", res.Why)
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "healthy-route", "reason": "backend_zero_endpoints"}); m != nil {
		t.Fatal("gauge emitted for a healthy route")
	}
}

// A resolved signature clears both the FAIL verdict and the gauge
// tuple — the series must not leak a stale 1.
func TestGatewayRouteHealthResolvedClearsGauge(t *testing.T) {
	base := time.Now()
	route := routeFixture("HTTPRoute", "apps", "clears-route")
	setRouteParents(route, routeCond("Accepted", "False"))
	dyn := probetest.OpDyn(route)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*gatewayRouteHealthCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(gatewayRouteUnhealthyMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatal("persisted Accepted=False did not fail")
	}
	// The controller re-accepts the route — next sweep must heal.
	setRouteParents(route, routeCond("Accepted", "True"))
	if _, err := dyn.Resource(kube.GVRHTTPRoute).Namespace("apps").
		UpdateStatus(ctx, route, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(2*gatewayRouteUnhealthyMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("healed route must pass: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "clears-route", "reason": "accepted_false"}); m != nil {
		t.Fatal("gauge not cleared after the route healed")
	}
}

func TestGatewayRouteCarryRouteSignature(t *testing.T) {
	p := &gatewayRouteHealthCheck{
		liveLast: map[string][]string{
			"HTTPRoute/apps/r1/backend_zero_endpoints": {"HTTPRoute", "apps", "r1", "backend_zero_endpoints"},
			"HTTPRoute/apps/r2/accepted_false":         {"HTTPRoute", "apps", "r2", "accepted_false"},
		},
		zeroLast: map[string][]string{
			"HTTPRoute/apps/r1/web-svc": {"HTTPRoute", "apps", "r1", "web-svc"},
			"HTTPRoute/apps/r2/other":   {"HTTPRoute", "apps", "r2", "other"},
		},
	}
	live := map[string][]string{}
	zeroNow := map[string][]string{}

	p.carryRouteSignature("HTTPRoute", "apps", "r1", routeReasonZeroEndpoints, live, zeroNow)
	if len(live) != 1 || len(zeroNow) != 1 {
		t.Fatalf("zero-endpoints carry: live=%v zeroNow=%v", live, zeroNow)
	}

	p.carryRouteSignature("HTTPRoute", "apps", "r2", "accepted_false", live, zeroNow)
	if len(live) != 2 || len(zeroNow) != 1 {
		t.Fatalf("non-zero carry should not copy zeroLast: live=%v zeroNow=%v", live, zeroNow)
	}
}

// ---------------------------------------------------------------------------
// R6-K4: GatewayClass, Gateway, TLSRoute, 403/404 skip & controller bounce
// ---------------------------------------------------------------------------

func gatewayClassFixture(name, controllerName string, conds ...map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "GatewayClass",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"controllerName": controllerName},
	}}
	if len(conds) > 0 {
		anyConds := make([]any, 0, len(conds))
		for _, c := range conds {
			anyConds = append(anyConds, c)
		}
		_ = unstructured.SetNestedSlice(u.Object, anyConds, "status", "conditions")
	}
	return u
}

func gatewayFixture(ns, name, className string, created time.Time, conds ...map[string]any) *unstructured.Unstructured {
	metaMap := map[string]any{"namespace": ns, "name": name}
	if !created.IsZero() {
		metaMap["creationTimestamp"] = created.UTC().Format(time.RFC3339)
	}
	obj := map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata":   metaMap,
	}
	if className != "" {
		obj["spec"] = map[string]any{"gatewayClassName": className}
	}
	if len(conds) > 0 {
		anyConds := make([]any, 0, len(conds))
		for _, c := range conds {
			anyConds = append(anyConds, c)
		}
		obj["status"] = map[string]any{"conditions": anyConds}
	}
	return &unstructured.Unstructured{Object: obj}
}

func gwCondAt(condType, status, reason string, ltt time.Time) map[string]any {
	m := map[string]any{"type": condType, "status": status}
	if reason != "" {
		m["reason"] = reason
	}
	if !ltt.IsZero() {
		m["lastTransitionTime"] = ltt.UTC().Format(time.RFC3339)
	}
	return m
}

// gwOpDyn seeds non-Gateway objects through probetest.OpDyn and adds
// Gateway objects under kube.GVRGateway ("gateways") explicitly —
// client-go's NewSimpleDynamicClientWithCustomListKinds otherwise
// seeds Gateway via UnsafeGuessKindToResource ("gatewaies").
func gwOpDyn(t *testing.T, objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	t.Helper()
	var nonGW []runtime.Object
	var gws []*unstructured.Unstructured
	for _, o := range objs {
		if u, ok := o.(*unstructured.Unstructured); ok && u.GetKind() == "Gateway" {
			gws = append(gws, u)
			continue
		}
		nonGW = append(nonGW, o)
	}
	dyn := probetest.OpDyn(nonGW...)
	for _, gw := range gws {
		if err := dyn.Tracker().Create(kube.GVRGateway, gw, gw.GetNamespace()); err != nil {
			t.Fatalf("seed gateway %s/%s: %v", gw.GetNamespace(), gw.GetName(), err)
		}
	}
	return dyn
}

func TestGatewayAuditMissingClassAndConditions(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name           string
		objs           []runtime.Object
		driveThreeStep bool
		wantPass       bool
		wantKind       string
		wantNS         string
		wantObjName    string
		wantReason     string
	}{
		{
			name: "missing_class_old_creation_fails_first_sweep",
			objs: []runtime.Object{
				gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute))),
				gatewayFixture("apps", "gw-noclass", "", now.Add(-20*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-20*time.Minute)),
					gwCondAt("Programmed", "True", "", now.Add(-20*time.Minute))),
			},
			wantPass:    false,
			wantKind:    "Gateway",
			wantNS:      "apps",
			wantObjName: "gw-noclass",
			wantReason:  gwReasonClassMissing,
		},
		{
			name: "nonexistent_class_fresh_creation_needs_10m_window",
			objs: []runtime.Object{
				gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute))),
				gatewayFixture("apps", "gw-badclass", "does-not-exist", now.Add(-1*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-1*time.Minute)),
					gwCondAt("Programmed", "True", "", now.Add(-1*time.Minute))),
			},
			driveThreeStep: true,
			wantPass:       false,
			wantKind:       "Gateway",
			wantNS:         "apps",
			wantObjName:    "gw-badclass",
			wantReason:     gwReasonClassMissing,
		},
		{
			name: "gateway_accepted_false_old_ltt_first_sweep",
			objs: []runtime.Object{
				gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute))),
				gatewayFixture("apps", "gw-acc-false", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "False", "Invalid", now.Add(-15*time.Minute)),
					gwCondAt("Programmed", "True", "", now.Add(-15*time.Minute))),
			},
			wantPass:    false,
			wantKind:    "Gateway",
			wantNS:      "apps",
			wantObjName: "gw-acc-false",
			wantReason:  routeReasonAcceptedFalse,
		},
		{
			name: "gateway_programmed_false_old_ltt_first_sweep",
			objs: []runtime.Object{
				gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute))),
				gatewayFixture("apps", "gw-prog-false", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-15*time.Minute))),
			},
			wantPass:    false,
			wantKind:    "Gateway",
			wantNS:      "apps",
			wantObjName: "gw-prog-false",
			wantReason:  gwReasonProgrammedFalse,
		},
		{
			name: "gateway_programmed_false_zero_ltt_persisted_10m",
			objs: []runtime.Object{
				gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute))),
				gatewayFixture("apps", "gw-prog-zero", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", time.Time{})),
			},
			driveThreeStep: true,
			wantPass:       false,
			wantKind:       "Gateway",
			wantNS:         "apps",
			wantObjName:    "gw-prog-zero",
			wantReason:     gwReasonProgrammedFalse,
		},
		{
			name: "gatewayclass_accepted_false_old_ltt_first_sweep",
			objs: []runtime.Object{
				gatewayClassFixture("bad-gc", "io.cilium/gateway-controller", gwCondAt("Accepted", "False", "InvalidParams", now.Add(-20*time.Minute))),
			},
			wantPass:    false,
			wantKind:    "GatewayClass",
			wantNS:      "",
			wantObjName: "bad-gc",
			wantReason:  routeReasonAcceptedFalse,
		},
		{
			name: "healthy_gateway_passes",
			objs: []runtime.Object{
				gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute))),
				gatewayFixture("apps", "gw-ok", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "True", "", now.Add(-30*time.Minute))),
			},
			wantPass: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantKind != "" {
				testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, tc.wantKind, tc.wantNS, tc.wantObjName, tc.wantReason)
			}
			p := testProberDyn(fake.NewSimpleClientset(), gwOpDyn(t, tc.objs...))
			chk := probetest.MustCheck[*gatewayRouteHealthCheck](t, p)
			var res probefw.Result
			if tc.driveThreeStep {
				res = driveRouteCheck(t, p, now)
			} else {
				probetest.FreezeNow(p.Deps, now)
				res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			}
			if res.Pass != tc.wantPass {
				t.Fatalf("Pass = %v (Why=%q), want %v", res.Pass, res.Why, tc.wantPass)
			}
			if !tc.wantPass {
				m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy", map[string]string{
					"kind": tc.wantKind, "namespace": tc.wantNS, "name": tc.wantObjName, "reason": tc.wantReason,
				})
				if m == nil || m.GetGauge().GetValue() != 1 {
					t.Fatalf("expected unhealthy metric %s/%s/%s/%s=1, got %v", tc.wantKind, tc.wantNS, tc.wantObjName, tc.wantReason, m)
				}
			}
		})
	}

	t.Run("gateway_resolution_clears_gauge", func(t *testing.T) {
		testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "Gateway", "apps", "gw-heal", gwReasonProgrammedFalse)
		gw := gatewayFixture("apps", "gw-heal", "cilium", now.Add(-30*time.Minute),
			gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
			gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
		gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
		dyn := gwOpDyn(t, gc, gw)
		p := testProberDyn(fake.NewSimpleClientset(), dyn)
		chk := probetest.MustCheck[*gatewayRouteHealthCheck](t, p)
		probetest.FreezeNow(p.Deps, now)

		if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
			t.Fatal("expected initial Programmed=False to fail")
		}
		_ = unstructured.SetNestedSlice(gw.Object, []any{
			gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
			gwCondAt("Programmed", "True", "", now),
		}, "status", "conditions")
		if _, err := dyn.Resource(kube.GVRGateway).Namespace("apps").UpdateStatus(ctx, gw, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		probetest.FreezeNow(p.Deps, now.Add(time.Minute))
		if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
			t.Fatalf("healed gateway must pass: %+v", res)
		}
		if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy", map[string]string{
			"kind": "Gateway", "namespace": "apps", "name": "gw-heal", "reason": gwReasonProgrammedFalse,
		}); m != nil {
			t.Fatalf("gauge not cleared after gateway healed: %v", m)
		}
	})
}

func TestGatewayCrossNamespaceCertRefGrant(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	makeGWWithCert := func(ns, name, secretNS, secretName string) *unstructured.Unstructured {
		gw := gatewayFixture(ns, name, "cilium", now.Add(-30*time.Minute),
			gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
			gwCondAt("Programmed", "True", "", now.Add(-30*time.Minute)))
		_ = unstructured.SetNestedSlice(gw.Object, []any{map[string]any{
			"name": "https",
			"tls": map[string]any{
				"certificateRefs": []any{map[string]any{
					"kind": "Secret", "namespace": secretNS, "name": secretName,
				}},
			},
		}}, "spec", "listeners")
		return gw
	}

	cases := []struct {
		name     string
		gwName   string
		grants   []runtime.Object
		wantPass bool
	}{
		{
			name:     "missing_reference_grant_flags_ref_not_permitted",
			gwName:   "gw-no-grant",
			grants:   nil,
			wantPass: false,
		},
		{
			name:   "wrong_from_kind_flags_ref_not_permitted",
			gwName: "gw-wrong-from",
			grants: []runtime.Object{
				referenceGrantFixture("certs", "g1", "HTTPRoute", "edge", "Secret", "tls-cert"),
			},
			wantPass: false,
		},
		{
			name:   "wrong_secret_name_flags_ref_not_permitted",
			gwName: "gw-wrong-sec",
			grants: []runtime.Object{
				referenceGrantFixture("certs", "g1", "Gateway", "edge", "Secret", "other-cert"),
			},
			wantPass: false,
		},
		{
			name:   "permitted_v1_grant_passes",
			gwName: "gw-ok-v1",
			grants: []runtime.Object{
				referenceGrantFixture("certs", "g-v1", "Gateway", "edge", "Secret", "tls-cert"),
			},
			wantPass: true,
		},
		{
			name:   "permitted_v1alpha2_grant_passes",
			gwName: "gw-ok-v1alpha2",
			grants: []runtime.Object{
				func() *unstructured.Unstructured {
					u := referenceGrantFixture("certs", "g-v1a2", "Gateway", "edge", "Secret", "tls-cert")
					u.SetAPIVersion("gateway.networking.k8s.io/v1alpha2")
					return u
				}(),
			},
			wantPass: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "Gateway", "edge", tc.gwName, routeReasonRefNotPermitted)
			objs := []runtime.Object{
				gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute))),
				makeGWWithCert("edge", tc.gwName, "certs", "tls-cert"),
			}
			objs = append(objs, tc.grants...)
			// Set permitted_v1_grant_passes to explicitly use v1 apiVersion.
			if tc.name == "permitted_v1_grant_passes" {
				objs[2].(*unstructured.Unstructured).SetAPIVersion("gateway.networking.k8s.io/v1")
			}
			p := testProberDyn(fake.NewSimpleClientset(), gwOpDyn(t, objs...))
			res := driveRouteCheck(t, p, now)
			if res.Pass != tc.wantPass {
				t.Fatalf("Pass = %v (Why=%q), want %v", res.Pass, res.Why, tc.wantPass)
			}
			m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy", map[string]string{
				"kind": "Gateway", "namespace": "edge", "name": tc.gwName, "reason": routeReasonRefNotPermitted,
			})
			if !tc.wantPass && (m == nil || m.GetGauge().GetValue() != 1) {
				t.Fatalf("expected ref_not_permitted metric=1, got %v", m)
			}
			if tc.wantPass && m != nil {
				t.Fatalf("unexpected ref_not_permitted metric: %v", m)
			}
		})
	}
}

func TestTLSRouteAudit(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	tlsRoute := func(apiVersion, ns, name string) *unstructured.Unstructured {
		u := routeFixture("TLSRoute", ns, name)
		u.SetAPIVersion(apiVersion)
		return u
	}

	cases := []struct {
		name       string
		routeName  string
		build      func() (*unstructured.Unstructured, []runtime.Object, []runtime.Object)
		wantPass   bool
		wantReason string
	}{
		{
			name:      "v1_accepted_false",
			routeName: "tls-acc",
			build: func() (*unstructured.Unstructured, []runtime.Object, []runtime.Object) {
				r := tlsRoute("gateway.networking.k8s.io/v1", "apps", "tls-acc")
				setRouteParents(r, routeCond("Accepted", "False"))
				return r, nil, nil
			},
			wantPass:   false,
			wantReason: routeReasonAcceptedFalse,
		},
		{
			name:      "v1alpha2_resolved_refs_false",
			routeName: "tls-res",
			build: func() (*unstructured.Unstructured, []runtime.Object, []runtime.Object) {
				r := tlsRoute("gateway.networking.k8s.io/v1alpha2", "apps", "tls-res")
				setRouteParents(r, routeCond("Accepted", "True"), routeCond("ResolvedRefs", "False"))
				return r, nil, nil
			},
			wantPass:   false,
			wantReason: routeReasonResolvedRefsFalse,
		},
		{
			name:      "v1alpha2_missing_reference_grant",
			routeName: "tls-xns",
			build: func() (*unstructured.Unstructured, []runtime.Object, []runtime.Object) {
				r := tlsRoute("gateway.networking.k8s.io/v1alpha2", "apps", "tls-xns")
				setRouteBackends(r, map[string]any{"name": "tcp-svc", "namespace": "backend", "port": int64(80)})
				setRouteParents(r, routeCond("Accepted", "True"), routeCond("ResolvedRefs", "True"))
				return r, []runtime.Object{clusterIPService("backend", "tcp-svc", map[string]string{"app": "tcp"})}, nil
			},
			wantPass:   false,
			wantReason: routeReasonRefNotPermitted,
		},
		{
			name:      "v1_backend_unresolved",
			routeName: "tls-unres",
			build: func() (*unstructured.Unstructured, []runtime.Object, []runtime.Object) {
				r := tlsRoute("gateway.networking.k8s.io/v1", "apps", "tls-unres")
				setRouteBackends(r, map[string]any{"name": "missing-svc", "port": int64(80)})
				setRouteParents(r, routeCond("Accepted", "True"))
				return r, nil, nil
			},
			wantPass:   false,
			wantReason: routeReasonBackendUnresolved,
		},
		{
			name:      "v1_backend_zero_endpoints",
			routeName: "tls-zero",
			build: func() (*unstructured.Unstructured, []runtime.Object, []runtime.Object) {
				r := tlsRoute("gateway.networking.k8s.io/v1", "apps", "tls-zero")
				setRouteBackends(r, map[string]any{"name": "tcp-svc", "port": int64(80)})
				setRouteParents(r, routeCond("Accepted", "True"))
				return r, []runtime.Object{clusterIPService("apps", "tcp-svc", map[string]string{"app": "tcp"})}, nil
			},
			wantPass:   false,
			wantReason: routeReasonZeroEndpoints,
		},
		{
			name:      "v1_healthy_tlsroute_passes",
			routeName: "tls-ok",
			build: func() (*unstructured.Unstructured, []runtime.Object, []runtime.Object) {
				r := tlsRoute("gateway.networking.k8s.io/v1", "apps", "tls-ok")
				setRouteBackends(r, map[string]any{"name": "tcp-svc", "port": int64(80)})
				setRouteParents(r, routeCond("Accepted", "True"), routeCond("ResolvedRefs", "True"))
				return r, []runtime.Object{
					clusterIPService("apps", "tcp-svc", map[string]string{"app": "tcp"}),
					probetest.EndpointSliceForService("apps", "tcp-svc", "10.244.0.10"),
				}, nil
			},
			wantPass: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantReason != "" {
				testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "TLSRoute", "apps", tc.routeName, tc.wantReason)
			}
			r, csObjs, extraDyn := tc.build()
			dynObjs := append([]runtime.Object{r}, extraDyn...)
			dyn := probetest.OpDyn(dynObjs...)
			// Simulate cluster serving v1alpha2 only when fixture uses v1alpha2.
			if r.GetAPIVersion() == "gateway.networking.k8s.io/v1alpha2" {
				dyn.PrependReactor("list", "tlsroutes", func(a ktesting.Action) (bool, runtime.Object, error) {
					gvr := a.(ktesting.ListAction).GetResource()
					if gvr.Version == "v1" || gvr.Version == "v1alpha3" {
						return true, nil, apierrors.NewNotFound(gvr.GroupResource(), "")
					}
					return false, nil, nil
				})
			}
			p := testProberDyn(fake.NewSimpleClientset(csObjs...), dyn)
			res := driveRouteCheck(t, p, now)
			if res.Pass != tc.wantPass {
				t.Fatalf("Pass = %v (Why=%q), want %v", res.Pass, res.Why, tc.wantPass)
			}
			if !tc.wantPass {
				m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy", map[string]string{
					"kind": "TLSRoute", "namespace": "apps", "name": tc.routeName, "reason": tc.wantReason,
				})
				if m == nil || m.GetGauge().GetValue() != 1 {
					t.Fatalf("expected TLSRoute unhealthy metric=1 for reason %q, got %v", tc.wantReason, m)
				}
			}
		})
	}
}

func TestGatewayCRDAbsentAnd403AutoSkip(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		setup func() (*fake.Clientset, []runtime.Object)
	}{
		{
			name: "all_crds_absent_404_and_nomatch",
			setup: func() (*fake.Clientset, []runtime.Object) {
				return fake.NewSimpleClientset(), nil
			},
		},
		{
			name: "tlsroute_404_while_httproute_present",
			setup: func() (*fake.Clientset, []runtime.Object) {
				r := routeFixture("HTTPRoute", "apps", "ok")
				setRouteParents(r, routeCond("Accepted", "True"), routeCond("ResolvedRefs", "True"))
				return fake.NewSimpleClientset(), []runtime.Object{r}
			},
		},
		{
			name: "forbidden_403_across_gateway_resources_and_referencegrants",
			setup: func() (*fake.Clientset, []runtime.Object) {
				r := routeFixture("HTTPRoute", "apps", "xns")
				setRouteBackends(r, map[string]any{"name": "svc", "namespace": "other", "port": int64(80)})
				return fake.NewSimpleClientset(), []runtime.Object{r}
			},
		},
		{
			name: "gatewayclass_404_does_not_false_flag_missing_class",
			setup: func() (*fake.Clientset, []runtime.Object) {
				gw := gatewayFixture("apps", "gw-with-class", "foo", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "True", "", now.Add(-30*time.Minute)))
				return fake.NewSimpleClientset(), []runtime.Object{gw}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs, objs := tc.setup()
			dyn := gwOpDyn(t, objs...)
			switch tc.name {
			case "all_crds_absent_404_and_nomatch":
				for _, res := range []string{"gatewayclasses", "gateways", "httproutes", "grpcroutes"} {
					r := res
					dyn.PrependReactor("list", r, func(a ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, apierrors.NewNotFound(a.GetResource().GroupResource(), "")
					})
				}
				dyn.PrependReactor("list", "tlsroutes", func(a ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "gateway.networking.k8s.io", Kind: "TLSRoute"}}
				})
			case "tlsroute_404_while_httproute_present":
				dyn.PrependReactor("list", "tlsroutes", func(a ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewNotFound(a.GetResource().GroupResource(), "")
				})
			case "forbidden_403_across_gateway_resources_and_referencegrants":
				for _, res := range []string{"gatewayclasses", "gateways", "tlsroutes", "referencegrants"} {
					r := res
					dyn.PrependReactor("list", r, func(a ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, apierrors.NewForbidden(a.GetResource().GroupResource(), "", errors.New("rbac"))
					})
				}
			case "gatewayclass_404_does_not_false_flag_missing_class":
				dyn.PrependReactor("list", "gatewayclasses", func(a ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewNotFound(a.GetResource().GroupResource(), "")
				})
			}

			p := testProberDyn(cs, dyn)
			chk := probetest.MustCheck[*gatewayRouteHealthCheck](t, p)
			probetest.FreezeNow(p.Deps, now)
			beforeErr := probetest.CounterSnapshot(t, p.Name)

			res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			if !res.Pass || res.Infra != nil {
				t.Fatalf("expected clean auto-skip Pass=true Infra=nil, got %+v", res)
			}
			probetest.AssertCounterDelta(t, p.Name, beforeErr, 0)
			if tc.name == "gatewayclass_404_does_not_false_flag_missing_class" {
				if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy", map[string]string{
					"kind": "Gateway", "namespace": "apps", "name": "gw-with-class", "reason": gwReasonClassMissing,
				}); m != nil {
					t.Fatalf("unexpected gateway_class_missing metric when GatewayClass CRD absent: %v", m)
				}
			}
		})
	}
}

// TestGatewayControllerPodBounce verifies all safety guards and EvictPodV
// behavior when a Gateway has Programmed=False >= 10m.
// Non-parallel: mutates global heal.ConfigureBudget and shared counters.
func TestGatewayControllerPodBounce(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	makeControllerPod := func(ns, name string, labels map[string]string, age time.Duration, nodeName string, owned bool) *corev1.Pod {
		p := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, age)
		p.CreationTimestamp = metav1.NewTime(now.Add(-age))
		p.Labels = labels
		p.Spec.NodeName = nodeName
		if owned {
			p.OwnerReferences = []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: name + "-rs",
				UID: types.UID("uid-" + name + "-rs"), Controller: ptr.To(true),
			}}
		}
		return p
	}

	healthyRouteAndBackend := func() ([]runtime.Object, []runtime.Object) {
		r := routeFixture("HTTPRoute", "apps", "ok-route")
		_ = unstructured.SetNestedSlice(r.Object, []any{map[string]any{"name": "gw-stuck"}}, "spec", "parentRefs")
		setRouteBackends(r, map[string]any{"name": "web-svc", "port": int64(80)})
		setRouteParents(r, routeCond("Accepted", "True"), routeCond("ResolvedRefs", "True"))
		csObjs := []runtime.Object{
			clusterIPService("apps", "web-svc", map[string]string{"app": "web"}),
			probetest.EndpointSliceForService("apps", "web-svc", "10.244.0.12"),
		}
		return csObjs, []runtime.Object{r}
	}

	cases := []struct {
		name              string
		configureBudget   bool
		setup             func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod)
		wantEvicted       bool
		wantHealDelta     float64
		wantErrDelta      float64
		wantCooldownStamp bool
		wantGrantRefunded bool
	}{
		{
			name: "bounces_cilium_operator_pod_on_programmed_false",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("kube-system", "cilium-operator-abc", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				cs := fake.NewSimpleClientset(append(csObjs, ctrlPod, node)...)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, append(dynObjs, gc, gw)...)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
			wantEvicted:       true,
			wantHealDelta:     1,
			wantCooldownStamp: true,
		},
		{
			name: "bounces_per_gateway_labeled_pod",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("envoy", "custom.example/gw", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "envoy", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("apps", "gw-stuck-envoy-0", map[string]string{"gateway.networking.k8s.io/gateway-name": "gw-stuck"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				cs := fake.NewSimpleClientset(append(csObjs, ctrlPod, node)...)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, append(dynObjs, gc, gw)...)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
			wantEvicted:       true,
			wantHealDelta:     1,
			wantCooldownStamp: true,
		},
		{
			name: "suppressed_when_programmed_false_reason_is_address_not_assigned",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "AddressNotAssigned", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("kube-system", "cilium-operator-abc", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				cs := fake.NewSimpleClientset(append(csObjs, ctrlPod, node)...)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, append(dynObjs, gc, gw)...)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
		},
		{
			name: "suppressed_when_accepted_false",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "False", "Invalid", now.Add(-20*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("kube-system", "cilium-operator-abc", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				cs := fake.NewSimpleClientset(append(csObjs, ctrlPod, node)...)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, append(dynObjs, gc, gw)...)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
		},
		{
			name: "suppressed_when_gateway_class_missing",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "missing", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("kube-system", "cilium-operator-abc", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				cs := fake.NewSimpleClientset(append(csObjs, ctrlPod, node)...)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, append(dynObjs, gc, gw)...)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
		},
		{
			name: "suppressed_when_attached_route_has_zero_endpoints",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				r := routeFixture("HTTPRoute", "apps", "bad-route")
				_ = unstructured.SetNestedSlice(r.Object, []any{map[string]any{"name": "gw-stuck"}}, "spec", "parentRefs")
				setRouteBackends(r, map[string]any{"name": "web-svc", "port": int64(80)})
				setRouteParents(r, routeCond("Accepted", "True"), routeCond("ResolvedRefs", "True"))
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("kube-system", "cilium-operator-abc", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				cs := fake.NewSimpleClientset(clusterIPService("apps", "web-svc", map[string]string{"app": "web"}), ctrlPod, node)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, gc, gw, r)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
		},
		{
			name: "suppressed_when_pod_young_node_notready_or_unowned",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				youngPod := makeControllerPod("kube-system", "cilium-operator-young", map[string]string{"io.cilium/app": "operator"}, 2*time.Minute, "w1", true)
				unownedPod := makeControllerPod("kube-system", "cilium-operator-static", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", false)
				notReadyPod := makeControllerPod("kube-system", "cilium-operator-nr", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w2", true)
				node1 := probetest.ReadyWorkerNode("w1", "", 0, false)
				node2 := testutil.Node("w2", corev1.ConditionFalse, nil)
				cs := fake.NewSimpleClientset(append(csObjs, youngPod, unownedPod, notReadyPod, node1, node2)...)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, append(dynObjs, gc, gw)...)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, youngPod
			},
		},
		{
			name: "suppressed_on_cooldown_and_maintenance_hold",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("kube-system", "cilium-operator-abc", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				plan := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "autopilot.k0sproject.io/v1beta2",
					"kind":       "Plan",
					"metadata":   map[string]any{"name": "autopilot"},
					"status":     map[string]any{"state": "Executing"},
				}}
				cs := fake.NewSimpleClientset(append(csObjs, ctrlPod, node)...)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, append(dynObjs, gc, gw, plan)...)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
		},
		{
			name: "unverifiable_maintenance_incerrors_and_skips",
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("kube-system", "cilium-operator-abc", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				cs := fake.NewSimpleClientset(append(csObjs, ctrlPod, node)...)
				testutil.EmulateEviction(cs)
				dyn := gwOpDyn(t, append(dynObjs, gc, gw)...)
				dyn.PrependReactor("list", "plans", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("autopilot api unavailable")
				})
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
			wantErrDelta: 1,
		},
		{
			name:            "pdb_429_refusal_refunds_budget_and_skips_cooldown",
			configureBudget: true,
			setup: func(t *testing.T) (*probetest.Prober, *gatewayRouteHealthCheck, *fake.Clientset, *corev1.Pod) {
				csObjs, dynObjs := healthyRouteAndBackend()
				gc := gatewayClassFixture("cilium", "io.cilium/gateway-controller", gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)))
				gw := gatewayFixture("apps", "gw-stuck", "cilium", now.Add(-30*time.Minute),
					gwCondAt("Accepted", "True", "", now.Add(-30*time.Minute)),
					gwCondAt("Programmed", "False", "Pending", now.Add(-20*time.Minute)))
				ctrlPod := makeControllerPod("kube-system", "cilium-operator-abc", map[string]string{"io.cilium/app": "operator"}, 30*time.Minute, "w1", true)
				node := probetest.ReadyWorkerNode("w1", "", 0, false)
				cs := fake.NewSimpleClientset(append(csObjs, ctrlPod, node)...)
				cs.PrependReactor("create", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
					if a.GetSubresource() == "eviction" {
						return true, nil, apierrors.NewTooManyRequests("pdb busy", 1)
					}
					return false, nil, nil
				})
				dyn := gwOpDyn(t, append(dynObjs, gc, gw)...)
				p := testProberDyn(cs, dyn)
				probetest.FreezeNow(p.Deps, now)
				return p, probetest.MustCheck[*gatewayRouteHealthCheck](t, p), cs, ctrlPod
			},
			wantGrantRefunded: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
			if tc.configureBudget {
				heal.ConfigureBudget(1, time.Hour)
			} else {
				heal.ConfigureBudget(0, 0)
			}
			testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "Gateway", "apps", "gw-stuck", gwReasonProgrammedFalse)
			testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "Gateway", "apps", "gw-stuck", routeReasonAcceptedFalse)
			testutil.CleanupMetric(t, gatewayRouteUnhealthyGauge, "Gateway", "apps", "gw-stuck", gwReasonClassMissing)

			p, chk, cs, targetPod := tc.setup(t)
			errBefore := probetest.CounterSnapshot(t, p.Name)
			healBefore := promtestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameGatewayRouteHealth))

			_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))

			probetest.AssertCounterDelta(t, p.Name, errBefore, tc.wantErrDelta)
			healDelta := promtestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameGatewayRouteHealth)) - healBefore
			if healDelta != tc.wantHealDelta {
				t.Fatalf("ControlPlanePodHealsTotal delta = %v, want %v", healDelta, tc.wantHealDelta)
			}
			_, podErr := cs.CoreV1().Pods(targetPod.Namespace).Get(ctx, targetPod.Name, metav1.GetOptions{})
			if tc.wantEvicted && !apierrors.IsNotFound(podErr) {
				t.Fatalf("expected controller pod %s/%s to be evicted, got err=%v", targetPod.Namespace, targetPod.Name, podErr)
			}
			if !tc.wantEvicted && podErr != nil {
				t.Fatalf("expected controller pod %s/%s to survive, got err=%v", targetPod.Namespace, targetPod.Name, podErr)
			}
			ck := probefw.SelfHealKey(CheckNameGatewayRouteHealth, "gw-controller/"+kube.PodControllerKey(targetPod))
			_, stamped := chk.Heals.Last(ck)
			if stamped != tc.wantCooldownStamp {
				t.Fatalf("Heals.Last(%q) = %v, want %v", ck, stamped, tc.wantCooldownStamp)
			}
			if tc.wantCooldownStamp {
				// Second sweep within 1h cooldown must not evict a recreated pod.
				recreated := targetPod.DeepCopy()
				recreated.Name = targetPod.Name + "-new"
				recreated.UID = "uid-recreated"
				if _, err := cs.CoreV1().Pods(recreated.Namespace).Create(ctx, recreated, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				probetest.FreezeNow(p.Deps, now.Add(10*time.Minute))
				_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				if _, err := cs.CoreV1().Pods(recreated.Namespace).Get(ctx, recreated.Name, metav1.GetOptions{}); err != nil {
					t.Fatalf("cooldown failed to suppress second eviction: %v", err)
				}
			}
			if tc.wantGrantRefunded {
				proceed, unverifiable := heal.Gate(ctx, logr.Discard(), p.Maintenance, p.CS, p.Dyn, "after-pdb-429", now.Add(time.Second))
				if !proceed || unverifiable {
					t.Fatalf("Gate after PDB 429 = (%v,%v), want (true,false) — grant not refunded", proceed, unverifiable)
				}
			}
		})
	}
}

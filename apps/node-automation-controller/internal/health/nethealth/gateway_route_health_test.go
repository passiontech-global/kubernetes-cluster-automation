// gateway_route_health_test.go — coverage for the gateway-route-health
// check: the four flagged reasons, the 10m persistence window, the
// downscaler/selectorless exemptions and resolved routes staying clean.
package nethealth

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
	r0 := chk.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(5*time.Minute))
	r1 := chk.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(gatewayRouteUnhealthyMinAge+time.Minute))
	r2 := chk.Run(ctx)
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
	chk.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(gatewayRouteUnhealthyMinAge+time.Minute))
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("persisted Accepted=False did not fail")
	}
	// The controller re-accepts the route — next sweep must heal.
	setRouteParents(route, routeCond("Accepted", "True"))
	if _, err := dyn.Resource(kube.GVRHTTPRoute).Namespace("apps").
		UpdateStatus(ctx, route, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(2*gatewayRouteUnhealthyMinAge+time.Minute))
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("healed route must pass: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_gateway_route_unhealthy",
		map[string]string{"kind": "HTTPRoute", "namespace": "apps",
			"name": "clears-route", "reason": "accepted_false"}); m != nil {
		t.Fatal("gauge not cleared after the route healed")
	}
}

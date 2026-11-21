// service_traffic_policy_guard_test.go — coverage for service-traffic-policy-guard (#71):
// externalTrafficPolicy=Local single_node_concentration and all_ready_on_unschedulable (>=10m),
// stuck Terminating EndpointSlice entries (missing/UID-mismatch/grace+60s), passive-only
// missing_prestop (LoadBalancer/HTTPRoute/Ingress, never fails check), 403/404 graceful skip,
// lazy Pod loading, and GaugeLedger stale label cleanup.
package nethealth

import (
	"errors"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func trafficPolicyDegradedSeries(t *testing.T, ns, svc, reason string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_service_traffic_policy_degraded",
		map[string]string{"namespace": ns, "service": svc, "reason": reason})
}

func endpointSliceTerminatingStuckSeries(t *testing.T, ns, svc string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_endpointslice_terminating_stuck",
		map[string]string{"namespace": ns, "service": svc})
}

func workloadMissingPreStopSeries(t *testing.T, ns, dep string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_workload_missing_prestop",
		map[string]string{"namespace": ns, "deployment": dep})
}

func makeLocalService(ns, name string, svcType corev1.ServiceType, policy corev1.ServiceExternalTrafficPolicy) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			Type:                  svcType,
			ExternalTrafficPolicy: policy,
			Selector:              map[string]string{"app": name},
			Ports:                 []corev1.ServicePort{{Port: 80}},
		},
	}
}

func makeNode(name string, unschedulable bool) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: unschedulable},
	}
}

func makeEndpointSlice(ns, name, svcName string, eps ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    map[string]string{discoveryv1.LabelServiceName: svcName},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   eps,
	}
}

func TestServiceTrafficPolicyLocalConcentrationAndUnschedulable(t *testing.T) {
	now := time.Now()
	svcConc := makeLocalService("prod", "api-lb", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyLocal)
	svcDraining := makeLocalService("prod", "web-np", corev1.ServiceTypeNodePort, corev1.ServiceExternalTrafficPolicyLocal)
	svcCluster := makeLocalService("prod", "cluster-lb", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyCluster)

	n1 := makeNode("w-1", false)
	n2 := makeNode("w-2", true)

	esConc := makeEndpointSlice("prod", "api-lb-1", "api-lb",
		discoveryv1.Endpoint{Addresses: []string{"10.1.0.1"}, NodeName: ptr.To("w-1"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
		discoveryv1.Endpoint{Addresses: []string{"10.1.0.2"}, NodeName: ptr.To("w-1"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
		// Terminating endpoint on w-2 must not count as healthy spread.
		discoveryv1.Endpoint{Addresses: []string{"10.1.0.3"}, NodeName: ptr.To("w-2"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true), Terminating: ptr.To(true)}},
	)
	esDraining := makeEndpointSlice("prod", "web-np-1", "web-np",
		discoveryv1.Endpoint{Addresses: []string{"10.1.0.4"}, NodeName: ptr.To("w-2"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
	)
	esCluster := makeEndpointSlice("prod", "cluster-lb-1", "cluster-lb",
		discoveryv1.Endpoint{Addresses: []string{"10.1.0.5"}, NodeName: ptr.To("w-1"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
		discoveryv1.Endpoint{Addresses: []string{"10.1.0.6"}, NodeName: ptr.To("w-1"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
	)

	// Note: esConc has a Terminating endpoint without TargetRef.Kind=="Pod", so Pods is not touched either.
	cs := fake.NewSimpleClientset(svcConc, svcDraining, svcCluster, n1, n2, esConc, esDraining, esCluster)
	p := testProber(cs)
	chk := probetest.MustCheck[*serviceTrafficPolicyGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("t=0s must arm inside 10m window, got %+v", res)
	}

	probetest.FreezeNow(p.Deps, now.Add(11*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=11m expected failure for single_node_concentration and all_ready_on_unschedulable")
	}
	if v, ok := trafficPolicyDegradedSeries(t, "prod", "api-lb", "single_node_concentration"); !ok || v != 1 {
		t.Fatalf("missing single_node_concentration series: v=%v ok=%v", v, ok)
	}
	if v, ok := trafficPolicyDegradedSeries(t, "prod", "web-np", "all_ready_on_unschedulable"); !ok || v != 1 {
		t.Fatalf("missing all_ready_on_unschedulable series: v=%v ok=%v", v, ok)
	}
	if _, ok := trafficPolicyDegradedSeries(t, "prod", "cluster-lb", "single_node_concentration"); ok {
		t.Fatal("ExternalTrafficPolicy=Cluster must not be flagged")
	}

	// Spread api-lb to w-2 (schedulable) and un-drain w-2 -> both must recover and delete series.
	n2.Spec.Unschedulable = false
	_, _ = cs.CoreV1().Nodes().Update(ctx, n2, metav1.UpdateOptions{})
	esConc.Endpoints[1].NodeName = ptr.To("w-2")
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Update(ctx, esConc, metav1.UpdateOptions{})

	probetest.FreezeNow(p.Deps, now.Add(15*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered sweep must pass: %+v", res)
	}
	if _, ok := trafficPolicyDegradedSeries(t, "prod", "api-lb", "single_node_concentration"); ok {
		t.Fatal("stale single_node_concentration series not deleted")
	}
	if _, ok := trafficPolicyDegradedSeries(t, "prod", "web-np", "all_ready_on_unschedulable"); ok {
		t.Fatal("stale all_ready_on_unschedulable series not deleted")
	}
}

func TestServiceTrafficPolicyStuckTerminatingEndpoints(t *testing.T) {
	now := time.Now()
	svcMissing := makeLocalService("apps", "svc-missing", corev1.ServiceTypeClusterIP, "")
	svcUID := makeLocalService("apps", "svc-uid", corev1.ServiceTypeClusterIP, "")
	svcLongGrace := makeLocalService("apps", "svc-grace", corev1.ServiceTypeClusterIP, "")
	svcStuck := makeLocalService("apps", "svc-stuck", corev1.ServiceTypeClusterIP, "")

	podUIDMismatch := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pod-uid", UID: types.UID("new-uid")},
	}
	podGraceOK := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "pod-grace", UID: types.UID("uid-grace"),
			DeletionTimestamp: &metav1.Time{Time: now.Add(-6 * time.Minute)},
		},
		Spec: corev1.PodSpec{TerminationGracePeriodSeconds: ptr.To(int64(600))}, // 600+60 = 660s > 360s
	}
	podStuck := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "pod-stuck", UID: types.UID("uid-stuck"),
			DeletionTimestamp: &metav1.Time{Time: now.Add(-6 * time.Minute)},
		},
		Spec: corev1.PodSpec{TerminationGracePeriodSeconds: ptr.To(int64(30))}, // max(90s, 5m) = 5m < 6m
	}

	es1 := makeEndpointSlice("apps", "es-missing", "svc-missing", discoveryv1.Endpoint{
		Addresses:  []string{"10.2.0.1"},
		Conditions: discoveryv1.EndpointConditions{Terminating: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "gone-pod", UID: "gone"},
	})
	es2 := makeEndpointSlice("apps", "es-uid", "svc-uid", discoveryv1.Endpoint{
		Addresses:  []string{"10.2.0.2"},
		Conditions: discoveryv1.EndpointConditions{Terminating: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "pod-uid", UID: "old-uid"},
	})
	es3 := makeEndpointSlice("apps", "es-grace", "svc-grace", discoveryv1.Endpoint{
		Addresses:  []string{"10.2.0.3"},
		Conditions: discoveryv1.EndpointConditions{Terminating: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "pod-grace", UID: "uid-grace"},
	})
	es4 := makeEndpointSlice("apps", "es-stuck", "svc-stuck", discoveryv1.Endpoint{
		Addresses:  []string{"10.2.0.4"},
		Conditions: discoveryv1.EndpointConditions{Terminating: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "apps", Name: "pod-stuck", UID: "uid-stuck"},
	})

	cs := fake.NewSimpleClientset(svcMissing, svcUID, svcLongGrace, svcStuck, podUIDMismatch, podGraceOK, podStuck, es1, es2, es3, es4)
	p := testProber(cs)
	chk := probetest.MustCheck[*serviceTrafficPolicyGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("expected failure for stuck terminating endpoints")
	}
	for _, svcName := range []string{"svc-missing", "svc-uid", "svc-stuck"} {
		if v, ok := endpointSliceTerminatingStuckSeries(t, "apps", svcName); !ok || v != 1 {
			t.Fatalf("missing stuck terminating series for %s: v=%v ok=%v", svcName, v, ok)
		}
	}
	if _, ok := endpointSliceTerminatingStuckSeries(t, "apps", "svc-grace"); ok {
		t.Fatal("pod still within terminationGracePeriodSeconds+60s must not be flagged")
	}

	// Clean up stuck slices -> series must be deleted.
	_ = cs.DiscoveryV1().EndpointSlices("apps").Delete(ctx, "es-missing", metav1.DeleteOptions{})
	_ = cs.DiscoveryV1().EndpointSlices("apps").Delete(ctx, "es-uid", metav1.DeleteOptions{})
	_ = cs.DiscoveryV1().EndpointSlices("apps").Delete(ctx, "es-stuck", metav1.DeleteOptions{})
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("cleaned sweep must pass: %+v", res)
	}
	for _, svcName := range []string{"svc-missing", "svc-uid", "svc-stuck"} {
		if _, ok := endpointSliceTerminatingStuckSeries(t, "apps", svcName); ok {
			t.Fatalf("stale stuck terminating series not deleted for %s", svcName)
		}
	}
}

func TestServiceTrafficPolicyPassivePreStopAnd403GracefulSkip(t *testing.T) {
	now := time.Now()
	svcLB := makeLocalService("web", "svc-lb", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyCluster)
	svcRoute := makeLocalService("web", "svc-route", corev1.ServiceTypeClusterIP, "")
	svcIng := makeLocalService("web", "svc-ing", corev1.ServiceTypeClusterIP, "")

	makeDep := func(name string, replicas int32, withPreStop bool) *appsv1.Deployment {
		var lc *corev1.Lifecycle
		if withPreStop {
			lc = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"sleep", "5"}}}}
		}
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: name},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(replicas),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "app", Image: "nginx", Lifecycle: lc}},
					},
				},
			},
		}
	}

	depLB := makeDep("svc-lb", 2, false)
	depRoute := makeDep("svc-route", 3, false)
	depIng := makeDep("svc-ing", 2, false)
	depSingle := makeDep("svc-single", 1, false)
	svcSingle := makeLocalService("web", "svc-single", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyCluster)
	depWithHook := makeDep("svc-hook", 2, true)
	svcHook := makeLocalService("web", "svc-hook", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyCluster)

	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "web-ing"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{Name: "svc-ing"},
							},
						}},
					},
				},
			}},
		},
	}

	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"namespace": "web", "name": "web-route"},
		"spec": map[string]any{
			"rules": []any{
				map[string]any{
					"backendRefs": []any{
						map[string]any{"name": "svc-route", "port": int64(80)},
					},
				},
			},
		},
	}}

	cs := fake.NewSimpleClientset(svcLB, svcRoute, svcIng, svcSingle, svcHook, depLB, depRoute, depIng, depSingle, depWithHook, ing)
	// Empty-cluster / no-terminating-slice path must never list pods.
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("pods must not be listed when no endpoint lacks NodeName or is Terminating")
	})
	dyn := probetest.OpDyn(route)
	p := testProberDyn(cs, dyn)
	chk := probetest.MustCheck[*serviceTrafficPolicyGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass || res.Infra != nil {
		t.Fatalf("missing_prestop is PASSIVE-ONLY and must pass with nil Infra, got %+v", res)
	}
	for _, depName := range []string{"svc-lb", "svc-route", "svc-ing"} {
		if v, ok := workloadMissingPreStopSeries(t, "web", depName); !ok || v != 1 {
			t.Fatalf("missing prestop series for %s: v=%v ok=%v", depName, v, ok)
		}
	}
	for _, depName := range []string{"svc-single", "svc-hook"} {
		if _, ok := workloadMissingPreStopSeries(t, "web", depName); ok {
			t.Fatalf("%s must not emit missing_prestop series", depName)
		}
	}

	// Next sweep: 403 Forbidden on Ingress and HTTPRoute must carry held tuples without failing!
	cs.PrependReactor("list", "ingresses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingresses"}, "", errors.New("forbidden"))
	})
	dyn403 := probetest.OpDyn()
	dyn403.PrependReactor("list", "httproutes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "httproutes"}, "", errors.New("forbidden"))
	})
	chk.Dyn = dyn403
	res403 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res403.Pass || res403.Infra != nil {
		t.Fatalf("403 on Ingress/HTTPRoute must pass with nil Infra, got %+v", res403)
	}
	if _, ok := workloadMissingPreStopSeries(t, "web", "svc-ing"); !ok {
		t.Fatal("403 on Ingress must carry held prestop series")
	}

	// Clean up gauges for subsequent tests.
	workloadMissingPreStopGauge.DeleteLabelValues("web", "svc-lb")
	workloadMissingPreStopGauge.DeleteLabelValues("web", "svc-route")
	workloadMissingPreStopGauge.DeleteLabelValues("web", "svc-ing")
}

func TestServiceTrafficPolicyPreStopPrunesRecoveredScaledDeletedUnder403(t *testing.T) {
	now := time.Now()
	svcLBPreStop := makeLocalService("web", "lb-prestop", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyCluster)
	svcLBScale := makeLocalService("web", "lb-scale", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyCluster)
	svcLBDel := makeLocalService("web", "lb-del", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyCluster)

	makeDep := func(name string, replicas int32) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: name},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(replicas),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
					},
				},
			},
		}
	}

	depPreStop := makeDep("lb-prestop", 2)
	depScale := makeDep("lb-scale", 2)
	depDel := makeDep("lb-del", 2)

	cs := fake.NewSimpleClientset(svcLBPreStop, svcLBScale, svcLBDel, depPreStop, depScale, depDel)
	dyn403 := probetest.OpDyn()
	dyn403.PrependReactor("list", "httproutes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "httproutes"}, "", errors.New("forbidden"))
	})
	p := testProberDyn(cs, dyn403)
	chk := probetest.MustCheck[*serviceTrafficPolicyGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass || res.Infra != nil {
		t.Fatalf("sweep 1 must pass with nil Infra, got %+v", res)
	}
	for _, depName := range []string{"lb-prestop", "lb-scale", "lb-del"} {
		if v, ok := workloadMissingPreStopSeries(t, "web", depName); !ok || v != 1 {
			t.Fatalf("sweep 1 missing prestop series for %s: v=%v ok=%v", depName, v, ok)
		}
	}

	// Sweep 2 (while HTTPRoute still returns 403):
	// - lb-prestop adds preStop
	// - lb-scale scales down to 1 replica
	// - lb-del is deleted
	uPreStop, _ := cs.AppsV1().Deployments("web").Get(ctx, "lb-prestop", metav1.GetOptions{})
	uPreStop.Spec.Template.Spec.Containers[0].Lifecycle = &corev1.Lifecycle{
		PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"sleep", "5"}}},
	}
	_, _ = cs.AppsV1().Deployments("web").Update(ctx, uPreStop, metav1.UpdateOptions{})

	uScale, _ := cs.AppsV1().Deployments("web").Get(ctx, "lb-scale", metav1.GetOptions{})
	uScale.Spec.Replicas = ptr.To(int32(1))
	_, _ = cs.AppsV1().Deployments("web").Update(ctx, uScale, metav1.UpdateOptions{})

	_ = cs.AppsV1().Deployments("web").Delete(ctx, "lb-del", metav1.DeleteOptions{})

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass || res.Infra != nil {
		t.Fatalf("sweep 2 must pass with nil Infra, got %+v", res)
	}
	for _, depName := range []string{"lb-prestop", "lb-scale", "lb-del"} {
		if _, ok := workloadMissingPreStopSeries(t, "web", depName); ok {
			t.Fatalf("%s series must be pruned even while HTTPRoute returns 403", depName)
		}
	}
	if cnt := ptestutil.CollectAndCount(workloadMissingPreStopGauge); cnt != 0 {
		t.Fatalf("expected 0 workloadMissingPreStopGauge series after recovery, got %d", cnt)
	}
}

func TestServiceTrafficPolicyIngressCRDAbsentDoesNotPinPreStop(t *testing.T) {
	now := time.Now()
	svcIng := makeLocalService("web", "svc-ing-absent", corev1.ServiceTypeClusterIP, "")
	depIng := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "dep-ing-absent"},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(2)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "svc-ing-absent"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
				},
			},
		},
	}
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "ing-absent"},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{Name: "svc-ing-absent"},
			},
		},
	}

	cs := fake.NewSimpleClientset(svcIng, depIng, ing)
	p := testProber(cs)
	chk := probetest.MustCheck[*serviceTrafficPolicyGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass || res.Infra != nil {
		t.Fatalf("sweep 1 must pass with nil Infra, got %+v", res)
	}
	if v, ok := workloadMissingPreStopSeries(t, "web", "dep-ing-absent"); !ok || v != 1 {
		t.Fatalf("expected missing_prestop=1 on sweep 1, got v=%v ok=%v", v, ok)
	}

	// Ingress list returns 404 (IsCRDAbsent): must NOT pin dep-ing-absent.
	cs.PrependReactor("list", "ingresses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingresses"}, "")
	})
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass || res.Infra != nil {
		t.Fatalf("sweep 2 must pass with nil Infra, got %+v", res)
	}
	if _, ok := workloadMissingPreStopSeries(t, "web", "dep-ing-absent"); ok {
		t.Fatal("Ingress IsCRDAbsent must not pin previously flagged missing_prestop series")
	}
	if cnt := ptestutil.CollectAndCount(workloadMissingPreStopGauge); cnt != 0 {
		t.Fatalf("expected 0 workloadMissingPreStopGauge series when Ingress CRD absent, got %d", cnt)
	}
}

func TestServiceTrafficPolicyDualStackSingleReplicaNoFalsePositive(t *testing.T) {
	now := time.Now()
	svc := makeLocalService("prod", "dual-lb", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyLocal)
	n1 := makeNode("w-1", false)
	n2 := makeNode("w-2", false)

	epDual0V4 := discoveryv1.Endpoint{
		Addresses:  []string{"10.1.0.10"},
		NodeName:   ptr.To("w-1"),
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "dual-0", UID: "uid-dual-0"},
	}
	epDual0V6 := discoveryv1.Endpoint{
		Addresses:  []string{"fd00::10"},
		NodeName:   ptr.To("w-1"),
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "dual-0", UID: "uid-dual-0"},
	}

	esV4 := makeEndpointSlice("prod", "dual-lb-v4", "dual-lb", epDual0V4)
	esV4.AddressType = discoveryv1.AddressTypeIPv4
	esV6 := makeEndpointSlice("prod", "dual-lb-v6", "dual-lb", epDual0V6)
	esV6.AddressType = discoveryv1.AddressTypeIPv6

	cs := fake.NewSimpleClientset(svc, n1, n2, esV4, esV6)
	p := testProber(cs)
	chk := probetest.MustCheck[*serviceTrafficPolicyGuardCheck](t, p)

	// 1 Pod on 1 node across IPv4+IPv6 slices must NEVER trigger single_node_concentration.
	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("t=0s expected PASS for single dual-stack Pod, got %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(11*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("t=11m expected PASS (no dual-stack false positive), got %+v", res)
	}
	if _, ok := trafficPolicyDegradedSeries(t, "prod", "dual-lb", "single_node_concentration"); ok {
		t.Fatal("single dual-stack Pod must not emit single_node_concentration")
	}

	// Add a second distinct Pod (dual-1) on the SAME node w-1 across IPv4+IPv6 slices -> must flag after 10m!
	epDual1V4 := discoveryv1.Endpoint{
		Addresses:  []string{"10.1.0.11"},
		NodeName:   ptr.To("w-1"),
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "dual-1", UID: "uid-dual-1"},
	}
	epDual1V6 := discoveryv1.Endpoint{
		Addresses:  []string{"fd00::11"},
		NodeName:   ptr.To("w-1"),
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "dual-1", UID: "uid-dual-1"},
	}
	esV4.Endpoints = append(esV4.Endpoints, epDual1V4)
	esV6.Endpoints = append(esV6.Endpoints, epDual1V6)
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Update(ctx, esV4, metav1.UpdateOptions{})
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Update(ctx, esV6, metav1.UpdateOptions{})

	probetest.FreezeNow(p.Deps, now.Add(12*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("t=12m must arm inside 10m window, got %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(23*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=23m expected failure when 2 distinct dual-stack Pods are co-located on 1 node")
	}
	if v, ok := trafficPolicyDegradedSeries(t, "prod", "dual-lb", "single_node_concentration"); !ok || v != 1 {
		t.Fatalf("expected single_node_concentration=1 for 2 distinct dual-stack Pods, got v=%v ok=%v", v, ok)
	}

	// Spread dual-1 to w-2 -> recovers and prunes series.
	esV4.Endpoints[1].NodeName = ptr.To("w-2")
	esV6.Endpoints[1].NodeName = ptr.To("w-2")
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Update(ctx, esV4, metav1.UpdateOptions{})
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Update(ctx, esV6, metav1.UpdateOptions{})
	probetest.FreezeNow(p.Deps, now.Add(24*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered dual-stack sweep must pass: %+v", res)
	}
	if _, ok := trafficPolicyDegradedSeries(t, "prod", "dual-lb", "single_node_concentration"); ok {
		t.Fatal("stale single_node_concentration series not deleted after spread")
	}
}

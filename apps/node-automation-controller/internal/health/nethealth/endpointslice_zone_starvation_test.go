// endpointslice_zone_starvation_test.go — coverage for the
// endpointslice-zone-starvation check (zone-starvation): starved/covered
// zones, the zero-endpoint outage exclusion, audit-scope gating,
// the inactive-zone exclusion, gauge reconcile and event dedup.
package nethealth

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// zonedWorker builds a Ready worker node labeled into zone.
func zonedWorker(name, zone string) *corev1.Node {
	n := probetest.ReadyWorkerNode(name, "", 0, false)
	n.Labels = map[string]string{corev1.LabelTopologyZone: zone}
	return n
}

// zonePod builds a Running pod scheduled on node — the client
// workload that makes a zone "active" for topology purposes.
func zonePod(ns, name, node string) *corev1.Pod {
	p := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	p.Spec.NodeName = node
	return p
}

// hintedSlice builds an EndpointSlice bound to svc: each endpoint
// is ready=<ready> and advertises hints.forZones for every zone in
// zones (nil zones = no hints at all).
func hintedSlice(ns, name, svc string, ready bool,
	eps map[string][]string) *discoveryv1.EndpointSlice {

	s := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Labels: map[string]string{discoveryv1.LabelServiceName: svc},
		},
	}
	for addr, zones := range eps {
		ep := discoveryv1.Endpoint{
			Addresses:  []string{addr},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(ready)},
		}
		if zones != nil {
			ep.Hints = &discoveryv1.EndpointHints{}
			for _, z := range zones {
				ep.Hints.ForZones = append(ep.Hints.ForZones,
					discoveryv1.ForZone{Name: z})
			}
		}
		s.Endpoints = append(s.Endpoints, ep)
	}
	return s
}

// topologyService builds a Service carrying the topology-mode=Auto
// annotation — the opt-in the audit keys on.
func topologyService(ns, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Annotations: map[string]string{
				corev1.AnnotationTopologyMode: topologyModeAuto,
			},
		},
	}
}

// twoActiveZones returns workers+client pods for zones a and b.
func twoActiveZones() (*corev1.Node, *corev1.Node, *corev1.Pod, *corev1.Pod) {
	return zonedWorker("w-a", "zone-a"), zonedWorker("w-b", "zone-b"),
		zonePod("apps", "client-a", "w-a"), zonePod("apps", "client-b", "w-b")
}

// A topology-opted Service whose hinted endpoints only cover zone-a
// starves zone-b: gauge fires at 1, the check FAILs, and the
// EndpointSliceZoneHintStarved Warning Event lands on the Service.
func TestEndpointSliceZoneStarved(t *testing.T) {
	nA, nB, cA, cB := twoActiveZones()
	svc := topologyService("apps", "web")
	slice := hintedSlice("apps", "web-1", "web", true,
		map[string][]string{"10.0.0.1": {"zone-a"}})
	cs := fake.NewSimpleClientset(nA, nB, cA, cB, svc, slice)
	p := testProber(cs)
	res := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("starved zone must fail: %+v", res)
	}
	m := probetest.FindMetric(t, "node_automation_service_topology_zone_starved",
		map[string]string{"namespace": "apps", "service": "web", "zone": "zone-b"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("starved-zone gauge = %v, want 1", m)
	}
	if m := probetest.FindMetric(t, "node_automation_service_topology_zone_starved",
		map[string]string{"namespace": "apps", "service": "web", "zone": "zone-a"}); m != nil {
		t.Fatal("covered zone must not emit a starved series")
	}
	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 {
		t.Fatalf("events = %v, %v — want exactly 1", evs, err)
	}
	if ev := evs.Items[0]; ev.Reason != "EndpointSliceZoneHintStarved" ||
		ev.Regarding.Kind != "Service" || ev.Regarding.Name != "web" ||
		ev.Type != corev1.EventTypeWarning {
		t.Fatalf("bad event: %+v", ev)
	}
	t.Cleanup(func() {
		serviceTopologyZoneStarvedGauge.DeleteLabelValues("apps", "web", "zone-b")
	})
}

// The dedup set suppresses repeat Events while the zone stays
// starved — one episode, one Event (the gauge re-asserts every
// sweep either way).
func TestEndpointSliceZoneStarvedEventDeduped(t *testing.T) {
	nA, nB, cA, cB := twoActiveZones()
	svc := topologyService("apps", "web")
	slice := hintedSlice("apps", "web-1", "web", true,
		map[string][]string{"10.0.0.1": {"zone-a"}})
	cs := fake.NewSimpleClientset(nA, nB, cA, cB, svc, slice)
	p := testProber(cs)
	chk := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p)
	for i := 0; i < 3; i++ {
		if res := chk.Run(ctx); res.Pass {
			t.Fatalf("sweep %d: starved zone must fail", i)
		}
	}
	evs, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("3 starved sweeps emitted %d events, want 1 (dedup)",
			len(evs.Items))
	}
	t.Cleanup(func() {
		serviceTopologyZoneStarvedGauge.DeleteLabelValues("apps", "web", "zone-b")
	})
}

// Both zones hinted → pass, no gauge, no event.
func TestEndpointSliceZonesCoveredPass(t *testing.T) {
	nA, nB, cA, cB := twoActiveZones()
	svc := topologyService("apps", "web")
	slice := hintedSlice("apps", "web-1", "web", true,
		map[string][]string{"10.0.0.1": {"zone-a"}, "10.0.0.2": {"zone-b"}})
	cs := fake.NewSimpleClientset(nA, nB, cA, cB, svc, slice)
	p := testProber(cs)
	if res := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("covered zones must pass: %+v", res)
	}
	evs, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 0 {
		t.Fatalf("covered zones emitted %d events, want 0", len(evs.Items))
	}
}

// A Service with zero ready endpoints anywhere is a real outage —
// the zero-endpoint alerts own it; every zone reading "starved"
// would misattribute the failure.
func TestEndpointSliceZeroReadySkipped(t *testing.T) {
	nA, nB, cA, cB := twoActiveZones()
	svc := topologyService("apps", "web")
	slice := hintedSlice("apps", "web-1", "web", false,
		map[string][]string{"10.0.0.1": {"zone-a"}})
	cs := fake.NewSimpleClientset(nA, nB, cA, cB, svc, slice)
	p := testProber(cs)
	if res := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("zero-endpoint outage must pass (not topology starvation): %+v", res)
	}
}

// A Service with no topology opt-in and unhinted slices is not
// audited — plain ClusterIP routing cannot starve a zone.
func TestEndpointSliceNonAuditedServiceSkipped(t *testing.T) {
	nA, nB, cA, cB := twoActiveZones()
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"}}
	slice := hintedSlice("apps", "web-1", "web", true,
		map[string][]string{"10.0.0.1": nil})
	cs := fake.NewSimpleClientset(nA, nB, cA, cB, svc, slice)
	p := testProber(cs)
	if res := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("non-audited service must pass: %+v", res)
	}
}

// A slice already carrying hints.forZones proves the Service is in
// play even without the annotation — the hinted-slice audit path.
func TestEndpointSliceHintedServiceAudited(t *testing.T) {
	nA, nB, cA, cB := twoActiveZones()
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"}}
	slice := hintedSlice("apps", "web-1", "web", true,
		map[string][]string{"10.0.0.1": {"zone-a"}})
	cs := fake.NewSimpleClientset(nA, nB, cA, cB, svc, slice)
	p := testProber(cs)
	res := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("hinted service with a starved zone must fail: %+v", res)
	}
	t.Cleanup(func() {
		serviceTopologyZoneStarvedGauge.DeleteLabelValues("apps", "web", "zone-b")
	})
}

// PreferClose on spec.trafficDistribution is the second opt-in
// spelling — an uncovered active zone still starves.
func TestEndpointSlicePreferCloseAudited(t *testing.T) {
	nA, nB, cA, cB := twoActiveZones()
	td := corev1.ServiceTrafficDistributionPreferClose
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"},
		Spec:       corev1.ServiceSpec{TrafficDistribution: &td},
	}
	slice := hintedSlice("apps", "web-1", "web", true,
		map[string][]string{"10.0.0.1": {"zone-a"}})
	cs := fake.NewSimpleClientset(nA, nB, cA, cB, svc, slice)
	p := testProber(cs)
	if res := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p).Run(ctx); res.Pass {
		t.Fatalf("PreferClose service with a starved zone must fail: %+v", res)
	}
	t.Cleanup(func() {
		serviceTopologyZoneStarvedGauge.DeleteLabelValues("apps", "web", "zone-b")
	})
}

// A zone with a Ready worker but no running pod is not a consumer
// — nothing there can starve, so it is not flagged.
func TestEndpointSliceInactiveZoneNotFlagged(t *testing.T) {
	nA, nB, cA := zonedWorker("w-a", "zone-a"), zonedWorker("w-b", "zone-b"),
		zonePod("apps", "client-a", "w-a")
	svc := topologyService("apps", "web")
	slice := hintedSlice("apps", "web-1", "web", true,
		map[string][]string{"10.0.0.1": {"zone-a"}})
	cs := fake.NewSimpleClientset(nA, nB, cA, svc, slice)
	p := testProber(cs)
	if res := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("zone without running pods must not be flagged: %+v", res)
	}
}

// The gauge tuple reconciles away once the zone gets a covering
// endpoint — no stale 1 leaks past the resolve.
func TestEndpointSliceZoneStarvedGaugeClears(t *testing.T) {
	nA, nB, cA, cB := twoActiveZones()
	svc := topologyService("apps", "web")
	slice := hintedSlice("apps", "web-1", "web", true,
		map[string][]string{"10.0.0.1": {"zone-a"}})
	cs := fake.NewSimpleClientset(nA, nB, cA, cB, svc, slice)
	p := testProber(cs)
	chk := probetest.MustCheck[*endpointSliceZoneStarvationCheck](t, p)
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("starved zone must fail")
	}
	if m := probetest.FindMetric(t, "node_automation_service_topology_zone_starved",
		map[string]string{"namespace": "apps", "service": "web", "zone": "zone-b"}); m == nil {
		t.Fatal("starved-zone gauge missing")
	}
	// Cover zone-b — the next sweep must prune the series.
	slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{
		Addresses:  []string{"10.0.0.9"},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		Hints: &discoveryv1.EndpointHints{
			ForZones: []discoveryv1.ForZone{{Name: "zone-b"}},
		},
	})
	if _, err := cs.DiscoveryV1().EndpointSlices("apps").
		Update(ctx, slice, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update slice: %v", err)
	}
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("re-covered zones must pass: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_service_topology_zone_starved",
		map[string]string{"namespace": "apps", "service": "web", "zone": "zone-b"}); m != nil {
		t.Fatal("starved-zone gauge not cleared after re-cover")
	}
}

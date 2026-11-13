// sweep_partition_test.go — the endpoint-census signature: backends
// whose Ready endpoints all sit on partitioned nodes trip on the fast
// partition threshold; a healthy-node endpoint or a blind node census
// must never trip.
package circuitbreaker

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// endpoint-census — partitioned-node-aware circuit breaker
// ---------------------------------------------------------------------------

// wgReadyNode builds a Ready Node carrying the given taints.
func wgReadyNode(name string, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionTrue,
		}}},
	}
}

// wgSliceOnNode builds a slice with one Ready endpoint bound to
// nodeName — the shape that exercises the endpoint-census effective-ready math.
func wgSliceOnNode(ns, svc, nodeName string) *discoveryv1.EndpointSlice {
	es := wgEndpointSlice(ns, svc, 0, 0)
	up := true
	es.Endpoints = []discoveryv1.Endpoint{{
		Addresses:  []string{"10.10.5.5"},
		NodeName:   &nodeName,
		Conditions: discoveryv1.EndpointConditions{Ready: &up},
	}}
	return es
}

// The endpoint-census signature: every Ready endpoint of the backend Service sits
// on a partitioned node — raw > 0, effective == 0 — so the breaker
// trips on the 90s partition threshold instead of waiting 5m.
func TestWebhookCircuitBreakerPartitionedBackendTripsFast(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-part"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgSliceOnNode("backend", "dead-svc", "node-part"),
		wgReadyNode("node-part",
			corev1.Taint{Key: "passiontech.dev/network-partitioned", Effect: corev1.TaintEffectNoSchedule}),
		mwc)
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	patches := wgPatchCounter(cs)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-part", "dead.example.com")
	})

	// First sighting — tracked, not tripped.
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	// 60s in — inside the 90s partition window, nowhere near 5m.
	now = now.Add(60 * time.Second)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-part", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("60s streak < %s partition threshold must not trip, failurePolicy=%q",
			PartitionedThreshold, got)
	}
	// 100s in — past the partition window, still far under 5m.
	now = now.Add(40 * time.Second)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-part", "dead.example.com"); got != admissionv1.Ignore {
		t.Fatalf("partitioned backend must trip on the fast threshold, failurePolicy=%q", got)
	}
	if anno, ok := wgMutatingAnno(t, cs, "cb-part"); !ok || anno != "dead.example.com" {
		t.Fatalf("annotation = %q (present=%v), want %q", anno, ok, "dead.example.com")
	}
	if got := atomic.LoadInt32(patches); got == 0 {
		t.Fatal("expected a breaker patch")
	}
}

// A Ready endpoint on a HEALTHY node keeps effective > 0 — the
// partition fast-path must never engage even past both thresholds.
func TestWebhookCircuitBreakerHealthyNodeBackendNeverTrips(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-healthy-node"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "live.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "live-svc"),
			},
		}},
	}
	// One endpoint stranded on a partitioned node, one healthy —
	// effective counts the healthy one.
	healthySlice := wgSliceOnNode("backend", "live-svc", "node-ok")
	healthySlice.Name = "live-svc-slice-ok"
	badSlice := wgSliceOnNode("backend", "live-svc", "node-part")
	badSlice.Name = "live-svc-slice-bad"
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "live-svc"),
		healthySlice, badSlice,
		wgReadyNode("node-ok"),
		wgReadyNode("node-part",
			corev1.Taint{Key: "passiontech.dev/network-partitioned", Effect: corev1.TaintEffectNoSchedule}),
		mwc)
	patches := wgPatchCounter(cs)
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * DeadThreshold)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-healthy-node", "live.example.com"); got != admissionv1.Fail {
		t.Fatalf("a reachable Ready endpoint must never trip, failurePolicy=%q", got)
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("reachable backend must not be patched, got %d patch(es)", got)
	}
}

// A node list failure is indistinguishable from "no node data" — the
// breaker must skip the sweep rather than trip webhooks on a blind
// effective-ready reading.
func TestWebhookCircuitBreakerNodeListErrorSkips(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-nodeerr"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		mwc)
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("nodes unreachable")
		})
	patches := wgPatchCounter(cs)
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	if err := runBreaker(ctx, g, b); err == nil {
		t.Fatal("expected an error when the node census fails")
	}
	now = now.Add(2 * DeadThreshold)
	_ = runBreaker(ctx, g, b)
	if got := wgMutatingFP(t, cs, "cb-nodeerr", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("blind node census must not trip, failurePolicy=%q", got)
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("blind node census must not patch, got %d patch(es)", got)
	}
}

// crd_conversion_test.go — coverage for the CRD spec.conversion
// webhook backend-health duty: the three unhealthy reasons
// (missing_service / zero_endpoints / tls_probe_failed), the pod
// bounce behind the shared cooldown + maintenance mutex, and the
// gauge's series hygiene.
package webhookguard

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// Builders + readers (cw-prefixed to stay unique across sibling files)
// ---------------------------------------------------------------------------

// cwPodSlice builds an EndpointSlice whose Ready endpoints each
// targetRef one of pods — the shape the conversion-backend probe +
// bounce candidates are read from.
func cwPodSlice(ns, svc string, pods ...string) *discoveryv1.EndpointSlice {
	es := wgEndpointSlice(ns, svc, 0, 0)
	up := true
	for i, p := range pods {
		es.Endpoints = append(es.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{fmt.Sprintf("10.20.0.%d", i+1)},
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Name: p},
			Conditions: discoveryv1.EndpointConditions{Ready: &up},
		})
	}
	return es
}

// cwGuard builds a guard with a scripted clock and a scripted TLS
// prober — the brownout seam the tls_probe_failed verdict needs.
func cwGuard(cs *fake.Clientset, now *time.Time, responsive bool,
	dynObjs ...runtime.Object) *webhookGuard {
	return &webhookGuard{cs: cs, dyn: wgDyn(dynObjs...),
		now:            func() time.Time { return *now },
		circuitBreaker: circuitBreaker{},
		endpointProber: func(context.Context, string, int32) bool {
			return responsive
		}}
}

// cwUnhealthy reads the unhealthy gauge for one (crd, service,
// reason) tuple.
func cwUnhealthy(crd, svc, reason string) float64 {
	return ptestutil.ToFloat64(
		crdConversionWebhookUnhealthy.WithLabelValues(crd, svc, reason))
}

// cwCleanup drops every unhealthy series a test may have emitted for
// the (crd, svc) tuple — the vec is process-global.
func cwCleanup(t *testing.T, crd, svc string) {
	t.Helper()
	t.Cleanup(func() {
		for _, reason := range []string{
			crdReasonMissingService, crdReasonZeroEndpoints, crdReasonTLSProbeFailed} {
			crdConversionWebhookUnhealthy.DeleteLabelValues(crd, svc, reason)
		}
	})
}

func cwPodGone(cs *fake.Clientset, ns, name string) bool {
	_, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

// ---------------------------------------------------------------------------
// The three unhealthy reasons
// ---------------------------------------------------------------------------

// The conversion clientConfig points at a Service that does not
// exist (namespace still lives — the orphan sweep warns, this sweep
// gauges): reason=missing_service.
func TestCRDConversionUnhealthyMissingService(t *testing.T) {
	cwCleanup(t, "widgets.example.com", "conv/conv-svc")
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("conv"))
	now := time.Unix(1_700_000_000, 0)
	g := cwGuard(cs, &now, true, wgCRDConversion("widgets.example.com", "conv", "conv-svc"))

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cwUnhealthy("widgets.example.com", "conv/conv-svc", "missing_service"); got != 1 {
		t.Fatalf("missing_service gauge = %v, want 1", got)
	}
}

// The Service exists but reports 0 Ready endpoints — reason
// zero_endpoints. A healthy sibling CRD emits nothing.
func TestCRDConversionUnhealthyZeroEndpoints(t *testing.T) {
	cwCleanup(t, "widgets.example.com", "conv/conv-svc")
	cwCleanup(t, "healthy.example.com", "conv/live-svc")
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("conv"),
		wgService("conv", "conv-svc"),
		wgEndpointSlice("conv", "conv-svc", 0, 2), // 2 endpoints, none ready
		wgService("conv", "live-svc"),
		wgEndpointSlice("conv", "live-svc", 1, 0))
	now := time.Unix(1_700_000_000, 0)
	g := cwGuard(cs, &now, true,
		wgCRDConversion("widgets.example.com", "conv", "conv-svc"),
		wgCRDConversion("healthy.example.com", "conv", "live-svc"))

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cwUnhealthy("widgets.example.com", "conv/conv-svc", "zero_endpoints"); got != 1 {
		t.Fatalf("zero_endpoints gauge = %v, want 1", got)
	}
	for _, reason := range []string{
		crdReasonMissingService, crdReasonZeroEndpoints, crdReasonTLSProbeFailed} {
		if crdConversionWebhookUnhealthy.DeleteLabelValues(
			"healthy.example.com", "conv/live-svc", reason) {
			t.Fatalf("healthy backend produced a %s series", reason)
		}
	}
}

// Ready endpoints exist but EVERY probed pod fails the TCP+TLS
// handshake — reason tls_probe_failed, and the sweep bounces the
// OLDEST Ready backing pod on the first sweep (the wedged process is
// usually the longest-lived replica).
func TestCRDConversionUnhealthyTLSProbeFailedBounces(t *testing.T) {
	cwCleanup(t, "widgets.example.com", "conv/conv-svc")
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("conv"),
		wgService("conv", "conv-svc"),
		cwPodSlice("conv", "conv-svc", "conv-old", "conv-new"),
		wgPod("conv", "conv-old", 48*time.Hour),
		wgPod("conv", "conv-new", time.Hour))
	now := time.Unix(1_700_000_000, 0)
	g := cwGuard(cs, &now, false, wgCRDConversion("widgets.example.com", "conv", "conv-svc"))

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cwUnhealthy("widgets.example.com", "conv/conv-svc", "tls_probe_failed"); got != 1 {
		t.Fatalf("tls_probe_failed gauge = %v, want 1", got)
	}
	if !cwPodGone(cs, "conv", "conv-old") {
		t.Fatal("oldest wedged conversion pod must be bounced on first sweep")
	}
	if cwPodGone(cs, "conv", "conv-new") {
		t.Fatal("single-pod bounce must leave the sibling alive")
	}

	// Inside the 15m cooldown the survivor is untouchable.
	now = now.Add(time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if cwPodGone(cs, "conv", "conv-new") {
		t.Fatal("15m bounce cooldown must protect the surviving pod")
	}

	// Past the cooldown the next wedged pod bounces.
	now = now.Add(webhookBounceCooldown + time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !cwPodGone(cs, "conv", "conv-new") {
		t.Fatal("post-cooldown sweep must bounce the remaining wedged pod")
	}
}

// A maintenance mutex holder (a freshly cordoned node = drain in
// flight) defers the pod kill — the gauge still emits (detect-only)
// but no pod is touched while the mutex is held.
func TestCRDConversionBounceDefersDuringMaintenance(t *testing.T) {
	cwCleanup(t, "widgets.example.com", "conv/conv-svc")
	fresh := metav1.NewTime(time.Now())
	cordoned := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "w1"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				TimeAdded: &fresh,
			}},
		},
	}
	cs := fake.NewSimpleClientset(cordoned,
		wgNamespace("kube-system"), wgNamespace("conv"),
		wgService("conv", "conv-svc"),
		cwPodSlice("conv", "conv-svc", "conv-old"),
		wgPod("conv", "conv-old", 48*time.Hour))
	now := time.Unix(1_700_000_000, 0)
	g := cwGuard(cs, &now, false, wgCRDConversion("widgets.example.com", "conv", "conv-svc"))

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cwUnhealthy("widgets.example.com", "conv/conv-svc", "tls_probe_failed"); got != 1 {
		t.Fatalf("tls_probe_failed gauge = %v, want 1", got)
	}
	if cwPodGone(cs, "conv", "conv-old") {
		t.Fatal("pod deleted while the maintenance mutex is held")
	}
}

// The shared ops lever: WEBHOOK_CIRCUIT_BREAKER_ENABLED=false
// silences the bounce (the module's only pod-kill switch) while the
// detect-only gauge stays live.
func TestCRDConversionBounceDisabledByEnv(t *testing.T) {
	t.Setenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED", "false")
	cwCleanup(t, "widgets.example.com", "conv/conv-svc")
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("conv"),
		wgService("conv", "conv-svc"),
		cwPodSlice("conv", "conv-svc", "conv-old"),
		wgPod("conv", "conv-old", 48*time.Hour))
	now := time.Unix(1_700_000_000, 0)
	g := cwGuard(cs, &now, false, wgCRDConversion("widgets.example.com", "conv", "conv-svc"))

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cwUnhealthy("widgets.example.com", "conv/conv-svc", "tls_probe_failed"); got != 1 {
		t.Fatalf("gauge must stay live with the lever off, got %v", got)
	}
	if cwPodGone(cs, "conv", "conv-old") {
		t.Fatal("pod deleted while the circuit-breaker lever is off")
	}
}

// Recovery: once the backend serves again the emitted series is
// pruned outright — a recovered CRD emits no series, not a parked 0.
func TestCRDConversionUnhealthySeriesPrunedOnRecovery(t *testing.T) {
	cwCleanup(t, "widgets.example.com", "conv/conv-svc")
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("conv"))
	now := time.Unix(1_700_000_000, 0)
	g := cwGuard(cs, &now, true, wgCRDConversion("widgets.example.com", "conv", "conv-svc"))

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cwUnhealthy("widgets.example.com", "conv/conv-svc", "missing_service"); got != 1 {
		t.Fatalf("precondition: missing_service gauge = %v, want 1", got)
	}

	// Service materializes with a Ready, responsive endpoint.
	if _, err := cs.CoreV1().Services("conv").Create(ctx,
		wgService("conv", "conv-svc"), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("conv").Create(ctx,
		wgEndpointSlice("conv", "conv-svc", 1, 0), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create slice: %v", err)
	}
	now = now.Add(time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if crdConversionWebhookUnhealthy.DeleteLabelValues(
		"widgets.example.com", "conv/conv-svc", "missing_service") {
		t.Fatal("recovered backend must prune the unhealthy series, not park it")
	}
}

// A healthy conversion backend — Service up, Ready endpoints,
// responsive probe — emits no series at all. The non-Webhook CRD is
// never even classified.
func TestCRDConversionHealthyBackendQuiet(t *testing.T) {
	plain := wgCRDConversion("no-conv.example.com", "conv", "none-svc")
	_ = unstructured.SetNestedField(plain.Object, "None",
		"spec", "conversion", "strategy")
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("conv"),
		wgService("conv", "conv-svc"),
		cwPodSlice("conv", "conv-svc", "conv-pod"),
		wgPod("conv", "conv-pod", time.Hour))
	now := time.Unix(1_700_000_000, 0)
	g := cwGuard(cs, &now, true,
		wgCRDConversion("widgets.example.com", "conv", "conv-svc"), plain)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range [][3]string{
		{"widgets.example.com", "conv/conv-svc", crdReasonMissingService},
		{"widgets.example.com", "conv/conv-svc", crdReasonZeroEndpoints},
		{"widgets.example.com", "conv/conv-svc", crdReasonTLSProbeFailed},
		{"no-conv.example.com", "conv/none-svc", crdReasonMissingService},
	} {
		if crdConversionWebhookUnhealthy.DeleteLabelValues(tc[0], tc[1], tc[2]) {
			t.Fatalf("unexpected %s series for %s", tc[2], tc[0])
		}
	}
}

// A CRD list failure (API flap) is an error for the run AND carries
// the last sweep's series forward — an active alert must not flap
// off on a transient read failure.
func TestCRDConversionListErrorCarriesSeries(t *testing.T) {
	cwCleanup(t, "widgets.example.com", "conv/conv-svc")
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("conv"))
	now := time.Unix(1_700_000_000, 0)
	dyn := wgDyn(wgCRDConversion("widgets.example.com", "conv", "conv-svc"))
	g := cwGuard(cs, &now, true)
	g.dyn = dyn

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cwUnhealthy("widgets.example.com", "conv/conv-svc", "missing_service"); got != 1 {
		t.Fatalf("precondition: missing_service gauge = %v, want 1", got)
	}

	dyn.PrependReactor("list", "customresourcedefinitions",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	now = now.Add(time.Minute)
	err := g.run(ctx)
	if err == nil {
		t.Fatal("expected error when the CRD list fails")
	}
	if got := cwUnhealthy("widgets.example.com", "conv/conv-svc", "missing_service"); got != 1 {
		t.Fatalf("unhealthy series flapped off on a transient list failure: %v", got)
	}
}

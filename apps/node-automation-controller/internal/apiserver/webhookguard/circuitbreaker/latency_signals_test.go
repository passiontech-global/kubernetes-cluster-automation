package circuitbreaker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

type promResponse struct {
	Status string   `json:"status"`
	Data   promData `json:"data"`
}
type promData struct {
	ResultType string       `json:"resultType"`
	Result     []promResult `json:"result"`
}
type promResult struct {
	Metric map[string]string `json:"metric"`
	Value  [2]any            `json:"value"`
}

func mockPromServer(t *testing.T, handler func(query string) []promResult) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		q := r.FormValue("query")
		res := handler(q)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(promResponse{
			Status: "success",
			Data:   promData{ResultType: "vector", Result: res},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func readySliceWithPod(ns, svc, podName string) *discoveryv1.EndpointSlice {
	es := wgEndpointSlice(ns, svc, 1, 0)
	es.Endpoints[0].TargetRef = &corev1.ObjectReference{
		Kind: "Pod", Namespace: ns, Name: podName,
	}
	return es
}

func TestLatencySignal10mBounce15mTripAndDualGateRecovery(t *testing.T) {
	metrics.WebhookAdmissionDegraded.Reset()
	metrics.WebhookCircuitBroken.Reset()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "backend"}}
	pod := wgPod("backend", "wh-pod-0", 30*time.Minute)
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "slow-mwc"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "slow.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("backend", "wh-svc")},
		}},
	}
	cs := fake.NewSimpleClientset(ns, mwc, readySliceWithPod("backend", "wh-svc", "wh-pod-0"), pod)
	testutil.EmulateEviction(cs)

	var breaching atomic.Bool
	breaching.Store(true)
	srv := mockPromServer(t, func(query string) []promResult {
		if !breaching.Load() {
			return nil
		}
		if strings.Contains(query, "rejection_count") {
			// Include a no_error sample which must be ignored, plus a real error_rate breach.
			return []promResult{
				{Metric: map[string]string{"name": "noerror.example.com", "error_type": "no_error"}, Value: [2]any{1, "0.99"}},
				{Metric: map[string]string{"name": "slow.example.com", "error_type": "calling_webhook_error"}, Value: [2]any{1, "0.8"}},
			}
		}
		return nil
	})

	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	g, b := wgBreakerGuard(cs, &now)
	g.PromEndpoint = srv.URL + "/api/v1/query"
	g.PromClient = promq.Client{HTTP: srv.Client()}
	g.WebhookErrorRateThreshold = 0.5
	g.WebhookLatencyP99Seconds = 5.0
	g.LatencyBreakerTripEnabled = true
	b.degradedThreshold = 10 * time.Minute
	b.latencyTripThreshold = 15 * time.Minute

	// T=0: first sight -> no gauge, no bounce, no trip.
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=0: %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookAdmissionDegraded.WithLabelValues("mutating", "slow-mwc", "slow.example.com", "error_rate")); v != 0 {
		t.Fatalf("expected 0 degraded metric at T=0, got %v", v)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-pod-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected pod still present at T=0, got %v", err)
	}

	// T=10m: degraded metric + pod bounce, not yet tripped (<15m).
	now = now.Add(10 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=10m: %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookAdmissionDegraded.WithLabelValues("mutating", "slow-mwc", "slow.example.com", "error_rate")); v != 1 {
		t.Fatalf("expected WebhookAdmissionDegraded=1 at T=10m, got %v", v)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-pod-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected eviction of backend/wh-pod-0 at T=10m, got err=%v", err)
	}
	gotMWC, _ := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "slow-mwc", metav1.GetOptions{})
	if *gotMWC.Webhooks[0].FailurePolicy != admissionv1.Fail {
		t.Fatalf("expected Fail at T=10m, got %v", *gotMWC.Webhooks[0].FailurePolicy)
	}

	// T=15m: trips to Ignore and stamps annotation.
	now = now.Add(5 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=15m: %v", err)
	}
	gotMWC, _ = cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "slow-mwc", metav1.GetOptions{})
	if *gotMWC.Webhooks[0].FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected Ignore at T=15m, got %v", *gotMWC.Webhooks[0].FailurePolicy)
	}
	if !strings.Contains(gotMWC.Annotations[guardstate.CircuitBrokenAnno], "slow.example.com") {
		t.Fatalf("expected circuit broken annotation, got %v", gotMWC.Annotations)
	}

	// T=20m: endpoints are Ready, but metrics STILL breach -> MUST stay Ignore!
	now = now.Add(5 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=20m: %v", err)
	}
	gotMWC, _ = cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "slow-mwc", metav1.GetOptions{})
	if *gotMWC.Webhooks[0].FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected webhook to stay Ignore while metrics still breach, got %v", *gotMWC.Webhooks[0].FailurePolicy)
	}

	// Metrics become clean -> 1st clean sweep defers recovery, 2nd clean sweep restores Fail!
	breaching.Store(false)
	now = now.Add(5 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=25m: %v", err)
	}
	gotMWC, _ = cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "slow-mwc", metav1.GetOptions{})
	if *gotMWC.Webhooks[0].FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected first clean sweep to defer recovery, got %v", *gotMWC.Webhooks[0].FailurePolicy)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookAdmissionDegraded.WithLabelValues("mutating", "slow-mwc", "slow.example.com", "error_rate")); v != 0 {
		t.Fatalf("expected degraded metric pruned on clean sweep, got %v", v)
	}

	now = now.Add(5 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=30m: %v", err)
	}
	gotMWC, _ = cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "slow-mwc", metav1.GetOptions{})
	if *gotMWC.Webhooks[0].FailurePolicy != admissionv1.Fail {
		t.Fatalf("expected Fail restored on 2nd consecutive clean sweep, got %v", *gotMWC.Webhooks[0].FailurePolicy)
	}
}

func TestLatencySignalNeverFailOpenBlocksTripButAllowsBounce(t *testing.T) {
	metrics.WebhookAdmissionDegraded.Reset()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "backend"}}
	pod := wgPod("backend", "wh-pod-0", 30*time.Minute)
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "optout-vwc",
			Annotations: map[string]string{kube.AnnoWebhookNeverFailOpen: "true"},
		},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:          "strict.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("backend", "wh-svc")},
		}},
	}
	cs := fake.NewSimpleClientset(ns, vwc, readySliceWithPod("backend", "wh-svc", "wh-pod-0"), pod)
	testutil.EmulateEviction(cs)

	srv := mockPromServer(t, func(query string) []promResult {
		if strings.Contains(query, "duration_seconds_bucket") {
			return []promResult{
				{Metric: map[string]string{"name": "strict.example.com"}, Value: [2]any{1, "9.5"}},
			}
		}
		return nil
	})

	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	g, b := wgBreakerGuard(cs, &now)
	g.PromEndpoint = srv.URL + "/api/v1/query"
	g.PromClient = promq.Client{HTTP: srv.Client()}
	g.WebhookLatencyP99Seconds = 5.0
	g.LatencyBreakerTripEnabled = true
	b.degradedThreshold = 10 * time.Minute
	b.latencyTripThreshold = 15 * time.Minute

	_ = runBreaker(ctx, g, b)
	now = now.Add(20 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=20m: %v", err)
	}
	gotVWC, _ := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "optout-vwc", metav1.GetOptions{})
	if *gotVWC.Webhooks[0].FailurePolicy != admissionv1.Fail {
		t.Fatalf("never-fail-open webhook should NOT trip to Ignore, got %v", *gotVWC.Webhooks[0].FailurePolicy)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-pod-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected backing pod bounce even with never-fail-open, got err=%v", err)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookAdmissionDegraded.WithLabelValues("validating", "optout-vwc", "strict.example.com", "latency_p99")); v != 1 {
		t.Fatalf("expected degraded latency_p99 gauge=1, got %v", v)
	}
}

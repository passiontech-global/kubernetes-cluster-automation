package circuitbreaker

import (
	json "encoding/json/v2"
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
		_ = json.MarshalWrite(w, promResponse{
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

// The 25-minute sawtooth: once the breaker flips to Ignore the
// apiserver stops recording rejections, so a rejection-only numerator
// falls to 0 and the breaker re-closes ~10m later. fail_open_count is
// the signal that survives the flip and holds the degraded verdict.
func TestLatencyErrorRateIncludesFailOpenAndRequestFloor(t *testing.T) {
	var queries []string
	srv := mockPromServer(t, func(query string) []promResult {
		queries = append(queries, query)
		if strings.Contains(query, "fail_open_count") {
			// rejection_count is empty here — the webhook already
			// flipped to Ignore and only fail-open admissions remain.
			return []promResult{{
				Metric: map[string]string{"name": "sawtooth.example.com"},
				Value:  [2]any{1, "0.9"},
			}}
		}
		return nil
	})
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	g, b := wgBreakerGuard(fake.NewSimpleClientset(), &now)
	g.PromEndpoint = srv.URL + "/api/v1/query"
	g.PromClient = promq.Client{HTTP: srv.Client()}
	g.WebhookErrorRateThreshold = 0.5

	sig := b.queryLatencySignals(ctx, g)
	if sig.queryError {
		t.Fatal("unexpected prom query error")
	}
	if got := sig.breaches["sawtooth.example.com"]; got != reasonErrorRate {
		t.Fatalf("breach reason = %q, want %q", got, reasonErrorRate)
	}
	if len(queries) == 0 || !strings.Contains(queries[0], "apiserver_admission_webhook_fail_open_count") {
		t.Fatalf("error-rate query omits fail_open_count: %q", queries)
	}
	if !strings.Contains(queries[0], "increase(") {
		t.Fatalf("error-rate query omits the minimum-request floor: %q", queries[0])
	}
}

// A bare `X + Y` in PromQL is an inner join on {name}: a Fail webhook
// that has NEVER fail-opened has no fail_open_count series, and an
// Ignore webhook after an apiserver restart has no rejection_count
// series. Either way the naked sum yields an EMPTY vector and the
// error-rate trip is dead. The query must carry the `or X or Y`
// rescue, and the one-sided result Prometheus returns after the
// rescue must still register as a breach.
func TestLatencyErrorRateRescuesOneSidedSeries(t *testing.T) {
	// Structural guarantee: both signals appear in the (X+Y) sum AND
	// in the rescue arms, so neither one-sided case can collapse to
	// an empty numerator.
	if n := strings.Count(promErrorRateQuery, promRejectRate); n != 2 {
		t.Fatalf("rejection_count rate must appear in (X+Y) and in `or X`, got %d", n)
	}
	if n := strings.Count(promErrorRateQuery, promFailOpenRate); n != 2 {
		t.Fatalf("fail_open_count rate must appear in (X+Y) and in `or Y`, got %d", n)
	}

	for _, tc := range []struct {
		name    string
		webhook string
	}{
		{"never fail-opened (rejection series only)", "fail-only.example.com"},
		{"Ignore after apiserver restart (fail-open series only)", "ignore-restart.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// After the `or` rescue Prometheus returns one series
			// for the webhook, carrying the surviving signal's value.
			srv := mockPromServer(t, func(query string) []promResult {
				if strings.Contains(query, "rejection_count") {
					return []promResult{{
						Metric: map[string]string{"name": tc.webhook, "error_type": "calling_webhook_error"},
						Value:  [2]any{1, "0.9"},
					}}
				}
				return nil
			})
			now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
			g, b := wgBreakerGuard(fake.NewSimpleClientset(), &now)
			g.PromEndpoint = srv.URL + "/api/v1/query"
			g.PromClient = promq.Client{HTTP: srv.Client()}
			g.WebhookErrorRateThreshold = 0.5

			sig := b.queryLatencySignals(ctx, g)
			if sig.queryError {
				t.Fatal("unexpected prom query error")
			}
			if got := sig.breaches[tc.webhook]; got != reasonErrorRate {
				t.Fatalf("breach reason = %q, want %q", got, reasonErrorRate)
			}
		})
	}
}

// The p99 latency signal must carry the same request floor as the
// error-rate signal — a single slow admission on a low-traffic
// webhook must not trip the breaker.
func TestLatencyP99QueryHasRequestFloor(t *testing.T) {
	if !strings.Contains(promLatencyP99Query, "increase(") ||
		!strings.Contains(promLatencyP99Query, ">= 5") {
		t.Fatalf("p99 query lost its minimum-request floor: %q", promLatencyP99Query)
	}
}

// A URL webhook has no measurable backend (svcEffective == -1). A
// latency trip there freezes in evalStillBroken forever — no census
// evidence can ever confirm its recovery — so only Service-backed
// webhooks may be tripped by the Prometheus signal.
func TestLatencyTripSkipsURLWebhook(t *testing.T) {
	metrics.WebhookAdmissionDegraded.Reset()
	metrics.WebhookCircuitBroken.Reset()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "backend"}}
	pod := wgPod("backend", "wh-pod-0", 30*time.Minute)
	urlVal := "https://webhook.example.com/validate"
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "latency-url"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name:          "url.example.com",
				FailurePolicy: new(admissionv1.Fail),
				ClientConfig:  admissionv1.WebhookClientConfig{URL: &urlVal},
			},
			{
				Name:          "svc.example.com",
				FailurePolicy: new(admissionv1.Fail),
				ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("backend", "wh-svc")},
			},
		},
	}
	cs := fake.NewSimpleClientset(ns, mwc, readySliceWithPod("backend", "wh-svc", "wh-pod-0"), pod)
	srv := mockPromServer(t, func(query string) []promResult {
		if strings.Contains(query, "duration_seconds_bucket") {
			return []promResult{
				{Metric: map[string]string{"name": "url.example.com"}, Value: [2]any{1, "9.5"}},
				{Metric: map[string]string{"name": "svc.example.com"}, Value: [2]any{1, "9.5"}},
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

	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=0: %v", err)
	}
	now = now.Add(20 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=20m: %v", err)
	}
	got, _ := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "latency-url", metav1.GetOptions{})
	if fp := *got.Webhooks[0].FailurePolicy; fp != admissionv1.Fail {
		t.Fatalf("URL webhook must never be latency-tripped, got %q", fp)
	}
	if fp := *got.Webhooks[1].FailurePolicy; fp != admissionv1.Ignore {
		t.Fatalf("Service-backed webhook must be latency-tripped, got %q", fp)
	}
}

// RestoreOnly (kill-switch off) must not re-arm latency holds: querying
// Prometheus there could hold a recovered entry Ignore indefinitely.
func TestRestoreOnlySkipsLatencyQuery(t *testing.T) {
	queries := 0
	srv := mockPromServer(t, func(query string) []promResult {
		queries++
		return []promResult{{
			Metric: map[string]string{"name": "x.example.com"},
			Value:  [2]any{1, "0.9"},
		}}
	})
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	g, b := wgBreakerGuard(fake.NewSimpleClientset(), &now)
	g.PromEndpoint = srv.URL + "/api/v1/query"
	g.PromClient = promq.Client{HTTP: srv.Client()}
	g.WebhookErrorRateThreshold = 0.5
	if err := b.RestoreOnly(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatalf("RestoreOnly: %v", err)
	}
	if queries != 0 {
		t.Fatalf("RestoreOnly issued %d Prometheus queries, want 0", queries)
	}
}

func TestRestoreOnlyClearsDegradedSinceOnReenable(t *testing.T) {
	metrics.WebhookAdmissionDegraded.Reset()
	metrics.WebhookCircuitBroken.Reset()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "backend"}}
	pod := wgPod("backend", "wh-pod-0", 30*time.Minute)
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "reenable-mwc"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "slow.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("backend", "wh-svc")},
		}},
	}
	cs := fake.NewSimpleClientset(ns, mwc, readySliceWithPod("backend", "wh-svc", "wh-pod-0"), pod)
	testutil.EmulateEviction(cs)

	srv := mockPromServer(t, func(query string) []promResult {
		if strings.Contains(query, "rejection_count") {
			return []promResult{{
				Metric: map[string]string{"name": "slow.example.com", "error_type": "calling_webhook_error"},
				Value:  [2]any{1, "0.8"},
			}}
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

	// T=0: breaker enabled, observes breach -> degradedSince stamped at T=0.
	t.Setenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED", "true")
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=0: %v", err)
	}

	// T=5m: disable breaker -> RestoreOnly runs and prunes stale degradedSince.
	now = now.Add(5 * time.Minute)
	t.Setenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED", "false")
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("RestoreOnly T=5m: %v", err)
	}

	// T=20m (past 15m from T=0): re-enable breaker with Prom still breaching.
	// Must NOT trip, bounce pod, or emit degraded immediately — needs a fresh window from T=20m.
	now = now.Add(15 * time.Minute)
	t.Setenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED", "true")
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=20m: %v", err)
	}
	gotMWC, _ := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "reenable-mwc", metav1.GetOptions{})
	if *gotMWC.Webhooks[0].FailurePolicy != admissionv1.Fail {
		t.Fatalf("stale degradedSince tripped immediately on re-enable, got %v", *gotMWC.Webhooks[0].FailurePolicy)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-pod-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected pod still present at T=20m, got %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookAdmissionDegraded.WithLabelValues("mutating", "reenable-mwc", "slow.example.com", "error_rate")); v != 0 {
		t.Fatalf("expected WebhookAdmissionDegraded=0 on re-enable at T=20m, got %v", v)
	}

	// T=30m (10m from T=20m): degraded gauge + pod bounce.
	now = now.Add(10 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=30m: %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookAdmissionDegraded.WithLabelValues("mutating", "reenable-mwc", "slow.example.com", "error_rate")); v != 1 {
		t.Fatalf("expected WebhookAdmissionDegraded=1 at T=30m, got %v", v)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-pod-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected eviction at T=30m, got %v", err)
	}

	// T=35m (15m from T=20m): trips to Ignore.
	now = now.Add(5 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatalf("sweep T=35m: %v", err)
	}
	gotMWC, _ = cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "reenable-mwc", metav1.GetOptions{})
	if *gotMWC.Webhooks[0].FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected Ignore after fresh 15m window at T=35m, got %v", *gotMWC.Webhooks[0].FailurePolicy)
	}
}

func TestLatencyQueryErrorPreservesDegradedSince(t *testing.T) {
	metrics.WebhookAdmissionDegraded.Reset()
	metrics.WebhookCircuitBroken.Reset()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "backend"}}
	pod := wgPod("backend", "wh-pod-0", 30*time.Minute)
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "qerr-mwc"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "slow.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("backend", "wh-svc")},
		}},
	}
	cs := fake.NewSimpleClientset(ns, mwc, readySliceWithPod("backend", "wh-svc", "wh-pod-0"), pod)
	testutil.EmulateEviction(cs)

	var promDown atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if promDown.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = r.ParseForm()
		var res []promResult
		if strings.Contains(r.FormValue("query"), "rejection_count") {
			res = []promResult{{
				Metric: map[string]string{"name": "slow.example.com", "error_type": "calling_webhook_error"},
				Value:  [2]any{1, "0.8"},
			}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, promResponse{
			Status: "success",
			Data:   promData{ResultType: "vector", Result: res},
		})
	}))
	t.Cleanup(srv.Close)

	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	g, b := wgBreakerGuard(cs, &now)
	g.Queue = "admission-webhook-guard"
	g.PromEndpoint = srv.URL + "/api/v1/query"
	g.PromClient = promq.Client{HTTP: srv.Client()}
	g.WebhookErrorRateThreshold = 0.5
	g.WebhookLatencyP99Seconds = 5.0
	g.LatencyBreakerTripEnabled = true
	b.degradedThreshold = 10 * time.Minute
	b.latencyTripThreshold = 15 * time.Minute

	// T=0: breach observed, degradedSince stamped.
	if err := b.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatalf("sweep T=0: %v", err)
	}

	// T=5m: Prometheus returns 500 -> queryError=true must preserve degradedSince.
	now = now.Add(5 * time.Minute)
	promDown.Store(true)
	if err := b.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatalf("sweep T=5m: %v", err)
	}

	// T=15m: Prometheus recovers, still breaching -> trips using preserved T=0 timestamp.
	now = now.Add(10 * time.Minute)
	promDown.Store(false)
	if err := b.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatalf("sweep T=15m: %v", err)
	}
	gotMWC, _ := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "qerr-mwc", metav1.GetOptions{})
	if *gotMWC.Webhooks[0].FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected degradedSince to survive Prom queryError and trip to Ignore at T=15m, got %v",
			*gotMWC.Webhooks[0].FailurePolicy)
	}
}

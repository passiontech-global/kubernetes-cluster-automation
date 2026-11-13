// sweep_trip_test.go — the trip/recover core: threshold streaks, the
// strategic-merge patch payload, the recover-confirm gate, the env
// kill-switch and the never-trip paths.
package circuitbreaker

import (
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// C1 circuit breaker — tests
// ---------------------------------------------------------------------------

// A fail-closed sub-webhook whose Service reports 0 Ready endpoints
// does NOT trip on first sight nor inside the threshold — only a
// continuous >= DeadThreshold streak flips it to Ignore and
// records the name in the annotation.
func TestWebhookCircuitBreakerTripsAfterThreshold(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-mwc"},
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
		wgEndpointSlice("backend", "dead-svc", 0, 1), // 0 ready, 1 unready
		mwc)
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	patches := wgPatchCounter(cs)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-mwc", "dead.example.com")
	})
	tripsBefore := wgTripCount(t, guardstate.KindMutating, "cb-mwc")

	// First sighting — recorded, not tripped.
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-mwc", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("first sighting must not trip, failurePolicy=%q", got)
	}

	// Inside the threshold — still no trip.
	now = now.Add(4 * time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-mwc", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("4m streak < %s must not trip, failurePolicy=%q",
			DeadThreshold, got)
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("breaker must not patch before the threshold, got %d patch(es)", got)
	}

	// Past the threshold — trip.
	now = now.Add(2 * time.Minute) // 6m of dead backend
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-mwc", "dead.example.com"); got != admissionv1.Ignore {
		t.Fatalf("expected failurePolicy=Ignore after trip, got %q", got)
	}
	anno, ok := wgMutatingAnno(t, cs, "cb-mwc")
	if !ok || anno != "dead.example.com" {
		t.Fatalf("annotation = %q (present=%v), want %q", anno, ok, "dead.example.com")
	}
	if got := wgBrokenGauge(t, guardstate.KindMutating, "cb-mwc", "dead.example.com"); got != 1 {
		t.Fatalf("WebhookCircuitBroken = %v, want 1", got)
	}
	if got := wgTripCount(t, guardstate.KindMutating, "cb-mwc"); got != tripsBefore+1 {
		t.Fatalf("trips = %v, want %v", got, tripsBefore+1)
	}
}

// The trip lands as ONE strategic-merge patch carrying both the
// flipped failurePolicy (a {"name": X, "failurePolicy": ...} entry —
// merged by name, never a whole-array replace) and the annotation —
// inspect the payload.
func TestWebhookCircuitBreakerPatchContents(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-doc"},
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
		wgEndpointSlice("backend", "dead-svc", 0, 2),
		mwc)
	var doc map[string]any
	var patchType string
	cs.PrependReactor("patch", "mutatingwebhookconfigurations",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			pa := action.(ktesting.PatchAction)
			patchType = string(pa.GetPatchType())
			if err := json.Unmarshal(pa.GetPatch(), &doc); err != nil {
				t.Errorf("unmarshal patch: %v", err)
			}
			return false, nil, nil // passthrough
		})
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DeadThreshold + time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if doc == nil {
		t.Fatal("no patch issued for the trip")
	}
	if patchType != string(types.StrategicMergePatchType) {
		t.Fatalf("patch type = %s, want StrategicMergePatchType", patchType)
	}
	annos, _ := doc["metadata"].(map[string]any)["annotations"].(map[string]any)
	if got := annos[guardstate.CircuitBrokenAnno]; got != "dead.example.com" {
		t.Fatalf("patch annotation = %v, want %q", got, "dead.example.com")
	}
	whs, _ := doc["webhooks"].([]any)
	if len(whs) != 1 {
		t.Fatalf("patch webhooks = %v, want 1 entry", whs)
	}
	entry, _ := whs[0].(map[string]any)
	if len(entry) != 2 || entry["name"] != "dead.example.com" ||
		entry["failurePolicy"] != "Ignore" {
		t.Fatalf("merge entry = %v, want exactly {name, failurePolicy:Ignore}", entry)
	}
}

// Recovery: once the Service reports a Ready endpoint the breaker
// restores failurePolicy=Fail, clears the now-empty annotation and
// deletes the gauge series outright — a cleared breaker emits no
// series, not a 0 (DeleteLabelValues doubles as the exists-probe).
// Exercised on the validating kind.
func TestWebhookCircuitBreakerRecoversAndClears(t *testing.T) {
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{{
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
		vwc)
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)

	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DeadThreshold + time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgValidatingFP(t, cs, "cb-vwc", "dead.example.com"); got != admissionv1.Ignore {
		t.Fatalf("precondition: expected tripped webhook, failurePolicy=%q", got)
	}
	tripsAfterTrip := wgTripCount(t, guardstate.KindValidating, "cb-vwc")

	// Backend comes back — one Ready endpoint.
	if _, err := cs.DiscoveryV1().EndpointSlices("backend").Update(ctx,
		wgEndpointSlice("backend", "dead-svc", 1, 0), metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update slice: %v", err)
	}
	// First healthy sweep DEFERS: one healthy sweep is not a
	// recovery (a 0↔1 flapping backend would trip and recover in
	// alternating sweeps, churning the WebhookConfiguration). The
	// entry stays broken — policy re-asserted Ignore, series still
	// held, annotation still listing the entry.
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgValidatingFP(t, cs, "cb-vwc", "dead.example.com"); got != admissionv1.Ignore {
		t.Fatalf("first healthy sweep must defer the recover, got %q", got)
	}
	if anno, ok := wgValidatingAnno(t, cs, "cb-vwc"); !ok {
		t.Fatal("deferred recover must keep the circuit-broken annotation")
	} else if len(anno) == 0 {
		t.Fatalf("deferred recover must keep a non-empty annotation, got %q", anno)
	}
	if !metrics.WebhookCircuitBroken.DeleteLabelValues(
		guardstate.KindValidating, "cb-vwc", "dead.example.com") {
		t.Fatal("deferred recover must keep the WebhookCircuitBroken series held")
	}
	// Second CONSECUTIVE healthy sweep confirms: Fail restored,
	// annotation cleared, series deleted.
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgValidatingFP(t, cs, "cb-vwc", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("expected failurePolicy=Fail after recovery, got %q", got)
	}
	if anno, ok := wgValidatingAnno(t, cs, "cb-vwc"); ok {
		t.Fatalf("annotation must be removed when empty, still %q", anno)
	}
	// The probe runs before any WithLabelValues read — the gauge call
	// itself would recreate the series at 0 and mask the deletion.
	if metrics.WebhookCircuitBroken.DeleteLabelValues(
		guardstate.KindValidating, "cb-vwc", "dead.example.com") {
		t.Fatal("recovery must delete the WebhookCircuitBroken series, not park it at 0")
	}
	if got := wgTripCount(t, guardstate.KindValidating, "cb-vwc"); got != tripsAfterTrip {
		t.Fatalf("recovery must not count as a trip: %v != %v", got, tripsAfterTrip)
	}
}

// The kill-switch: WEBHOOK_CIRCUIT_BREAKER_ENABLED=false leaves
// fail-closed webhooks on dead Services untouched forever.
func TestWebhookCircuitBreakerDisabledByEnv(t *testing.T) {
	t.Setenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED", "false")
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-off"},
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
	patches := wgPatchCounter(cs)
	b := &Breaker{}
	g := &guardstate.Guard{CS: cs, Dyn: wgDyn()}
	for range 3 {
		if err := runBreaker(ctx, g, b); err != nil {
			t.Fatal(err)
		}
	}
	if got := wgMutatingFP(t, cs, "cb-off", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("disabled breaker must not touch failurePolicy, got %q", got)
	}
	if _, ok := wgMutatingAnno(t, cs, "cb-off"); ok {
		t.Fatal("disabled breaker must not write the annotation")
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("disabled breaker must not patch, got %d patch(es)", got)
	}
}

// A Service with Ready endpoints — including a nil conditions.ready,
// which the API treats as ready — never accumulates a streak.
func TestWebhookCircuitBreakerReadyBackendNeverTrips(t *testing.T) {
	for _, tc := range []struct {
		name  string
		slice *discoveryv1.EndpointSlice
	}{
		{"explicit ready", wgEndpointSlice("backend", "live-svc", 1, 0)},
		{"nil ready counts ready", wgNilReadySlice("backend", "live-svc")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mwc := &admissionv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "cb-live"},
				Webhooks: []admissionv1.MutatingWebhook{{
					Name:          "live.example.com",
					FailurePolicy: new(admissionv1.Fail),
					ClientConfig: admissionv1.WebhookClientConfig{
						Service: wgSvcRef("backend", "live-svc"),
					},
				}},
			}
			cs := fake.NewSimpleClientset(
				wgNamespace("kube-system"), wgNamespace("backend"),
				wgService("backend", "live-svc"), tc.slice, mwc)
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
			if got := wgMutatingFP(t, cs, "cb-live", "live.example.com"); got != admissionv1.Fail {
				t.Fatalf("ready backend must never trip, failurePolicy=%q", got)
			}
			if got := atomic.LoadInt32(patches); got != 0 {
				t.Fatalf("ready backend must not be patched, got %d patch(es)", got)
			}
		})
	}
}

// Entries already fail-open (failurePolicy=Ignore) are never
// tracked — there is no deadlock to break.
func TestWebhookCircuitBreakerIgnorePolicyNeverTrips(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-open"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "open.example.com",
			FailurePolicy: new(admissionv1.Ignore),
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
	if _, ok := wgMutatingAnno(t, cs, "cb-open"); ok {
		t.Fatal("an Ignore entry must never enter the annotation")
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("Ignore entry must not be patched, got %d patch(es)", got)
	}
}

// A failed patch on one config must not abort the sweep — the sibling
// config still trips, and the failure surfaces as an error.
func TestWebhookCircuitBreakerPatchFailureDoesNotAbort(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-m-ok"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead-m.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-v-fail"},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:          "dead-v.example.com",
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
		mwc, vwc)
	cs.PrependReactor("patch", "validatingwebhookconfigurations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-m-ok", "dead-m.example.com")
	})
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DeadThreshold + time.Minute)
	err := runBreaker(ctx, g, b)
	if err == nil {
		t.Fatal("expected the aggregated circuit breaker patch failure")
	}
	if !strings.Contains(err.Error(), "circuit breaker") {
		t.Fatalf("expected a circuit breaker error, got %v", err)
	}
	if got := wgMutatingFP(t, cs, "cb-m-ok", "dead-m.example.com"); got != admissionv1.Ignore {
		t.Fatalf("sibling config must still trip, failurePolicy=%q", got)
	}
	if got := wgValidatingFP(t, cs, "cb-v-fail", "dead-v.example.com"); got != admissionv1.Fail {
		t.Fatalf("failed config keeps its policy, failurePolicy=%q", got)
	}
}

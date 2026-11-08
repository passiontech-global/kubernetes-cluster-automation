// sweep_facade_test.go — the C1 circuit-breaker facade suites
// relocated from the webhookguard package when the duty moved to this
// leaf subpackage: mechanical moves. They drive the same path the
// facade's run() drives — shared snapshot taken once behind the
// Enabled() lever, then Breaker.Sweep — via runBreaker below.
package circuitbreaker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

func wgDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynWithCRDs(objs...)
}

// runBreaker drives one facade sweep's breaker leg — the shared
// snapshot is taken once and the breaker runs behind its Enabled()
// lever, exactly as webhookGuard.run does.
func runBreaker(ctx context.Context, g *guardstate.Guard, b *Breaker) error {
	if !Enabled() {
		return nil
	}
	return b.Sweep(ctx, g.TakeSnapshot(ctx))
}

// ---------------------------------------------------------------------------
// Builders (wg-prefixed, relocated verbatim from the facade suite)
// ---------------------------------------------------------------------------

func wgNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func wgService(ns, name string) *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
}

func wgSvcRef(ns, name string) *admissionv1.ServiceReference {
	return &admissionv1.ServiceReference{Namespace: ns, Name: name}
}

func wgMutatingHook(name string, svc *admissionv1.ServiceReference) admissionv1.MutatingWebhook {
	return admissionv1.MutatingWebhook{
		Name:         name,
		ClientConfig: admissionv1.WebhookClientConfig{Service: svc},
	}
}

func wgValidatingHook(name string, svc *admissionv1.ServiceReference) admissionv1.ValidatingWebhook {
	return admissionv1.ValidatingWebhook{
		Name:         name,
		ClientConfig: admissionv1.WebhookClientConfig{Service: svc},
	}
}

// wgMutatingNames returns the webhook names of a MutatingWebhookConfiguration.
func wgMutatingNames(t *testing.T, cs *fake.Clientset, cfg string) []string {
	t.Helper()
	got, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Get(ctx, cfg, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get mutatingwebhookconfiguration %s: %v", cfg, err)
	}
	names := make([]string, 0, len(got.Webhooks))
	for _, w := range got.Webhooks {
		names = append(names, w.Name)
	}
	return names
}

// wgValidatingNames returns the webhook names of a ValidatingWebhookConfiguration.
func wgValidatingNames(t *testing.T, cs *fake.Clientset, cfg string) []string {
	t.Helper()
	got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Get(ctx, cfg, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get validatingwebhookconfiguration %s: %v", cfg, err)
	}
	names := make([]string, 0, len(got.Webhooks))
	for _, w := range got.Webhooks {
		names = append(names, w.Name)
	}
	return names
}

func wgAssertNames(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("webhook names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("webhook names = %v, want %v", got, want)
		}
	}
}

// wgPatchCounter installs a passthrough reactor that counts every patch call.
func wgPatchCounter(cs *fake.Clientset) *int32 {
	var calls int32
	cs.PrependReactor("patch", "*",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			atomic.AddInt32(&calls, 1)
			return false, nil, nil // passthrough — let the tracker apply it
		})
	return &calls
}

// ---------------------------------------------------------------------------
// C1 circuit breaker — builders
// ---------------------------------------------------------------------------

// wgBreakerGuard builds a guard with a scripted clock — advance *now
// between runs to walk the deadSince streak past DeadThreshold.
// The endpointProber stub answers "responsive" for every IP so the
// W9-CP1 brownout probe never fires in tests that predate it — those
// fixtures have no TLS server to dial anyway.
func wgBreakerGuard(cs *fake.Clientset, now *time.Time) (*guardstate.Guard, *Breaker) {
	return &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return *now },
		EndpointProber: func(context.Context, string, int32) bool {
			return true
		}}, &Breaker{}
}

func wgFP(v admissionv1.FailurePolicyType) *admissionv1.FailurePolicyType {
	return &v
}

// wgEndpointSlice builds a discovery.k8s.io/v1 slice carrying `ready`
// ready + `notReady` unready endpoints, bound to svc via the
// kubernetes.io/service-name label.
func wgEndpointSlice(ns, svc string, ready, notReady int) *discoveryv1.EndpointSlice {
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: svc + "-slice",
			Labels: map[string]string{discoveryv1.LabelServiceName: svc},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	up, down := true, false
	for i := 0; i < ready; i++ {
		es.Endpoints = append(es.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{fmt.Sprintf("10.10.0.%d", i+1)},
			Conditions: discoveryv1.EndpointConditions{Ready: &up},
		})
	}
	for i := 0; i < notReady; i++ {
		es.Endpoints = append(es.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{fmt.Sprintf("10.10.1.%d", i+1)},
			Conditions: discoveryv1.EndpointConditions{Ready: &down},
		})
	}
	return es
}

// wgNilReadySlice builds a slice whose endpoint leaves Ready unset —
// nil counts as ready per the EndpointConditions contract.
func wgNilReadySlice(ns, svc string) *discoveryv1.EndpointSlice {
	es := wgEndpointSlice(ns, svc, 0, 0)
	es.Endpoints = []discoveryv1.Endpoint{{
		Addresses:  []string{"10.10.9.9"},
		Conditions: discoveryv1.EndpointConditions{}, // Ready nil → ready
	}}
	return es
}

// wgMutatingFP returns the effective failurePolicy of one sub-webhook
// ("" when unset) — the observable result of a breaker patch.
func wgMutatingFP(t *testing.T, cs *fake.Clientset, cfg, hook string) admissionv1.FailurePolicyType {
	t.Helper()
	got, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Get(ctx, cfg, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get mutatingwebhookconfiguration %s: %v", cfg, err)
	}
	for _, w := range got.Webhooks {
		if w.Name == hook {
			if w.FailurePolicy == nil {
				return ""
			}
			return *w.FailurePolicy
		}
	}
	t.Fatalf("webhook %q not found in %s", hook, cfg)
	return ""
}

func wgValidatingFP(t *testing.T, cs *fake.Clientset, cfg, hook string) admissionv1.FailurePolicyType {
	t.Helper()
	got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Get(ctx, cfg, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get validatingwebhookconfiguration %s: %v", cfg, err)
	}
	for _, w := range got.Webhooks {
		if w.Name == hook {
			if w.FailurePolicy == nil {
				return ""
			}
			return *w.FailurePolicy
		}
	}
	t.Fatalf("webhook %q not found in %s", hook, cfg)
	return ""
}

// wgMutatingAnno reads the circuit-broken annotation of a config;
// ok=false means the key is absent (fully cleared).
func wgMutatingAnno(t *testing.T, cs *fake.Clientset, cfg string) (string, bool) {
	t.Helper()
	got, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Get(ctx, cfg, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get mutatingwebhookconfiguration %s: %v", cfg, err)
	}
	v, ok := got.Annotations[guardstate.CircuitBrokenAnno]
	return v, ok
}

func wgValidatingAnno(t *testing.T, cs *fake.Clientset, cfg string) (string, bool) {
	t.Helper()
	got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Get(ctx, cfg, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get validatingwebhookconfiguration %s: %v", cfg, err)
	}
	v, ok := got.Annotations[guardstate.CircuitBrokenAnno]
	return v, ok
}

// wgBrokenGauge reads the WebhookCircuitBroken series for one
// (kind, config, webhook) label set.
func wgBrokenGauge(t *testing.T, kind, cfg, hook string) float64 {
	t.Helper()
	return ptestutil.ToFloat64(
		metrics.WebhookCircuitBroken.WithLabelValues(kind, cfg, hook))
}

// wgTripCount reads the WebhookCircuitBreakerTripsTotal series — call
// before and after and compare deltas (the counter is process-global).
func wgTripCount(t *testing.T, kind, cfg string) float64 {
	t.Helper()
	return ptestutil.ToFloat64(
		metrics.WebhookCircuitBreakerTripsTotal.WithLabelValues(kind, cfg))
}

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
			FailurePolicy: wgFP(admissionv1.Fail),
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
			FailurePolicy: wgFP(admissionv1.Fail),
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
			FailurePolicy: wgFP(admissionv1.Fail),
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
			FailurePolicy: wgFP(admissionv1.Fail),
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
	for i := 0; i < 3; i++ {
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
					FailurePolicy: wgFP(admissionv1.Fail),
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
			FailurePolicy: wgFP(admissionv1.Ignore),
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
			FailurePolicy: wgFP(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-v-fail"},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:          "dead-v.example.com",
			FailurePolicy: wgFP(admissionv1.Fail),
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

// Annotation names that no longer match a live sub-webhook drop out —
// e.g. after the orphan sweep removed the entry — while genuinely
// broken names are kept.
func TestWebhookCircuitBreakerDropsStaleAnnotationNames(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cb-stale",
			Annotations: map[string]string{
				guardstate.CircuitBrokenAnno: "gone.example.com,still-dead.example.com",
			},
		},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "still-dead.example.com",
			FailurePolicy: wgFP(admissionv1.Ignore),
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
	b := &Breaker{}
	g := &guardstate.Guard{CS: cs, Dyn: wgDyn()}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-stale", "still-dead.example.com")
	})
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	anno, ok := wgMutatingAnno(t, cs, "cb-stale")
	if !ok || anno != "still-dead.example.com" {
		t.Fatalf("annotation = %q (present=%v), want %q",
			anno, ok, "still-dead.example.com")
	}
}

// A webhook config DELETED while circuit-broken must not pin the alert
// forever — the sweep prunes every WebhookCircuitBroken series whose
// kind/config/webhook tuple it did not re-see.
// DeleteLabelValues doubles as the exists-probe: it reports whether a
// series was still registered (and removes it if so).
func TestWebhookCircuitBreakerPrunesSeriesForDeletedConfig(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-deleted"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: wgFP(admissionv1.Fail),
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
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-deleted", "dead.example.com")
	})

	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DeadThreshold + time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgBrokenGauge(t, guardstate.KindMutating, "cb-deleted", "dead.example.com"); got != 1 {
		t.Fatalf("precondition: WebhookCircuitBroken = %v, want 1", got)
	}

	// The whole config vanishes — the next sweep never re-sees the
	// tuple, so its =1 series must be deleted, not left firing.
	if err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Delete(ctx, "cb-deleted", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete config: %v", err)
	}
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if metrics.WebhookCircuitBroken.DeleteLabelValues(
		guardstate.KindMutating, "cb-deleted", "dead.example.com") {
		t.Fatal("WebhookCircuitBroken series for a deleted config must be pruned")
	}
}

// A config recreated under the SAME name but without the
// circuit-broken annotation — the outage resolved before GitOps
// reapplied it — must not inherit the old object's =1 series: the
// sweep that no longer re-sees a broken tuple prunes it.
// (A recreated config whose backend is STILL dead legitimately
// re-trips the same sweep — deadSince deliberately survives a trip so
// a failed patch retries immediately — so the healthy-backend case is
// the one that proves the prune.)
func TestWebhookCircuitBreakerPrunesSeriesForRecreatedConfig(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-recreated"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: wgFP(admissionv1.Fail),
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
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-recreated", "dead.example.com")
	})

	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DeadThreshold + time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgBrokenGauge(t, guardstate.KindMutating, "cb-recreated", "dead.example.com"); got != 1 {
		t.Fatalf("precondition: WebhookCircuitBroken = %v, want 1", got)
	}

	// Delete + recreate under the same name with failurePolicy=Fail
	// and no annotation — and the Service is healthy again by then
	// (the fix and the re-apply land together).
	if err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Delete(ctx, "cb-recreated", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete config: %v", err)
	}
	fresh := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-recreated"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: wgFP(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	if _, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Create(ctx, fresh, metav1.CreateOptions{}); err != nil {
		t.Fatalf("recreate config: %v", err)
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("backend").Update(ctx,
		wgEndpointSlice("backend", "dead-svc", 1, 0), metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update slice: %v", err)
	}
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}

	if metrics.WebhookCircuitBroken.DeleteLabelValues(
		guardstate.KindMutating, "cb-recreated", "dead.example.com") {
		t.Fatal("WebhookCircuitBroken series for a recreated (un-annotated) config must be pruned")
	}
	if got := wgMutatingFP(t, cs, "cb-recreated", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("recreated webhook keeps its declared policy, failurePolicy=%q", got)
	}
	if anno, ok := wgMutatingAnno(t, cs, "cb-recreated"); ok {
		t.Fatalf("recreated config must not carry the annotation, still %q", anno)
	}
}

// ---------------------------------------------------------------------------
// W5.5 — partitioned-node-aware circuit breaker
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
// nodeName — the shape that exercises the W5.5 effective-ready math.
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

// The W5.5 signature: every Ready endpoint of the backend Service sits
// on a partitioned node — raw > 0, effective == 0 — so the breaker
// trips on the 90s partition threshold instead of waiting 5m.
func TestWebhookCircuitBreakerPartitionedBackendTripsFast(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-part"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: wgFP(admissionv1.Fail),
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
			FailurePolicy: wgFP(admissionv1.Fail),
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
			FailurePolicy: wgFP(admissionv1.Fail),
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

// ---------------------------------------------------------------------------
// W9-CP1 — brownout probe, pod bounce, unresponsive breaker
// ---------------------------------------------------------------------------

// wgPod builds a Running+Ready Pod fixture for the bounce path.
func wgPod(ns, name string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
}

// wgHungSlice builds a slice whose single Ready endpoint targets a
// Pod and carries no NodeName — effective-ready by benefit of the
// doubt, exactly the brownout shape W9-CP1 probes.
func wgHungSlice(ns, svc, pod string) *discoveryv1.EndpointSlice {
	es := wgEndpointSlice(ns, svc, 0, 0)
	up := true
	es.Endpoints = []discoveryv1.Endpoint{{
		Addresses:  []string{"10.10.7.7"},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Name: pod},
		Conditions: discoveryv1.EndpointConditions{Ready: &up},
	}}
	return es
}

// A webhook backend whose Ready endpoints ALL fail the TCP+TLS
// handshake is "unresponsive": stage 1 bounces the oldest Ready
// backing pod immediately (15m per-service cooldown), and stage 2
// trips the breaker to Ignore after the 90s partition threshold —
// then restores Fail once a probe answers again.
func TestWebhookCircuitBreakerUnresponsiveTripsAndBounces(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "brownout"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "hung.example.com",
			FailurePolicy: wgFP(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "hung-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "hung-svc"),
		wgHungSlice("backend", "hung-svc", "wh-old"),
		wgPod("backend", "wh-old", 48*time.Hour),
		wgPod("backend", "wh-new", time.Hour),
		mwc)
	now := time.Unix(1_700_000_000, 0)
	// endpointProber=false — every handshake fails: the pods are hung.
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return now },
		EndpointProber: func(context.Context, string, int32) bool {
			return false
		}}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "brownout", "hung.example.com")
	})

	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	// Stage 1 fired on first sight: the OLDEST Ready pod is gone,
	// its younger sibling survives.
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-old",
		metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("oldest hung pod must be bounced, get err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-new",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("younger pod must survive the single-pod bounce: %v", err)
	}
	// Too early for the breaker — inside the 90s partition window.
	if got := wgMutatingFP(t, cs, "brownout", "hung.example.com"); got != admissionv1.Fail {
		t.Fatalf("unresponsive backend must not trip inside threshold, failurePolicy=%q", got)
	}

	// Past the threshold the breaker trips to Ignore.
	now = now.Add(PartitionedThreshold + time.Second)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "brownout", "hung.example.com"); got != admissionv1.Ignore {
		t.Fatalf("unresponsive backend past threshold must trip to Ignore, got %q", got)
	}
	// Bounce cooldown: the surviving pod is NOT deleted again.
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-new",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("15m bounce cooldown must protect the surviving pod: %v", err)
	}

	// The pod came back healthy — the next probe answers. The FIRST
	// responsive sweep only DEFERS (the recover-confirm gate — one
	// healthy sweep is not a recovery); the SECOND confirms the
	// declared Fail policy.
	g.EndpointProber = func(context.Context, string, int32) bool { return true }
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "brownout", "hung.example.com"); got != admissionv1.Ignore {
		t.Fatalf("first responsive sweep must defer the recover, got %q", got)
	}
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "brownout", "hung.example.com"); got != admissionv1.Fail {
		t.Fatalf("responsive backend must recover to Fail, got %q", got)
	}
}

// A responsive backend never bounces and never trips — the probe's
// ANY-success verdict keeps one healthy replica honest even when a
// sibling hangs.
func TestWebhookCircuitBreakerResponsiveSkipsBounce(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy-brownout"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "ok.example.com",
			FailurePolicy: wgFP(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "ok-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "ok-svc"),
		wgHungSlice("backend", "ok-svc", "ok-pod"),
		wgPod("backend", "ok-pod", 48*time.Hour),
		mwc)
	now := time.Unix(1_700_000_000, 0)
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return now },
		EndpointProber: func(context.Context, string, int32) bool {
			return true // at least one endpoint answers
		}}
	for i := 0; i < 3; i++ {
		if err := runBreaker(ctx, g, b); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "ok-pod",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("responsive backend must never bounce its pod: %v", err)
	}
	if got := wgMutatingFP(t, cs, "healthy-brownout", "ok.example.com"); got != admissionv1.Fail {
		t.Fatalf("responsive backend must never trip, got %q", got)
	}
}

// A webhook deleted from the config while its patch keeps failing must
// not pin its WebhookCircuitBroken series: the patch-failure
// carry-forward re-asserts only the sub-webhooks still in the
// config's snapshot views, so the sweep-end prune forgets the deleted
// webhook's series while a still-present one survives.
func TestWebhookCircuitBreakerCarryForwardSkipsDeletedWebhooks(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-carry"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name:          "keep.example.com",
				FailurePolicy: wgFP(admissionv1.Fail),
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: wgSvcRef("backend", "dead-svc"),
				},
			},
			{
				Name:          "gone.example.com",
				FailurePolicy: wgFP(admissionv1.Fail),
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: wgSvcRef("backend", "dead-svc"),
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		mwc)
	keepLV := []string{guardstate.KindMutating, "cb-carry", "keep.example.com"}
	goneLV := []string{guardstate.KindMutating, "cb-carry", "gone.example.com"}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(keepLV...)
		metrics.WebhookCircuitBroken.DeleteLabelValues(goneLV...)
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
	if got := ptestutil.ToFloat64(metrics.WebhookCircuitBroken.WithLabelValues(keepLV...)); got != 1 {
		t.Fatalf("keep series = %v, want both webhooks tripped", got)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookCircuitBroken.WithLabelValues(goneLV...)); got != 1 {
		t.Fatalf("gone series = %v, want both webhooks tripped", got)
	}

	// A concurrent writer deletes gone.example.com from the config,
	// then every patch starts failing — the trip state is now
	// unverifiable and the carry-forward decides what survives.
	live, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Get(ctx, "cb-carry", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	live.Webhooks = live.Webhooks[:1] // drop gone.example.com
	if err := cs.Tracker().Update(
		admissionv1.SchemeGroupVersion.WithResource("mutatingwebhookconfigurations"),
		live, ""); err != nil {
		t.Fatal(err)
	}
	cs.PrependReactor("patch", "mutatingwebhookconfigurations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	for sweep := 3; sweep <= 4; sweep++ {
		now = now.Add(DeadThreshold + time.Minute)
		if err := runBreaker(ctx, g, b); err == nil {
			t.Fatal("expected the aggregated circuit breaker patch failure")
		}
		if got := ptestutil.ToFloat64(metrics.WebhookCircuitBroken.WithLabelValues(keepLV...)); got != 1 {
			t.Fatalf("sweep %d: webhook still in the census must survive the failed patch, got %v", sweep, got)
		}
		if metrics.WebhookCircuitBroken.DeleteLabelValues(goneLV...) {
			t.Fatalf("sweep %d: deleted webhook's series must be forgotten, not re-pinned", sweep)
		}
	}
}

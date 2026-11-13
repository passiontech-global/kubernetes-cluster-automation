// sweep_facade_test.go — shared fixtures for the C1 circuit-breaker
// facade suites (split by scenario into sweep_trip/sweep_series/
// sweep_partition/sweep_bounce_test.go): builders, probe/annotation
// readers and the runBreaker driver the scenario files share. They
// drive the same path the facade's run() drives — shared snapshot
// taken once behind the Enabled() lever, then Breaker.Sweep — via
// runBreaker below.
package circuitbreaker

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	// Mirrors the facade's run() lever split: enabled → full sweep,
	// kill-switched → RestoreOnly (recover half only).
	if !Enabled() {
		return b.RestoreOnly(ctx, g.TakeSnapshot(ctx))
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
// circuit-breaker-bounce brownout probe never fires in tests that predate it — those
// fixtures have no TLS server to dial anyway.
func wgBreakerGuard(cs *fake.Clientset, now *time.Time) (*guardstate.Guard, *Breaker) {
	return &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return *now },
		EndpointProber: func(context.Context, string, int32) bool {
			return true
		}}, &Breaker{}
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
	for i := range ready {
		es.Endpoints = append(es.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{fmt.Sprintf("10.10.0.%d", i+1)},
			Conditions: discoveryv1.EndpointConditions{Ready: &up},
		})
	}
	for i := range notReady {
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

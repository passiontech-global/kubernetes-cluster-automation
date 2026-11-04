package webhookguard

import (
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// Builders (wg-prefixed to stay unique across sibling test files)
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
// Tests
// ---------------------------------------------------------------------------

// Orphan inside a ValidatingWebhookConfiguration: entry whose backend
// namespace is gone gets removed while a healthy sibling stays.
func TestWebhookGuardRemovesValidatingOrphan(t *testing.T) {
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "vcfg"},
		Webhooks: []admissionv1.ValidatingWebhook{
			wgValidatingHook("keep.example.com", wgSvcRef("alive", "svc")),
			wgValidatingHook("orphan.example.com", wgSvcRef("dead-ns", "svc")),
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("alive"),
		wgService("alive", "svc"),
		vwc)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	wgAssertNames(t, wgValidatingNames(t, cs, "vcfg"), []string{"keep.example.com"})
}

// Two orphans plus healthy entries in the same config: both orphans are
// dropped, the healthy entries keep their relative order.
func TestWebhookGuardMixedOrphansPreserveOrder(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			wgMutatingHook("orphan-a.example.com", wgSvcRef("dead-a", "svc")),
			wgMutatingHook("keep-a.example.com", wgSvcRef("alive", "svc")),
			wgMutatingHook("orphan-b.example.com", wgSvcRef("dead-b", "svc")),
			wgMutatingHook("keep-b.example.com", wgSvcRef("alive2", "svc2")),
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("alive"), wgNamespace("alive2"),
		wgService("alive", "svc"), wgService("alive2", "svc2"),
		mwc)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	wgAssertNames(t, wgMutatingNames(t, cs, "cfg"),
		[]string{"keep-a.example.com", "keep-b.example.com"})
}

// A config whose every entry is an orphan ends up with an empty webhook
// list — the config object itself is never deleted.
func TestWebhookGuardEmptiesFullyOrphanConfig(t *testing.T) {
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "all-dead"},
		Webhooks: []admissionv1.ValidatingWebhook{
			wgValidatingHook("gone.example.com", wgSvcRef("dead-ns", "svc")),
		},
	}
	cs := fake.NewSimpleClientset(wgNamespace("kube-system"), vwc)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Get(ctx, "all-dead", metav1.GetOptions{})
	if err != nil {
		t.Fatal("config must survive — only its entries are pruned")
	}
	if len(got.Webhooks) != 0 {
		t.Fatalf("expected empty webhook list, got %+v", got.Webhooks)
	}
}

// Entries that do not point at an in-cluster Service — a URL-based
// webhook (ClientConfig.Service == nil) and a ServiceReference with an
// empty namespace — are never flagged as orphans.
func TestWebhookGuardKeepsNonServiceEntries(t *testing.T) {
	url := "https://webhook.example.com/mutate"
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name: "url.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					URL: &url, // Service nil — external endpoint
				},
			},
			wgMutatingHook("empty-ns.example.com",
				&admissionv1.ServiceReference{Namespace: "", Name: "svc"}),
		},
	}
	cs := fake.NewSimpleClientset(wgNamespace("kube-system"), mwc)
	patches := wgPatchCounter(cs)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	wgAssertNames(t, wgMutatingNames(t, cs, "cfg"),
		[]string{"url.example.com", "empty-ns.example.com"})
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("expected no patches, got %d", got)
	}
}

// Namespace alive but the referenced Service missing is WARN-only:
// the entry is kept and no patch is ever issued (a mid-rollout Service
// looks exactly like this).
func TestWebhookGuardMissingServiceWarnOnly(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			wgMutatingHook("rolling.example.com", wgSvcRef("alive", "not-yet-created")),
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("alive"), // no Service objects at all
		mwc)
	patches := wgPatchCounter(cs)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	wgAssertNames(t, wgMutatingNames(t, cs, "cfg"), []string{"rolling.example.com"})
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("missing-Service warn path must not patch, got %d patch(es)", got)
	}
}

// Every entry healthy → run returns nil and issues zero patches.
func TestWebhookGuardNoOrphansNoPatch(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "mwc"},
		Webhooks: []admissionv1.MutatingWebhook{
			wgMutatingHook("a.example.com", wgSvcRef("alive", "svc")),
		},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			wgValidatingHook("b.example.com", wgSvcRef("alive", "svc")),
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("alive"),
		wgService("alive", "svc"),
		mwc, vwc)
	patches := wgPatchCounter(cs)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("expected zero patch calls, got %d", got)
	}
	wgAssertNames(t, wgMutatingNames(t, cs, "mwc"), []string{"a.example.com"})
	wgAssertNames(t, wgValidatingNames(t, cs, "vwc"), []string{"b.example.com"})
}

// Orphans in both webhook kinds are pruned in a single run.
func TestWebhookGuardOrphansAcrossBothKinds(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg-m"},
		Webhooks: []admissionv1.MutatingWebhook{
			wgMutatingHook("keep-m.example.com", wgSvcRef("alive", "svc")),
			wgMutatingHook("orphan-m.example.com", wgSvcRef("dead-m", "svc")),
		},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg-v"},
		Webhooks: []admissionv1.ValidatingWebhook{
			wgValidatingHook("orphan-v.example.com", wgSvcRef("dead-v", "svc")),
			wgValidatingHook("keep-v.example.com", wgSvcRef("alive", "svc")),
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("alive"),
		wgService("alive", "svc"),
		mwc, vwc)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	wgAssertNames(t, wgMutatingNames(t, cs, "cfg-m"), []string{"keep-m.example.com"})
	wgAssertNames(t, wgValidatingNames(t, cs, "cfg-v"), []string{"keep-v.example.com"})
}

// The namespace list is the only "namespace deleted" truth — an error
// aborts the run before anything is patched (an API flap must never
// read as "namespace deleted").
func TestWebhookGuardNamespaceListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "namespaces",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when the namespace list fails")
	}
}

// The Service list feeds only the WARN branch: a failure degrades to
// namespace-only checking — orphan removal must still happen.
func TestWebhookGuardServiceListErrorStillRemovesOrphans(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			wgMutatingHook("orphan.example.com", wgSvcRef("dead-ns", "svc")),
			wgMutatingHook("keep.example.com", wgSvcRef("alive", "svc")),
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("alive"), mwc)
	cs.PrependReactor("list", "services",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("services unreachable")
		})
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatalf("service list failure must degrade, not abort: %v", err)
	}
	wgAssertNames(t, wgMutatingNames(t, cs, "cfg"), []string{"keep.example.com"})
}

// A webhook-config list failure is an API flap — abort with error.
func TestWebhookGuardWebhookConfigListErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resource string
	}{
		{"mutating list fails", "mutatingwebhookconfigurations"},
		{"validating list fails", "validatingwebhookconfigurations"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(wgNamespace("kube-system"))
			cs.PrependReactor("list", tc.resource,
				func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("api down")
				})
			g := &webhookGuard{cs: cs}
			if err := g.run(ctx); err == nil {
				t.Fatalf("expected error when %s list fails", tc.resource)
			}
		})
	}
}

// Orphan removal is a strategic-merge patch: every dropped entry is
// listed as {"name": X, "$patch": "delete"} and NOTHING else is in
// the webhooks list — the merge-key delete can never revert a
// concurrent writer's sibling entries the way a whole-array
// "replace /webhooks" did.
func TestWebhookGuardOrphanPatchIsStrategicDelete(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			wgMutatingHook("keep.example.com", wgSvcRef("alive", "svc")),
			wgMutatingHook("orphan.example.com", wgSvcRef("dead-ns", "svc")),
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("alive"),
		wgService("alive", "svc"),
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
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if patchType != string(types.StrategicMergePatchType) {
		t.Fatalf("patch type = %s, want StrategicMergePatchType", patchType)
	}
	whs, _ := doc["webhooks"].([]any)
	if len(whs) != 1 {
		t.Fatalf("patch webhooks = %v, want exactly the 1 delete directive", whs)
	}
	entry, _ := whs[0].(map[string]any)
	if len(entry) != 2 || entry["name"] != "orphan.example.com" ||
		entry["$patch"] != "delete" {
		t.Fatalf("merge entry = %v, want exactly {name, $patch:delete}", entry)
	}
	if _, ok := doc["metadata"]; ok {
		t.Fatalf("orphan patch must not touch metadata: %v", doc)
	}
	wgAssertNames(t, wgMutatingNames(t, cs, "cfg"), []string{"keep.example.com"})
}

// The cluster-wide inputs are shared across the run's three duties:
// namespaces, both webhook-config lists, EndpointSlices and pods are
// each listed exactly once per run — never once per consumer.
func TestWebhookGuardListsClusterStateOncePerRun(t *testing.T) {
	cs := fake.NewSimpleClientset(wgNamespace("kube-system"))
	counts := map[string]int{}
	cs.PrependReactor("list", "*",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			counts[a.GetResource().Resource]++
			return false, nil, nil // passthrough to the tracker
		})
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	for res, want := range map[string]int{
		"namespaces":                      1,
		"mutatingwebhookconfigurations":   1,
		"validatingwebhookconfigurations": 1,
		"endpointslices":                  1,
		"pods":                            1,
		"services":                        1,
	} {
		if counts[res] != want {
			t.Fatalf("list %s = %d, want %d per run", res, counts[res], want)
		}
	}
}

// A failed /webhooks patch is surfaced as an error — silently
// swallowing it would leave orphan entries fail-closed forever.
func TestWebhookGuardPatchFailureReturnsError(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			wgMutatingHook("orphan.example.com", wgSvcRef("dead-ns", "svc")),
		},
	}
	cs := fake.NewSimpleClientset(wgNamespace("kube-system"), mwc)
	cs.PrependReactor("patch", "mutatingwebhookconfigurations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	g := &webhookGuard{cs: cs}
	err := g.run(ctx)
	if err == nil {
		t.Fatal("expected error when the webhook patch fails")
	}
	if !strings.Contains(err.Error(), "patches failed") {
		t.Fatalf("expected the aggregated patch failure, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// C1 circuit breaker — builders
// ---------------------------------------------------------------------------

// wgBreakerGuard builds a guard with a scripted clock — advance *now
// between runs to walk the deadSince streak past webhookDeadThreshold.
func wgBreakerGuard(cs *fake.Clientset, now *time.Time) *webhookGuard {
	return &webhookGuard{cs: cs,
		nowFn:     func() time.Time { return *now },
		deadSince: map[string]time.Time{}}
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
	v, ok := got.Annotations[webhookCircuitAnno]
	return v, ok
}

func wgValidatingAnno(t *testing.T, cs *fake.Clientset, cfg string) (string, bool) {
	t.Helper()
	got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Get(ctx, cfg, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get validatingwebhookconfiguration %s: %v", cfg, err)
	}
	v, ok := got.Annotations[webhookCircuitAnno]
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
// continuous >= webhookDeadThreshold streak flips it to Ignore and
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
	g := wgBreakerGuard(cs, &now)
	patches := wgPatchCounter(cs)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			webhookKindMutating, "cb-mwc", "dead.example.com")
	})
	tripsBefore := wgTripCount(t, webhookKindMutating, "cb-mwc")

	// First sighting — recorded, not tripped.
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-mwc", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("first sighting must not trip, failurePolicy=%q", got)
	}

	// Inside the threshold — still no trip.
	now = now.Add(4 * time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-mwc", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("4m streak < %s must not trip, failurePolicy=%q",
			webhookDeadThreshold, got)
	}
	if got := atomic.LoadInt32(patches); got != 0 {
		t.Fatalf("breaker must not patch before the threshold, got %d patch(es)", got)
	}

	// Past the threshold — trip.
	now = now.Add(2 * time.Minute) // 6m of dead backend
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "cb-mwc", "dead.example.com"); got != admissionv1.Ignore {
		t.Fatalf("expected failurePolicy=Ignore after trip, got %q", got)
	}
	anno, ok := wgMutatingAnno(t, cs, "cb-mwc")
	if !ok || anno != "dead.example.com" {
		t.Fatalf("annotation = %q (present=%v), want %q", anno, ok, "dead.example.com")
	}
	if got := wgBrokenGauge(t, webhookKindMutating, "cb-mwc", "dead.example.com"); got != 1 {
		t.Fatalf("WebhookCircuitBroken = %v, want 1", got)
	}
	if got := wgTripCount(t, webhookKindMutating, "cb-mwc"); got != tripsBefore+1 {
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
	g := wgBreakerGuard(cs, &now)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(webhookDeadThreshold + time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if doc == nil {
		t.Fatal("no patch issued for the trip")
	}
	if patchType != string(types.StrategicMergePatchType) {
		t.Fatalf("patch type = %s, want StrategicMergePatchType", patchType)
	}
	annos, _ := doc["metadata"].(map[string]any)["annotations"].(map[string]any)
	if got := annos[webhookCircuitAnno]; got != "dead.example.com" {
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
	g := wgBreakerGuard(cs, &now)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(webhookDeadThreshold + time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := wgValidatingFP(t, cs, "cb-vwc", "dead.example.com"); got != admissionv1.Ignore {
		t.Fatalf("precondition: expected tripped webhook, failurePolicy=%q", got)
	}
	tripsAfterTrip := wgTripCount(t, webhookKindValidating, "cb-vwc")

	// Backend comes back — one Ready endpoint.
	if _, err := cs.DiscoveryV1().EndpointSlices("backend").Update(ctx,
		wgEndpointSlice("backend", "dead-svc", 1, 0), metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update slice: %v", err)
	}
	now = now.Add(time.Minute)
	if err := g.run(ctx); err != nil {
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
		webhookKindValidating, "cb-vwc", "dead.example.com") {
		t.Fatal("recovery must delete the WebhookCircuitBroken series, not park it at 0")
	}
	if got := wgTripCount(t, webhookKindValidating, "cb-vwc"); got != tripsAfterTrip {
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
	g := &webhookGuard{cs: cs}
	for i := 0; i < 3; i++ {
		if err := g.run(ctx); err != nil {
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
			g := wgBreakerGuard(cs, &now)
			if err := g.run(ctx); err != nil {
				t.Fatal(err)
			}
			now = now.Add(2 * webhookDeadThreshold)
			if err := g.run(ctx); err != nil {
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
	g := wgBreakerGuard(cs, &now)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * webhookDeadThreshold)
	if err := g.run(ctx); err != nil {
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
			webhookKindMutating, "cb-m-ok", "dead-m.example.com")
	})
	now := time.Unix(1_700_000_000, 0)
	g := wgBreakerGuard(cs, &now)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(webhookDeadThreshold + time.Minute)
	err := g.run(ctx)
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
				webhookCircuitAnno: "gone.example.com,still-dead.example.com",
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
	g := &webhookGuard{cs: cs}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			webhookKindMutating, "cb-stale", "still-dead.example.com")
	})
	if err := g.run(ctx); err != nil {
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
	g := wgBreakerGuard(cs, &now)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			webhookKindMutating, "cb-deleted", "dead.example.com")
	})

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(webhookDeadThreshold + time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := wgBrokenGauge(t, webhookKindMutating, "cb-deleted", "dead.example.com"); got != 1 {
		t.Fatalf("precondition: WebhookCircuitBroken = %v, want 1", got)
	}

	// The whole config vanishes — the next sweep never re-sees the
	// tuple, so its =1 series must be deleted, not left firing.
	if err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Delete(ctx, "cb-deleted", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete config: %v", err)
	}
	now = now.Add(time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.WebhookCircuitBroken.DeleteLabelValues(
		webhookKindMutating, "cb-deleted", "dead.example.com") {
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
	g := wgBreakerGuard(cs, &now)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			webhookKindMutating, "cb-recreated", "dead.example.com")
	})

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(webhookDeadThreshold + time.Minute)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := wgBrokenGauge(t, webhookKindMutating, "cb-recreated", "dead.example.com"); got != 1 {
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
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}

	if metrics.WebhookCircuitBroken.DeleteLabelValues(
		webhookKindMutating, "cb-recreated", "dead.example.com") {
		t.Fatal("WebhookCircuitBroken series for a recreated (un-annotated) config must be pruned")
	}
	if got := wgMutatingFP(t, cs, "cb-recreated", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("recreated webhook keeps its declared policy, failurePolicy=%q", got)
	}
	if anno, ok := wgMutatingAnno(t, cs, "cb-recreated"); ok {
		t.Fatalf("recreated config must not carry the annotation, still %q", anno)
	}
}

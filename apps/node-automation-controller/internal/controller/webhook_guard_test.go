package controller

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
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

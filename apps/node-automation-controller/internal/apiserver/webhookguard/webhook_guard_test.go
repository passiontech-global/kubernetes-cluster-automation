// webhook_guard_test.go — whole-sweep coverage for the C1
// admission-webhook circuit breaker driven through the facade's
// run(): dead-backend streaks, failurePolicy Fail↔Ignore trips and
// restores, the circuit-broken annotation record, node-health
// endpoint discounting, the circuit-breaker-bounce brownout probe and pod bounce,
// and the missing-critical-namespace warning series.
package webhookguard

import (
	"encoding/json"
	"errors"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
			g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
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
		// endpoint-census — the node census feeds the effective-ready math.
		"nodes": 1,
	} {
		if counts[res] != want {
			t.Fatalf("list %s = %d, want %d per run", res, counts[res], want)
		}
	}
}

// critical-ns-audit: fail-closed webhooks whose namespaceSelector still matches
// kube-system/kube-node-lease/node-ops/medik8s emit
// node_automation_webhook_missing_critical_ns_exclusion=1;
// webhooks with NotIn exclusion, opt-in matchLabels, or failurePolicy=Ignore do not,
// and updating the selector prunes the stale gauge series. The
// lease-exposed hook pins the kube-node-lease membership: an
// exclusion covering only the older trio still matches the node
// heartbeat namespace and must flag.
func TestWebhookGuardCriticalNSExclusionAudit(t *testing.T) {
	excludedSel := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"kube-system", "kube-node-lease", "node-ops", "medik8s"},
		}},
	}
	optInSel := &metav1.LabelSelector{
		MatchLabels: map[string]string{"linkerd.io/inject": "enabled"},
	}
	partialSel := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"kube-system"}, // missing the other critical namespaces
		}},
	}
	// The older exclusion trio — kube-node-lease missing, so it
	// still matches the node heartbeat namespace.
	leaseExposedSel := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"kube-system", "node-ops", "medik8s"},
		}},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cpb-vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			{
				Name:              "missing-nil.example.com",
				FailurePolicy:     wgFP(admissionv1.Fail),
				NamespaceSelector: nil, // matches all
				ClientConfig:      admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
			},
			{
				Name:              "missing-partial.example.com",
				FailurePolicy:     wgFP(admissionv1.Fail),
				NamespaceSelector: partialSel,
				ClientConfig:      admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
			},
			{
				Name:              "lease-exposed.example.com",
				FailurePolicy:     wgFP(admissionv1.Fail),
				NamespaceSelector: leaseExposedSel,
				ClientConfig:      admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
			},
			{
				Name:              "excluded-notin.example.com",
				FailurePolicy:     wgFP(admissionv1.Fail),
				NamespaceSelector: excludedSel,
				ClientConfig:      admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
			},
			{
				Name:              "excluded-optin.example.com",
				FailurePolicy:     wgFP(admissionv1.Fail),
				NamespaceSelector: optInSel,
				ClientConfig:      admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
			},
			{
				Name:              "ignore-policy.example.com",
				FailurePolicy:     wgFP(admissionv1.Ignore),
				NamespaceSelector: nil,
				ClientConfig:      admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
			},
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("node-ops"),
		wgNamespace("medik8s"), wgNamespace("alive"),
		wgService("alive", "svc"), vwc)
	g := &webhookGuard{Guard: guardstate.Guard{CS: cs, Dyn: wgDyn()}}
	t.Cleanup(func() {
		for _, wh := range vwc.Webhooks {
			metrics.WebhookMissingCriticalNSExclusion.DeleteLabelValues(
				guardstate.KindValidating, "cpb-vwc", wh.Name)
		}
	})
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, wh := range []string{"missing-nil.example.com", "missing-partial.example.com", "lease-exposed.example.com"} {
		if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
			guardstate.KindValidating, "cpb-vwc", wh)); got != 1 {
			t.Fatalf("expected missing_critical_ns_exclusion=1 for %s, got %v", wh, got)
		}
	}
	for _, wh := range []string{"excluded-notin.example.com", "excluded-optin.example.com", "ignore-policy.example.com"} {
		if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
			guardstate.KindValidating, "cpb-vwc", wh)); got != 0 {
			t.Fatalf("expected missing_critical_ns_exclusion=0 for %s, got %v", wh, got)
		}
	}

	// Fix missing-nil, missing-partial and lease-exposed -> series
	// pruned on next sweep.
	vwc.Webhooks[0].NamespaceSelector = excludedSel
	vwc.Webhooks[1].NamespaceSelector = excludedSel
	vwc.Webhooks[2].NamespaceSelector = excludedSel
	if _, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Update(ctx, vwc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, wh := range []string{"missing-nil.example.com", "missing-partial.example.com", "lease-exposed.example.com"} {
		if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
			guardstate.KindValidating, "cpb-vwc", wh)); got != 0 {
			t.Fatalf("expected pruned series=0 for %s after fix, got %v", wh, got)
		}
	}
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

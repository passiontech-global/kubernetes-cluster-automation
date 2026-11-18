package timeoutclamp

import (
	"context"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func i32(v int32) *int32 { return &v }

func TestTimeoutClampMWCVWCAndCRDAudit(t *testing.T) {
	metrics.WebhookExcessiveTimeout.Reset()

	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "clamp-mwc"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name:           "pods.example.com",
				FailurePolicy:  new(admissionv1.Fail),
				TimeoutSeconds: i32(30),
				Rules: []admissionv1.RuleWithOperations{{
					Rule: admissionv1.Rule{Resources: []string{"pods"}},
				}},
			},
			{
				Name:           "widgets.example.com",
				FailurePolicy:  new(admissionv1.Fail),
				TimeoutSeconds: i32(30),
				Rules: []admissionv1.RuleWithOperations{{
					Rule: admissionv1.Rule{Resources: []string{"widgets"}},
				}},
			},
			{
				Name:           "ignore.example.com",
				FailurePolicy:  new(admissionv1.Ignore),
				TimeoutSeconds: i32(30),
				Rules: []admissionv1.RuleWithOperations{{
					Rule: admissionv1.Rule{Resources: []string{"nodes"}},
				}},
			},
		},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "optout-vwc",
			Annotations: map[string]string{kube.AnnoWebhookNeverFailOpen: "true"},
		},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:           "leases.example.com",
			FailurePolicy:  new(admissionv1.Fail),
			TimeoutSeconds: i32(25),
			Rules: []admissionv1.RuleWithOperations{{
				Rule: admissionv1.Rule{Resources: []string{"leases"}},
			}},
		}},
	}
	crd := testutil.Unstructured(
		kube.GVRCustomResourceDefinition.GroupVersion().WithKind("CustomResourceDefinition"),
		"", "slowcrds.example.com", nil)
	_ = unstructured.SetNestedField(crd.Object, "Webhook", "spec", "conversion", "strategy")
	_ = unstructured.SetNestedField(crd.Object, int64(25), "spec", "conversion", "webhook", "timeoutSeconds")

	cs := fake.NewSimpleClientset(mwc, vwc)
	dyn := testutil.NewDynWithCRDs(crd)
	g := &guardstate.Guard{
		CS:                       cs,
		Dyn:                      dyn,
		Now:                      func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) },
		TimeoutClampEnabled:      true,
		MaxWebhookTimeoutSeconds: 10,
	}
	var s Sweeper
	snap := g.TakeSnapshot(context.Background())
	if err := s.Sweep(context.Background(), snap); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	gotMWC, _ := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), "clamp-mwc", metav1.GetOptions{})
	if got := *gotMWC.Webhooks[0].TimeoutSeconds; got != 5 {
		t.Fatalf("pods.example.com timeoutSeconds = %d, want 5", got)
	}
	if got := *gotMWC.Webhooks[1].TimeoutSeconds; got != 30 {
		t.Fatalf("non-core widgets.example.com timeoutSeconds = %d, want 30", got)
	}
	if got := *gotMWC.Webhooks[2].TimeoutSeconds; got != 30 {
		t.Fatalf("Ignore webhook timeoutSeconds = %d, want 30", got)
	}

	gotVWC, _ := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), "optout-vwc", metav1.GetOptions{})
	if got := *gotVWC.Webhooks[0].TimeoutSeconds; got != 25 {
		t.Fatalf("opt-out VWC timeoutSeconds should remain 25, got %d", got)
	}

	// A DELIVERED clamp clears the debt: the gauge is held only while
	// the timeout is still excessive AND unclamped. Re-emitting 1 here
	// pages on a webhook that was just fixed.
	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues("mutating", "clamp-mwc", "pods.example.com")); v != 0 {
		t.Fatalf("expected clamped MWC excessive timeout gauge=0, got %v", v)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues("validating", "optout-vwc", "leases.example.com")); v != 1 {
		t.Fatalf("expected opt-out VWC excessive timeout gauge=1, got %v", v)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues("crd", "slowcrds.example.com", "slowcrds.example.com")); v != 1 {
		t.Fatalf("expected CRD excessive timeout gauge=1, got %v", v)
	}

	// Next sweep sees clamped MWC (timeoutSeconds=5) -> MWC gauge prunes to 0.
	snap2 := g.TakeSnapshot(context.Background())
	if err := s.Sweep(context.Background(), snap2); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues("mutating", "clamp-mwc", "pods.example.com")); v != 0 {
		t.Fatalf("expected MWC excessive timeout gauge pruned to 0 after clamp, got %v", v)
	}
}

func clampWebhook(name string, groups, resources []string, timeout int32) admissionv1.ValidatingWebhook {
	return admissionv1.ValidatingWebhook{
		Name:           name,
		FailurePolicy:  new(admissionv1.Fail),
		TimeoutSeconds: i32(timeout),
		Rules: []admissionv1.RuleWithOperations{{
			Rule: admissionv1.Rule{APIGroups: groups, Resources: resources},
		}},
	}
}

// The clamp used to match on resource name alone, so a third-party CRD
// webhook's apiGroups:[widgets.example.com], resources:["*"] was
// mistaken for a control-plane webhook and had its timeout rewritten.
func TestTimeoutClampChecksAPIGroupResourcePair(t *testing.T) {
	metrics.WebhookExcessiveTimeout.Reset()
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "pair-vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			clampWebhook("crd-wildcard.example.com", []string{"widgets.example.com"}, []string{"*"}, 30),
			clampWebhook("crd-pods.example.com", []string{"widgets.example.com"}, []string{"pods"}, 30),
			clampWebhook("core-leases.example.com", []string{"coordination.k8s.io"}, []string{"leases"}, 30),
			clampWebhook("global-wildcard.example.com", []string{"*"}, []string{"*"}, 30),
			// A wildcard resource in an in-tree control-plane group is
			// still a core-resource webhook — those groups were missing
			// from coreResourceGroups["*"] and escaped the clamp.
			clampWebhook("discovery-wildcard.example.com", []string{"discovery.k8s.io"}, []string{"*"}, 30),
			clampWebhook("coordination-wildcard.example.com", []string{"coordination.k8s.io"}, []string{"*"}, 30),
			clampWebhook("authn-wildcard.example.com", []string{"authentication.k8s.io"}, []string{"*"}, 30),
			// SAR/SSAR/LSAR are authorization.k8s.io resources — the
			// old authentication.k8s.io mapping let a fail-closed
			// authz webhook keep a 30s timeout.
			clampWebhook("sar.example.com", []string{"authorization.k8s.io"}, []string{"subjectaccessreviews"}, 30),
			clampWebhook("ssar.example.com", []string{"authorization.k8s.io"}, []string{"selfsubjectaccessreviews"}, 30),
			clampWebhook("lsar.example.com", []string{"authorization.k8s.io"}, []string{"localsubjectaccessreviews"}, 30),
			clampWebhook("authz-wildcard.example.com", []string{"authorization.k8s.io"}, []string{"*"}, 30),
			// The mislabeled group/resource pair must NOT clamp: the
			// group is part of the matching contract.
			clampWebhook("sar-wrong-group.example.com", []string{"authentication.k8s.io"}, []string{"subjectaccessreviews"}, 30),
		},
	}
	cs := fake.NewSimpleClientset(vwc)
	g := &guardstate.Guard{
		CS: cs, Now: func() time.Time { return now },
		TimeoutClampEnabled: true, MaxWebhookTimeoutSeconds: 10,
	}
	var s Sweeper
	if err := s.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	got, _ := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "pair-vwc", metav1.GetOptions{})
	wantClamped := map[string]bool{
		"crd-wildcard.example.com":          false,
		"crd-pods.example.com":              false,
		"core-leases.example.com":           true,
		"global-wildcard.example.com":       true,
		"discovery-wildcard.example.com":    true,
		"coordination-wildcard.example.com": true,
		"authn-wildcard.example.com":        true,
		"sar.example.com":                   true,
		"ssar.example.com":                  true,
		"lsar.example.com":                  true,
		"authz-wildcard.example.com":        true,
		"sar-wrong-group.example.com":       false,
	}
	for _, w := range got.Webhooks {
		want := int32(30)
		if wantClamped[w.Name] {
			want = 5
		}
		if *w.TimeoutSeconds != want {
			t.Errorf("%s timeoutSeconds = %d, want %d", w.Name, *w.TimeoutSeconds, want)
		}
		// Clamped core entries clear the debt; a third-party CRD
		// webhook is not a control-plane target at all and never
		// enters the audit — so no gauge for any of these entries.
		if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues(
			guardstate.KindValidating, "pair-vwc", w.Name)); v != 0 {
			t.Errorf("%s gauge = %v, want 0", w.Name, v)
		}
	}
}

func TestTimeoutClampHonorsMaxTimeoutAndIgnoresNotFound(t *testing.T) {
	metrics.WebhookExcessiveTimeout.Reset()
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cap-vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			clampWebhook("cap.example.com", []string{""}, []string{"pods"}, 30),
		},
	}
	cs := fake.NewSimpleClientset(vwc)
	g := &guardstate.Guard{
		CS: cs, Now: func() time.Time { return now },
		TimeoutClampEnabled: true, MaxWebhookTimeoutSeconds: 3, // below the 5s default
	}
	var s Sweeper

	// A 404 (config deleted mid-sweep) is not an error and leaves no
	// debt series on an object that no longer exists.
	notFound := true
	cs.PrependReactor("patch", "validatingwebhookconfigurations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			if !notFound {
				return false, nil, nil
			}
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "admissionregistration.k8s.io",
					Resource: "validatingwebhookconfigurations"}, "cap-vwc")
		})
	if err := s.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatalf("404 sweep: %v", err)
	}
	if v := ptestutil.ToFloat64(metrics.WebhookExcessiveTimeout.WithLabelValues(
		guardstate.KindValidating, "cap-vwc", "cap.example.com")); v != 0 {
		t.Fatalf("404 sweep left a gauge on a deleted config: %v", v)
	}
	notFound = false
	if err := s.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatalf("clamp sweep: %v", err)
	}
	got, _ := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "cap-vwc", metav1.GetOptions{})
	if want := int32(3); *got.Webhooks[0].TimeoutSeconds != want {
		t.Fatalf("timeoutSeconds = %d, want min(5, max=3) = %d", *got.Webhooks[0].TimeoutSeconds, want)
	}
}

func TestTimeoutClampUsesOwnFluxGateKey(t *testing.T) {
	metrics.WebhookExcessiveTimeout.Reset()
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	heal.ConfigureFluxConflictLoop(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureFluxConflictLoop(0, 0) })
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "flux-vwc",
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm-controller", Operation: "Update"}},
		},
		Webhooks: []admissionv1.ValidatingWebhook{
			clampWebhook("flux.example.com", []string{""}, []string{"pods"}, 30),
		},
	}
	cs := fake.NewSimpleClientset(vwc)
	g := &guardstate.Guard{
		CS: cs, Now: func() time.Time { return now },
		TimeoutClampEnabled: true, MaxWebhookTimeoutSeconds: 10,
	}
	// Burn two of the three allowed stamps on the circuit breaker's
	// key. The clamp's third call must NOT be denied by that history.
	heal.FluxPatchGate(guardstate.KindValidating, vwc, guardstate.KindValidating+"/flux-vwc", now)
	heal.FluxPatchGate(guardstate.KindValidating, vwc, guardstate.KindValidating+"/flux-vwc", now)
	var s Sweeper
	if err := s.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	got, _ := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "flux-vwc", metav1.GetOptions{})
	if want := int32(5); *got.Webhooks[0].TimeoutSeconds != want {
		t.Fatalf("timeoutSeconds = %d, want %d — clamp was blocked by another duty's Flux gate key",
			*got.Webhooks[0].TimeoutSeconds, want)
	}
}

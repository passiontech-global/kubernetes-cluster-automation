// criticalns_test.go — the critical-ns audit suites relocated from the
// unmeshed package when the duty moved to its own leaf subpackage:
// mechanical moves, driving Sweeper.Sweep over the shared snapshot
// exactly as the facade's run() does.
package criticalns

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

func wgDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynWithCRDs(objs...)
}

func wgSvcRef(ns, name string) *admissionv1.ServiceReference {
	return &admissionv1.ServiceReference{Namespace: ns, Name: name}
}

func upNamespace(name, inject string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if inject != "" {
		ns.Annotations = map[string]string{kube.LinkerdInjectKey: inject}
	}
	return ns
}

// upGuard builds what the relocated suites drive: the Sweeper holds
// the ledgers now, the shared deps come from the Guard — the same
// shape the unmeshed upGuard had before the duty moved here.
func upGuard(cs *fake.Clientset) (*Sweeper, *guardstate.Guard) {
	return &Sweeper{}, &guardstate.Guard{CS: cs, Dyn: wgDyn(), Now: time.Now}
}

// cpValidatingHook builds a fail-closed validating webhook entry with
// an optional namespaceSelector and one admission rule carrying
// resources (nil/empty resources = no rules at all).
func cpValidatingHook(name string, sel *metav1.LabelSelector,
	fp admissionv1.FailurePolicyType, resources []string) admissionv1.ValidatingWebhook {
	w := admissionv1.ValidatingWebhook{
		Name:          name,
		FailurePolicy: ptr.To(fp),
		ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
	}
	if sel != nil {
		w.NamespaceSelector = sel
	}
	if len(resources) > 0 {
		w.Rules = []admissionv1.RuleWithOperations{{
			Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
			Rule: admissionv1.Rule{
				APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: resources,
			},
		}}
	}
	return w
}

// cpCoordLeasesRule builds an admission rule serving resources in the
// coordination.k8s.io group — the group real Lease heartbeat writes
// live in.
func cpCoordLeasesRule(resources []string) admissionv1.RuleWithOperations {
	return admissionv1.RuleWithOperations{
		Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
		Rule: admissionv1.Rule{
			APIGroups: []string{"coordination.k8s.io"}, APIVersions: []string{"v1"}, Resources: resources,
		},
	}
}

func cpFullExclusion() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   slices.Clone(criticalSelfHealingNamespaces),
		}},
	}
}

// Kube-node-lease joined the critical self-healing set: an
// exclusion covering only the older trio still matches the node
// heartbeat namespace and must flag; the full four-namespace exclusion
// must not.
func TestCriticalNSAuditCoversKubeNodeLease(t *testing.T) {
	oldTrio := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"kube-system", "node-ops", "medik8s"},
		}},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "lease-vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			cpValidatingHook("lease-exposed.example.com", oldTrio, admissionv1.Fail, nil),
			cpValidatingHook("lease-excluded.example.com", cpFullExclusion(), admissionv1.Fail, nil),
		},
	}
	for _, wh := range vwc.Webhooks {
		testutil.CleanupMetric(t, metrics.WebhookMissingCriticalNSExclusion,
			guardstate.KindValidating, "lease-vwc", wh.Name)
	}
	cs := fake.NewSimpleClientset(upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), vwc)
	s, g := upGuard(cs)
	s.Sweep(g.TakeSnapshot(ctx))
	if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
		guardstate.KindValidating, "lease-vwc", "lease-exposed.example.com")); got != 1 {
		t.Fatalf("kube-node-lease not covered: lease-exposed = %v, want 1", got)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
		guardstate.KindValidating, "lease-vwc", "lease-excluded.example.com")); got != 0 {
		t.Fatalf("full exclusion still flagged: %v, want 0", got)
	}
}

// Fail-closed webhooks whose rules intercept a heartbeat resource
// while their selector still matches a critical namespace emit one
// series per matched resource literal (wildcards stay wildcards);
// excluded selectors, Ignore policies and non-heartbeat resources
// emit nothing. Mutating configs audit under the mutating kind.
func TestWebhookHeartbeatResourceExposedDetection(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "heartbeat-mwc"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "eviction.example.com",
			FailurePolicy: ptr.To(admissionv1.Fail),
			ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
			Rules: []admissionv1.RuleWithOperations{{
				Operations: []admissionv1.OperationType{admissionv1.Create},
				Rule: admissionv1.Rule{
					APIGroups: []string{""}, APIVersions: []string{"v1"},
					Resources: []string{"pods/eviction"},
				},
			}},
		}},
	}
	// multi carries a core pods/status rule plus a coordination.k8s.io
	// leases rule — both remain heartbeat-path after the group-aware
	// fix; crd-leases is the regression case: a foreign "leases"
	// resource served by the CORE group is not the kubelet heartbeat.
	multi := cpValidatingHook("multi.example.com", nil, admissionv1.Fail, []string{"pods/status"})
	multi.Rules = append(multi.Rules, cpCoordLeasesRule([]string{"leases"}))
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "heartbeat-vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			cpValidatingHook("node-status.example.com", nil, admissionv1.Fail, []string{"nodes/status"}),
			multi,
			cpValidatingHook("crd-leases.example.com", nil, admissionv1.Fail, []string{"leases"}),
			cpValidatingHook("wildcard-star.example.com", nil, admissionv1.Fail, []string{"*"}),
			cpValidatingHook("wildcard-slashstar.example.com", nil, admissionv1.Fail, []string{"*/*"}),
			cpValidatingHook("excluded.example.com", cpFullExclusion(), admissionv1.Fail, []string{"leases"}),
			cpValidatingHook("ignore-policy.example.com", nil, admissionv1.Ignore, []string{"*"}),
			cpValidatingHook("innocent.example.com", nil, admissionv1.Fail, []string{"configmaps", "pods"}),
		},
	}
	cleanup := func(kind, cfg, wh, res string) {
		testutil.CleanupMetric(t, metrics.WebhookHeartbeatResourceExposed, kind, cfg, wh, res)
	}
	for _, w := range vwc.Webhooks {
		for _, r := range w.Rules {
			for _, res := range r.Resources {
				cleanup(guardstate.KindValidating, "heartbeat-vwc", w.Name, res)
			}
		}
	}
	cleanup(guardstate.KindMutating, "heartbeat-mwc", "eviction.example.com", "pods/eviction")

	cs := fake.NewSimpleClientset(
		upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), mwc, vwc)
	s, g := upGuard(cs)
	s.Sweep(g.TakeSnapshot(ctx))
	for _, tc := range []struct{ kind, cfg, wh, res string }{
		{guardstate.KindValidating, "heartbeat-vwc", "node-status.example.com", "nodes/status"},
		{guardstate.KindValidating, "heartbeat-vwc", "multi.example.com", "leases"},
		{guardstate.KindValidating, "heartbeat-vwc", "multi.example.com", "pods/status"},
		{guardstate.KindValidating, "heartbeat-vwc", "wildcard-star.example.com", "*"},
		{guardstate.KindValidating, "heartbeat-vwc", "wildcard-slashstar.example.com", "*/*"},
		{guardstate.KindMutating, "heartbeat-mwc", "eviction.example.com", "pods/eviction"},
	} {
		if got := ptestutil.ToFloat64(metrics.WebhookHeartbeatResourceExposed.WithLabelValues(
			tc.kind, tc.cfg, tc.wh, tc.res)); got != 1 {
			t.Fatalf("heartbeat %s/%s/%s/%s = %v, want 1", tc.kind, tc.cfg, tc.wh, tc.res, got)
		}
	}
	for _, tc := range []struct{ kind, cfg, wh, res string }{
		// The excluded selector already rules out every critical
		// namespace — no exposure to report.
		{guardstate.KindValidating, "heartbeat-vwc", "excluded.example.com", "leases"},
		// An Ignore webhook cannot wedge admission.
		{guardstate.KindValidating, "heartbeat-vwc", "ignore-policy.example.com", "*"},
		// A foreign group's "leases" resource (CRD grammar reuse) is
		// not the kubelet heartbeat — the group-aware fix must not
		// flag it.
		{guardstate.KindValidating, "heartbeat-vwc", "crd-leases.example.com", "leases"},
		// pods (no subresource) and configmaps are not heartbeat-path.
		{guardstate.KindValidating, "heartbeat-vwc", "innocent.example.com", "pods"},
		{guardstate.KindValidating, "heartbeat-vwc", "innocent.example.com", "configmaps"},
	} {
		if got := ptestutil.ToFloat64(metrics.WebhookHeartbeatResourceExposed.WithLabelValues(
			tc.kind, tc.cfg, tc.wh, tc.res)); got != 0 {
			t.Fatalf("heartbeat %s/%s/%s/%s = %v, want 0", tc.kind, tc.cfg, tc.wh, tc.res, got)
		}
	}
	// Changing the offending webhook's rules prunes its stale series
	// on the next sweep.
	vwc.Webhooks[0].Rules = nil
	if _, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Update(ctx, vwc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	s.Sweep(g.TakeSnapshot(ctx))
	if got := ptestutil.ToFloat64(metrics.WebhookHeartbeatResourceExposed.WithLabelValues(
		guardstate.KindValidating, "heartbeat-vwc", "node-status.example.com", "nodes/status")); got != 0 {
		t.Fatalf("stale heartbeat series not pruned after rule change: %v", got)
	}
}

// The auto-patch (WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED): off (default)
// touches nothing; on, it
// injects the four-namespace NotIn into every flagged fail-closed
// webhook — replacing a partial exclusion wholesale, preserving
// matchLabels — while Ignore-policy and allowlisted entries stay
// untouched.
func TestCriticalNSAutoPatch(t *testing.T) {
	newCS := func(hooks ...admissionv1.ValidatingWebhook) *fake.Clientset {
		vwc := &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "patch-vwc"},
			Webhooks:   hooks,
		}
		return fake.NewSimpleClientset(
			upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), vwc)
	}
	fetchVWC := func(t *testing.T, cs *fake.Clientset) []admissionv1.ValidatingWebhook {
		t.Helper()
		got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
			Get(ctx, "patch-vwc", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return got.Webhooks
	}
	hookByName := func(t *testing.T, hooks []admissionv1.ValidatingWebhook, name string) admissionv1.ValidatingWebhook {
		t.Helper()
		for _, w := range hooks {
			if w.Name == name {
				return w
			}
		}
		t.Fatalf("webhook %s vanished from the config", name)
		return admissionv1.ValidatingWebhook{}
	}
	assertNotInInjected := func(t *testing.T, w admissionv1.ValidatingWebhook) {
		t.Helper()
		sel := w.NamespaceSelector
		if sel == nil || len(sel.MatchExpressions) != 1 {
			t.Fatalf("webhook %s missing the injected NotIn selector: %+v", w.Name, sel)
		}
		expr := sel.MatchExpressions[0]
		if expr.Key != "kubernetes.io/metadata.name" || expr.Operator != metav1.LabelSelectorOpNotIn {
			t.Fatalf("webhook %s wrong expression: %+v", w.Name, expr)
		}
		got := map[string]bool{}
		for _, v := range expr.Values {
			got[v] = true
		}
		for _, ns := range criticalSelfHealingNamespaces {
			if !got[ns] {
				t.Fatalf("webhook %s NotIn missing %s: %v", w.Name, ns, expr.Values)
			}
		}
	}

	t.Run("off by default — config untouched", func(t *testing.T) {
		cs := newCS(cpValidatingHook("matchall.example.com", nil, admissionv1.Fail, nil))
		s, g := upGuard(cs)
		s.Sweep(g.TakeSnapshot(ctx))
		if w := hookByName(t, fetchVWC(t, cs), "matchall.example.com"); w.NamespaceSelector != nil {
			t.Fatalf("namespaceSelector patched with the gate off: %+v", w.NamespaceSelector)
		}
	})

	t.Run("explicit false — config untouched", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "false")
		cs := newCS(cpValidatingHook("matchall.example.com", nil, admissionv1.Fail, nil))
		s, g := upGuard(cs)
		s.Sweep(g.TakeSnapshot(ctx))
		if w := hookByName(t, fetchVWC(t, cs), "matchall.example.com"); w.NamespaceSelector != nil {
			t.Fatalf("namespaceSelector patched with the gate false: %+v", w.NamespaceSelector)
		}
	})

	t.Run("on — exclusion injected, partial replaced, matchLabels preserved", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "true")
		pinnedToSystem := &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}}
		partial := &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{"kube-system"},
			}},
		}
		cs := newCS(
			cpValidatingHook("matchall.example.com", nil, admissionv1.Fail, nil),
			cpValidatingHook("pinned.example.com", pinnedToSystem, admissionv1.Fail, nil),
			cpValidatingHook("partial.example.com", partial, admissionv1.Fail, nil),
			cpValidatingHook("ignore.example.com", nil, admissionv1.Ignore, nil),
		)
		s, g := upGuard(cs)
		s.Sweep(g.TakeSnapshot(ctx))
		hooks := fetchVWC(t, cs)
		assertNotInInjected(t, hookByName(t, hooks, "matchall.example.com"))
		assertNotInInjected(t, hookByName(t, hooks, "partial.example.com"))
		pinned := hookByName(t, hooks, "pinned.example.com")
		assertNotInInjected(t, pinned)
		if pinned.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "kube-system" {
			t.Fatalf("matchLabels clobbered by the patch: %+v", pinned.NamespaceSelector)
		}
		if w := hookByName(t, hooks, "ignore.example.com"); w.NamespaceSelector != nil {
			t.Fatalf("Ignore-policy webhook patched: %+v", w.NamespaceSelector)
		}
	})

	t.Run("allowlisted entry untouched", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "true")
		criticalNSPatchAllowlist["patch-vwc/keep.example.com"] = true
		t.Cleanup(func() { delete(criticalNSPatchAllowlist, "patch-vwc/keep.example.com") })
		cs := newCS(cpValidatingHook("keep.example.com", nil, admissionv1.Fail, nil))
		s, g := upGuard(cs)
		s.Sweep(g.TakeSnapshot(ctx))
		if w := hookByName(t, fetchVWC(t, cs), "keep.example.com"); w.NamespaceSelector != nil {
			t.Fatalf("allowlisted webhook patched: %+v", w.NamespaceSelector)
		}
	})
}

// The auto-patch must MERGE into the webhook's existing selector, not
// replace it: MatchExpressions is a plain list in the Kubernetes API,
// so the exclusion patch carries the FULL union — existing matchLabels
// cloned, existing matchExpressions elements preserved, the missing
// critical namespaces appended into the existing
// kubernetes.io/metadata.name NotIn rule's values.
func TestCriticalNSAutoPatchMergesSelector(t *testing.T) {
	t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "true")
	sel := &metav1.LabelSelector{
		MatchLabels: map[string]string{"tier": "prod"},
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
			{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpNotIn,
				Values: []string{"kube-system"}},
		},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "merge-vwc"},
		Webhooks:   []admissionv1.ValidatingWebhook{cpValidatingHook("narrow.example.com", sel, admissionv1.Fail, nil)},
	}
	// tier=prod on node-ops so the narrowing selector still MATCHES a
	// critical namespace (kube-system is excluded by the partial
	// NotIn; the audit only patches flagged webhooks).
	nodeOps := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "node-ops",
		Labels: map[string]string{"tier": "prod"},
	}}
	cs := fake.NewSimpleClientset(nodeOps, upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), vwc)
	s, g := upGuard(cs)
	s.Sweep(g.TakeSnapshot(ctx))
	got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Get(ctx, "merge-vwc", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := got.Webhooks[0].NamespaceSelector
	if !maps.Equal(out.MatchLabels, map[string]string{"tier": "prod"}) {
		t.Fatalf("matchLabels not preserved: %+v", out.MatchLabels)
	}
	if len(out.MatchExpressions) != 2 {
		t.Fatalf("matchExpressions replaced, want both preserved: %+v", out.MatchExpressions)
	}
	tier := out.MatchExpressions[0]
	if tier.Key != "tier" || tier.Operator != metav1.LabelSelectorOpIn ||
		!slices.Equal(tier.Values, []string{"prod"}) {
		t.Fatalf("foreign expression clobbered: %+v", tier)
	}
	notIn := out.MatchExpressions[1]
	if notIn.Key != "kubernetes.io/metadata.name" || notIn.Operator != metav1.LabelSelectorOpNotIn {
		t.Fatalf("NotIn rule wrong: %+v", notIn)
	}
	for _, ns := range criticalSelfHealingNamespaces {
		if !slices.Contains(notIn.Values, ns) {
			t.Fatalf("NotIn values not merged to the full set: %v", notIn.Values)
		}
	}
}

// Under the auto-patch the missing-exclusion series only reports
// webhooks the patch does not cover: a LANDED patch suppresses the
// series (the exclusion now exists), a FAILED patch and an allowlisted
// webhook keep it live.
func TestCriticalNSAutoPatchSeriesEmission(t *testing.T) {
	cleanup := func(t *testing.T, name string) {
		testutil.CleanupMetric(t, metrics.WebhookMissingCriticalNSExclusion,
			guardstate.KindValidating, "series-vwc", name)
	}
	t.Run("landed patch suppresses the series", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "true")
		testutil.CleanupMetric(t, metrics.WebhookMissingCriticalNSExclusion,
			guardstate.KindValidating, "series-vwc", "quiet.example.com")
		vwc := &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "series-vwc"},
			Webhooks:   []admissionv1.ValidatingWebhook{cpValidatingHook("quiet.example.com", nil, admissionv1.Fail, nil)},
		}
		cs := fake.NewSimpleClientset(upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), vwc)
		s, g := upGuard(cs)
		s.Sweep(g.TakeSnapshot(ctx))
		// DeleteLabelValues doubles as the exists-probe (returns whether
		// the series was registered) — same pattern as the breaker's
		// prune tests.
		if metrics.WebhookMissingCriticalNSExclusion.DeleteLabelValues(
			guardstate.KindValidating, "series-vwc", "quiet.example.com") {
			t.Fatal("landed patch must not emit the missing-exclusion series")
		}
	})
	t.Run("failed patch emits the series", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "true")
		t.Cleanup(func() { cleanup(t, "flaky.example.com") })
		vwc := &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "series-vwc"},
			Webhooks:   []admissionv1.ValidatingWebhook{cpValidatingHook("flaky.example.com", nil, admissionv1.Fail, nil)},
		}
		cs := fake.NewSimpleClientset(upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), vwc)
		cs.PrependReactor("patch", "validatingwebhookconfigurations",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("patch denied")
			})
		s, g := upGuard(cs)
		s.Sweep(g.TakeSnapshot(ctx))
		if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
			guardstate.KindValidating, "series-vwc", "flaky.example.com")); got != 1 {
			t.Fatalf("failed patch must emit the series, got %v", got)
		}
	})
	t.Run("allowlisted webhook keeps its series under enforce", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "true")
		t.Cleanup(func() { cleanup(t, "keep.example.com") })
		criticalNSPatchAllowlist["series-vwc/keep.example.com"] = true
		t.Cleanup(func() { delete(criticalNSPatchAllowlist, "series-vwc/keep.example.com") })
		vwc := &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "series-vwc"},
			Webhooks:   []admissionv1.ValidatingWebhook{cpValidatingHook("keep.example.com", nil, admissionv1.Fail, nil)},
		}
		cs := fake.NewSimpleClientset(upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), vwc)
		s, g := upGuard(cs)
		s.Sweep(g.TakeSnapshot(ctx))
		if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
			guardstate.KindValidating, "series-vwc", "keep.example.com")); got != 1 {
			t.Fatalf("allowlisted webhook must keep its series, got %v", got)
		}
	})
}

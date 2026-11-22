package celpolicy

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

func newTestSweeperAndGuard(t *testing.T, cs *fake.Clientset, objs ...runtime.Object) (*Sweeper, *guardstate.Guard, *time.Time) {
	t.Helper()
	t.Setenv("CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED", "true")
	t.Setenv("CEL_POLICY_CIRCUIT_BREAKER_ENABLED", "true")
	t.Cleanup(func() {
		metrics.CELPolicyCircuitBroken.Reset()
		metrics.CELPolicyCriticalNSExposed.Reset()
	})
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	if cs != nil && cs.Resources == nil {
		cs.Resources = []*metav1.APIResourceList{{
			GroupVersion: "example.com/v1",
			APIResources: []metav1.APIResource{{
				Name:       "policyparams",
				Namespaced: true,
				Kind:       "PolicyParam",
			}},
		}}
	}
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "policyparams"}] = "PolicyParamList"
	kinds[schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "clusterpolicyparams"}] = "ClusterPolicyParamList"
	dyn := testutil.NewFakeDyn(kinds, objs...)
	g := &guardstate.Guard{
		CS:    cs,
		Dyn:   dyn,
		Queue: "test-celpolicy",
		Now:   func() time.Time { return now },
	}
	return &Sweeper{}, g, &now
}

func makeSnap(ctx context.Context, g *guardstate.Guard) *guardstate.Snapshot {
	return &guardstate.Snapshot{
		G:   g,
		Ctx: ctx,
		NS: &corev1.NamespaceList{Items: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", Labels: map[string]string{"env": "prod"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		}},
	}
}

func testVAP(name string, fp *admissionv1.FailurePolicyType, sel *metav1.LabelSelector) *admissionv1.ValidatingAdmissionPolicy {
	return &admissionv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: fp,
			MatchConstraints: &admissionv1.MatchResources{
				NamespaceSelector: sel,
				ResourceRules: []admissionv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionv1.RuleWithOperations{
						Operations: []admissionv1.OperationType{admissionv1.Create},
						Rule: admissionv1.Rule{
							APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"},
						},
					},
				}},
			},
		},
	}
}

func testMAP(name string, fp *admissionv1.FailurePolicyType, sel *metav1.LabelSelector) *admissionv1.MutatingAdmissionPolicy {
	return &admissionv1.MutatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionv1.MutatingAdmissionPolicySpec{
			FailurePolicy: fp,
			MatchConstraints: &admissionv1.MatchResources{
				NamespaceSelector: sel,
				ResourceRules: []admissionv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionv1.RuleWithOperations{
						Operations: []admissionv1.OperationType{admissionv1.Create},
						Rule: admissionv1.Rule{
							APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"},
						},
					},
				}},
			},
		},
	}
}

func critNSExcludedSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   slices.Clone(guardstate.CriticalSelfHealingNamespaces),
		}},
	}
}

func TestCELPolicyGracefulSkipOn403And404(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"403 forbidden", apierrors.NewForbidden(schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingadmissionpolicies"}, "", errors.New("forbidden"))},
		{"404 not found", apierrors.NewNotFound(schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingadmissionpolicies"}, "")},
		{"nomatch", &meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingadmissionpolicies"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			cs.PrependReactor("list", "mutatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})
			cs.PrependReactor("list", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})
			s, g, _ := newTestSweeperAndGuard(t, cs)
			beforeErrs := queueErrCount(t, g.Queue)
			if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
				t.Fatalf("Sweep returned error on %s: %v", tc.name, err)
			}
			afterErrs := queueErrCount(t, g.Queue)
			if afterErrs != beforeErrs {
				t.Fatalf("error counter incremented on %s: %v -> %v", tc.name, beforeErrs, afterErrs)
			}
		})
	}
}

func TestCELCriticalNSIdempotencyAndGaugeCleanup(t *testing.T) {
	vap := testVAP("vap-crit", ptr.To(admissionv1.Fail), &metav1.LabelSelector{
		MatchLabels: map[string]string{"env": "prod"},
	})
	mapObj := testMAP("map-crit", nil, nil) // nil FailurePolicy defaults to Fail
	cs := fake.NewSimpleClientset(vap, mapObj)
	s, g, _ := newTestSweeperAndGuard(t, cs)

	// Sweep 1: auto-enforces NotIn exclusion on both VAP and MAP while
	// preserving existing MatchLabels.
	beforePatches := ptestutil.ToFloat64(metrics.CELPolicyActionsTotal.WithLabelValues(KindValidatingPolicy, "criticalns_patch"))
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 1: %v", err)
	}
	gotVAP, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-crit", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotVAP.Spec.MatchConstraints.NamespaceSelector.MatchLabels["env"] != "prod" {
		t.Fatalf("existing MatchLabels lost: %+v", gotVAP.Spec.MatchConstraints.NamespaceSelector)
	}
	if m, ok := guardstate.CriticalNSMatcher(makeSnap(ctx, g)); !ok || m(gotVAP.Spec.MatchConstraints.NamespaceSelector) {
		t.Fatalf("VAP still matches critical NS after patch: %+v", gotVAP.Spec.MatchConstraints.NamespaceSelector)
	}
	gotMAP, err := cs.AdmissionregistrationV1().MutatingAdmissionPolicies().Get(ctx, "map-crit", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := guardstate.CriticalNSMatcher(makeSnap(ctx, g)); !ok || m(gotMAP.Spec.MatchConstraints.NamespaceSelector) {
		t.Fatalf("MAP still matches critical NS after patch: %+v", gotMAP.Spec.MatchConstraints.NamespaceSelector)
	}
	afterPatches := ptestutil.ToFloat64(metrics.CELPolicyActionsTotal.WithLabelValues(KindValidatingPolicy, "criticalns_patch"))
	if afterPatches-beforePatches != 1 {
		t.Fatalf("criticalns_patch delta = %v, want 1", afterPatches-beforePatches)
	}

	// Sweep 2 (idempotency): no additional patch should be issued.
	var patchCount int
	cs.PrependReactor("patch", "*", func(ktesting.Action) (bool, runtime.Object, error) {
		patchCount++
		return false, nil, nil
	})
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	if patchCount != 0 {
		t.Fatalf("expected 0 patches on idempotent second sweep, got %d", patchCount)
	}

	// Test GaugeLedger emission + cleanup when enforce is disabled then re-enabled.
	t.Setenv("CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED", "false")
	exposed := testVAP("vap-exposed", ptr.To(admissionv1.Fail), nil)
	if _, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, exposed, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 3: %v", err)
	}
	if got := ptestutil.ToFloat64(metrics.CELPolicyCriticalNSExposed.WithLabelValues(KindValidatingPolicy, "vap-exposed", "kube-system")); got != 1 {
		t.Fatalf("exposed gauge = %v, want 1", got)
	}

	// Re-enable enforce -> policy gets patched and GaugeLedger prunes stale series.
	t.Setenv("CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED", "true")
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 4: %v", err)
	}
	if n := countGaugeSeries(metrics.CELPolicyCriticalNSExposed, KindValidatingPolicy, "vap-exposed"); n != 0 {
		t.Fatalf("expected stale critical_ns_exposed series pruned, found %d", n)
	}
}

func TestCELPolicyMissingParamRefHysteresisTripAndRestore(t *testing.T) {
	paramGVK := schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "PolicyParam"}
	paramGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "policyparams"}

	vap := testVAP("vap-param", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
	vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-param"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-param",
			ParamRef:   &admissionv1.ParamRef{Name: "missing-cfg", Namespace: "default"},
		},
	}
	// Policy with ParameterNotFoundAction=Allow must NOT trip even when missing.
	mapAllow := testMAP("map-allow", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	mapAllow.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
	allowAction := admissionv1.AllowAction
	mapbAllow := &admissionv1.MutatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "mapb-allow"},
		Spec: admissionv1.MutatingAdmissionPolicyBindingSpec{
			PolicyName: "map-allow",
			ParamRef: &admissionv1.ParamRef{
				Name:                    "missing-allow",
				Namespace:               "default",
				ParameterNotFoundAction: &allowAction,
			},
		},
	}

	cs := fake.NewSimpleClientset(vap, vapb, mapAllow, mapbAllow)
	s, g, now := newTestSweeperAndGuard(t, cs)

	// Cycle 1 (t=0): missing paramRef sighted -> inside hysteresis window, no trip.
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 1: %v", err)
	}
	got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-param", metav1.GetOptions{})
	if got.Spec.FailurePolicy == nil || *got.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("cycle 1 tripped prematurely: %v", got.Spec.FailurePolicy)
	}

	// Cycle 2 (t+6m): >= 2 cycles AND >= 5m -> trips vap-param to Ignore!
	*now = now.Add(6 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-param", metav1.GetOptions{})
	if got.Spec.FailurePolicy == nil || *got.Spec.FailurePolicy != admissionv1.Ignore {
		t.Fatalf("cycle 2 did not trip failurePolicy to Ignore: %v", got.Spec.FailurePolicy)
	}
	if got.Annotations[kube.AnnoCircuitBrokenCELPolicy] == "" {
		t.Fatal("missing AnnoCircuitBrokenCELPolicy stamp on tripped policy")
	}
	if v := ptestutil.ToFloat64(metrics.CELPolicyCircuitBroken.WithLabelValues(KindValidatingPolicy, "vap-param")); v != 1 {
		t.Fatalf("circuit_broken gauge = %v, want 1", v)
	}
	// ParameterNotFoundAction=Allow policy stayed Fail.
	gotAllow, _ := cs.AdmissionregistrationV1().MutatingAdmissionPolicies().Get(ctx, "map-allow", metav1.GetOptions{})
	if *gotAllow.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("Allow paramRef policy should not trip, got %v", *gotAllow.Spec.FailurePolicy)
	}

	// Param object appears; test RestoreOnly even with breaker trip disabled.
	t.Setenv("CEL_POLICY_CIRCUIT_BREAKER_ENABLED", "false")
	paramObj := &unstructured.Unstructured{}
	paramObj.SetGroupVersionKind(paramGVK)
	paramObj.SetNamespace("default")
	paramObj.SetName("missing-cfg")
	if _, err := testCreateUnstructured(g, paramGVR, paramObj); err != nil {
		t.Fatal(err)
	}

	// Clean cycle 1: still broken (requires 2 consecutive clean cycles).
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 3 (clean 1): %v", err)
	}
	got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-param", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Ignore {
		t.Fatalf("restored after 1 clean cycle; want 2-cycle hysteresis")
	}

	// Clean cycle 2: restored to Fail, annotation cleared, gauge pruned!
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 4 (clean 2): %v", err)
	}
	got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-param", metav1.GetOptions{})
	if got.Spec.FailurePolicy == nil || *got.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("not restored to Fail after 2 clean cycles: %v", got.Spec.FailurePolicy)
	}
	if got.Annotations[kube.AnnoCircuitBrokenCELPolicy] != "" {
		t.Fatalf("AnnoCircuitBrokenCELPolicy not cleared on restore: %q", got.Annotations[kube.AnnoCircuitBrokenCELPolicy])
	}
	if n := countGaugeSeries(metrics.CELPolicyCircuitBroken, KindValidatingPolicy, "vap-param"); n != 0 {
		t.Fatalf("expected circuit_broken series pruned on restore, found %d", n)
	}
}

func TestCELPolicySelectorParamRefTripAndRecover(t *testing.T) {
	paramGVK := schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "PolicyParam"}
	paramGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "policyparams"}

	vap := testVAP("vap-sel-param", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
	vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-sel-param"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-sel-param",
			ParamRef: &admissionv1.ParamRef{
				Namespace: "default",
				Selector:  &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guard"}},
			},
		},
	}

	cs := fake.NewSimpleClientset(vap, vapb)
	s, g, now := newTestSweeperAndGuard(t, cs)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 1: %v", err)
	}
	*now = now.Add(6 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-sel-param", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected Ignore for missing selector paramRef, got %v", *got.Spec.FailurePolicy)
	}

	paramObj := &unstructured.Unstructured{}
	paramObj.SetGroupVersionKind(paramGVK)
	paramObj.SetNamespace("default")
	paramObj.SetName("matched-cfg")
	paramObj.SetLabels(map[string]string{"app": "guard"})
	if _, err := testCreateUnstructured(g, paramGVR, paramObj); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(5 * time.Minute)
	_ = s.Sweep(ctx, makeSnap(ctx, g))
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 4: %v", err)
	}
	got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-sel-param", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("expected Fail after selector paramRef appeared, got %v", *got.Spec.FailurePolicy)
	}
}

func testCreateUnstructured(g *guardstate.Guard, gvr schema.GroupVersionResource, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return g.Dyn.Resource(gvr).Namespace(obj.GetNamespace()).Create(ctx, obj, metav1.CreateOptions{})
}

func TestCELPolicyPromQLErrorStormTripAndRestore(t *testing.T) {
	firing := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.FormValue("query")
		if !strings.Contains(q, "sum by (policy)") {
			t.Errorf("PromQL missing sum by (policy): %q", q)
		}
		if firing && strings.Contains(q, "apiserver_validating_admission_policy_check_total") {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"policy":"vap-storm"},"value":[1700000000,"0.5"]}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()

	vap := testVAP("vap-storm", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	cs := fake.NewSimpleClientset(vap)
	s, g, now := newTestSweeperAndGuard(t, cs)
	g.PromEndpoint = srv.URL + "/api/v1/query"
	g.PromClient = promq.Client{HTTP: srv.Client(), Timeout: time.Second}

	// Cycle 1: error rate seen, < 5m -> no trip.
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 1: %v", err)
	}
	got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-storm", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("tripped too early: %v", *got.Spec.FailurePolicy)
	}

	// Cycle 2 (+5m): sustained >= 5m -> trip!
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-storm", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected Ignore after 5m error storm, got %v", *got.Spec.FailurePolicy)
	}

	// Error clears -> 2 clean cycles -> restored.
	firing = false
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 3: %v", err)
	}
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 4: %v", err)
	}
	got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-storm", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("expected Fail after 2 clean cycles, got %v", *got.Spec.FailurePolicy)
	}
}

func TestCELPolicyMaintenanceHoldAndFluxPatchGate(t *testing.T) {
	// 1. Maintenance hold (cordoned node -> AllowedV defers): neither critical-NS
	// patch nor breaker trip executes.
	vap := testVAP("vap-hold", ptr.To(admissionv1.Fail), nil)
	vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
	vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-hold"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-hold",
			ParamRef:   &admissionv1.ParamRef{Name: "missing", Namespace: "default"},
		},
	}
	cordonedNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec:       corev1.NodeSpec{Unschedulable: true},
	}
	cs := fake.NewSimpleClientset(vap, vapb, cordonedNode)
	s, g, now := newTestSweeperAndGuard(t, cs)
	s.tripWindow = time.Minute
	s.minMissingCycles = 1

	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep under maintenance hold: %v", err)
	}
	*now = now.Add(2 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 2 under maintenance hold: %v", err)
	}
	got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-hold", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("maintenance hold failed to block trip: %v", *got.Spec.FailurePolicy)
	}
	if got.Spec.MatchConstraints.NamespaceSelector != nil {
		t.Fatalf("maintenance hold failed to block critical-NS patch: %+v", got.Spec.MatchConstraints.NamespaceSelector)
	}

	// 2. FluxPatchGate blocks repeated critical-NS desired-state patches after
	// loop threshold, while emergency breaker trip bypasses FluxPatchGate.
	heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
	t.Cleanup(func() { heal.ConfigureFluxConflictLoop(0, 0) })

	fluxCritVAP := testVAP("vap-flux-crit", ptr.To(admissionv1.Fail), nil)
	fluxCritVAP.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kustomize-controller"}}

	fluxBreakVAP := testVAP("vap-flux-break", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	fluxBreakVAP.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kustomize-controller"}}
	fluxBreakVAP.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
	fluxBreakVAPB := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-flux-break"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-flux-break",
			ParamRef:   &admissionv1.ParamRef{Name: "missing", Namespace: "default"},
		},
	}
	cs2 := fake.NewSimpleClientset(fluxCritVAP, fluxBreakVAP, fluxBreakVAPB)
	s2, g2, now2 := newTestSweeperAndGuard(t, cs2)
	s2.tripWindow = 10 * time.Minute

	// First sweep consumes sighting 1 on vap-flux-crit (allowed).
	if err := s2.Sweep(ctx, makeSnap(ctx, g2)); err != nil {
		t.Fatalf("flux sweep 1: %v", err)
	}
	// Simulate Flux reverting NamespaceSelector back to nil.
	curCrit, _ := cs2.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-flux-crit", metav1.GetOptions{})
	curCrit.Spec.MatchConstraints.NamespaceSelector = nil
	_, _ = cs2.AdmissionregistrationV1().ValidatingAdmissionPolicies().Update(ctx, curCrit, metav1.UpdateOptions{})

	// Second sweep hits loop max (2) -> FluxPatchGate blocks critical-NS patch
	// on vap-flux-crit and emits CELPolicyCriticalNSExposed, while emergency
	// breaker still trips vap-flux-break despite Flux management!
	*now2 = now2.Add(11 * time.Minute)
	if err := s2.Sweep(ctx, makeSnap(ctx, g2)); err != nil {
		t.Fatalf("flux sweep 2: %v", err)
	}
	curCrit, _ = cs2.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-flux-crit", metav1.GetOptions{})
	if curCrit.Spec.MatchConstraints.NamespaceSelector != nil {
		t.Fatalf("FluxPatchGate failed to defer critical-NS patch: %+v", curCrit.Spec.MatchConstraints.NamespaceSelector)
	}
	if v := ptestutil.ToFloat64(metrics.CELPolicyCriticalNSExposed.WithLabelValues(KindValidatingPolicy, "vap-flux-crit", "kube-system")); v != 1 {
		t.Fatalf("expected critical_ns_exposed=1 when FluxPatchGate deferred, got %v", v)
	}
	curBreak, _ := cs2.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-flux-break", metav1.GetOptions{})
	if curBreak.Spec.FailurePolicy == nil || *curBreak.Spec.FailurePolicy != admissionv1.Ignore {
		t.Fatalf("emergency circuit-breaker should bypass FluxPatchGate and trip to Ignore, got %v", curBreak.Spec.FailurePolicy)
	}

	// 3. Maintenance hold must NOT record phantom FluxPatchGate sightings
	// (AllowedV runs before FluxPatchGate), and FluxPatchGate denial must
	// refund the heal budget grant.
	t.Run("AllowedV precedes FluxPatchGate and RefundGrant on denial", func(t *testing.T) {
		heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() {
			heal.ConfigureFluxConflictLoop(0, 0)
			heal.ConfigureBudget(0, 0)
		})

		heldNode := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "worker-held"},
			Spec:       corev1.NodeSpec{Unschedulable: true},
		}
		fluxVAP := testVAP("vap-flux-maint", ptr.To(admissionv1.Fail), nil)
		fluxVAP.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kustomize-controller"}}
		cs3 := fake.NewSimpleClientset(heldNode, fluxVAP)
		s3, g3, now3 := newTestSweeperAndGuard(t, cs3)

		// Run 3 sweeps under maintenance hold: AllowedV defers so FluxPatchGate
		// must accumulate zero sightings.
		for i := 0; i < 3; i++ {
			if err := s3.Sweep(ctx, makeSnap(ctx, g3)); err != nil {
				t.Fatalf("maint sweep %d: %v", i+1, err)
			}
			*now3 = now3.Add(time.Minute)
		}
		gotHeld, _ := cs3.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-flux-maint", metav1.GetOptions{})
		if gotHeld.Spec.MatchConstraints.NamespaceSelector != nil {
			t.Fatalf("expected no patch under maintenance hold, got %+v", gotHeld.Spec.MatchConstraints.NamespaceSelector)
		}

		// Lift maintenance hold: first post-maintenance sweep MUST succeed
		// (0 phantom sightings recorded during hold).
		heldNode.Spec.Unschedulable = false
		if _, err := cs3.CoreV1().Nodes().Update(ctx, heldNode, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := s3.Sweep(ctx, makeSnap(ctx, g3)); err != nil {
			t.Fatalf("post-maint sweep 1: %v", err)
		}
		gotHeld, _ = cs3.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-flux-maint", metav1.GetOptions{})
		if gotHeld.Spec.MatchConstraints.NamespaceSelector == nil {
			t.Fatal("expected critical-NS patch after maintenance lifted (FluxPatchGate must not have accumulated phantom sightings during hold)")
		}

		// Advance past budget window, revert selector twice so FluxPatchGate denies
		// on the 2nd sighting, and verify RefundGrant returns the budget token.
		*now3 = now3.Add(2 * time.Hour)
		gotHeld.Spec.MatchConstraints.NamespaceSelector = nil
		_, _ = cs3.AdmissionregistrationV1().ValidatingAdmissionPolicies().Update(ctx, gotHeld, metav1.UpdateOptions{})
		// Re-use a fresh budget of 1 for this exact instant.
		heal.ConfigureBudget(1, time.Hour)
		if err := s3.Sweep(ctx, makeSnap(ctx, g3)); err != nil {
			t.Fatalf("post-maint sweep 2: %v", err)
		}
		// Budget of 1 was spent by sweep 2 (patch succeeded). Reset budget=1 for denial check.
		heal.ConfigureBudget(1, time.Hour)
		gotHeld, _ = cs3.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-flux-maint", metav1.GetOptions{})
		gotHeld.Spec.MatchConstraints.NamespaceSelector = nil
		_, _ = cs3.AdmissionregistrationV1().ValidatingAdmissionPolicies().Update(ctx, gotHeld, metav1.UpdateOptions{})
		if err := s3.Sweep(ctx, makeSnap(ctx, g3)); err != nil {
			t.Fatalf("post-maint sweep 3 (FluxPatchGate deny): %v", err)
		}
		// Because FluxPatchGate denied and RefundGrant(now) was called, the 1-grant
		// budget at *now3 must still be available!
		if proceed, _ := heal.AllowedV(ctx, logf.FromContext(ctx), nil, cs3, g3.Dyn, nil, "check-refund", 0, *now3); !proceed {
			t.Fatal("expected budget grant to be available after RefundGrant on FluxPatchGate denial")
		}
	})
}

func TestCELPolicyMAPErrorStormAndKindIsolation(t *testing.T) {
	var mapFiring, vapFiring bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.FormValue("query")
		switch {
		case strings.Contains(q, "apiserver_mutating_admission_policy_check_total") && mapFiring:
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"policy":"shared-policy"},"value":[1700000000,"0.5"]}]}}`))
		case strings.Contains(q, "apiserver_validating_admission_policy_check_total") && vapFiring:
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"policy":"shared-policy"},"value":[1700000000,"0.5"]}]}}`))
		default:
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}
	}))
	defer srv.Close()

	// Both a VAP and a MAP share the identical policy name "shared-policy".
	vap := testVAP("shared-policy", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	mapObj := testMAP("shared-policy", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	cs := fake.NewSimpleClientset(vap, mapObj)
	s, g, now := newTestSweeperAndGuard(t, cs)
	g.PromEndpoint = srv.URL + "/api/v1/query"
	g.PromClient = promq.Client{HTTP: srv.Client(), Timeout: time.Second}

	// Only MAP is erroring -> MAP trips, VAP with identical name must stay Fail!
	mapFiring = true
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 1: %v", err)
	}
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	gotMAP, _ := cs.AdmissionregistrationV1().MutatingAdmissionPolicies().Get(ctx, "shared-policy", metav1.GetOptions{})
	if gotMAP.Spec.FailurePolicy == nil || *gotMAP.Spec.FailurePolicy != admissionv1.Ignore {
		t.Fatalf("MAP shared-policy did not trip to Ignore: %v", gotMAP.Spec.FailurePolicy)
	}
	gotVAP, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "shared-policy", metav1.GetOptions{})
	if gotVAP.Spec.FailurePolicy == nil || *gotVAP.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("VAP shared-policy cross-tripped from MAP error storm: %v", gotVAP.Spec.FailurePolicy)
	}
	if v := ptestutil.ToFloat64(metrics.CELPolicyCircuitBroken.WithLabelValues(KindMutatingPolicy, "shared-policy")); v != 1 {
		t.Fatalf("MAP circuit_broken gauge = %v, want 1", v)
	}
	if n := countGaugeSeries(metrics.CELPolicyCircuitBroken, KindValidatingPolicy, "shared-policy"); n != 0 {
		t.Fatalf("VAP should not have circuit_broken series, found %d", n)
	}

	// Clear MAP storm -> 2 clean cycles -> MAP restores; then VAP storm -> VAP trips while MAP stays Fail.
	mapFiring = false
	*now = now.Add(5 * time.Minute)
	_ = s.Sweep(ctx, makeSnap(ctx, g))
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep restore: %v", err)
	}
	gotMAP, _ = cs.AdmissionregistrationV1().MutatingAdmissionPolicies().Get(ctx, "shared-policy", metav1.GetOptions{})
	if *gotMAP.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("MAP did not restore to Fail: %v", *gotMAP.Spec.FailurePolicy)
	}

	vapFiring = true
	*now = now.Add(5 * time.Minute)
	_ = s.Sweep(ctx, makeSnap(ctx, g))
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep VAP trip: %v", err)
	}
	gotVAP, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "shared-policy", metav1.GetOptions{})
	if *gotVAP.Spec.FailurePolicy != admissionv1.Ignore {
		t.Fatalf("VAP shared-policy did not trip: %v", *gotVAP.Spec.FailurePolicy)
	}
	gotMAP, _ = cs.AdmissionregistrationV1().MutatingAdmissionPolicies().Get(ctx, "shared-policy", metav1.GetOptions{})
	if *gotMAP.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("MAP shared-policy cross-tripped from VAP error storm: %v", *gotMAP.Spec.FailurePolicy)
	}
}

func TestCELPolicyNoDoubleIncErrorOnReturnedErrors(t *testing.T) {
	t.Run("returned list and patch errors do not IncError inside celpolicy", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("list", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver transient 500")
		})
		s, g, _ := newTestSweeperAndGuard(t, cs)
		g.Queue = "test-celpolicy-no-double-list"
		before := queueErrCount(t, g.Queue)
		err := s.Sweep(ctx, makeSnap(ctx, g))
		if err == nil {
			t.Fatal("expected Sweep to return list error")
		}
		if after := queueErrCount(t, g.Queue); after != before {
			t.Fatalf("Sweep incremented IncError on returned list error: %v -> %v", before, after)
		}

		// Returned tripPolicy patch error must not IncError.
		vap := testVAP("vap-patch-err", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
		vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-patch-err"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-patch-err",
				ParamRef:   &admissionv1.ParamRef{Name: "missing", Namespace: "default"},
			},
		}
		cs2 := fake.NewSimpleClientset(vap, vapb)
		cs2.PrependReactor("patch", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch conflict 500")
		})
		s2, g2, now2 := newTestSweeperAndGuard(t, cs2)
		g2.Queue = "test-celpolicy-no-double-trip"
		s2.tripWindow = time.Minute
		s2.minMissingCycles = 1
		_ = s2.Sweep(ctx, makeSnap(ctx, g2))
		*now2 = now2.Add(2 * time.Minute)
		beforeTrip := queueErrCount(t, g2.Queue)
		if err := s2.Sweep(ctx, makeSnap(ctx, g2)); err == nil {
			t.Fatal("expected Sweep to return trip patch error")
		}
		if afterTrip := queueErrCount(t, g2.Queue); afterTrip != beforeTrip {
			t.Fatalf("Sweep incremented IncError on returned trip patch error: %v -> %v", beforeTrip, afterTrip)
		}

		// Returned restorePolicy patch error must not IncError.
		brokenVAP := testVAP("vap-restore-err", ptr.To(admissionv1.Ignore), critNSExcludedSelector())
		brokenVAP.Annotations = map[string]string{kube.AnnoCircuitBrokenCELPolicy: "2026-11-21T12:00:00Z missing_param_ref"}
		cs3 := fake.NewSimpleClientset(brokenVAP)
		cs3.PrependReactor("patch", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("restore patch 500")
		})
		s3, g3, now3 := newTestSweeperAndGuard(t, cs3)
		g3.Queue = "test-celpolicy-no-double-restore"
		_ = s3.Sweep(ctx, makeSnap(ctx, g3))
		*now3 = now3.Add(5 * time.Minute)
		beforeRestore := queueErrCount(t, g3.Queue)
		if err := s3.Sweep(ctx, makeSnap(ctx, g3)); err == nil {
			t.Fatal("expected Sweep to return restore patch error")
		}
		if afterRestore := queueErrCount(t, g3.Queue); afterRestore != beforeRestore {
			t.Fatalf("Sweep incremented IncError on returned restore patch error: %v -> %v", beforeRestore, afterRestore)
		}
	})

	t.Run("absorbed promErr increments IncError once and Sweep returns nil", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "prom down", http.StatusInternalServerError)
		}))
		defer srv.Close()

		cs := fake.NewSimpleClientset()
		s, g, _ := newTestSweeperAndGuard(t, cs)
		g.Queue = "test-celpolicy-absorbed-prom"
		g.PromEndpoint = srv.URL + "/api/v1/query"
		g.PromClient = promq.Client{HTTP: srv.Client(), Timeout: time.Second}
		before := queueErrCount(t, g.Queue)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("expected absorbed promErr to return nil, got %v", err)
		}
		if after := queueErrCount(t, g.Queue); after-before != 1 {
			t.Fatalf("absorbed promErr IncError delta = %v, want 1", after-before)
		}
	})
}

func TestCELPolicyCircuitBreakerDisabledRestoreOnly(t *testing.T) {
	paramGVK := schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "PolicyParam"}
	paramGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "policyparams"}

	firing := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if firing && strings.Contains(r.FormValue("query"), "apiserver_validating_admission_policy_check_total") {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"policy":"vap-unbroken"},"value":[1700000000,"0.5"]}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()

	// 1. Unbroken policy with missing paramRef + PromQL error storm.
	vapUnbroken := testVAP("vap-unbroken", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	vapUnbroken.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
	vapbUnbroken := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-unbroken"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-unbroken",
			ParamRef:   &admissionv1.ParamRef{Name: "missing-unbroken", Namespace: "default"},
		},
	}

	// 2. Previously broken policy whose FailurePolicy drifted back to Fail while fault is active.
	vapReverted := testVAP("vap-reverted", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	vapReverted.Annotations = map[string]string{kube.AnnoCircuitBrokenCELPolicy: "2026-11-21T11:00:00Z missing_param_ref"}
	vapReverted.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
	vapbReverted := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-reverted"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-reverted",
			ParamRef:   &admissionv1.ParamRef{Name: "missing-reverted", Namespace: "default"},
		},
	}

	// 3. Previously broken policy whose paramRef is now present -> should restore after 2 clean cycles.
	vapRecover := testVAP("vap-recover", ptr.To(admissionv1.Ignore), critNSExcludedSelector())
	vapRecover.Annotations = map[string]string{kube.AnnoCircuitBrokenCELPolicy: "2026-11-21T11:00:00Z missing_param_ref"}
	vapRecover.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
	vapbRecover := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-recover"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-recover",
			ParamRef:   &admissionv1.ParamRef{Name: "present-cfg", Namespace: "default"},
		},
	}
	presentParam := &unstructured.Unstructured{}
	presentParam.SetGroupVersionKind(paramGVK)
	presentParam.SetNamespace("default")
	presentParam.SetName("present-cfg")

	cs := fake.NewSimpleClientset(vapUnbroken, vapbUnbroken, vapReverted, vapbReverted, vapRecover, vapbRecover)
	s, g, now := newTestSweeperAndGuard(t, cs)
	if _, err := testCreateUnstructured(g, paramGVR, presentParam); err != nil {
		t.Fatal(err)
	}
	g.PromEndpoint = srv.URL + "/api/v1/query"
	g.PromClient = promq.Client{HTTP: srv.Client(), Timeout: time.Second}

	t.Setenv("CEL_POLICY_CIRCUIT_BREAKER_ENABLED", "false")

	// Sweep 1 & Sweep 2 (t+10m) while disabled.
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 1: %v", err)
	}
	*now = now.Add(10 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}

	// Unbroken policy must not trip AND fault windows must not advance.
	gotUnbroken, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-unbroken", metav1.GetOptions{})
	if *gotUnbroken.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("vap-unbroken tripped while breaker disabled: %v", *gotUnbroken.Spec.FailurePolicy)
	}
	unbrokenKey := KindValidatingPolicy + "/vap-unbroken"
	if s.paramMissingStreak.Count(unbrokenKey) != 0 {
		t.Fatalf("paramMissingStreak advanced while disabled: %d", s.paramMissingStreak.Count(unbrokenKey))
	}
	if _, ok := s.paramMissingSince.Seen(unbrokenKey, *now); ok {
		t.Fatal("paramMissingSince recorded while disabled")
	}
	if _, ok := s.celErrorSince.Seen(unbrokenKey, *now); ok {
		t.Fatal("celErrorSince recorded while disabled")
	}

	// Broken policy whose FailurePolicy drifted to Fail must NOT be re-asserted to Ignore while disabled,
	// yet still emits CELPolicyCircuitBroken=1.
	gotReverted, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-reverted", metav1.GetOptions{})
	if *gotReverted.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("vap-reverted re-asserted to Ignore while breaker disabled: %v", *gotReverted.Spec.FailurePolicy)
	}
	if v := ptestutil.ToFloat64(metrics.CELPolicyCircuitBroken.WithLabelValues(KindValidatingPolicy, "vap-reverted")); v != 1 {
		t.Fatalf("expected CELPolicyCircuitBroken=1 for vap-reverted, got %v", v)
	}

	// Clean broken policy restores after 2 clean cycles even with breaker disabled.
	gotRecover, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-recover", metav1.GetOptions{})
	if *gotRecover.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("vap-recover did not restore in RestoreOnly mode: %v", *gotRecover.Spec.FailurePolicy)
	}
	if gotRecover.Annotations[kube.AnnoCircuitBrokenCELPolicy] != "" {
		t.Fatalf("vap-recover annotation not cleared: %q", gotRecover.Annotations[kube.AnnoCircuitBrokenCELPolicy])
	}

	// Re-enable breaker: vap-unbroken must start a fresh tripWindow (not trip on Sweep 3!).
	t.Setenv("CEL_POLICY_CIRCUIT_BREAKER_ENABLED", "true")
	*now = now.Add(5 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 3 (re-enabled): %v", err)
	}
	gotUnbroken, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-unbroken", metav1.GetOptions{})
	if *gotUnbroken.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("vap-unbroken tripped immediately on re-enable without waiting tripWindow")
	}
}

func TestCELPolicyPatch403And404GracefulSkip(t *testing.T) {
	gr := schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicies"}
	err403 := apierrors.NewForbidden(gr, "", errors.New("forbidden"))
	err404 := apierrors.NewNotFound(gr, "")

	for _, tc := range []struct {
		name     string
		patchErr error
		is404    bool
	}{
		{name: "403 forbidden", patchErr: err403, is404: false},
		{name: "404 not found", patchErr: err404, is404: true},
	} {
		t.Run("criticalns/"+tc.name, func(t *testing.T) {
			vap := testVAP("vap-crit-skip", ptr.To(admissionv1.Fail), nil)
			cs := fake.NewSimpleClientset(vap)
			s, g, now := newTestSweeperAndGuard(t, cs)
			g.Queue = "test-celpolicy-critns-" + tc.name

			// Pre-populate critNSEmitted via enforce=false so 404 also proves stale series pruning.
			t.Setenv("CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED", "false")
			if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
				t.Fatalf("warmup sweep: %v", err)
			}
			if n := countGaugeSeries(metrics.CELPolicyCriticalNSExposed, KindValidatingPolicy, "vap-crit-skip"); n == 0 {
				t.Fatal("expected warmup critical_ns_exposed series to be emitted")
			}

			t.Setenv("CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED", "true")
			cs.PrependReactor("patch", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.patchErr
			})

			heal.ConfigureBudget(1, time.Hour)
			t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

			beforeErrs := queueErrCount(t, g.Queue)
			if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
				t.Fatalf("Sweep returned error on %s: %v", tc.name, err)
			}
			if afterErrs := queueErrCount(t, g.Queue); afterErrs != beforeErrs {
				t.Fatalf("queueErrCount incremented on %s: %v -> %v", tc.name, beforeErrs, afterErrs)
			}
			if proceed, _ := heal.AllowedV(ctx, logf.FromContext(ctx), nil, cs, g.Dyn, nil, "check-refund", 0, *now); !proceed {
				t.Fatalf("expected heal budget grant to be refunded on %s", tc.name)
			}
			n := countGaugeSeries(metrics.CELPolicyCriticalNSExposed, KindValidatingPolicy, "vap-crit-skip")
			if tc.is404 && n != 0 {
				t.Fatalf("expected vanished policy critical_ns_exposed series pruned on 404, found %d", n)
			}
			if !tc.is404 && n == 0 {
				t.Fatal("expected still-exposed policy critical_ns_exposed series preserved on 403")
			}
		})

		t.Run("trip/"+tc.name, func(t *testing.T) {
			vap := testVAP("vap-trip-skip", ptr.To(admissionv1.Fail), critNSExcludedSelector())
			vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
			vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "vapb-trip-skip"},
				Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
					PolicyName: "vap-trip-skip",
					ParamRef:   &admissionv1.ParamRef{Name: "missing", Namespace: "default"},
				},
			}
			cs := fake.NewSimpleClientset(vap, vapb)
			cs.PrependReactor("patch", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.patchErr
			})
			s, g, now := newTestSweeperAndGuard(t, cs)
			g.Queue = "test-celpolicy-trip-" + tc.name
			s.tripWindow = time.Minute
			s.minMissingCycles = 1

			if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
				t.Fatalf("arm sweep: %v", err)
			}
			*now = now.Add(2 * time.Minute)

			heal.ConfigureBudget(1, time.Hour)
			t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

			beforeErrs := queueErrCount(t, g.Queue)
			if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
				t.Fatalf("trip Sweep returned error on %s: %v", tc.name, err)
			}
			if afterErrs := queueErrCount(t, g.Queue); afterErrs != beforeErrs {
				t.Fatalf("queueErrCount incremented on %s: %v -> %v", tc.name, beforeErrs, afterErrs)
			}
			if proceed, _ := heal.AllowedV(ctx, logf.FromContext(ctx), nil, cs, g.Dyn, nil, "check-refund", 0, *now); !proceed {
				t.Fatalf("expected heal budget grant to be refunded on %s", tc.name)
			}
			if n := countGaugeSeries(metrics.CELPolicyCircuitBroken, KindValidatingPolicy, "vap-trip-skip"); n != 0 {
				t.Fatalf("expected 0 circuit_broken series when trip skipped on %s, found %d", tc.name, n)
			}
		})

		t.Run("restore/"+tc.name, func(t *testing.T) {
			brokenVAP := testVAP("vap-restore-skip", ptr.To(admissionv1.Ignore), critNSExcludedSelector())
			brokenVAP.Annotations = map[string]string{kube.AnnoCircuitBrokenCELPolicy: "2026-11-21T12:00:00Z missing_param_ref"}
			cs := fake.NewSimpleClientset(brokenVAP)
			cs.PrependReactor("patch", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.patchErr
			})
			s, g, now := newTestSweeperAndGuard(t, cs)
			g.Queue = "test-celpolicy-restore-" + tc.name

			// Clean cycle 1 emits CELPolicyCircuitBroken=1.
			if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
				t.Fatalf("clean sweep 1: %v", err)
			}
			if v := ptestutil.ToFloat64(metrics.CELPolicyCircuitBroken.WithLabelValues(KindValidatingPolicy, "vap-restore-skip")); v != 1 {
				t.Fatalf("expected circuit_broken=1 on clean cycle 1, got %v", v)
			}

			// Clean cycle 2 triggers restorePolicy.
			*now = now.Add(5 * time.Minute)
			heal.ConfigureBudget(1, time.Hour)
			t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

			beforeErrs := queueErrCount(t, g.Queue)
			if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
				t.Fatalf("restore Sweep returned error on %s: %v", tc.name, err)
			}
			if afterErrs := queueErrCount(t, g.Queue); afterErrs != beforeErrs {
				t.Fatalf("queueErrCount incremented on %s: %v -> %v", tc.name, beforeErrs, afterErrs)
			}
			if proceed, _ := heal.AllowedV(ctx, logf.FromContext(ctx), nil, cs, g.Dyn, nil, "check-refund", 0, *now); !proceed {
				t.Fatalf("expected heal budget grant to be refunded on %s", tc.name)
			}
			n := countGaugeSeries(metrics.CELPolicyCircuitBroken, KindValidatingPolicy, "vap-restore-skip")
			if tc.is404 && n != 0 {
				t.Fatalf("expected vanished policy circuit_broken series pruned on 404, found %d", n)
			}
			if !tc.is404 && n != 1 {
				t.Fatalf("expected still-broken policy circuit_broken series kept on 403, found %d", n)
			}
		})
	}

	t.Run("reassert/404 not found", func(t *testing.T) {
		// Broken policy drifted back to FailurePolicy=Fail while fault active, then vanished mid-sweep.
		driftedVAP := testVAP("vap-reassert-404", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		driftedVAP.Annotations = map[string]string{kube.AnnoCircuitBrokenCELPolicy: "2026-11-21T12:00:00Z missing_param_ref"}
		driftedVAP.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
		vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-reassert-404"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-reassert-404",
				ParamRef:   &admissionv1.ParamRef{Name: "missing", Namespace: "default"},
			},
		}
		cs := fake.NewSimpleClientset(driftedVAP, vapb)
		cs.PrependReactor("patch", "validatingadmissionpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, err404
		})
		s, g, now := newTestSweeperAndGuard(t, cs)
		g.Queue = "test-celpolicy-reassert-404"

		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		beforeErrs := queueErrCount(t, g.Queue)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("reassert 404 Sweep returned error: %v", err)
		}
		if afterErrs := queueErrCount(t, g.Queue); afterErrs != beforeErrs {
			t.Fatalf("queueErrCount incremented on reassert 404: %v -> %v", beforeErrs, afterErrs)
		}
		if proceed, _ := heal.AllowedV(ctx, logf.FromContext(ctx), nil, cs, g.Dyn, nil, "check-refund", 0, *now); !proceed {
			t.Fatal("expected heal budget grant to be refunded on reassert 404")
		}
		if n := countGaugeSeries(metrics.CELPolicyCircuitBroken, KindValidatingPolicy, "vap-reassert-404"); n != 0 {
			t.Fatalf("expected vanished policy circuit_broken series omitted on reassert 404, found %d", n)
		}
	})
}

func countGaugeSeries(vec *prometheus.GaugeVec, kind, policy string) int {
	ch := make(chan prometheus.Metric, 32)
	vec.Collect(ch)
	close(ch)
	count := 0
	for range ch {
		// Re-check via DeleteLabelValues? Easier: use Gather or inspect Metric.
		count++
	}
	// Filter specifically by inspecting DeleteLabelValues without deleting other tests' series:
	_ = count
	// Test helper: check if kube-system or generic tuple exists via probetest-free check.
	if kind != "" && policy != "" {
		// Try DeleteLabelValues for standard critical namespaces or 2-label broken gauge.
		if vec == metrics.CELPolicyCircuitBroken {
			if vec.DeleteLabelValues(kind, policy) {
				return 1
			}
			return 0
		}
		n := 0
		for _, ns := range guardstate.CriticalSelfHealingNamespaces {
			if vec.DeleteLabelValues(kind, policy, ns) {
				n++
			}
		}
		return n
	}
	return 0
}

func queueErrCount(t *testing.T, queue string) float64 {
	t.Helper()
	fams, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != "shell_operator_hook_run_errors_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "queue" && lp.GetValue() == queue {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestCELPolicyParamKindIrregularPluralDiscovery(t *testing.T) {
	gwGVK := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway"}
	gwGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}

	t.Run("present irregular-plural param resolves gateways not gatewaies and ignores subresource", func(t *testing.T) {
		vap := testVAP("vap-gw-present", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway"}
		vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-gw-present"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-gw-present",
				ParamRef:   &admissionv1.ParamRef{Name: "gw-cfg", Namespace: "default"},
			},
		}
		gwObj := &unstructured.Unstructured{}
		gwObj.SetGroupVersionKind(gwGVK)
		gwObj.SetNamespace("default")
		gwObj.SetName("gw-cfg")

		cs := fake.NewSimpleClientset(vap, vapb)
		cs.Resources = []*metav1.APIResourceList{{
			GroupVersion: "gateway.networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				// Subresource listed first to verify subresource skipping.
				{Name: "gateways/status", Namespaced: true, Kind: "Gateway"},
				{Name: "gateways", Namespaced: true, Kind: "Gateway"},
			},
		}}
		s, g, now := newTestSweeperAndGuard(t, cs)
		s.tripWindow = time.Minute
		s.minMissingCycles = 1
		if _, err := testCreateUnstructured(g, gwGVR, gwObj); err != nil {
			t.Fatal(err)
		}

		g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("*", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetResource().Group == "gateway.networking.k8s.io" && a.GetResource().Resource != "gateways" {
				t.Fatalf("unexpected dynamic resource %q (expected gateways)", a.GetResource().Resource)
			}
			return false, nil, nil
		})

		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 1: %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 2: %v", err)
		}
		got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-gw-present", metav1.GetOptions{})
		if *got.Spec.FailurePolicy != admissionv1.Fail {
			t.Fatalf("healthy irregular-plural Gateway policy tripped: %v", *got.Spec.FailurePolicy)
		}
	})

	t.Run("missing irregular-plural param trips via real NotFound on gateways", func(t *testing.T) {
		vap := testVAP("vap-gw-missing", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway"}
		vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-gw-missing"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-gw-missing",
				ParamRef:   &admissionv1.ParamRef{Name: "missing-gw", Namespace: "default"},
			},
		}
		cs := fake.NewSimpleClientset(vap, vapb)
		cs.Resources = []*metav1.APIResourceList{{
			GroupVersion: "gateway.networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "gateways/status", Namespaced: true, Kind: "Gateway"},
				{Name: "gateways", Namespaced: true, Kind: "Gateway"},
			},
		}}
		s, g, now := newTestSweeperAndGuard(t, cs)
		s.tripWindow = time.Minute
		s.minMissingCycles = 1

		var seenResource string
		g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("get", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetResource().Group == "gateway.networking.k8s.io" {
				seenResource = a.GetResource().Resource
			}
			return false, nil, nil
		})

		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 1: %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 2: %v", err)
		}
		if seenResource != gwGVR.Resource {
			t.Fatalf("queried resource = %q, want %q", seenResource, gwGVR.Resource)
		}
		got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-gw-missing", metav1.GetOptions{})
		if *got.Spec.FailurePolicy != admissionv1.Ignore {
			t.Fatalf("expected Ignore after missing Gateway paramRef, got %v", *got.Spec.FailurePolicy)
		}
	})
}

func TestCELPolicyNamespacedParamRefWithoutNamespace(t *testing.T) {
	t.Run("Name without Namespace skips cluster-scoped Get and recovers after PromQL trip", func(t *testing.T) {
		firing := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if firing && strings.Contains(r.FormValue("query"), "apiserver_validating_admission_policy_check_total") {
				_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"policy":"vap-per-ns"},"value":[1700000000,"0.5"]}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}))
		defer srv.Close()

		vap := testVAP("vap-per-ns", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
		vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-per-ns"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-per-ns",
				ParamRef:   &admissionv1.ParamRef{Name: "per-ns-cfg", Namespace: ""},
			},
		}
		cs := fake.NewSimpleClientset(vap, vapb)
		s, g, now := newTestSweeperAndGuard(t, cs)
		s.tripWindow = time.Minute
		s.minMissingCycles = 1
		g.PromEndpoint = srv.URL + "/api/v1/query"
		g.PromClient = promq.Client{HTTP: srv.Client(), Timeout: time.Second}

		g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("*", "policyparams", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetNamespace() == "" {
				t.Fatalf("unexpected cluster-scoped %s on namespaced PolicyParam", a.GetVerb())
			}
			return false, nil, nil
		})

		// Healthy across > tripWindow: stays Fail.
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 1: %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 2: %v", err)
		}
		got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-per-ns", metav1.GetOptions{})
		if *got.Spec.FailurePolicy != admissionv1.Fail {
			t.Fatalf("per-ns binding tripped falsely: %v", *got.Spec.FailurePolicy)
		}

		// Trip via PromQL error storm.
		firing = true
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 3 (storm 1): %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 4 (storm 2): %v", err)
		}
		got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-per-ns", metav1.GetOptions{})
		if *got.Spec.FailurePolicy != admissionv1.Ignore {
			t.Fatalf("expected Ignore after PromQL storm, got %v", *got.Spec.FailurePolicy)
		}

		// Clear PromQL storm: 2 clean cycles must restore to Fail (not stuck unverifiable!).
		firing = false
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 5 (clean 1): %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 6 (clean 2): %v", err)
		}
		got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-per-ns", metav1.GetOptions{})
		if *got.Spec.FailurePolicy != admissionv1.Fail {
			t.Fatalf("per-ns binding failed to auto-restore after PromQL storm cleared: %v", *got.Spec.FailurePolicy)
		}
	})

	t.Run("Selector without Namespace skips cluster-scoped List", func(t *testing.T) {
		vap := testVAP("vap-per-ns-sel", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
		vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-per-ns-sel"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-per-ns-sel",
				ParamRef: &admissionv1.ParamRef{
					Namespace: "",
					Selector:  &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guard"}},
				},
			},
		}
		cs := fake.NewSimpleClientset(vap, vapb)
		s, g, now := newTestSweeperAndGuard(t, cs)
		s.tripWindow = time.Minute
		s.minMissingCycles = 1

		g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("*", "policyparams", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetNamespace() == "" {
				t.Fatalf("unexpected cluster-scoped %s on namespaced PolicyParam", a.GetVerb())
			}
			return false, nil, nil
		})

		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 1: %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 2: %v", err)
		}
		got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-per-ns-sel", metav1.GetOptions{})
		if *got.Spec.FailurePolicy != admissionv1.Fail {
			t.Fatalf("per-ns selector binding tripped falsely: %v", *got.Spec.FailurePolicy)
		}
	})
}

func TestCELPolicyDiscoveryMissingAndCRDAbsentFailClosed(t *testing.T) {
	t.Run("missing GroupVersion in discovery stays Fail with 0 dyn calls and 0 IncError", func(t *testing.T) {
		vap := testVAP("vap-missing-gv", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "missing.example.com/v1", Kind: "MissingParam"}
		vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-missing-gv"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-missing-gv",
				ParamRef:   &admissionv1.ParamRef{Name: "cfg", Namespace: "default"},
			},
		}
		cs := fake.NewSimpleClientset(vap, vapb)
		cs.Resources = []*metav1.APIResourceList{} // explicitly non-nil empty
		s, g, now := newTestSweeperAndGuard(t, cs)
		g.Queue = "test-celpolicy-disc-missing-gv"
		s.tripWindow = time.Minute
		s.minMissingCycles = 1

		var dynCalls int
		g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("*", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetResource().Group == "missing.example.com" {
				dynCalls++
			}
			return false, nil, nil
		})

		beforeErrs := queueErrCount(t, g.Queue)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 1: %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 2: %v", err)
		}
		if dynCalls != 0 {
			t.Fatalf("dynCalls = %d, want 0", dynCalls)
		}
		if afterErrs := queueErrCount(t, g.Queue); afterErrs != beforeErrs {
			t.Fatalf("IncError incremented on absent GV discovery: %v -> %v", beforeErrs, afterErrs)
		}
		got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-missing-gv", metav1.GetOptions{})
		if *got.Spec.FailurePolicy != admissionv1.Fail {
			t.Fatalf("expected Fail on missing GV discovery, got %v", *got.Spec.FailurePolicy)
		}
	})

	t.Run("GroupVersion without Kind stays Fail with 0 dyn calls and 0 IncError", func(t *testing.T) {
		vap := testVAP("vap-missing-kind", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "OtherKind"}
		vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-missing-kind"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-missing-kind",
				ParamRef:   &admissionv1.ParamRef{Name: "cfg", Namespace: "default"},
			},
		}
		cs := fake.NewSimpleClientset(vap, vapb)
		s, g, now := newTestSweeperAndGuard(t, cs) // seeds only PolicyParam
		g.Queue = "test-celpolicy-disc-missing-kind"
		s.tripWindow = time.Minute
		s.minMissingCycles = 1

		var dynCalls int
		g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("*", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetResource().Group == "example.com" {
				dynCalls++
			}
			return false, nil, nil
		})

		beforeErrs := queueErrCount(t, g.Queue)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 1: %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 2: %v", err)
		}
		if dynCalls != 0 {
			t.Fatalf("dynCalls = %d, want 0", dynCalls)
		}
		if afterErrs := queueErrCount(t, g.Queue); afterErrs != beforeErrs {
			t.Fatalf("IncError incremented on missing Kind discovery: %v -> %v", beforeErrs, afterErrs)
		}
		got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-missing-kind", metav1.GetOptions{})
		if *got.Spec.FailurePolicy != admissionv1.Fail {
			t.Fatalf("expected Fail on missing Kind discovery, got %v", *got.Spec.FailurePolicy)
		}
	})

	t.Run("discovery 500 error fails closed (neither trips nor restores) and increments IncError", func(t *testing.T) {
		unbroken := testVAP("vap-disc-unbroken", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		unbroken.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
		unbrokenB := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-disc-unbroken"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-disc-unbroken",
				ParamRef:   &admissionv1.ParamRef{Name: "cfg", Namespace: "default"},
			},
		}
		broken := testVAP("vap-disc-broken", ptr.To(admissionv1.Ignore), critNSExcludedSelector())
		broken.Annotations = map[string]string{kube.AnnoCircuitBrokenCELPolicy: "2026-11-21T12:00:00Z missing_param_ref"}
		broken.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
		brokenB := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-disc-broken"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-disc-broken",
				ParamRef:   &admissionv1.ParamRef{Name: "cfg", Namespace: "default"},
			},
		}

		cs := fake.NewSimpleClientset(unbroken, unbrokenB, broken, brokenB)
		cs.Discovery().(*fakediscovery.FakeDiscovery).PrependReactor("get", "resource", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("discovery 500"))
		})
		s, g, now := newTestSweeperAndGuard(t, cs)
		g.Queue = "test-celpolicy-disc-500"
		s.tripWindow = time.Minute
		s.minMissingCycles = 1

		beforeErrs := queueErrCount(t, g.Queue)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 1: %v", err)
		}
		*now = now.Add(6 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 2: %v", err)
		}
		if afterErrs := queueErrCount(t, g.Queue); afterErrs <= beforeErrs {
			t.Fatalf("expected IncError on 500 discovery error, got %v -> %v", beforeErrs, afterErrs)
		}
		gotUnbroken, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-disc-unbroken", metav1.GetOptions{})
		if *gotUnbroken.Spec.FailurePolicy != admissionv1.Fail {
			t.Fatalf("unbroken policy tripped during discovery 500: %v", *gotUnbroken.Spec.FailurePolicy)
		}
		gotBroken, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-disc-broken", metav1.GetOptions{})
		if *gotBroken.Spec.FailurePolicy != admissionv1.Ignore {
			t.Fatalf("broken policy restored during discovery 500 (must fail closed): %v", *gotBroken.Spec.FailurePolicy)
		}
	})

	t.Run("Selector List CRD-absent and Get NoMatch fail closed without tripping", func(t *testing.T) {
		vapSel := testVAP("vap-list-nomatch", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vapSel.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
		vapbSel := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-list-nomatch"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-list-nomatch",
				ParamRef: &admissionv1.ParamRef{
					Namespace: "default",
					Selector:  &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guard"}},
				},
			},
		}
		vapGet := testVAP("vap-get-nomatch", ptr.To(admissionv1.Fail), critNSExcludedSelector())
		vapGet.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "PolicyParam"}
		vapbGet := &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "vapb-get-nomatch"},
			Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
				PolicyName: "vap-get-nomatch",
				ParamRef:   &admissionv1.ParamRef{Name: "cfg", Namespace: "default"},
			},
		}
		cs := fake.NewSimpleClientset(vapSel, vapbSel, vapGet, vapbGet)
		s, g, now := newTestSweeperAndGuard(t, cs)
		g.Queue = "test-celpolicy-nomatch"
		s.tripWindow = time.Minute
		s.minMissingCycles = 1

		noMatch := &meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "policyparams"}}
		g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("list", "policyparams", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, noMatch
		})
		g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("get", "policyparams", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, noMatch
		})

		beforeErrs := queueErrCount(t, g.Queue)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 1: %v", err)
		}
		*now = now.Add(2 * time.Minute)
		if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
			t.Fatalf("Sweep 2: %v", err)
		}
		if afterErrs := queueErrCount(t, g.Queue); afterErrs != beforeErrs {
			t.Fatalf("IncError incremented on CRD-absent NoMatch: %v -> %v", beforeErrs, afterErrs)
		}
		for _, name := range []string{"vap-list-nomatch", "vap-get-nomatch"} {
			got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, name, metav1.GetOptions{})
			if *got.Spec.FailurePolicy != admissionv1.Fail {
				t.Fatalf("%s tripped on CRD-absent NoMatch: %v", name, *got.Spec.FailurePolicy)
			}
		}
	})
}

func TestCELPolicyClusterScopedParamKind(t *testing.T) {
	paramGVK := schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "ClusterPolicyParam"}
	paramGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "clusterpolicyparams"}

	vap := testVAP("vap-cluster-param", ptr.To(admissionv1.Fail), critNSExcludedSelector())
	vap.Spec.ParamKind = &admissionv1.ParamKind{APIVersion: "example.com/v1", Kind: "ClusterPolicyParam"}
	vapb := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "vapb-cluster-param"},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "vap-cluster-param",
			ParamRef:   &admissionv1.ParamRef{Name: "missing-global", Namespace: ""},
		},
	}

	cs := fake.NewSimpleClientset(vap, vapb)
	cs.Resources = []*metav1.APIResourceList{{
		GroupVersion: "example.com/v1",
		APIResources: []metav1.APIResource{{
			Name:       "clusterpolicyparams",
			Namespaced: false,
			Kind:       "ClusterPolicyParam",
		}},
	}}
	s, g, now := newTestSweeperAndGuard(t, cs)
	s.tripWindow = time.Minute
	s.minMissingCycles = 1

	var getNamespace string
	var getCalls int
	g.Dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("get", "clusterpolicyparams", func(a ktesting.Action) (bool, runtime.Object, error) {
		getCalls++
		getNamespace = a.GetNamespace()
		return false, nil, nil
	})

	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 1: %v", err)
	}
	*now = now.Add(2 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	if getCalls == 0 || getNamespace != "" {
		t.Fatalf("expected cluster-scoped Get (calls=%d ns=%q)", getCalls, getNamespace)
	}
	got, _ := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-cluster-param", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected Ignore for missing cluster-scoped ParamKind, got %v", *got.Spec.FailurePolicy)
	}

	// Create cluster-scoped param object -> 2 clean cycles restore to Fail.
	paramObj := &unstructured.Unstructured{}
	paramObj.SetGroupVersionKind(paramGVK)
	paramObj.SetName("missing-global")
	if _, err := g.Dyn.Resource(paramGVR).Create(ctx, paramObj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 3 (clean 1): %v", err)
	}
	*now = now.Add(2 * time.Minute)
	if err := s.Sweep(ctx, makeSnap(ctx, g)); err != nil {
		t.Fatalf("Sweep 4 (clean 2): %v", err)
	}
	got, _ = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "vap-cluster-param", metav1.GetOptions{})
	if *got.Spec.FailurePolicy != admissionv1.Fail {
		t.Fatalf("expected Fail after cluster-scoped param created, got %v", *got.Spec.FailurePolicy)
	}
}

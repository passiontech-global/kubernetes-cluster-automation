// olm_subscription_health_test.go — coverage for the
// olm-subscription-health check (W7-C5): absent-CRD quiet, stuck
// CSV heal, unhealthy subscription, cert-rotation overdue.
package datastore

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// W7-C5 — olm-subscription-health
// ---------------------------------------------------------------------------

// olmUnstructured builds an OLM object with the fields the check
// reads, supplied by the caller as nested status fields.
func olmUnstructured(apiVersion, kind, ns, name string, status map[string]any) *unstructured.Unstructured {
	obj := testutil.Unstructured(
		schema.FromAPIVersionAndKind(apiVersion, kind), ns, name, nil)
	for k, v := range status {
		_ = unstructured.SetNestedField(obj.Object, v, "status", k)
	}
	return obj
}

// Absent OLM CRDs read as "not installed" — the check stays quiet.
func TestCheckOLMHealthAbsentCRDsQuiet(t *testing.T) {
	dyn := probetest.OpDyn()
	dyn.PrependReactor("list", "clusterserviceversions",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				olmCSVGVR.GroupResource(), "")
		})
	dyn.PrependReactor("list", "subscriptions",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				olmSubGVR.GroupResource(), "")
		})
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("absent OLM CRDs must pass quietly: %+v", res)
	}
}

// A CSV stuck off Succeeded past 15m fires the gauge; past 20m the
// olm-operator leader gets bounced to force re-reconciliation.
func TestCheckOLMHealthStuckCSVHeals(t *testing.T) {
	olmUnhealthyResourcesGauge.DeleteLabelValues(
		olmKindCSV, "operators", "rabbitmq.v1.2.3", olmReasonCSVStuck)
	t.Cleanup(func() {
		olmUnhealthyResourcesGauge.DeleteLabelValues(
			olmKindCSV, "operators", "rabbitmq.v1.2.3", olmReasonCSVStuck)
		olmOperatorHealsTotal.DeleteLabelValues(olmReasonCSVStuck)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-77dc", UID: "o1"}}
	cs := fake.NewSimpleClientset(opPod)
	csv := olmUnstructured("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "rabbitmq.v1.2.3", map[string]any{"phase": "Installing"})
	p := testProberDyn(cs, probetest.OpDyn(csv))
	p.Now = func() time.Time { return base }

	// First sighting — tracked, quiet.
	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen CSV must pass: %+v", res)
	}

	// 16m — gauge fires, still under the heal window.
	at := base.Add(16 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("CSV stuck >=15m must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_olm_unhealthy_resources",
		map[string]string{"kind": olmKindCSV, "namespace": "operators",
			"name": "rabbitmq.v1.2.3", "reason": olmReasonCSVStuck})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("olm unhealthy gauge missing/0, want 1")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); err != nil {
		t.Fatal("olm-operator deleted before the 20m heal window")
	}

	// 21m — the operator is bounced.
	at = base.Add(21 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("still stuck — must keep FAILING")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("olm-operator must be deleted past 20m, err=%v", err)
	}
}

// Restart resume: a CSV still carrying the persisted first-seen
// stamp past the heal window bounces the olm-operator on the FIRST
// post-restart sweep — the in-RAM ledger is empty but the per-reason
// stamp map proves the stuck-CSV signature held.
func TestCheckOLMHealthRestartResumeHeals(t *testing.T) {
	t.Cleanup(func() {
		olmUnhealthyResourcesGauge.DeleteLabelValues(
			olmKindCSV, "operators", "rabbitmq.v1.2.3", olmReasonCSVStuck)
		olmOperatorHealsTotal.DeleteLabelValues(olmReasonCSVStuck)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-77dc", UID: "o1"}}
	cs := fake.NewSimpleClientset(opPod)
	csv := olmUnstructured("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "rabbitmq.v1.2.3", map[string]any{"phase": "Installing"})
	csv.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenOLMUnhealthy: `{"ClusterServiceVersion/operators/rabbitmq.v1.2.3/` +
			olmReasonCSVStuck + `":"` +
			base.Add(-21*time.Minute).UTC().Format(time.RFC3339) + `"}`})
	p := testProberDyn(cs, probetest.OpDyn(csv))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted CSV window past the heal window must FAIL on the first sweep")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("resumed window must bounce the operator, err=%v", err)
	}
}

// A Subscription carrying CatalogSourcesUnhealthy=True flags after
// the window but never triggers the operator heal — that's the
// CSV-scoped path.
func TestCheckOLMHealthUnhealthySubscription(t *testing.T) {
	t.Cleanup(func() {
		olmUnhealthyResourcesGauge.DeleteLabelValues(
			olmKindSubscription, "operators", "keda", olmReasonCatalogUnhealthy)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-77dc", UID: "o1"}}
	cs := fake.NewSimpleClientset(opPod)
	sub := olmUnstructured("operators.coreos.com/v1alpha1", "Subscription",
		"operators", "keda", map[string]any{
			"conditions": []any{map[string]any{
				"type": "CatalogSourcesUnhealthy", "status": "True"}},
		})
	p := testProberDyn(cs, probetest.OpDyn(sub))
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*olmHealthCheck](t, p).olmFirstSeen.
		Observe("Subscription/operators/keda/"+olmReasonCatalogUnhealthy,
			base.Add(-time.Hour))

	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("unhealthy subscription must FAIL")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); err != nil {
		t.Fatal("olm-operator deleted for a subscription-only failure")
	}
}

// An expired certsRotateAt counts the same as a wedged phase — the
// webhook certs OLM owes the operand never landed.
func TestCheckOLMHealthCertRotationOverdue(t *testing.T) {
	t.Cleanup(func() {
		olmUnhealthyResourcesGauge.DeleteLabelValues(
			olmKindCSV, "operators", "nhc.v1", olmReasonCertOverdue)
		olmOperatorHealsTotal.DeleteLabelValues(olmReasonCertOverdue)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-77dc", UID: "o1"}}
	cs := fake.NewSimpleClientset(opPod)
	csv := olmUnstructured("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "nhc.v1", map[string]any{
			"phase":         "Succeeded",
			"certsRotateAt": base.Add(-30 * time.Minute).UTC().Format(time.RFC3339),
		})
	p := testProberDyn(cs, probetest.OpDyn(csv))
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*olmHealthCheck](t, p).olmFirstSeen.
		Observe("ClusterServiceVersion/operators/nhc.v1/"+olmReasonCertOverdue,
			base.Add(-25*time.Minute))

	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("overdue cert rotation past the heal window must FAIL")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("olm-operator must be deleted, err=%v", err)
	}
}

// A healthy CSV + clean subscription pass quietly.
func TestCheckOLMHealthHealthyPasses(t *testing.T) {
	csv := olmUnstructured("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "nhc.v1", map[string]any{"phase": "Succeeded"})
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(csv))
	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("healthy OLM state must pass: %+v", res)
	}
	if keys := probetest.LedgerKeys(&probetest.MustCheck[*olmHealthCheck](t, p).olmFirstSeen); len(keys) != 0 {
		t.Fatalf("healthy objects must not be tracked: %v", keys)
	}
}

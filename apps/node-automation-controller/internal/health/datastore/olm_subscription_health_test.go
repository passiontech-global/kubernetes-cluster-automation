// olm_subscription_health_test.go — coverage for the
// olm-subscription-health check (W7-C5): absent-CRD quiet, stuck
// CSV heal, unhealthy subscription, cert-rotation overdue.
package datastore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
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

// The olm-operator heal stamps passiontech.dev/last-olm-operator-heal
// on the operator Deployment, and a fresh post-restart process reads
// it back: a stamp inside the 1h window defers the bounce with an
// empty in-RAM ledger.
func TestCheckOLMHealthHealStampPersistedOnDeployment(t *testing.T) {
	t.Cleanup(func() {
		olmUnhealthyResourcesGauge.DeleteLabelValues(
			olmKindCSV, "operators", "rabbitmq.v1.2.3", olmReasonCSVStuck)
		olmOperatorHealsTotal.DeleteLabelValues(olmReasonCSVStuck)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-77dc", UID: "o1"}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: olmOperatorPodPrefix}}
	csv := olmUnstructured("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "rabbitmq.v1.2.3", map[string]any{"phase": "Installing"})
	csv.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenOLMUnhealthy: `{"ClusterServiceVersion/operators/rabbitmq.v1.2.3/` +
			olmReasonCSVStuck + `":"` +
			base.Add(-21*time.Minute).UTC().Format(time.RFC3339) + `"}`})
	p := testProberDyn(fake.NewSimpleClientset(opPod, dep), probetest.OpDyn(csv))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*olmHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stuck CSV past the heal window must FAIL")
	}
	if _, err := p.CS.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("olm-operator must be deleted, err=%v", err)
	}
	depGot, err := p.CS.AppsV1().Deployments("olm").
		Get(ctx, olmOperatorPodPrefix, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kube.AnnoTime(depGot, olmHealAnno); !ok {
		t.Fatalf("deployment missing %s stamp", olmHealAnno)
	}

	// Restart: the same CSV still wedged, the same Deployment now
	// carrying a fresh stamp — the annotation alone defers the bounce.
	opPod2 := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-88de", UID: "o2"}}
	dep2 := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: olmOperatorPodPrefix,
		Annotations: map[string]string{
			olmHealAnno: base.Add(-10 * time.Minute).UTC().Format(time.RFC3339)}}}
	csv2 := olmUnstructured("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "rabbitmq.v1.2.3", map[string]any{"phase": "Installing"})
	csv2.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenOLMUnhealthy: `{"ClusterServiceVersion/operators/rabbitmq.v1.2.3/` +
			olmReasonCSVStuck + `":"` +
			base.Add(-21*time.Minute).UTC().Format(time.RFC3339) + `"}`})
	p2 := testProberDyn(fake.NewSimpleClientset(opPod2, dep2), probetest.OpDyn(csv2))
	p2.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*olmHealthCheck](t, p2).Run(ctx); res.Pass {
		t.Fatal("stuck CSV must still FAIL under the persisted cooldown")
	}
	if _, err := p2.CS.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-88de", metav1.GetOptions{}); err != nil {
		t.Fatal("post-restart bounce ignored the persisted Deployment stamp")
	}
}

// olmCRPatch mirrors an annotation stamp into the listed object ONLY
// after the patch landed — a failed patch must leave no phantom key
// the sweep's stamp/clear loops then read back (the pre-patch mirror
// left the failed key in the local map until the next List).
func TestOLMCRPatchMirrorsOnlyLandedStamps(t *testing.T) {
	csv := olmUnstructured("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "nhc.v1", map[string]any{"phase": "Installing"})
	dyn := testutil.NewDynamicClient(csv)
	fail := true
	dyn.PrependReactor("patch", "clusterserviceversions",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if fail {
				return true, nil, errors.New("patch rejected")
			}
			return false, nil, nil
		})
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*olmHealthCheck](t, p)
	obj, err := dyn.Resource(olmCSVGVR).Namespace("operators").
		Get(ctx, "nhc.v1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	patch := chk.olmCRPatch(olmCSVGVR, obj)
	// stampMap builds the patch payload the way heal.stampFirstSeen
	// does: the annotation VALUE is the full per-key stamp map read
	// off the listed object (the mirror), so a landed write replaces
	// the whole map with itself + the new key.
	stampMap := func(keys ...string) []byte {
		m := map[string]string{}
		for _, k := range keys {
			m[k] = time.Now().UTC().Format(time.RFC3339)
		}
		// firstSeenValue encodes the map as a JSON STRING — the
		// annotation value the merge patch carries.
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		data, err := kube.MergePatchAnnos(map[string]any{
			kube.AnnoFirstSeenOLMUnhealthy: string(raw),
		})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	// A rejected patch must leave the local map untouched.
	if err := patch(ctx, stampMap("phantom")); err == nil {
		t.Fatal("reactor did not reject the patch")
	}
	if _, ok := olmAnnoKeys(obj)["phantom"]; ok {
		t.Fatal("failed patch left a phantom stamp in the listed object")
	}
	if raw := obj.GetAnnotations()[kube.AnnoFirstSeenOLMUnhealthy]; raw != "" {
		t.Fatalf("failed patch left annotation %q behind", raw)
	}
	// A landed patch mirrors into the listed object.
	fail = false
	if err := patch(ctx, stampMap("k1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := olmAnnoKeys(obj)["k1"]; !ok {
		t.Fatal("landed k1 stamp not mirrored into the listed object")
	}
	// The NEXT stamp builds from the mirrored map — k1 survives the
	// k2 write (the pre-patch mirror made this a phantom-clobbering
	// sequence when the first patch failed).
	if err := patch(ctx, stampMap("k1", "k2")); err != nil {
		t.Fatal(err)
	}
	m := olmAnnoKeys(obj)
	if _, ok := m["k1"]; !ok {
		t.Fatal("k2 stamp dropped the mirrored k1 key")
	}
	if _, ok := m["k2"]; !ok {
		t.Fatal("landed k2 stamp not mirrored into the listed object")
	}
	if _, ok := m["phantom"]; ok {
		t.Fatal("phantom key resurrected by a later stamp")
	}
}

// olmAnnoKeys parses the per-key first-seen stamp map off a listed
// OLM object — the test-side read of what olmCRPatch mirrored.
func olmAnnoKeys(obj *unstructured.Unstructured) map[string]string {
	raw := obj.GetAnnotations()[kube.AnnoFirstSeenOLMUnhealthy]
	if raw == "" {
		return map[string]string{}
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return map[string]string{}
	}
	return m
}

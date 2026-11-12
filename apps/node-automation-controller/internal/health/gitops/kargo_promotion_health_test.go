// kargo_promotion_health_test.go — coverage for the
// kargo-promotion-health check (kargo-promotion-health): stuck Promotions,
// unhealthy Warehouses (emit + persisted-cooldown refresh nudge),
// zombie AnalysisRuns, and the CRD-absent tolerance.
package gitops

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// kargoPromotion builds a Promotion CR in the given phase, created
// `age` ago.
func kargoPromotion(ns, name, stage, phase string, age time.Duration) *unstructured.Unstructured {
	obj := probetest.UnstructuredObj("kargo.akuity.io/v1alpha1", "Promotion",
		ns, name, 1, 0)
	obj.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	_ = unstructured.SetNestedField(obj.Object, stage, "spec", "stage")
	_ = unstructured.SetNestedField(obj.Object, phase, "status", "phase")
	return obj
}

// kargoWarehouse builds a Warehouse whose Ready condition flipped
// `ready` at `since`.
func kargoWarehouse(ns, name, status string, since time.Time) *unstructured.Unstructured {
	obj := probetest.UnstructuredObj("kargo.akuity.io/v1alpha1", "Warehouse",
		ns, name, 1, 0)
	_ = unstructured.SetNestedSlice(obj.Object, []any{map[string]any{
		"type":               "Ready",
		"status":             status,
		"lastTransitionTime": since.UTC().Format(time.RFC3339),
	}}, "status", "conditions")
	return obj
}

// argoAnalysisRun builds an AnalysisRun CR in the given phase,
// created `age` ago.
func argoAnalysisRun(ns, name, phase string, age time.Duration) *unstructured.Unstructured {
	obj := probetest.UnstructuredObj("argoproj.io/v1alpha1", "AnalysisRun",
		ns, name, 1, 0)
	obj.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	_ = unstructured.SetNestedField(obj.Object, phase, "status", "phase")
	return obj
}

// No Kargo/Rollouts objects at all — every family lists empty, the
// check passes.
func TestKargoPromotionHealthEmptyPasses(t *testing.T) {
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn())
	if res := probetest.MustCheck[*kargoPromotionHealthCheck](t, p).
		Run(ctx); !res.Pass {
		t.Fatalf("empty cluster must pass: %+v", res)
	}
}

// A Promotion stuck Running past the hour emits its stuck gauge and
// fails the check; a fresh one and a terminal one stay quiet.
func TestKargoPromotionStuckFlags(t *testing.T) {
	dyn := probetest.OpDyn(
		kargoPromotion("kargo", "promo-stuck", "prod", "Running", 2*time.Hour),
		kargoPromotion("kargo", "promo-fresh", "prod", "Running", 10*time.Minute),
		kargoPromotion("kargo", "promo-done", "prod", "Succeeded", 3*time.Hour),
	)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)

	res := probetest.MustCheck[*kargoPromotionHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("a >60m Running promotion must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_kargo_promotion_stuck",
		map[string]string{"namespace": "kargo", "name": "promo-stuck", "stage": "prod"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("stuck promotion gauge must emit {namespace,name,stage}")
	}
	if m := probetest.FindMetric(t, "node_automation_kargo_promotion_stuck",
		map[string]string{"namespace": "kargo", "name": "promo-fresh", "stage": "prod"}); m != nil {
		t.Fatal("a fresh Running promotion must not emit")
	}
}

// A Warehouse Ready=False past the half hour emits the unhealthy
// gauge AND gets the refresh nudge — both annotations land together.
func TestKargoWarehouseUnhealthyRefreshes(t *testing.T) {
	base := time.Now()
	dyn := probetest.OpDyn(
		kargoWarehouse("kargo", "wh-bad", "False", base.Add(-45*time.Minute)),
		kargoWarehouse("kargo", "wh-fresh", "False", base.Add(-5*time.Minute)),
	)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	probetest.FreezeNow(p.Deps, base)

	res := probetest.MustCheck[*kargoPromotionHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("a >30m unready warehouse must FAIL the check")
	}
	got, err := dyn.Resource(kube.GVRKargoWarehouse).Namespace("kargo").
		Get(ctx, "wh-bad", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get warehouse: %v", err)
	}
	annos := got.GetAnnotations()
	if annos[kube.AnnoKargoRefresh] == "" ||
		annos[kube.AnnoLastKargoRefresh] == "" {
		t.Fatalf("refresh nudge must stamp both annotations, got %v", annos)
	}
	// The fresh-failed warehouse stays unpatched — inside the window.
	got, err = dyn.Resource(kube.GVRKargoWarehouse).Namespace("kargo").
		Get(ctx, "wh-fresh", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get warehouse: %v", err)
	}
	if got.GetAnnotations()[kube.AnnoKargoRefresh] != "" {
		t.Fatal("a warehouse inside the 30m window must not be nudged")
	}

	// Second sweep inside the 1h cooldown: the persisted stamp must
	// suppress a re-patch — the annotation value must not move.
	probetest.FreezeNow(p.Deps, base.Add(10*time.Minute))
	_ = probetest.MustCheck[*kargoPromotionHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	got2, _ := dyn.Resource(kube.GVRKargoWarehouse).Namespace("kargo").
		Get(ctx, "wh-bad", metav1.GetOptions{})
	if got2.GetAnnotations()[kube.AnnoKargoRefresh] !=
		annos[kube.AnnoKargoRefresh] {
		t.Fatal("refresh nudge inside the 1h cooldown must not re-patch")
	}
}

// A persisted cooldown stamp from a PREVIOUS process (annotation
// survives a restart) suppresses the nudge even with an empty
// in-RAM ledger.
func TestKargoWarehouseRefreshRespectsPersistedStamp(t *testing.T) {
	base := time.Now()
	wh := kargoWarehouse("kargo", "wh-bad", "False", base.Add(-45*time.Minute))
	wh.SetAnnotations(map[string]string{
		kube.AnnoLastKargoRefresh: base.Add(-10 * time.Minute).
			UTC().Format(time.RFC3339)})
	dyn := probetest.OpDyn(wh)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	probetest.FreezeNow(p.Deps, base)

	res := probetest.MustCheck[*kargoPromotionHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("unhealthy warehouse must still FAIL")
	}
	got, _ := dyn.Resource(kube.GVRKargoWarehouse).Namespace("kargo").
		Get(ctx, "wh-bad", metav1.GetOptions{})
	if got.GetAnnotations()[kube.AnnoKargoRefresh] != "" {
		t.Fatal("a warm persisted cooldown must suppress the nudge")
	}
}

// An AnalysisRun still Running past the hour emits its zombie gauge.
func TestKargoAnalysisRunZombieFlags(t *testing.T) {
	dyn := probetest.OpDyn(
		argoAnalysisRun("app", "ar-stuck", "Running", 2*time.Hour),
		argoAnalysisRun("app", "ar-ok", "Successful", 2*time.Hour),
	)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)

	res := probetest.MustCheck[*kargoPromotionHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("a >60m Running analysisrun must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_analysisrun_stuck",
		map[string]string{"namespace": "app", "name": "ar-stuck"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("zombie analysisrun gauge must emit")
	}
}

// A NotFound on ONE family must not blind the others — the
// promotions CRD can be absent while warehouses still scan.
func TestKargoFamilyAbsenceTolerated(t *testing.T) {
	base := time.Now()
	dyn := probetest.OpDyn(
		kargoWarehouse("kargo", "wh-bad", "False", base.Add(-45*time.Minute)),
	)
	dyn.PrependReactor("list", "promotions",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{
				Group: "kargo.akuity.io", Resource: "promotions"}, "")
		})
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	probetest.FreezeNow(p.Deps, base)

	res := probetest.MustCheck[*kargoPromotionHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass || res.Infra != nil {
		t.Fatalf("one absent CRD family must not blind the others: %+v", res)
	}
}

// maybeRefreshKargoWarehouse's failure half: a failed refresh patch
// is IncError'd and leaves the cooldown ledger unstamped, so the
// next sweep retries the nudge rather than cooling down on a write
// that never landed.
func TestMaybeRefreshKargoWarehousePatchError(t *testing.T) {
	now := time.Now()
	wh := kargoWarehouse("kargo", "wh-bad", "False", now.Add(-45*time.Minute))
	dyn := probetest.OpDyn(wh)
	dyn.PrependReactor("patch", "warehouses",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver down")
		})
	p := &kargoPromotionHealthCheck{Deps: &probefw.Deps{
		Name: CheckNameKargoPromotionHealth,
		CS:   fake.NewSimpleClientset(), Dyn: dyn}}
	before := testutil.QueueErrorCount(t, CheckNameKargoPromotionHealth)
	p.maybeRefreshKargoWarehouse(ctx, logr.Discard(), wh,
		"kargo/wh-bad", now)
	if got := testutil.QueueErrorCount(t, CheckNameKargoPromotionHealth) - before; got != 1 {
		t.Fatalf("patch failure metered %v errors, want 1", got)
	}
	if p.warehouseRefreshHealed.CooledDown("kargo/wh-bad",
		kargoWarehouseRefreshCool, now) {
		t.Fatal("failed patch stamped the cooldown — next sweep would skip the nudge")
	}
}

// flux_source_healer_test.go — C1: the flux source healer that nudges
// chartRef/sourceRef sources for stale artifact failures, its dedupe
// economy and the counter series carry-forward.
package helmreleaseunlocker

import (
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/flux"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// 2.1 — passiontech.dev/last-helm-unlock persistence & C1 — flux source healer
// ---------------------------------------------------------------------------

func fluxSourceObj(kind, apiVersion, ns, name string) *unstructured.Unstructured {
	return testutil.Unstructured(
		schema.FromAPIVersionAndKind(apiVersion, kind), ns, name, nil)
}

func hrChartRef(hr *unstructured.Unstructured, kind, ns, name string) {
	spec, _, _ := unstructured.NestedMap(hr.Object, "spec")
	if spec == nil {
		spec = map[string]any{}
	}
	ref := map[string]any{"kind": kind, "name": name}
	if ns != "" {
		ref["namespace"] = ns
	}
	spec["chartRef"] = ref
	hr.Object["spec"] = spec
}

func ksObj(ns, name string, staleMsg string, failingFor time.Duration) *unstructured.Unstructured {
	k := testutil.Unstructured(
		fluxKustomizationGVR.GroupVersion().WithKind("Kustomization"), ns, name, nil)
	hrReady(k, "False", staleMsg)
	k.Object["status"].(map[string]any)["conditions"].([]any)[0].(map[string]any)["lastTransitionTime"] = time.Now().Add(-failingFor).UTC().Format(time.RFC3339)
	return k
}

// C1 — an HR Ready=False >=15m on "artifact not found" nudges its
// chartRef HelmChart source: requestedAt + last-source-nudge land and
// the counter increments. A stale message on a fresh failure does not.
func TestFluxSourceHealerHelmRelease(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "HelmChart 'flux-system/apps-myapp' artifact not found")
	hrChartRef(hr, "HelmChart", "flux-system", "apps-myapp")
	// A sibling HR failing for a non-artifact reason — untouched.
	other := hrObj("apps", "other", "v2")
	hrReady(other, "False", "rendering failed: values.schema violation")
	// A fresh artifact failure (<15m) — still inside flux's retry, not ours.
	fresh := hrObj("apps", "fresh", "v2")
	fresh.Object["status"] = map[string]any{"conditions": []any{map[string]any{
		"type": "Ready", "status": "False",
		"message":            "artifact not found",
		"lastTransitionTime": time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339),
	}}}
	hrChartRef(fresh, "HelmChart", "flux-system", "apps-fresh")
	src := fluxSourceObj("HelmChart", "source.toolkit.fluxcd.io/v1",
		"flux-system", "apps-myapp")
	srcFresh := fluxSourceObj("HelmChart", "source.toolkit.fluxcd.io/v1",
		"flux-system", "apps-fresh")
	dyn := newDynFake(hr, other, fresh, src, srcFresh)
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")

	before := promtestutil.ToFloat64(metrics.FluxSourceReconcilesTriggeredTotal.
		WithLabelValues("HelmChart", "flux-system", "apps-myapp"))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := hrAnnotation(t, dyn, flux.FluxSourceGVRs["HelmChart"], "flux-system",
		"apps-myapp", fluxReconcileAnno); got == "" {
		t.Fatal("HelmChart source not stamped with requestedAt")
	}
	if got := hrAnnotation(t, dyn, flux.FluxSourceGVRs["HelmChart"], "flux-system",
		"apps-myapp", fluxLastNudgeAnno); got == "" {
		t.Fatal("HelmChart source not stamped with last-source-nudge")
	}
	if got := hrAnnotation(t, dyn, flux.FluxSourceGVRs["HelmChart"], "flux-system",
		"apps-fresh", fluxReconcileAnno); got != "" {
		t.Fatal("fresh artifact failure nudged its source — 15m gate broken")
	}
	if got := promtestutil.ToFloat64(metrics.FluxSourceReconcilesTriggeredTotal.
		WithLabelValues("HelmChart", "flux-system", "apps-myapp")) - before; got != 1 {
		t.Fatalf("FluxSourceReconcilesTriggeredTotal delta = %v, want 1", got)
	}
}

// C1 — Kustomization with spec.sourceRef GitRepository gets the same
// treatment, and the 30m per-source cooldown blocks a repeat nudge.
func TestFluxSourceHealerKustomization(t *testing.T) {
	k := ksObj("apps", "root", "failed to fetch artifact: revision not found", 30*time.Minute)
	k.Object["spec"] = map[string]any{
		"sourceRef": map[string]any{"kind": "GitRepository", "name": "flux-system"},
	}
	src := fluxSourceObj("GitRepository", "source.toolkit.fluxcd.io/v1",
		"apps", "flux-system")
	dyn := newDynFake(k, src)
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	stamp := hrAnnotation(t, dyn, flux.FluxSourceGVRs["GitRepository"], "apps",
		"flux-system", fluxReconcileAnno)
	if stamp == "" {
		t.Fatal("GitRepository source not stamped")
	}
	// Second sweep inside the 30m cooldown → stamp must not change.
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := hrAnnotation(t, dyn, flux.FluxSourceGVRs["GitRepository"], "apps",
		"flux-system", fluxReconcileAnno); got != stamp {
		t.Fatal("source re-nudged inside the 30m per-source cooldown")
	}
}

// C1 sweep economy: N stale consumers sharing one GitRepository cost
// exactly ONE Get + one patch (the per-sweep dedupe claims the source
// for the first consumer), and the Kustomization list is paged once
// for BOTH K-scanning healers.
func TestFluxSourceHealerDedupesSharedSource(t *testing.T) {
	ks := func(name string) *unstructured.Unstructured {
		k := ksObj("apps", name, "failed to fetch artifact", time.Hour)
		k.Object["spec"] = map[string]any{
			"sourceRef": map[string]any{"kind": "GitRepository", "name": "flux-system"},
		}
		return k
	}
	src := fluxSourceObj("GitRepository", "source.toolkit.fluxcd.io/v1",
		"apps", "flux-system")
	dyn := newDynFake(ks("root"), ks("apps"), src)
	var gets, patches, ksLists int
	dyn.PrependReactor("get", "gitrepositories",
		func(ktesting.Action) (bool, runtime.Object, error) {
			gets++
			return false, nil, nil
		})
	dyn.PrependReactor("patch", "gitrepositories",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})
	dyn.PrependReactor("list", "kustomizations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			ksLists++
			return false, nil, nil
		})
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if gets != 1 || patches != 1 {
		t.Fatalf("shared source: %d Gets + %d patches, want 1 each", gets, patches)
	}
	if ksLists != 1 {
		t.Fatalf("kustomizations listed %d times in one sweep, want 1", ksLists)
	}
}

// FluxSourceReconcilesTriggeredTotal{kind,namespace,name} carries a
// 2-set carry-forward prune: once the sweep no longer resolves ANY
// consumer to a nudged source, its series is DeleteLabelValues'd; a
// source a consumer still resolves keeps both its series and its
// counter value (no reset, no re-Inc inside the 30m cooldown).
func TestFluxSourceSeriesPrunedWhenConsumerVanishes(t *testing.T) {
	staleHR := func(ns, name, repo string) *unstructured.Unstructured {
		hr := hrObj(ns, name, "v2")
		hrReady(hr, "False", "artifact not found: failed to fetch from origin")
		hr.Object["spec"] = map[string]any{
			"chart": map[string]any{"spec": map[string]any{
				"sourceRef": map[string]any{"kind": "GitRepository", "name": repo},
			}},
		}
		return hr
	}
	dyn := newDynFake(staleHR("apps", "stale-a", "repo-a"),
		staleHR("apps", "stale-c", "repo-c"),
		fluxSourceObj("GitRepository", "source.toolkit.fluxcd.io/v1", "apps", "repo-a"),
		fluxSourceObj("GitRepository", "source.toolkit.fluxcd.io/v1", "apps", "repo-c"))
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")
	for _, lv := range [][]string{
		{"GitRepository", "apps", "repo-a"},
		{"GitRepository", "apps", "repo-c"},
	} {
		testutil.CleanupMetric(t, metrics.FluxSourceReconcilesTriggeredTotal, lv...)
	}

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"repo-a", "repo-c"} {
		if got := promtestutil.ToFloat64(metrics.FluxSourceReconcilesTriggeredTotal.
			WithLabelValues("GitRepository", "apps", repo)); got != 1 {
			t.Fatalf("%s nudge counter = %v, want 1 after the first sweep", repo, got)
		}
	}

	// The consumer of repo-a is gone; repo-c keeps its consumer. The
	// next sweep prunes repo-a's series and leaves repo-c's untouched.
	if err := dyn.Resource(helmReleaseGVRs[0]).Namespace("apps").
		Delete(ctx, "stale-a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.FluxSourceReconcilesTriggeredTotal.DeleteLabelValues(
		"GitRepository", "apps", "repo-a") {
		t.Fatal("series for a source with no consumer left was not deleted")
	}
	if got := promtestutil.ToFloat64(metrics.FluxSourceReconcilesTriggeredTotal.
		WithLabelValues("GitRepository", "apps", "repo-c")); got != 1 {
		t.Fatalf("surviving source's counter reset: got %v, want 1", got)
	}
}

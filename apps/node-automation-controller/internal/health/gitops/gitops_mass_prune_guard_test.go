// gitops_mass_prune_guard_test.go — coverage for Wave 4C #13 GitOps
// mass-prune safety guard: warm-up & new-object skip, Flux Kustomization &
// ArgoCD Application inventory drop boundaries, retained pre-drop baseline,
// mass-prune-expected + error conditions, detect-only default vs opt-in Flux
// suspend (HealAllowed, no FluxPatchGate, never auto-unsuspends, never suspends
// ArgoCD), 403/404 handling, and GaugeLedger cleanup.
package gitops

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func makeFluxKust(ns, name string, prune bool, invCount int, annos map[string]string, conds ...map[string]any) *unstructured.Unstructured {
	entries := make([]any, 0, invCount)
	for i := range invCount {
		entries = append(entries, map[string]any{"id": fmt.Sprintf("ns_obj_%d", i)})
	}
	var condSlice []any
	for _, c := range conds {
		condSlice = append(condSlice, c)
	}
	u := testutil.Unstructured(schema.GroupVersionKind{
		Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Kind: "Kustomization",
	}, ns, name, map[string]any{
		"spec": map[string]any{
			"prune": prune,
		},
		"status": map[string]any{
			"inventory": map[string]any{
				"entries": entries,
			},
			"conditions": condSlice,
		},
	})
	if len(annos) > 0 {
		u.SetAnnotations(annos)
	}
	return u
}

func makeArgoApp(ns, name string, prune bool, resCount int, annos map[string]string, conds ...map[string]any) *unstructured.Unstructured {
	resources := make([]any, 0, resCount)
	for i := range resCount {
		resources = append(resources, map[string]any{"name": fmt.Sprintf("res-%d", i)})
	}
	var condSlice []any
	for _, c := range conds {
		condSlice = append(condSlice, c)
	}
	u := testutil.Unstructured(schema.GroupVersionKind{
		Group: "argoproj.io", Version: "v1alpha1", Kind: "Application",
	}, ns, name, map[string]any{
		"spec": map[string]any{
			"syncPolicy": map[string]any{
				"automated": map[string]any{
					"prune": prune,
				},
			},
		},
		"status": map[string]any{
			"resources":  resources,
			"conditions": condSlice,
		},
	})
	if len(annos) > 0 {
		u.SetAnnotations(annos)
	}
	return u
}

func setFluxInventoryCount(t *testing.T, p *probetest.Prober, ns, name string, count int) {
	t.Helper()
	u, err := p.Dyn.Resource(kube.GVRFluxKustomization).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get kustomization: %v", err)
	}
	entries := make([]any, 0, count)
	for i := range count {
		entries = append(entries, map[string]any{"id": fmt.Sprintf("ns_obj_%d", i)})
	}
	_ = unstructured.SetNestedSlice(u.Object, entries, "status", "inventory", "entries")
	if _, err := p.Dyn.Resource(kube.GVRFluxKustomization).Namespace(ns).UpdateStatus(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update kustomization status: %v", err)
	}
}

func setArgoResourceCount(t *testing.T, p *probetest.Prober, ns, name string, count int) {
	t.Helper()
	u, err := p.Dyn.Resource(kube.GVRArgoCDApplication).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get application: %v", err)
	}
	resources := make([]any, 0, count)
	for i := range count {
		resources = append(resources, map[string]any{"name": fmt.Sprintf("res-%d", i)})
	}
	_ = unstructured.SetNestedSlice(u.Object, resources, "status", "resources")
	if _, err := p.Dyn.Resource(kube.GVRArgoCDApplication).Namespace(ns).UpdateStatus(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update application status: %v", err)
	}
}

func TestGitOpsMassPruneGuard_WarmupBoundariesAndRetainedBaseline(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	kustAlert := makeFluxKust("flux-system", "apps", true, 20, nil)
	kustExact40 := makeFluxKust("flux-system", "exact40", true, 10, nil)
	kustSmall := makeFluxKust("flux-system", "small9", true, 9, nil)
	kustNoPrune := makeFluxKust("flux-system", "noprune", false, 20, nil)
	argoAlert := makeArgoApp("argocd", "web", true, 10, nil)

	cs := fake.NewSimpleClientset()
	dyn := probetest.OpDyn(kustAlert, kustExact40, kustSmall, kustNoPrune, argoAlert)
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, now)
	ch := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p)

	// Sweep 1: warm-up sweep must PASS and emit nothing.
	res1 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if !res1.Pass {
		t.Fatalf("warm-up sweep must pass, got %+v", res1)
	}

	// Apply drops:
	// - apps: 20 -> 10 (50% drop -> anomaly)
	// - exact40: 10 -> 6 (40% drop -> NOT >40%, passes)
	// - small9: 9 -> 0 (prev < 10 -> passes)
	// - noprune: 20 -> 0 (prune disabled -> ignored)
	// - argocd/web: 10 -> 5 (50% drop -> anomaly)
	// Also create a brand new Kustomization on sweep 2 with 15 resources -> must warm up cleanly.
	setFluxInventoryCount(t, p, "flux-system", "apps", 10)
	setFluxInventoryCount(t, p, "flux-system", "exact40", 6)
	setFluxInventoryCount(t, p, "flux-system", "small9", 0)
	setFluxInventoryCount(t, p, "flux-system", "noprune", 0)
	setArgoResourceCount(t, p, "argocd", "web", 5)
	if _, err := dyn.Resource(kube.GVRFluxKustomization).Namespace("flux-system").Create(
		ctx, makeFluxKust("flux-system", "newcomer", true, 15, nil), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create newcomer: %v", err)
	}

	probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
	res2 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res2.Pass {
		t.Fatalf("expected mass-prune failure, got PASS")
	}
	if !strings.Contains(res2.Why, "Kustomization/flux-system/apps(prev=20,curr=10)") ||
		!strings.Contains(res2.Why, "Application/argocd/web(prev=10,curr=5)") {
		t.Fatalf("unexpected Why: %q", res2.Why)
	}
	for _, okName := range []string{"exact40", "small9", "noprune", "newcomer"} {
		if strings.Contains(res2.Why, okName) {
			t.Fatalf("unexpected finding for %s in %q", okName, res2.Why)
		}
	}

	// Default detect-only must NOT patch spec.suspend.
	gotKust, _ := dyn.Resource(kube.GVRFluxKustomization).Namespace("flux-system").Get(ctx, "apps", metav1.GetOptions{})
	if suspended, _ := kube.NestedBool(gotKust.Object, "spec", "suspend"); suspended {
		t.Fatal("detect-only mode must not suspend Kustomization")
	}

	// Verify Warning Events emitted once per object.
	evs, _ := cs.EventsV1().Events("").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("expected 2 GitOpsMassPruneDetected events, got %d", len(evs.Items))
	}

	// Sweep 3: unchanged curr=10 / curr=5 must STILL alert (baseline retained, no flicker) and dedupe events.
	probetest.FreezeNow(p.Deps, now.Add(10*time.Minute))
	res3 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res3.Pass {
		t.Fatal("sweep 3 must retain pre-drop baseline and stay FAIL until recovery")
	}
	evs2, _ := cs.EventsV1().Events("").List(ctx, metav1.ListOptions{})
	if len(evs2.Items) != 2 {
		t.Fatalf("expected events deduped across sweep 3, got %d", len(evs2.Items))
	}

	// Sweep 4: recovery back to 20 and 10 -> PASS and GaugeLedger deletes series.
	setFluxInventoryCount(t, p, "flux-system", "apps", 20)
	setArgoResourceCount(t, p, "argocd", "web", 10)
	probetest.FreezeNow(p.Deps, now.Add(15*time.Minute))
	res4 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if !res4.Pass {
		t.Fatalf("expected PASS on recovery, got %+v", res4)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_mass_prune_alert",
		map[string]string{"kind": "Kustomization", "namespace": "flux-system", "name": "apps"}); ok {
		t.Fatal("stale alert gauge series not pruned on recovery")
	}
}

func TestGitOpsMassPruneGuard_ExpectedOptOutAndErrorConditions(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	// Case 1: expected=true without active error suppresses alert and updates baseline.
	kustOK := makeFluxKust("flux-system", "planned", true, 20, map[string]string{
		kube.AnnoMassPruneExpected: "true",
	})
	// Case 2: expected=true WITH ArtifactFailed still alerts.
	kustErr := makeFluxKust("flux-system", "broken", true, 20, map[string]string{
		kube.AnnoMassPruneExpected: "true",
	}, map[string]any{
		"type":   "Ready",
		"status": "False",
		"reason": "ArtifactFailed",
	})
	// Case 3: ArgoCD ComparisonError (status-less condition) with expected=true still alerts.
	argoErr := makeArgoApp("argocd", "broken-app", true, 20, map[string]string{
		kube.AnnoMassPruneExpected: "true",
	}, map[string]any{
		"type": "ComparisonError",
	})

	cs := fake.NewSimpleClientset()
	dyn := probetest.OpDyn(kustOK, kustErr, argoErr)
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, now)
	ch := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p)

	ch.Run(probetest.SweepCtx(ctx, p.Deps))
	setFluxInventoryCount(t, p, "flux-system", "planned", 2)
	setFluxInventoryCount(t, p, "flux-system", "broken", 2)
	setArgoResourceCount(t, p, "argocd", "broken-app", 2)

	probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("expected alert for active ArtifactFailed/ComparisonError despite expected=true")
	}
	if strings.Contains(res.Why, "planned") {
		t.Fatalf("healthy planned prune should be suppressed, Why=%q", res.Why)
	}
	if !strings.Contains(res.Why, "broken") || !strings.Contains(res.Why, "broken-app") {
		t.Fatalf("expected active-error objects in Why: %q", res.Why)
	}
}

func TestGitOpsMassPruneGuard_OptInSuspendAndNeverAutoUnsuspend(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	// Arm FluxPatchGate at 1 to prove emergency suspend bypasses FluxPatchGate.
	heal.ConfigureFluxConflictLoop(1, 30*time.Minute)
	defer heal.ConfigureFluxConflictLoop(0, 0)

	kust := makeFluxKust("flux-system", "guarded", true, 20, map[string]string{
		kube.AnnoMassPruneGuard: "suspend",
	})
	// ArgoCD Application with mass-prune-guard=suspend must NEVER be suspended.
	argo := makeArgoApp("argocd", "guarded-argo", true, 20, map[string]string{
		kube.AnnoMassPruneGuard: "suspend",
	})

	// Maintenance hold (in-flight autopilot Plan) blocks suspend on sweep 2.
	plan := testutil.Unstructured(
		kube.AutopilotPlanGVR.GroupVersion().WithKind("Plan"), "", "upgrade-1", nil)
	plan.Object["status"] = map[string]any{"state": "Running"}
	cs := fake.NewSimpleClientset()
	dyn := probetest.OpDyn(kust, argo, plan)
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, now)
	ch := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p)

	// Sweep 1: warm-up.
	ch.Run(probetest.SweepCtx(ctx, p.Deps))
	setFluxInventoryCount(t, p, "flux-system", "guarded", 5)
	setArgoResourceCount(t, p, "argocd", "guarded-argo", 5)

	// Sweep 2: maintenance active -> alert fires, suspend blocked.
	probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
	resMaint := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if resMaint.Pass {
		t.Fatal("expected alert during maintenance")
	}
	got1, _ := dyn.Resource(kube.GVRFluxKustomization).Namespace("flux-system").Get(ctx, "guarded", metav1.GetOptions{})
	if susp, _ := kube.NestedBool(got1.Object, "spec", "suspend"); susp {
		t.Fatal("HealAllowed must block suspend during active maintenance")
	}

	// Lift maintenance -> sweep 3 suspends Flux Kustomization (and leaves ArgoCD untouched).
	_ = dyn.Resource(kube.AutopilotPlanGVR).Delete(ctx, "upgrade-1", metav1.DeleteOptions{})
	probetest.FreezeNow(p.Deps, now.Add(10*time.Minute))
	ch.Run(probetest.SweepCtx(ctx, p.Deps))

	got2, _ := dyn.Resource(kube.GVRFluxKustomization).Namespace("flux-system").Get(ctx, "guarded", metav1.GetOptions{})
	if susp, _ := kube.NestedBool(got2.Object, "spec", "suspend"); !susp {
		t.Fatal("expected Flux Kustomization spec.suspend=true")
	}
	if got2.GetAnnotations()[kube.AnnoMassPruneSuspendedBy] != CheckNameGitOpsMassPruneGuard {
		t.Fatalf("missing AnnoMassPruneSuspendedBy, annos=%v", got2.GetAnnotations())
	}

	gotArgo, _ := dyn.Resource(kube.GVRArgoCDApplication).Namespace("argocd").Get(ctx, "guarded-argo", metav1.GetOptions{})
	if susp, _ := kube.NestedBool(gotArgo.Object, "spec", "suspend"); susp {
		t.Fatal("ArgoCD Application must NEVER be suspended")
	}

	// Sweep 4: inventory recovers -> NEVER auto-unsuspend.
	setFluxInventoryCount(t, p, "flux-system", "guarded", 20)
	probetest.FreezeNow(p.Deps, now.Add(15*time.Minute))
	ch.Run(probetest.SweepCtx(ctx, p.Deps))
	got3, _ := dyn.Resource(kube.GVRFluxKustomization).Namespace("flux-system").Get(ctx, "guarded", metav1.GetOptions{})
	if susp, _ := kube.NestedBool(got3.Object, "spec", "suspend"); !susp {
		t.Fatal("guard must NEVER auto-unsuspend Kustomization")
	}
}

func TestGitOpsMassPruneGuard_403And404Handling(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	kust := makeFluxKust("flux-system", "apps", true, 20, nil)
	cs := fake.NewSimpleClientset()
	dyn := probetest.OpDyn(kust)
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, now)
	ch := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p)

	// Seed alert.
	ch.Run(probetest.SweepCtx(ctx, p.Deps))
	setFluxInventoryCount(t, p, "flux-system", "apps", 5)
	probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("expected alert before 403/404 checks")
	}

	// 403 on list kustomizations: carries held series, preserves baseline, zero Infra error.
	dyn.PrependReactor("list", "kustomizations", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Status: metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden,
		}}
	})
	probetest.FreezeNow(p.Deps, now.Add(10*time.Minute))
	res403 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res403.Infra != nil {
		t.Fatalf("403 must not trigger Infra error: %v", res403.Infra)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_mass_prune_alert",
		map[string]string{"kind": "Kustomization", "namespace": "flux-system", "name": "apps"}); !ok {
		t.Fatal("403 must carry held alert series forward")
	}
	if _, ok := ch.prevInventory["Kustomization/flux-system/apps"]; !ok {
		t.Fatal("403 must preserve prevInventory baseline")
	}

	// 404/NoMatch CRD absent: resets warm-up and prunes stale series cleanly without Infra error.
	dyn.ReactionChain[0] = &ktesting.SimpleReactor{
		Verb:     "list",
		Resource: "kustomizations",
		Reaction: func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "kustomize.toolkit.fluxcd.io", Resource: "kustomizations"}, "")
		},
	}
	probetest.FreezeNow(p.Deps, now.Add(15*time.Minute))
	res404 := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res404.Infra != nil {
		t.Fatalf("404/CRD absent must not trigger Infra error: %v", res404.Infra)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_mass_prune_alert",
		map[string]string{"kind": "Kustomization", "namespace": "flux-system", "name": "apps"}); ok {
		t.Fatal("404/CRD absent must prune stale alert series")
	}
	if ch.warmedUp["Kustomization"] {
		t.Fatal("404/CRD absent must reset warmedUp for Kustomization")
	}

	// 403 on suspend patch: skips gracefully without IncError.
	kustPatch403 := makeFluxKust("flux-system", "guarded-403", true, 20, map[string]string{
		kube.AnnoMassPruneGuard: "suspend",
	})
	dynPatch := probetest.OpDyn(kustPatch403)
	dynPatch.PrependReactor("patch", "kustomizations", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Status: metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden,
		}}
	})
	p2 := testProberDyn(fake.NewSimpleClientset(), dynPatch)
	probetest.FreezeNow(p2.Deps, now)
	ch2 := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p2)
	ch2.Run(probetest.SweepCtx(ctx, p2.Deps))
	setFluxInventoryCount(t, p2, "flux-system", "guarded-403", 5)
	probetest.FreezeNow(p2.Deps, now.Add(5*time.Minute))
	beforeErrs := probetest.CounterSnapshot(t, p2.Name)
	resPatch := ch2.Run(probetest.SweepCtx(ctx, p2.Deps))
	if resPatch.Infra != nil {
		t.Fatalf("403 on patch must not set Infra: %v", resPatch.Infra)
	}
	probetest.AssertCounterDelta(t, p2.Name, beforeErrs, 0)

	t.Run("404_on_suspend_patch", func(t *testing.T) {
		kustPatch404 := makeFluxKust("flux-system", "guarded-404", true, 20, map[string]string{
			kube.AnnoMassPruneGuard: "suspend",
		})
		plan := testutil.Unstructured(
			kube.AutopilotPlanGVR.GroupVersion().WithKind("Plan"), "", "upgrade-404", nil)
		plan.Object["status"] = map[string]any{"state": "Running"}

		dyn404 := probetest.OpDyn(kustPatch404, plan)
		p3 := testProberDyn(fake.NewSimpleClientset(), dyn404)
		probetest.FreezeNow(p3.Deps, now)
		ch3 := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p3)

		// Sweep 1: warm-up.
		if res := ch3.Run(probetest.SweepCtx(ctx, p3.Deps)); !res.Pass {
			t.Fatalf("warm-up sweep must pass, got %+v", res)
		}

		// Sweep 2: drop while maintenance holds suspend -> emits alert gauge & pins baseline.
		setFluxInventoryCount(t, p3, "flux-system", "guarded-404", 5)
		probetest.FreezeNow(p3.Deps, now.Add(5*time.Minute))
		if res := ch3.Run(probetest.SweepCtx(ctx, p3.Deps)); res.Pass {
			t.Fatal("expected alert before 404 patch check")
		}
		if v, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_mass_prune_alert",
			map[string]string{"kind": "Kustomization", "namespace": "flux-system", "name": "guarded-404"}); !ok || v != 1 {
			t.Fatalf("expected seeded alert gauge before 404 patch, got v=%v ok=%v", v, ok)
		}

		// Lift maintenance and simulate object vanishing between list and patch (404 NotFound).
		_ = dyn404.Resource(kube.AutopilotPlanGVR).Delete(ctx, "upgrade-404", metav1.DeleteOptions{})
		dyn404.PrependReactor("patch", "kustomizations", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "kustomize.toolkit.fluxcd.io", Resource: "kustomizations"},
				"guarded-404",
			)
		})

		probetest.FreezeNow(p3.Deps, now.Add(10*time.Minute))
		before404Errs := probetest.CounterSnapshot(t, p3.Name)
		res404Patch := ch3.Run(probetest.SweepCtx(ctx, p3.Deps))
		if !res404Patch.Pass || res404Patch.Infra != nil {
			t.Fatalf("404 on suspend patch must pass cleanly with nil Infra, got %+v", res404Patch)
		}
		probetest.AssertCounterDelta(t, p3.Name, before404Errs, 0)
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_mass_prune_alert",
			map[string]string{"kind": "Kustomization", "namespace": "flux-system", "name": "guarded-404"}); ok {
			t.Fatal("404 on suspend patch must prune stale alert gauge series")
		}
		if _, ok := ch3.prevInventory["Kustomization/flux-system/guarded-404"]; ok {
			t.Fatal("404 on suspend patch must remove vanished object from prevInventory")
		}

		// Also verify meta.NoResourceMatchError (CRD removed mid-sweep) skips cleanly.
		kustNoMatch := makeFluxKust("flux-system", "guarded-nomatch", true, 20, map[string]string{
			kube.AnnoMassPruneGuard: "suspend",
		})
		dynNoMatch := probetest.OpDyn(kustNoMatch)
		dynNoMatch.PrependReactor("patch", "kustomizations", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, &meta.NoResourceMatchError{PartialResource: kube.GVRFluxKustomization}
		})
		p4 := testProberDyn(fake.NewSimpleClientset(), dynNoMatch)
		probetest.FreezeNow(p4.Deps, now)
		ch4 := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p4)
		ch4.Run(probetest.SweepCtx(ctx, p4.Deps))
		setFluxInventoryCount(t, p4, "flux-system", "guarded-nomatch", 5)
		probetest.FreezeNow(p4.Deps, now.Add(5*time.Minute))
		beforeNoMatchErrs := probetest.CounterSnapshot(t, p4.Name)
		resNoMatch := ch4.Run(probetest.SweepCtx(ctx, p4.Deps))
		if !resNoMatch.Pass || resNoMatch.Infra != nil {
			t.Fatalf("NoMatch on suspend patch must pass cleanly with nil Infra, got %+v", resNoMatch)
		}
		probetest.AssertCounterDelta(t, p4.Name, beforeNoMatchErrs, 0)
		if _, ok := ch4.prevInventory["Kustomization/flux-system/guarded-nomatch"]; ok {
			t.Fatal("NoMatch on suspend patch must remove vanished object from prevInventory")
		}
	})
}

func TestGitOpsMassPruneGuard_LongNamesSameSweepNoEventCollision(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	ns := strings.Repeat("n", 63)
	sharedPrefix := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "."
	name1 := sharedPrefix + strings.Repeat("d", 52) // 235 chars
	name2 := sharedPrefix + strings.Repeat("e", 52) // 235 chars

	k1 := makeFluxKust(ns, name1, true, 20, nil)
	k2 := makeFluxKust(ns, name2, true, 20, nil)

	cs := fake.NewSimpleClientset()
	dyn := probetest.OpDyn(k1, k2)
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, now)
	ch := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p)

	// Sweep 1: warm-up.
	if res := ch.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("warm-up sweep must pass, got %+v", res)
	}

	setFluxInventoryCount(t, p, ns, name1, 5)
	setFluxInventoryCount(t, p, ns, name2, 5)
	probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("expected mass-prune failure for long-named Kustomizations")
	}

	evs, err := cs.EventsV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(evs.Items) != 2 {
		t.Fatalf("expected 2 distinct GitOpsMassPruneDetected events, got %d", len(evs.Items))
	}
	seenNames := make(map[string]bool, 2)
	for _, ev := range evs.Items {
		if len(ev.Name) > 253 {
			t.Fatalf("event name len=%d exceeds 253: %q", len(ev.Name), ev.Name)
		}
		if errs := validation.IsDNS1123Subdomain(ev.Name); len(errs) > 0 {
			t.Fatalf("event name %q invalid RFC 1123 subdomain: %v", ev.Name, errs)
		}
		seenNames[ev.Name] = true
	}
	if len(seenNames) != 2 {
		t.Fatalf("expected 2 distinct event names, got %v", seenNames)
	}
}

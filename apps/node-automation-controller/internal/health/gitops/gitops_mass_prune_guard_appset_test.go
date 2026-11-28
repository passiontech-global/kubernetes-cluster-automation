package gitops

import (
	"maps"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func newAppSetDyn(objs ...runtime.Object) *probetest.Prober {
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[argoApplicationSetGVR] = "ApplicationSetList"
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewFakeDyn(kinds, objs...)
	return probetest.NewCheckProber(cs, dyn, NewGitOpsMassPruneGuardCheck)
}

func makeAppSet(ns, name string, errorCond, automatedPrune, preserve bool) *unstructured.Unstructured {
	u := testutil.Unstructured(argoApplicationSetGVR.GroupVersion().WithKind("ApplicationSet"), ns, name, nil)
	spec := map[string]any{}
	if automatedPrune {
		spec["template"] = map[string]any{
			"spec": map[string]any{
				"syncPolicy": map[string]any{
					"automated": map[string]any{"prune": true},
				},
			},
		}
	}
	if preserve {
		spec["syncPolicy"] = map[string]any{"preserveResourcesOnDeletion": true}
	}
	u.Object["spec"] = spec
	if errorCond {
		_ = unstructured.SetNestedSlice(u.Object, []any{map[string]any{
			"type": "ErrorOccurred", "status": "True", "message": "generator exploded",
		}}, "status", "conditions")
	}
	return u
}

func makeChildApp(ns, setName, name string) *unstructured.Unstructured {
	u := testutil.Unstructured(kube.GVRArgoCDApplication.GroupVersion().WithKind("Application"), ns, name, nil)
	u.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: "argoproj.io/v1alpha1", Kind: "ApplicationSet", Name: setName,
	}})
	return u
}

func TestGitOpsMassPruneApplicationSetAuditsAndDrop(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	t.Cleanup(func() {
		argoAppSetUnhealthyGauge.DeleteLabelValues("argocd", "appset-err", "error_occurred")
		argoAppSetUnhealthyGauge.DeleteLabelValues("argocd", "appset-err", "missing_preserve_resources_on_deletion")
		gitopsMassPruneAlertGauge.DeleteLabelValues("ApplicationSet", "argocd", "appset-ok")
	})

	asErr := makeAppSet("argocd", "appset-err", true, true, false)
	asOK := makeAppSet("argocd", "appset-ok", false, true, true)
	var objs []runtime.Object
	objs = append(objs, asErr, asOK)
	for _, n := range []string{"a1", "a2", "a3", "a4", "a5", "a6"} {
		objs = append(objs, makeChildApp("argocd", "appset-ok", n))
	}

	p := newAppSetDyn(objs...)
	probetest.FreezeNow(p.Deps, now)
	chk := probetest.MustCheck[*gitopsMassPruneGuardCheck](t, p)

	// Sweep 1: warm-up ApplicationSet child count (6 apps), flags ErrorOccurred + missing preserve.
	res1 := chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if res1.Pass {
		t.Fatal("expected appset-err failure on sweep 1")
	}
	if got, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_applicationset_unhealthy", map[string]string{
		"namespace": "argocd", "name": "appset-err", "reason": "error_occurred",
	}); !ok || got != 1 {
		t.Fatalf("error_occurred gauge = (%v, %v), want (1, true)", got, ok)
	}
	if got, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_applicationset_unhealthy", map[string]string{
		"namespace": "argocd", "name": "appset-err", "reason": "missing_preserve_resources_on_deletion",
	}); !ok || got != 1 {
		t.Fatalf("missing_preserve_resources_on_deletion gauge = (%v, %v), want (1, true)", got, ok)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_mass_prune_alert", map[string]string{
		"kind": "ApplicationSet", "namespace": "argocd", "name": "appset-ok",
	}); ok {
		t.Fatal("warm-up sweep must not alert on ApplicationSet child count")
	}

	// Delete 4 of 6 child Applications (>40% drop from >=5 baseline) -> mass-prune alert fires.
	for _, n := range []string{"a3", "a4", "a5", "a6"} {
		_ = p.Dyn.Resource(kube.GVRArgoCDApplication).Namespace("argocd").Delete(ctx, n, metav1.DeleteOptions{})
	}
	probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
	res2 := chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if res2.Pass {
		t.Fatal("expected ApplicationSet >40% drop failure on sweep 2")
	}
	if got, ok := testutil.GaugeSeriesValue(t, "node_automation_gitops_mass_prune_alert", map[string]string{
		"kind": "ApplicationSet", "namespace": "argocd", "name": "appset-ok",
	}); !ok || got != 1 {
		t.Fatalf("ApplicationSet mass-prune gauge = (%v, %v), want (1, true)", got, ok)
	}
}

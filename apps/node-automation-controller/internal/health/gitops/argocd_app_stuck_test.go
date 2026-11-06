// argocd_app_stuck_test.go — coverage for the argocd-app-stuck
// check (W10-CP6): absent-CRD quiet, Progressing refresh patch,
// ComparisonError repo-server restart.
package gitops

import (
	"strings"
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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// W10-CP6 — argocd-app-stuck
// ---------------------------------------------------------------------------

func TestArgoCDAppStuckSkipsWhenCRDAbsent(t *testing.T) {
	dyn := testutil.NewDynamicClient()
	dyn.PrependReactor("list", "applications",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "argoproj.io", Resource: "applications"}, "")
		})
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	if res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("absent Application CRD must pass: %+v", res)
	}
}

func TestArgoCDAppStuckProgressingRefreshPatch(t *testing.T) {
	app := argoCDApplication("argocd", "my-app", "Progressing")
	dyn := testutil.NewDynamicClient(app)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)

	// First sighting stamps the first-seen ledger — still inside 45m.
	if res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("young Progressing app must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(50*time.Minute))
	res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("Progressing >45m must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "my-app") {
		t.Fatalf("why missing app: %q", res.Why)
	}
	got, err := dyn.Resource(argocdAppGVR).Namespace("argocd").
		Get(ctx, "my-app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ann := got.GetAnnotations()
	if ann["argocd.argoproj.io/refresh"] != "hard" {
		t.Fatalf("refresh annotation = %q, want hard", ann["argocd.argoproj.io/refresh"])
	}
}

// A Progressing app whose only non-Healthy managed resource is a
// Deployment the go-kube-downscaler parked at replicas:0 is sleep,
// not stuck — no flag past the window and no refresh patch.
func TestArgoCDAppStuckSkipsDownscaledWorkload(t *testing.T) {
	app := argoCDApplication("argocd", "night-app", "Progressing")
	app.Object["status"].(map[string]any)["resources"] = []any{
		map[string]any{
			"kind":      "Deployment",
			"namespace": "web",
			"name":      "frontend",
			"health":    map[string]any{"status": "Suspended"},
		},
	}
	dyn := testutil.NewDynamicClient(app)
	zero := int32(0)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "web", Name: "frontend",
			Annotations: map[string]string{"downscaler/downtime": "22:00-06:00"},
		},
		Spec: appsv1.DeploymentSpec{Replicas: &zero},
	}
	cs := fake.NewSimpleClientset(dep)
	p := testProberDyn(cs, dyn)
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)

	if res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("downscaled-only app must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(50*time.Minute))
	if res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("downscaled-only app must still pass past the window: %+v", res)
	}
	got, err := dyn.Resource(argocdAppGVR).Namespace("argocd").
		Get(ctx, "night-app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAnnotations()["argocd.argoproj.io/refresh"] != "" {
		t.Fatal("downscaled app got a refresh patch")
	}
}

// The same Progressing roll-up IS real evidence when the zero-
// replica workload carries no downscaler/* annotation — a replicas:0
// nobody claims is a genuine stall.
func TestArgoCDAppStuckZeroReplicaNoAnnotationStillFlags(t *testing.T) {
	app := argoCDApplication("argocd", "stalled-app", "Progressing")
	app.Object["status"].(map[string]any)["resources"] = []any{
		map[string]any{
			"kind":      "Deployment",
			"namespace": "web",
			"name":      "frontend",
			"health":    map[string]any{"status": "Suspended"},
		},
	}
	dyn := testutil.NewDynamicClient(app)
	zero := int32(0)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "frontend"},
		Spec:       appsv1.DeploymentSpec{Replicas: &zero},
	}
	cs := fake.NewSimpleClientset(dep)
	p := testProberDyn(cs, dyn)
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)

	probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(50*time.Minute))
	res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("unexplained replicas:0 must still flag: %+v", res)
	}
	if !strings.Contains(res.Why, "stalled-app") {
		t.Fatalf("why missing app: %q", res.Why)
	}
}

func TestArgoCDComparisonErrorsRestartOldestRepoServer(t *testing.T) {
	cond := func() map[string]any {
		return map[string]any{
			// ArgoCD ApplicationCondition has no status field —
			// presence in status.conditions is the active signal.
			"type":               "ComparisonError",
			"lastTransitionTime": time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		}
	}
	appA := argoCDApplication("argocd", "app-a", "", cond())
	appB := argoCDApplication("argocd", "app-b", "", cond())
	dyn := testutil.NewDynamicClient(appA, appB)

	older := probetest.PodWithPhase("argocd", "argocd-repo-server-0", corev1.PodRunning, true, 2*time.Hour)
	older.Labels = map[string]string{"app.kubernetes.io/name": "argocd-repo-server"}
	newer := probetest.PodWithPhase("argocd", "argocd-repo-server-1", corev1.PodRunning, true, time.Hour)
	newer.Labels = map[string]string{"app.kubernetes.io/name": "argocd-repo-server"}
	cs := fake.NewSimpleClientset(older, newer)
	p := testProberDyn(cs, dyn)

	res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("two ComparisonErrors must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, "argocd-repo-server-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("oldest repo-server pod should be restarted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, "argocd-repo-server-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("newer repo-server pod must survive: %v", err)
	}
}

// argoCDApplication builds an ArgoCD Application unstructured carrying the
// given health status and conditions.
func argoCDApplication(ns, name, health string, conds ...map[string]any) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"namespace": ns, "name": name},
	}
	if health != "" {
		obj["status"] = map[string]any{
			"health": map[string]any{"status": health},
		}
	}
	if len(conds) > 0 {
		status, _ := obj["status"].(map[string]any)
		if status == nil {
			status = map[string]any{}
			obj["status"] = status
		}
		var list []any
		for _, c := range conds {
			list = append(list, c)
		}
		status["conditions"] = list
	}
	return &unstructured.Unstructured{Object: obj}
}

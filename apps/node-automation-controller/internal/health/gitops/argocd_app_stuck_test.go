// argocd_app_stuck_test.go — coverage for the argocd-app-stuck
// check (argocd-app-stuck): absent-CRD quiet, Progressing refresh patch,
// ComparisonError repo-server restart.
package gitops

import (
	"maps"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// argocd-app-stuck — argocd-app-stuck
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

// rollout-scale-flap — the same excuse covers a Rollout resource-tree entry: a
// Rollout the go-kube-downscaler parked at spec.replicas:0 with the
// downscaler/* annotations is sleep, not stuck evidence.
func TestArgoCDAppStuckSkipsDownscaledRollout(t *testing.T) {
	app := argoCDApplication("argocd", "rollout-app", "Progressing")
	app.Object["status"].(map[string]any)["resources"] = []any{
		map[string]any{
			"kind":      "Rollout",
			"namespace": "web",
			"name":      "canary-api",
			"health":    map[string]any{"status": "Suspended"},
		},
	}
	rollout := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata": map[string]any{
			"namespace":   "web",
			"name":        "canary-api",
			"annotations": map[string]any{"downscaler/downtime": "22:00-06:00"},
		},
		"spec": map[string]any{"replicas": int64(0)},
	}
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[kube.GVRArgoRollout] = "RolloutList"
	dyn := testutil.NewFakeDyn(kinds, app,
		&unstructured.Unstructured{Object: rollout})
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)

	if res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("downscaled-Rollout-only app must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(50*time.Minute))
	if res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("downscaled-Rollout-only app must pass past the window: %+v", res)
	}
	got, err := dyn.Resource(argocdAppGVR).Namespace("argocd").
		Get(ctx, "rollout-app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAnnotations()["argocd.argoproj.io/refresh"] != "" {
		t.Fatal("downscaled Rollout app got a refresh patch")
	}
}

// statefulSetDownscaled is the Deployment twin over the shared
// StatefulSet census — a StatefulSet the go-kube-downscaler parked
// at replicas:0 is sleep, not stuck evidence.
func TestArgoCDAppStuckSkipsDownscaledStatefulSet(t *testing.T) {
	app := argoCDApplication("argocd", "sts-app", "Progressing")
	app.Object["status"].(map[string]any)["resources"] = []any{
		map[string]any{
			"kind":      "StatefulSet",
			"namespace": "data",
			"name":      "db",
			"health":    map[string]any{"status": "Suspended"},
		},
	}
	dyn := testutil.NewDynamicClient(app)
	zero := int32(0)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "data", Name: "db",
			Annotations: map[string]string{"downscaler/downtime": "22:00-06:00"},
		},
		Spec: appsv1.StatefulSetSpec{Replicas: &zero},
	}
	cs := fake.NewSimpleClientset(sts)
	p := testProberDyn(cs, dyn)
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)

	if res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("downscaled-StatefulSet-only app must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(50*time.Minute))
	if res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("downscaled-StatefulSet-only app must pass past the window: %+v", res)
	}
	got, err := dyn.Resource(argocdAppGVR).Namespace("argocd").
		Get(ctx, "sts-app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAnnotations()["argocd.argoproj.io/refresh"] != "" {
		t.Fatal("downscaled StatefulSet app got a refresh patch")
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

// Restart-resume: an Application carrying a persisted first-seen
// stamp older than the Progressing window trips it on the FIRST
// sweep and draws the refresh patch — the in-RAM ledger is empty
// (operator restarted) but the annotation proves the stall held.
func TestArgoCDAppStuckPersistedFirstSeenResume(t *testing.T) {
	base := time.Now()
	app := argoCDApplication("argocd", "resume-app", "Progressing")
	app.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenArgoCDAppStuck: `{"prog/argocd/resume-app":"` +
			base.Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`,
	})
	dyn := testutil.NewDynamicClient(app)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)
	testutil.CleanupMetric(t, argoCDAppStuckGauge, "argocd", "resume-app", "progressing>45m0s")

	res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("persisted Progressing must fail on the first post-restart sweep: %+v", res)
	}
	got, err := dyn.Resource(argocdAppGVR).Namespace("argocd").
		Get(ctx, "resume-app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAnnotations()["argocd.argoproj.io/refresh"] != "hard" {
		t.Fatal("resumed window did not fire the refresh patch")
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
	older.OwnerReferences = repoServerOwnerRef("argocd-repo-server-0")
	newer := probetest.PodWithPhase("argocd", "argocd-repo-server-1", corev1.PodRunning, true, time.Hour)
	newer.Labels = map[string]string{"app.kubernetes.io/name": "argocd-repo-server"}
	newer.OwnerReferences = repoServerOwnerRef("argocd-repo-server-1")
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

// A non-Running repo-server pod is never the restart target — it has
// no repo cache to flush, so restarting it would spend the heal on a
// pod that cannot hold stale state while the Running cache-carrier
// survives.
func TestArgoCDRepoServerPendingPodNotPicked(t *testing.T) {
	cond := func() map[string]any {
		return map[string]any{
			"type":               "ComparisonError",
			"lastTransitionTime": time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		}
	}
	appA := argoCDApplication("argocd", "app-a", "", cond())
	appB := argoCDApplication("argocd", "app-b", "", cond())
	dyn := testutil.NewDynamicClient(appA, appB)

	pending := probetest.PodWithPhase("argocd", "argocd-repo-server-0", corev1.PodPending, false, 2*time.Hour)
	pending.Labels = map[string]string{"app.kubernetes.io/name": "argocd-repo-server"}
	pending.OwnerReferences = repoServerOwnerRef("argocd-repo-server-0")
	running := probetest.PodWithPhase("argocd", "argocd-repo-server-1", corev1.PodRunning, true, time.Hour)
	running.Labels = map[string]string{"app.kubernetes.io/name": "argocd-repo-server"}
	running.OwnerReferences = repoServerOwnerRef("argocd-repo-server-1")
	cs := fake.NewSimpleClientset(pending, running)
	p := testProberDyn(cs, dyn)

	res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("two ComparisonErrors must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, "argocd-repo-server-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("oldest RUNNING repo-server pod should be restarted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, "argocd-repo-server-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("pending repo-server pod must not consume the heal: %v", err)
	}
}

// repoServerOwnerRef builds the ReplicaSet controller ownerRef a
// real repo-server pod carries — the restart heal refuses a
// controller-less pod (deleting it would not be recreated).
func repoServerOwnerRef(rsName string) []metav1.OwnerReference {
	return []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: rsName, UID: types.UID("rs-" + rsName), Controller: ptr.To(true),
	}}
}

// A repo-server pod with NO controller owner is never deleted — the
// restart could not recreate it, so the heal skips it (the two stuck
// apps still FAIL the check through their findings).
func TestArgoCDRepoServerUnownedPodNotDeleted(t *testing.T) {
	cond := func() map[string]any {
		return map[string]any{
			"type":               "ComparisonError",
			"lastTransitionTime": time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		}
	}
	appA := argoCDApplication("argocd", "app-a", "", cond())
	appB := argoCDApplication("argocd", "app-b", "", cond())
	lone := probetest.PodWithPhase("argocd", "argocd-repo-server-0", corev1.PodRunning, true, 2*time.Hour)
	lone.Labels = map[string]string{"app.kubernetes.io/name": "argocd-repo-server"}
	cs := fake.NewSimpleClientset(lone)
	p := testProberDyn(cs, testutil.NewDynamicClient(appA, appB))

	res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("two ComparisonErrors must still fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, "argocd-repo-server-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("controller-less repo-server pod must not be deleted: %v", err)
	}
}

// CRD absence is a COMPLETE sweep (no Application can exist): the
// ledgers still close — held seen keys drop and emitted series are
// DeleteLabelValues'd instead of leaking a pinned 1 forever.
func TestArgoCDAppStuckCRDAbsentPrunesLedgers(t *testing.T) {
	base := time.Now()
	app := argoCDApplication("argocd", "gone-app", "Progressing")
	app.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenArgoCDAppStuck: `{"prog/argocd/gone-app":"` +
			base.Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`})
	dyn := testutil.NewDynamicClient(app)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAppStuckCheck](t, p)
	testutil.CleanupMetric(t, argoCDAppStuckGauge, "argocd", "gone-app", "progressing>45m0s")

	if res := chk.Run(ctx); res.Pass {
		t.Fatalf("precondition: stuck app must FAIL: %+v", res)
	}

	// ArgoCD uninstalled — the Application list goes NotFound.
	crdGone := false
	dyn.PrependReactor("list", "applications",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if !crdGone {
				return false, nil, nil
			}
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "argoproj.io", Resource: "applications"}, "")
		})
	crdGone = true
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("absent CRD must pass: %+v", res)
	}
	if keys := probetest.LedgerKeys(&chk.seen); len(keys) != 0 {
		t.Fatalf("seen ledger keys survived CRD absence: %v", keys)
	}
	if m := probetest.FindMetric(t, "node_automation_argocd_app_stuck",
		map[string]string{"namespace": "argocd", "name": "gone-app",
			"reason": "progressing>45m0s"}); m != nil {
		t.Fatal("emitted series survived CRD absence — must be pruned")
	}
}

// The refresh patch rides the shared heal gate: under an active
// maintenance mutex a stuck app still FAILs (the gauge carries the
// alert) but draws NO refresh patch — the old CooledDown-only gate
// patched straight through a drain.
func TestArgoCDRefreshDefersUnderMaintenance(t *testing.T) {
	base := time.Now()
	app := argoCDApplication("argocd", "maint-app", "Progressing")
	app.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenArgoCDAppStuck: `{"prog/argocd/maint-app":"` +
			base.Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`})
	dyn := probetest.OpDyn(app)
	cordoned := testutil.Node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	cs := fake.NewSimpleClientset(cordoned)
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)
	testutil.CleanupMetric(t, argoCDAppStuckGauge,
		"argocd", "maint-app", "progressing>45m0s")

	res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("stuck app must still FAIL under maintenance: %+v", res)
	}
	got, err := dyn.Resource(argocdAppGVR).Namespace("argocd").
		Get(ctx, "maint-app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAnnotations()["argocd.argoproj.io/refresh"] != "" {
		t.Fatal("refresh=hard patched through the maintenance mutex")
	}
}

// Two stuck Applications sharing one downscaled Deployment pay ONE
// workload census per sweep — the per-app×resource lookups memoize on
// downscaledSeen (ownerSeen's shape) without changing any verdict.
// The census itself is the sweep snapshot's cluster-wide Deployment
// LIST, so the pin counts "list" actions, not "get".
func TestArgoCDDownscaledLookupMemoizedPerSweep(t *testing.T) {
	base := time.Now()
	resources := func() []any {
		return []any{map[string]any{
			"kind": "Deployment", "namespace": "web", "name": "frontend",
			"health": map[string]any{"status": "Suspended"}},
		}
	}
	appA := argoCDApplication("argocd", "memo-a", "Progressing")
	appA.Object["status"].(map[string]any)["resources"] = resources()
	appA.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenArgoCDAppStuck: `{"prog/argocd/memo-a":"` +
			base.Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`})
	appB := argoCDApplication("argocd", "memo-b", "Progressing")
	appB.Object["status"].(map[string]any)["resources"] = resources()
	appB.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenArgoCDAppStuck: `{"prog/argocd/memo-b":"` +
			base.Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`})
	dyn := probetest.OpDyn(appA, appB)
	zero := int32(0)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "web",
			Name:        "frontend",
			Annotations: map[string]string{"downscaler/downtime": "22:00-06:00"},
		},
		Spec: appsv1.DeploymentSpec{Replicas: &zero},
	}
	cs := fake.NewSimpleClientset(dep)
	lists := 0
	cs.PrependReactor("list", "deployments",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			lists++
			return false, nil, nil
		})
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)

	res := probetest.MustCheck[*argoCDAppStuckCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("downscaled-only apps must pass: %+v", res)
	}
	if lists != 1 {
		t.Fatalf("deployment lists = %d, want 1 — the per-sweep memo collapsed the N+1", lists)
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

// keda_scaledobject_guard_test.go — coverage for the
// keda-scaledobject-guard check: persistence window, zero-replica
// rescue and the downscaler skip.
package gitops

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// kedaObj builds a ScaledObject CR targeting `target` with the given
// Ready/Active condition statuses ("" omits the condition).
func kedaObj(ns, name, target string, minReplicas int64,
	ready, active string) *unstructured.Unstructured {

	obj := testutil.Unstructured(
		kube.GVRKedaScaledObject.GroupVersion().WithKind("ScaledObject"), ns, name,
		map[string]any{"spec": map[string]any{
			"scaleTargetRef":  map[string]any{"name": target},
			"minReplicaCount": minReplicas,
		}})
	var conds []any
	if ready != "" {
		conds = append(conds, map[string]any{
			"type": "Ready", "status": ready,
			"lastTransitionTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	}
	if active != "" {
		conds = append(conds, map[string]any{
			"type": "Active", "status": active,
			"lastTransitionTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	}
	if len(conds) > 0 {
		_ = unstructured.SetNestedSlice(obj.Object, conds, "status", "conditions")
	}
	obj.SetUID(types.UID("uid-" + ns + "-" + name))
	return obj
}

func zeroDeploy(ns, name string, annotations map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Annotations: annotations},
		Spec: appsv1.DeploymentSpec{Replicas: ptr.To[int32](0)},
	}
}

// The KEDA zero-rescue consults the same Flux conflict gate as the
// HPA twin — a Git-owned target parked at zero must not be fought
// every sweep.
func TestKedaRescueRespectsFluxConflictGate(t *testing.T) {
	heal.ConfigureFluxConflictLoop(3, 30*time.Minute)
	t.Cleanup(func() { heal.ConfigureFluxConflictLoop(0, 0) })
	so := kedaObj("apps", "flux-scaler", "flux-worker", 1, "False", "")
	dep := zeroDeploy("apps", "flux-worker", nil)
	dep.ManagedFields = []metav1.ManagedFieldsEntry{{
		Manager: "helm-controller", Operation: metav1.ManagedFieldsOperationApply,
	}}
	cs := fake.NewSimpleClientset(dep)
	p := testProberDyn(cs, probetest.OpDyn(so))
	base := time.Now()
	p.Now = func() time.Time { return base }
	heal.FluxPatchGate("deployment", dep, "keda-scaledobject-guard:apps/Deployment/flux-worker", base)
	heal.FluxPatchGate("deployment", dep, "keda-scaledobject-guard:apps/Deployment/flux-worker", base)
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	base = base.Add(16 * time.Minute)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "flux-worker", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 0 {
		t.Fatalf("flux-gated rescue must not patch replicas, got %v",
			got.Spec.Replicas)
	}
}

func TestKedaGuardFlagsUnhealthyPastWindowAndRescuesZero(t *testing.T) {
	so := kedaObj("apps", "worker-scaler", "worker", 1, "False", "")
	dep := zeroDeploy("apps", "worker", nil)
	cs := fake.NewSimpleClientset(dep)
	p := testProberDyn(cs, probetest.OpDyn(so))
	base := time.Now()
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first sighting inside window must pass: %+v", res)
	}
	base = base.Add(16 * time.Minute)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("unhealthy scaledobject past window must fail: %+v", res)
	}
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 1 {
		t.Fatalf("wedged target replicas = %v want 1", got.Spec.Replicas)
	}
}

// The argo-rollout-gates Rollout twin: a ScaledObject targeting a wedged-at-zero
// argoproj.io Rollout gets the same rescue, patched through the
// dynamic client.
func TestKedaGuardRescuesZeroRollout(t *testing.T) {
	so := kedaObj("apps", "ro-scaler", "ro-worker", 1, "False", "")
	ro := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata":   map[string]any{"namespace": "apps", "name": "ro-worker"},
		"spec":       map[string]any{"replicas": int64(0)},
	}}
	dyn := probetest.OpDyn(so, ro)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	base := time.Now()
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	base = base.Add(16 * time.Minute)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("unhealthy scaledobject past window must fail: %+v", res)
	}
	got, err := dyn.Resource(kube.GVRArgoRollout).Namespace("apps").
		Get(ctx, "ro-worker", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get rollout: %v", err)
	}
	reps, _, _ := unstructured.NestedInt64(got.Object, "spec", "replicas")
	if reps != 1 {
		t.Fatalf("wedged Rollout replicas = %d want 1", reps)
	}
}

func TestKedaGuardSkipsDownscalerManagedZero(t *testing.T) {
	so := kedaObj("apps", "worker-scaler", "worker", 2, "", "Unknown")
	dep := zeroDeploy("apps", "worker",
		map[string]string{"downscaler/downtime-replicas": "0"})
	cs := fake.NewSimpleClientset(dep)
	p := testProberDyn(cs, probetest.OpDyn(so))
	base := time.Now()
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	base = base.Add(16 * time.Minute)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("active_unknown scaledobject past window must fail: %+v", res)
	}
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 0 {
		t.Fatalf("downscaler-parked target must stay at 0, got %v", got.Spec.Replicas)
	}
}

// The persisted twin of the unhealthy window: the ScaledObject
// carries a first-seen stamp already past kedaUnhealthyMinAge — the
// first post-restart sweep (empty ledger) must flag AND rescue, not
// sit the proven signature out a fresh 15m.
func TestKedaGuardRestartResume(t *testing.T) {
	so := kedaObj("apps", "worker-scaler", "worker", 1, "False", "")
	so.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenKedaScaledObject: `{"apps/worker-scaler":"` +
			time.Now().Add(-(kedaUnhealthyMinAge + time.Minute)).
				UTC().Format(time.RFC3339) + `"}`})
	dep := zeroDeploy("apps", "worker", nil)
	cs := fake.NewSimpleClientset(dep)
	p := testProberDyn(cs, probetest.OpDyn(so))
	res := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatalf("persisted window did not resume on the first post-restart sweep: %+v", res)
	}
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 1 {
		t.Fatalf("wedged target replicas = %v want 1", got.Spec.Replicas)
	}
}

func TestKedaGuardPassesOnHealthyObjects(t *testing.T) {
	so := kedaObj("apps", "worker-scaler", "worker", 1, "True", "True")
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(so))
	res := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("healthy scaledobject must pass: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// rescueZeroTarget — target resolution branches
// ---------------------------------------------------------------------------

// A ScaledObject with no spec.scaleTargetRef.name resolves no target —
// the rescue is a no-op before any census read.
func TestKedaRescueNoScaleTargetRef(t *testing.T) {
	so := kedaObj("apps", "scaler", "worker", 1, "False", "")
	unstructured.RemoveNestedField(so.Object, "spec", "scaleTargetRef", "name")
	cs := fake.NewSimpleClientset(zeroDeploy("apps", "worker", nil))
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	var lists int
	cs.PrependReactor("list", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			lists++
			return false, nil, nil
		})
	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now())
	if lists != 0 {
		t.Fatalf("deployment census reads = %d, want 0 — no target must return first", lists)
	}
}

// The StatefulSet leg of the census fallback: a target that is not a
// Deployment resolves through AllStatefulSets and patches via the
// typed client — with minReplicaCount=2 the rescue lands at 2, not 1.
func TestKedaRescueStatefulSetTarget(t *testing.T) {
	so := kedaObj("apps", "sts-scaler", "sts-worker", 2, "False", "")
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sts-worker"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To[int32](0)},
	}
	cs := fake.NewSimpleClientset(sts)
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now())
	got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "sts-worker", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 2 {
		t.Fatalf("statefulset replicas = %v want 2 (minReplicaCount)", got.Spec.Replicas)
	}
}

// spec.scaleTargetRef.kind is honored: a ScaledObject targeting a
// StatefulSet whose name collides with a same-namespace Deployment
// patches the StatefulSet, never the namesake.
func TestKedaRescueHonorsScaleTargetRefKind(t *testing.T) {
	so := kedaObj("apps", "sts-scaler", "worker", 1, "False", "")
	_ = unstructured.SetNestedField(so.Object, "StatefulSet",
		"spec", "scaleTargetRef", "kind")
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "worker"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To[int32](0)},
	}
	dep := zeroDeploy("apps", "worker", nil) // the namesake Deployment
	cs := fake.NewSimpleClientset(sts, dep)
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now())
	gotSts, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "worker", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotSts.Spec.Replicas == nil || *gotSts.Spec.Replicas != 1 {
		t.Fatalf("declared StatefulSet target not rescued: replicas = %v", gotSts.Spec.Replicas)
	}
	gotDep, _ := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if gotDep.Spec.Replicas == nil || *gotDep.Spec.Replicas != 0 {
		t.Fatal("the same-name Deployment was patched for a StatefulSet target")
	}
}

// minReplicaCount absent/zero clamps the rescue floor to 1 — a
// Deployment target proves the typed patch carries the computed value.
func TestKedaRescueMinReplicaFloor(t *testing.T) {
	so := kedaObj("apps", "scaler", "worker", 0, "False", "")
	cs := fake.NewSimpleClientset(zeroDeploy("apps", "worker", nil))
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now())
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 1 {
		t.Fatalf("rescue replicas = %v want the floor of 1", got.Spec.Replicas)
	}
}

// A target matching no Deployment, StatefulSet or Rollout in the
// censuses is inconclusive — never a "not at zero" verdict.
func TestKedaRescueUnresolvableTarget(t *testing.T) {
	so := kedaObj("apps", "scaler", "ghost", 1, "False", "")
	cs := fake.NewSimpleClientset(zeroDeploy("apps", "worker", nil))
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now()) // must not panic or patch
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 0 {
		t.Fatal("unrelated deployment patched for an unresolvable target")
	}
}

// A target already above zero is not wedged — the rescue leaves it.
func TestKedaRescueNonZeroTarget(t *testing.T) {
	so := kedaObj("apps", "scaler", "worker", 1, "False", "")
	dep := zeroDeploy("apps", "worker", nil)
	dep.Spec.Replicas = ptr.To[int32](3)
	cs := fake.NewSimpleClientset(dep)
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now())
	got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 3 {
		t.Fatalf("non-zero target touched: replicas = %v", got.Spec.Replicas)
	}
}

// A Rollout carrying no spec.replicas resolves kind=Rollout but
// replicas=nil — "cannot prove zero" stays inconclusive.
func TestKedaRescueRolloutNoReplicasField(t *testing.T) {
	so := kedaObj("apps", "scaler", "ro-worker", 1, "False", "")
	ro := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata":   map[string]any{"namespace": "apps", "name": "ro-worker"},
		"spec":       map[string]any{},
	}}
	dyn := probetest.OpDyn(so, ro)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now())
	got, err := dyn.Resource(kube.GVRArgoRollout).Namespace("apps").
		Get(ctx, "ro-worker", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _ := unstructured.NestedInt64(got.Object, "spec", "replicas"); found {
		t.Fatal("replicas-less Rollout was patched — nil is inconclusive, not zero")
	}
}

// Census failures are inconclusive at every leg: the Deployment
// census error returns before the StatefulSet/Rollout fallbacks even
// run.
func TestKedaRescueDeploymentCensusError(t *testing.T) {
	so := kedaObj("apps", "scaler", "worker", 1, "False", "")
	cs := fake.NewSimpleClientset(zeroDeploy("apps", "worker", nil))
	cs.PrependReactor("list", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now())
	got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 0 {
		t.Fatal("deployment patched although its census was unreadable")
	}
}

// The StatefulSet census error is the same inconclusive shape one leg
// down — the Deployment census ran clean (no match) first.
func TestKedaRescueStatefulSetCensusError(t *testing.T) {
	so := kedaObj("apps", "scaler", "sts-worker", 1, "False", "")
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "statefulsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now()) // must not panic
}

// The Rollout census error likewise — reached only after both typed
// censuses miss the target.
func TestKedaRescueRolloutCensusError(t *testing.T) {
	so := kedaObj("apps", "scaler", "ro-worker", 1, "False", "")
	dyn := probetest.OpDyn(so)
	dyn.PrependReactor("list", "rollouts",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, dyn)
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now()) // must not panic
}

// Inside the 30m rescue cooldown the gate refuses before any patch —
// the stamped key is ns/kind/target under the check's name.
func TestKedaRescueCooldownSkips(t *testing.T) {
	so := kedaObj("apps", "scaler", "worker", 1, "False", "")
	cs := fake.NewSimpleClientset(zeroDeploy("apps", "worker", nil))
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
	now := time.Now()
	chk.Heals.Stamp(probefw.SelfHealKey(
		CheckNameKedaScaledObjectGuard, "apps/Deployment/worker"), now)

	chk.rescueZeroTarget(ctx, logr.Discard(), so, now)
	got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 0 {
		t.Fatal("rescue fired inside its own cooldown")
	}
}

// A refused scale patch IncErrors and does NOT stamp the cooldown —
// the next sweep retries the same wedged target.
func TestKedaRescuePatchError(t *testing.T) {
	so := kedaObj("apps", "scaler", "worker", 1, "False", "")
	cs := fake.NewSimpleClientset(zeroDeploy("apps", "worker", nil))
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
	before := testutil.QueueErrorCount(t, "cluster-health-probes")

	chk.rescueZeroTarget(ctx, logr.Discard(), so, time.Now())
	got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "worker", metav1.GetOptions{})
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 0 {
		t.Fatal("deployment scaled although the patch was rejected")
	}
	if d := testutil.QueueErrorCount(t, "cluster-health-probes") - before; d != 1 {
		t.Fatalf("patch failure IncError delta = %v, want 1", d)
	}
}

func TestKedaRescueFluxGateOrderingRefundAndKeyspace(t *testing.T) {
	fluxManaged := []metav1.ManagedFieldsEntry{{
		Manager:   "helm-controller",
		Operation: metav1.ManagedFieldsOperationApply,
	}}

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "maintenance hold suppresses FluxPatchGate sightings",
			run: func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
				var hookCalls int
				heal.SetFluxConflictHook(func(heal.FluxConflictSignal) { hookCalls++ })
				t.Cleanup(func() {
					heal.ConfigureFluxConflictLoop(0, 0)
					heal.SetFluxConflictHook(nil)
				})

				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: "w-hold"},
					Spec:       corev1.NodeSpec{Unschedulable: true},
				}
				so := kedaObj("apps", "flux-hold-scaler", "flux-hold", 1, "False", "")
				dep := zeroDeploy("apps", "flux-hold", nil)
				dep.ManagedFields = fluxManaged
				cs := fake.NewSimpleClientset(dep, node)
				p := testProberDyn(cs, probetest.OpDyn(so))
				chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
				base := time.Now()

				probetest.FreezeNow(p.Deps, base)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				probetest.FreezeNow(p.Deps, base.Add(17*time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				if hookCalls != 0 {
					t.Fatalf("FluxConflictHook fired %d times during maintenance hold, want 0", hookCalls)
				}
				got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "flux-hold", metav1.GetOptions{})
				if *got.Spec.Replicas != 0 {
					t.Fatalf("replicas=%d during maintenance hold, want 0", *got.Spec.Replicas)
				}

				node.Spec.Unschedulable = false
				if _, err := cs.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				probetest.FreezeNow(p.Deps, base.Add(18*time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				got, _ = cs.AppsV1().Deployments("apps").Get(ctx, "flux-hold", metav1.GetOptions{})
				if *got.Spec.Replicas != 1 {
					t.Fatalf("post-hold replicas=%d, want 1 (phantom sightings leaked during hold)", *got.Spec.Replicas)
				}
			},
		},
		{
			name: "cooldown suppresses FluxPatchGate sightings",
			run: func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 2*time.Hour)
				var hookCalls int
				heal.SetFluxConflictHook(func(heal.FluxConflictSignal) { hookCalls++ })
				t.Cleanup(func() {
					heal.ConfigureFluxConflictLoop(0, 0)
					heal.SetFluxConflictHook(nil)
				})

				so := kedaObj("apps", "flux-cool-scaler", "flux-cool", 1, "False", "")
				dep := zeroDeploy("apps", "flux-cool", nil)
				dep.ManagedFields = fluxManaged
				cs := fake.NewSimpleClientset(dep)
				p := testProberDyn(cs, probetest.OpDyn(so))
				chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
				base := time.Now()

				probetest.FreezeNow(p.Deps, base)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				t1 := base.Add(16 * time.Minute)
				chk.Heals.Stamp(probefw.SelfHealKey(CheckNameKedaScaledObjectGuard, "apps/Deployment/flux-cool"), t1)
				probetest.FreezeNow(p.Deps, t1.Add(time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				probetest.FreezeNow(p.Deps, t1.Add(2*time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				if hookCalls != 0 {
					t.Fatalf("FluxConflictHook fired %d times during cooldown, want 0", hookCalls)
				}
				got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "flux-cool", metav1.GetOptions{})
				if *got.Spec.Replicas != 0 {
					t.Fatalf("replicas=%d during cooldown, want 0", *got.Spec.Replicas)
				}

				probetest.FreezeNow(p.Deps, t1.Add(kedaRescueCooldown+time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				got, _ = cs.AppsV1().Deployments("apps").Get(ctx, "flux-cool", metav1.GetOptions{})
				if *got.Spec.Replicas != 1 {
					t.Fatalf("post-cooldown replicas=%d, want 1 (phantom sightings leaked during cooldown)", *got.Spec.Replicas)
				}
			},
		},
		{
			name: "FluxPatchGate denial refunds budget grant for sibling target",
			run: func(t *testing.T) {
				heal.ConfigureBudget(1, time.Hour)
				heal.ConfigureFluxConflictLoop(1, 30*time.Minute)
				t.Cleanup(func() {
					heal.ConfigureBudget(0, 0)
					heal.ConfigureFluxConflictLoop(0, 0)
				})

				soFlux := kedaObj("apps", "a-flux-scaler", "flux-worker", 1, "False", "")
				soFree := kedaObj("apps", "b-free-scaler", "free-worker", 1, "False", "")
				depFlux := zeroDeploy("apps", "flux-worker", nil)
				depFlux.ManagedFields = fluxManaged
				depFree := zeroDeploy("apps", "free-worker", nil)
				cs := fake.NewSimpleClientset(depFlux, depFree)
				p := testProberDyn(cs, probetest.OpDyn(soFlux, soFree))
				chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
				base := time.Now()

				probetest.FreezeNow(p.Deps, base)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				gotFlux, _ := cs.AppsV1().Deployments("apps").Get(ctx, "flux-worker", metav1.GetOptions{})
				if *gotFlux.Spec.Replicas != 0 {
					t.Fatalf("flux-gated flux-worker replicas=%d, want 0", *gotFlux.Spec.Replicas)
				}
				gotFree, _ := cs.AppsV1().Deployments("apps").Get(ctx, "free-worker", metav1.GetOptions{})
				if *gotFree.Spec.Replicas != 1 {
					t.Fatalf("sibling free-worker replicas=%d, want 1 (grant not refunded on FluxPatchGate denial)", *gotFree.Spec.Replicas)
				}
			},
		},
		{
			name: "duty-prefixed keyspace isolates KEDA rescue from HPA and unprefixed keys",
			run: func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
				t.Cleanup(func() { heal.ConfigureFluxConflictLoop(0, 0) })

				so := kedaObj("apps", "iso-scaler", "flux-worker", 1, "False", "")
				dep := zeroDeploy("apps", "flux-worker", nil)
				dep.ManagedFields = fluxManaged
				cs := fake.NewSimpleClientset(dep)
				p := testProberDyn(cs, probetest.OpDyn(so))
				chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
				base := time.Now()

				heal.FluxPatchGate("deployment", dep, CheckNameHPAScalingGuard+":apps/Deployment/flux-worker", base)
				heal.FluxPatchGate("deployment", dep, CheckNameHPAScalingGuard+":apps/Deployment/flux-worker", base)
				heal.FluxPatchGate("deployment", dep, "apps/flux-worker", base)
				heal.FluxPatchGate("deployment", dep, "apps/flux-worker", base)

				probetest.FreezeNow(p.Deps, base)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				got, _ := cs.AppsV1().Deployments("apps").Get(ctx, "flux-worker", metav1.GetOptions{})
				if *got.Spec.Replicas != 1 {
					t.Fatalf("isolated KEDA rescue replicas=%d, want 1", *got.Spec.Replicas)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

func TestKedaRescueCrossKindIsolation(t *testing.T) {
	fluxManaged := []metav1.ManagedFieldsEntry{{
		Manager:   "kustomize-controller",
		Operation: metav1.ManagedFieldsOperationApply,
	}}
	newSO := func(name, targetKind string) *unstructured.Unstructured {
		so := kedaObj("apps", name, "web", 1, "False", "")
		_ = unstructured.SetNestedField(so.Object, targetKind, "spec", "scaleTargetRef", "kind")
		return so
	}
	newDep := func(mf []metav1.ManagedFieldsEntry) *appsv1.Deployment {
		dep := zeroDeploy("apps", "web", nil)
		dep.ManagedFields = mf
		return dep
	}
	newSts := func(mf []metav1.ManagedFieldsEntry) *appsv1.StatefulSet {
		return &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web", ManagedFields: mf},
			Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To[int32](0)},
		}
	}
	newRollout := func(mf []metav1.ManagedFieldsEntry) *unstructured.Unstructured {
		ro := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "argoproj.io/v1alpha1",
			"kind":       "Rollout",
			"metadata":   map[string]any{"namespace": "apps", "name": "web"},
			"spec":       map[string]any{"replicas": int64(0)},
		}}
		if mf != nil {
			ro.SetManagedFields(mf)
		}
		return ro
	}
	replicasOf := func(t *testing.T, cs *fake.Clientset, p *probefw.Deps, kind string) int64 {
		t.Helper()
		switch kind {
		case "Deployment":
			got, err := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			return int64(*got.Spec.Replicas)
		case "StatefulSet":
			got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "web", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			return int64(*got.Spec.Replicas)
		case "Rollout":
			got, err := p.Dyn.Resource(kube.GVRArgoRollout).Namespace("apps").Get(ctx, "web", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			reps, _, _ := unstructured.NestedInt64(got.Object, "spec", "replicas")
			return reps
		default:
			t.Fatalf("unexpected kind %q", kind)
			return 0
		}
	}
	revertZero := func(t *testing.T, cs *fake.Clientset, p *probefw.Deps, kind string) {
		t.Helper()
		switch kind {
		case "Deployment":
			got, err := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got.Spec.Replicas = ptr.To[int32](0)
			if _, err := cs.AppsV1().Deployments("apps").Update(ctx, got, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		case "StatefulSet":
			got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "web", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got.Spec.Replicas = ptr.To[int32](0)
			if _, err := cs.AppsV1().StatefulSets("apps").Update(ctx, got, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		case "Rollout":
			got, err := p.Dyn.Resource(kube.GVRArgoRollout).Namespace("apps").Get(ctx, "web", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := unstructured.SetNestedField(got.Object, int64(0), "spec", "replicas"); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Dyn.Resource(kube.GVRArgoRollout).Namespace("apps").Update(ctx, got, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unexpected kind %q", kind)
		}
	}

	t.Run("FluxPatchGate_cross_kind_isolation", func(t *testing.T) {
		orders := [][]string{
			{"Deployment", "StatefulSet", "Rollout"},
			{"Rollout", "StatefulSet", "Deployment"},
		}
		for _, order := range orders {
			name := order[0] + "_" + order[1] + "_" + order[2]
			t.Run(name, func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
				var signals []heal.FluxConflictSignal
				heal.SetFluxConflictHook(func(s heal.FluxConflictSignal) {
					signals = append(signals, s)
				})
				t.Cleanup(func() {
					heal.ConfigureFluxConflictLoop(0, 0)
					heal.SetFluxConflictHook(nil)
				})

				dynObjs := []runtime.Object{newRollout(fluxManaged)}
				for i, kind := range order {
					dynObjs = append(dynObjs, newSO(string(rune('a'+i))+"-"+kind, kind))
				}
				cs := fake.NewSimpleClientset(newDep(fluxManaged), newSts(fluxManaged))
				p := testProberDyn(cs, probetest.OpDyn(dynObjs...))
				chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
				base := time.Now()

				probetest.FreezeNow(p.Deps, base)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				for _, kind := range order {
					if r := replicasOf(t, cs, p.Deps, kind); r != 1 {
						t.Fatalf("%s replicas=%d, want 1 (cross-kind FluxPatchGate collision)", kind, r)
					}
				}
				if len(signals) != 0 {
					t.Fatalf("unexpected FluxConflictHook signals: %+v", signals)
				}
			})
		}
	})

	t.Run("non_flux_rescue_does_not_wipe_flux_history", func(t *testing.T) {
		for _, fluxKind := range []string{"Deployment", "StatefulSet", "Rollout"} {
			t.Run("flux_"+fluxKind, func(t *testing.T) {
				heal.ConfigureFluxConflictLoop(2, 2*time.Hour)
				var signals []heal.FluxConflictSignal
				heal.SetFluxConflictHook(func(s heal.FluxConflictSignal) {
					signals = append(signals, s)
				})
				t.Cleanup(func() {
					heal.ConfigureFluxConflictLoop(0, 0)
					heal.SetFluxConflictHook(nil)
				})

				var depMF, stsMF, roMF []metav1.ManagedFieldsEntry
				switch fluxKind {
				case "Deployment":
					depMF = fluxManaged
				case "StatefulSet":
					stsMF = fluxManaged
				case "Rollout":
					roMF = fluxManaged
				}

				soFlux := newSO("a-flux", fluxKind)
				dynObjs := []runtime.Object{newRollout(roMF), soFlux}
				var otherKinds []string
				for _, k := range []string{"Deployment", "StatefulSet", "Rollout"} {
					if k != fluxKind {
						otherKinds = append(otherKinds, k)
						dynObjs = append(dynObjs, newSO("b-free-"+k, k))
					}
				}
				cs := fake.NewSimpleClientset(newDep(depMF), newSts(stsMF))
				p := testProberDyn(cs, probetest.OpDyn(dynObjs...))
				chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
				for _, ok := range otherKinds {
					// Start non-Flux siblings at 1 so only the Flux target rescues in Sweep 2.
					switch ok {
					case "Deployment":
						d, _ := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
						d.Spec.Replicas = ptr.To[int32](1)
						_, _ = cs.AppsV1().Deployments("apps").Update(ctx, d, metav1.UpdateOptions{})
					case "StatefulSet":
						s, _ := cs.AppsV1().StatefulSets("apps").Get(ctx, "web", metav1.GetOptions{})
						s.Spec.Replicas = ptr.To[int32](1)
						_, _ = cs.AppsV1().StatefulSets("apps").Update(ctx, s, metav1.UpdateOptions{})
					case "Rollout":
						r, _ := p.Dyn.Resource(kube.GVRArgoRollout).Namespace("apps").Get(ctx, "web", metav1.GetOptions{})
						_ = unstructured.SetNestedField(r.Object, int64(1), "spec", "replicas")
						_, _ = p.Dyn.Resource(kube.GVRArgoRollout).Namespace("apps").Update(ctx, r, metav1.UpdateOptions{})
					}
				}
				base := time.Now()

				// Sweep 1: arm persistence window.
				probetest.FreezeNow(p.Deps, base)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				// Sweep 2: only the Flux target is at 0, so it rescues and records sighting #1.
				t1 := base.Add(16 * time.Minute)
				probetest.FreezeNow(p.Deps, t1)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				if r := replicasOf(t, cs, p.Deps, fluxKind); r != 1 {
					t.Fatalf("initial Flux %s rescue replicas=%d, want 1", fluxKind, r)
				}

				// Flux reverts its target to 0, while non-Flux siblings wedge at 0 inside 30m cooldown.
				revertZero(t, cs, p.Deps, fluxKind)
				for _, ok := range otherKinds {
					revertZero(t, cs, p.Deps, ok)
				}
				probetest.FreezeNow(p.Deps, t1.Add(time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				for _, ok := range otherKinds {
					if r := replicasOf(t, cs, p.Deps, ok); r != 1 {
						t.Fatalf("non-Flux %s rescue replicas=%d, want 1", ok, r)
					}
				}

				// Advance past 30m cooldown (still inside 2h Flux window): Flux target must be denied.
				probetest.FreezeNow(p.Deps, t1.Add(kedaRescueCooldown+time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				if r := replicasOf(t, cs, p.Deps, fluxKind); r != 0 {
					t.Fatalf("Flux %s replicas=%d after cooldown, want 0 (non-Flux loop.forget wiped Flux history)", fluxKind, r)
				}
				if len(signals) != 1 {
					t.Fatalf("FluxConflictHook signals=%d, want 1 (%+v)", len(signals), signals)
				}
			})
		}
	})

	t.Run("cooldown_cross_kind_isolation", func(t *testing.T) {
		for _, cooledKind := range []string{"Deployment", "StatefulSet", "Rollout"} {
			t.Run("cooled_"+cooledKind, func(t *testing.T) {
				soDep := newSO("a-dep", "Deployment")
				soSts := newSO("b-sts", "StatefulSet")
				soRo := newSO("c-ro", "Rollout")
				cs := fake.NewSimpleClientset(newDep(nil), newSts(nil))
				p := testProberDyn(cs, probetest.OpDyn(newRollout(nil), soDep, soSts, soRo))
				chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
				base := time.Now()

				probetest.FreezeNow(p.Deps, base)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				t1 := base.Add(16 * time.Minute)
				chk.Heals.Stamp(probefw.SelfHealKey(CheckNameKedaScaledObjectGuard, "apps/"+cooledKind+"/web"), t1)
				probetest.FreezeNow(p.Deps, t1.Add(time.Minute))
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))

				for _, kind := range []string{"Deployment", "StatefulSet", "Rollout"} {
					got := replicasOf(t, cs, p.Deps, kind)
					want := int64(1)
					if kind == cooledKind {
						want = 0
					}
					if got != want {
						t.Fatalf("kind %s replicas=%d, want %d (cooledKind=%s)", kind, got, want, cooledKind)
					}
				}
			})
		}
	})
}

// keda_scaledobject_guard_test.go — coverage for the
// keda-scaledobject-guard check: persistence window, zero-replica
// rescue and the downscaler skip.
package nodehealth

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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

func TestKedaGuardFlagsUnhealthyPastWindowAndRescuesZero(t *testing.T) {
	so := kedaObj("apps", "worker-scaler", "worker", 1, "False", "")
	dep := zeroDeploy("apps", "worker", nil)
	cs := fake.NewSimpleClientset(dep)
	p := testProberDyn(cs, probetest.OpDyn(so))
	base := time.Now()
	p.Now = func() time.Time { return base }
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sighting inside window must pass: %+v", res)
	}
	base = base.Add(16 * time.Minute)
	res := chk.Run(ctx)
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
	chk.Run(ctx)
	base = base.Add(16 * time.Minute)
	if res := chk.Run(ctx); res.Pass {
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
	chk.Run(ctx)
	base = base.Add(16 * time.Minute)
	res := chk.Run(ctx)
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
	res := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p).Run(ctx)
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
	res := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p).Run(ctx)
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
// the stamped key is ns/target under the check's name.
func TestKedaRescueCooldownSkips(t *testing.T) {
	so := kedaObj("apps", "scaler", "worker", 1, "False", "")
	cs := fake.NewSimpleClientset(zeroDeploy("apps", "worker", nil))
	p := testProberDyn(cs, probetest.OpDyn(so))
	chk := probetest.MustCheck[*kedaScaledObjectGuardCheck](t, p)
	now := time.Now()
	chk.Heals.Stamp(probefw.SelfHealKey(
		CheckNameKedaScaledObjectGuard, "apps/worker"), now)

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

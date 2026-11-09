// keda_scaledobject_guard_test.go — coverage for the
// keda-scaledobject-guard check: persistence window, zero-replica
// rescue and the downscaler skip.
package nodehealth

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

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

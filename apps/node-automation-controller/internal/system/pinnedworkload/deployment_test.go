// deployment_test.go — the DeploymentSpec reconcile skeleton: get →
// NotFound skip → proportional wantReplicas → Drifted →
// missing-container guard → PatchBody → strategic-merge Patch → 15m
// requeue. The module hooks (Drifted, PatchBody) are plain closures
// here — the skeleton owns the flow, so the tests drive every branch
// with generic fixtures instead of a real addon manifest.
package pinnedworkload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// pinnedDeploy is a kube-system/addon Deployment carrying the "app"
// container the spec's patch merges by name.
func pinnedDeploy() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "addon", Namespace: "kube-system"},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "addon:v1"}},
				},
			},
		},
	}
}

// baseDeploySpec is a fully-drifted DeploymentSpec with a static
// patch body — tests override Drifted/PatchBody/Replicas for the
// branch under test.
func baseDeploySpec(cs kubernetes.Interface) DeploymentSpec {
	return DeploymentSpec{
		CS:         cs,
		Namespace:  "kube-system",
		Name:       "addon",
		Container:  "app",
		NoDriftLog: "already pinned",
		Drifted:    func(*appsv1.Deployment, int32) bool { return true },
		PatchBody:  func(int32) ([]byte, error) { return []byte(`{"spec":{"replicas":3}}`), nil },
	}
}

func getDeploy(t *testing.T, cs *fake.Clientset) *appsv1.Deployment {
	t.Helper()
	d, err := cs.AppsV1().Deployments("kube-system").
		Get(context.Background(), "addon", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get addon: %v", err)
	}
	return d
}

// A missing Deployment is the "cluster without this addon" no-op —
// nil error on the 15m requeue, not a workqueue backoff.
func TestDeploymentSpecNotFound(t *testing.T) {
	res, err := baseDeploySpec(fake.NewSimpleClientset()).
		Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// A get failure other than NotFound is a real error — only NotFound
// is the skip path.
func TestDeploymentSpecGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDeploy())
	cs.PrependReactor("get", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	_, err := baseDeploySpec(cs).Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected error when the deployment get fails")
	}
	if !strings.Contains(err.Error(), "get deployment kube-system/addon") {
		t.Fatalf("error missing the wrapped ref: %v", err)
	}
}

// With the pin enabled, a node list failure surfaces before Drifted
// is ever consulted — the count is never taken off a partial picture.
func TestDeploymentSpecNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDeploy())
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	s := baseDeploySpec(cs)
	s.Replicas = ReplicaPin{MinReplicas: 4, NodesPerReplica: 1}
	s.Drifted = func(*appsv1.Deployment, int32) bool {
		t.Fatal("Drifted ran after a failed node list")
		return true
	}
	if _, err := s.Reconcile(context.Background()); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// Drift-free means no patch — the 15m requeue is the only output.
func TestDeploymentSpecNoDrift(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDeploy())
	var patched bool
	testutil.ForbidDeployPatch(cs, &patched)

	s := baseDeploySpec(cs)
	s.Drifted = func(*appsv1.Deployment, int32) bool { return false }
	res, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched a drift-free Deployment")
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// A missing container reads as drift, but the strategic-merge patch
// merges containers BY NAME — applied to a spec without it, the
// name-only entry has no image and the apiserver rejects it forever.
// The skeleton must skip with a warn, never attempt the patch.
func TestDeploymentSpecMissingContainerSkips(t *testing.T) {
	d := pinnedDeploy()
	d.Spec.Template.Spec.Containers = nil
	cs := fake.NewSimpleClientset(d)
	var patched bool
	testutil.ForbidDeployPatch(cs, &patched)

	res, err := baseDeploySpec(cs).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched a Deployment whose pinned container is absent — " +
			"the name-only merge entry has no image and is rejected forever")
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// A PatchBody render failure is a reconcile error, and no patch is
// sent for a body that never rendered.
func TestDeploymentSpecPatchBodyError(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDeploy())
	var patched bool
	testutil.ForbidDeployPatch(cs, &patched)

	s := baseDeploySpec(cs)
	s.PatchBody = func(int32) ([]byte, error) {
		return nil, errors.New("render blew up")
	}
	if _, err := s.Reconcile(context.Background()); err == nil {
		t.Fatal("expected error when PatchBody fails")
	}
	if patched {
		t.Fatal("patch was sent despite the PatchBody error")
	}
}

// A failed drift patch errors the reconcile — the metric must
// surface a persistent failure to re-pin.
func TestDeploymentSpecPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDeploy())
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	_, err := baseDeploySpec(cs).Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected error when the drift patch fails")
	}
	if !strings.Contains(err.Error(), "patch deployment kube-system/addon") {
		t.Fatalf("error missing the wrapped ref: %v", err)
	}
}

// The proportional pin threads end to end: 9 nodes / nodesPerReplica
// 2 ceils to 5 (above the min-4 floor), the SAME wantReplicas reaches
// Drifted and PatchBody, and the rendered replicas land on the
// Deployment in the tracker.
func TestDeploymentSpecAppliesPatch(t *testing.T) {
	objs := []runtime.Object{pinnedDeploy()}
	for i := range 9 {
		objs = append(objs, testutil.Node(
			fmt.Sprintf("n%d", i), corev1.ConditionTrue, nil))
	}
	cs := fake.NewSimpleClientset(objs...)
	var driftedWant, bodyWant int32 = -1, -1

	s := baseDeploySpec(cs)
	s.Replicas = ReplicaPin{MinReplicas: 4, NodesPerReplica: 2}
	s.Drifted = func(_ *appsv1.Deployment, want int32) bool {
		driftedWant = want
		return true
	}
	s.PatchBody = func(want int32) ([]byte, error) {
		bodyWant = want
		return []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, want)), nil
	}
	res, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if driftedWant != 5 || bodyWant != 5 {
		t.Fatalf("wantReplicas drifted=%d body=%d, want 5/5",
			driftedWant, bodyWant)
	}
	if got := getDeploy(t, cs).Spec.Replicas; got == nil || *got != 5 {
		t.Fatalf("deployment replicas = %v, want 5", got)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// ---------------------------------------------------------------------------
// Informer-cache read + direct-CS drift confirm (Reader seam)
// ---------------------------------------------------------------------------

// fakeCacheReader is a CachedObjectReader stub playing the informer
// cache: it serves exactly the objects handed to it, independent of
// the fake clientset that plays the live apiserver — the census/live
// split the direct-CS confirm must resolve.
type fakeCacheReader struct {
	objs []client.Object
}

func (f *fakeCacheReader) Get(_ context.Context, key client.ObjectKey,
	obj client.Object, _ ...client.GetOption) error {
	for _, o := range f.objs {
		if o.GetNamespace() == key.Namespace && o.GetName() == key.Name {
			// Round-trip into the caller's object — the shape the
			// cache client's Get delivers (fresh object, not alias).
			data, err := json.Marshal(o)
			if err != nil {
				return err
			}
			return json.Unmarshal(data, obj)
		}
	}
	return apierrors.NewNotFound(
		corev1.SchemeGroupVersion.WithResource("objects").GroupResource(),
		key.Name)
}

// A drifted cache read with a SETTLED live object must not patch:
// the destructive path confirms on the direct clientset before
// acting — a stale informer never fires a patch the live object no
// longer needs. Drifted keys on the container image so the cache
// copy (image stripped) reads drifted and the live copy settled.
func TestDeploymentSpecCachedReadConfirmSkipsSettled(t *testing.T) {
	live := pinnedDeploy()
	stale := pinnedDeploy()
	stale.Spec.Template.Spec.Containers[0].Image = ""
	cs := fake.NewSimpleClientset(live)
	var patched bool
	testutil.ForbidDeployPatch(cs, &patched)

	s := baseDeploySpec(cs)
	s.Reader = &fakeCacheReader{objs: []client.Object{stale}}
	s.Drifted = func(d *appsv1.Deployment, _ int32) bool {
		return kube.PodSpecHasContainer(&d.Spec.Template.Spec, "app") &&
			d.Spec.Template.Spec.Containers[0].Image == ""
	}
	res, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
	if patched {
		t.Fatal("patched off a stale cache read — the direct-CS confirm must veto")
	}
}

// A drifted cache read with a drifted LIVE object still patches —
// the confirm confirms real drift.
func TestDeploymentSpecCachedReadConfirmPatchesDrift(t *testing.T) {
	live := pinnedDeploy()
	live.Spec.Template.Spec.Containers[0].Image = ""
	stale := pinnedDeploy()
	stale.Spec.Template.Spec.Containers[0].Image = ""
	cs := fake.NewSimpleClientset(live)
	// Count patch attempts and let the tracker apply the real merge —
	// exactly one attempt proves the confirm kept the patch (and that
	// the cache-read path didn't double-fire).
	var patches int
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})

	s := baseDeploySpec(cs)
	s.Reader = &fakeCacheReader{objs: []client.Object{stale}}
	if _, err := s.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patches != 1 {
		t.Fatalf("confirmed drift patch attempts = %d, want 1", patches)
	}
}

// A NotFound from the cache is the cluster-without-this-addon skip —
// unchanged shape when the read rides the informer.
func TestDeploymentSpecCachedReadNotFound(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var patched bool
	testutil.ForbidDeployPatch(cs, &patched)
	s := baseDeploySpec(cs)
	s.Reader = &fakeCacheReader{}
	res, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
	if patched {
		t.Fatal("patched on a cache NotFound")
	}
}

package apiserviceguard

import (
	"errors"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders (asg-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

// asgObj builds an APIService unstructured — svcNs/svcName "" renders
// no spec.service at all (the local, non-Service-backed shape).
func asgObj(name, svcNs, svcName string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiregistration.k8s.io/v1",
		"kind":       "APIService",
		"metadata":   map[string]any{"name": name},
	}}
	if svcNs != "" && svcName != "" {
		u.Object["spec"] = map[string]any{
			"service": map[string]any{"namespace": svcNs, "name": svcName},
		}
	}
	return u
}

// asgUnavailable stamps an Available=False condition whose
// lastTransitionTime is `age` in the past.
func asgUnavailable(u *unstructured.Unstructured, age time.Duration) {
	u.Object["status"] = map[string]any{
		"conditions": []any{map[string]any{
			"type":               "Available",
			"status":             "False",
			"lastTransitionTime": time.Now().Add(-age).UTC().Format(time.RFC3339),
		}},
	}
}

func asgDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			apiServiceGVR: "APIServiceList",
		},
		objs...)
}

func asgExists(t *testing.T, dyn *dynamicfake.FakeDynamicClient, name string) bool {
	t.Helper()
	_, err := dyn.Resource(apiServiceGVR).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

func asgGuard(cs *fake.Clientset, dyn *dynamicfake.FakeDynamicClient) *apiServiceGuard {
	return &apiServiceGuard{cs: cs, dyn: dyn, nowFn: time.Now}
}

// ---------------------------------------------------------------------------
// (a) Orphan cleanup
// ---------------------------------------------------------------------------

// An APIService pointing at a deleted namespace is reaped while a
// healthy sibling and a non-Service-backed object are kept.
func TestAPIServiceGuardDeletesOrphan(t *testing.T) {
	orphan := asgObj("v1alpha1.dead.example.com", "dead-ns", "svc")
	alive := asgObj("v1.apps.example.com", "alive", "svc")
	local := asgObj("v1.", "", "") // no spec.service — never a candidate
	cs := fake.NewSimpleClientset(
		testutil.Namespace("kube-system"), testutil.Namespace("alive"))
	dyn := asgDynFake(orphan, alive, local)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if asgExists(t, dyn, "v1alpha1.dead.example.com") {
		t.Fatal("orphan apiservice not deleted")
	}
	for _, name := range []string{"v1.apps.example.com", "v1."} {
		if !asgExists(t, dyn, name) {
			t.Fatalf("apiservice %s wrongly deleted", name)
		}
	}
}

// An empty namespace list is an API flap — the deletion pass skips
// itself and every candidate survives (fail closed).
func TestAPIServiceGuardEmptyNamespaceListSkipsOrphans(t *testing.T) {
	orphan := asgObj("v1alpha1.dead.example.com", "dead-ns", "svc")
	cs := fake.NewSimpleClientset() // zero namespaces
	dyn := asgDynFake(orphan)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgExists(t, dyn, "v1alpha1.dead.example.com") {
		t.Fatal("apiservice deleted on an empty namespace snapshot")
	}
}

// A namespace-list error aborts the pass with a real error.
func TestAPIServiceGuardNamespaceListError(t *testing.T) {
	cs := fake.NewSimpleClientset(testutil.Namespace("kube-system"))
	cs.PrependReactor("list", "namespaces",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	dyn := asgDynFake(asgObj("v1alpha1.dead.example.com", "dead-ns", "svc"))
	g := asgGuard(cs, dyn)
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when the namespace list fails")
	}
}

// The Get re-confirm wins over a stale List: a namespace that exists
// but is absent from the snapshot keeps its APIService.
func TestAPIServiceGuardStaleSnapshotConfirmKeeps(t *testing.T) {
	orphan := asgObj("v1alpha1.dead.example.com", "dead-ns", "svc")
	liveNS := testutil.Namespace("dead-ns") // exists, but hidden from List below
	cs := fake.NewSimpleClientset(testutil.Namespace("kube-system"), liveNS)
	cs.PrependReactor("list", "namespaces",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, &corev1.NamespaceList{Items: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
			}}, nil
		})
	dyn := asgDynFake(orphan)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgExists(t, dyn, "v1alpha1.dead.example.com") {
		t.Fatal("apiservice deleted on a stale snapshot — Get re-confirm failed")
	}
}

// ---------------------------------------------------------------------------
// (b) Availability watchdog
// ---------------------------------------------------------------------------

// Available=False past the 10m threshold exports the gauge; a
// sub-threshold failure and a healthy APIService emit nothing.
func TestAPIServiceGuardUnavailableGauge(t *testing.T) {
	old := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(old, 30*time.Minute)
	fresh := asgObj("v1.fresh.example.com", "alive", "svc")
	asgUnavailable(fresh, 2*time.Minute)
	healthy := asgObj("v1.healthy.example.com", "alive", "svc")

	cs := fake.NewSimpleClientset(testutil.Namespace("kube-system"), testutil.Namespace("alive"))
	dyn := asgDynFake(old, fresh, healthy)
	g := asgGuard(cs, dyn)

	metrics.APIServiceUnavailable.DeleteLabelValues(
		"v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	t.Cleanup(func() {
		metrics.APIServiceUnavailable.DeleteLabelValues(
			"v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	})

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.APIServiceUnavailable.
		WithLabelValues("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")); got != 1 {
		t.Fatalf("unavailable gauge = %v, want 1", got)
	}
	if got := ptestutil.ToFloat64(metrics.APIServiceUnavailable.
		WithLabelValues("v1.fresh.example.com", "alive", "svc")); got != 0 {
		t.Fatalf("sub-threshold failure exported gauge %v", got)
	}
}

// A recovered APIService gets its series pruned — the alert must not
// pin at 1 forever.
func TestAPIServiceGuardGaugePrunedOnRecovery(t *testing.T) {
	old := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(old, 30*time.Minute)
	cs := fake.NewSimpleClientset(testutil.Namespace("kube-system"))
	dyn := asgDynFake(old)
	g := asgGuard(cs, dyn)

	metrics.APIServiceUnavailable.DeleteLabelValues(
		"v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.APIServiceUnavailable.
		WithLabelValues("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")); got != 1 {
		t.Fatalf("unavailable gauge = %v, want 1", got)
	}

	// APIService flips back to Available=True — next sweep deletes
	// the label tuple outright (no pinned 1, no lingering 0).
	u, err := dyn.Resource(apiServiceGVR).
		Get(ctx, "v1beta1.metrics.k8s.io", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u.Object["status"] = map[string]any{
		"conditions": []any{map[string]any{
			"type":               "Available",
			"status":             "True",
			"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
		}},
	}
	if _, err := dyn.Resource(apiServiceGVR).
		Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.APIServiceUnavailable.
		WithLabelValues("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")); got != 0 {
		t.Fatalf("recovered apiservice still exporting gauge %v", got)
	}
}

// Available=False without a parseable lastTransitionTime has no
// provable age — never flagged.
func TestAPIServiceGuardUnavailableNoTimestamp(t *testing.T) {
	broken := asgObj("v1.broken.example.com", "alive", "svc")
	broken.Object["status"] = map[string]any{
		"conditions": []any{map[string]any{
			"type":   "Available",
			"status": "False",
			// no lastTransitionTime — age unprovable
		}},
	}
	cs := fake.NewSimpleClientset(testutil.Namespace("kube-system"), testutil.Namespace("alive"))
	dyn := asgDynFake(broken)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.APIServiceUnavailable.
		WithLabelValues("v1.broken.example.com", "alive", "svc")); got != 0 {
		t.Fatalf("timestamp-less failure exported gauge %v", got)
	}
}

// The delete carries a UID precondition — a same-named APIService
// recreated between the IsNotFound re-confirm and the delete is not
// the object this sweep vetted.
func TestAPIServiceGuardDeleteUIDPrecondition(t *testing.T) {
	orphan := asgObj("v1alpha1.dead.example.com", "dead-ns", "svc")
	orphan.SetUID(types.UID("uid-orphan"))
	cs := fake.NewSimpleClientset(testutil.Namespace("kube-system"))
	dyn := asgDynFake(orphan)
	var gotUID *types.UID
	dyn.PrependReactor("delete", "apiservices",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	g := asgGuard(cs, dyn)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if gotUID == nil || *gotUID != "uid-orphan" {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
	if asgExists(t, dyn, "v1alpha1.dead.example.com") {
		t.Fatal("orphan APIService not reaped")
	}
}

// Both duties consume ONE APIService list per run — the orphan pass
// and the availability watchdog share the snapshot instead of listing
// twice.
func TestAPIServiceGuardListsOncePerRun(t *testing.T) {
	cs := fake.NewSimpleClientset(testutil.Namespace("kube-system"))
	dyn := asgDynFake(asgObj("v1.apps.example.com", "alive", "svc"))
	lists := 0
	dyn.PrependReactor("list", "apiservices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			lists++
			return false, nil, nil // passthrough
		})
	g := asgGuard(cs, dyn)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if lists != 1 {
		t.Fatalf("apiservices listed %d times in one run, want 1", lists)
	}
}

// ---------------------------------------------------------------------------
// (c) W10-CP1 — dead-APIService unblocker
// ---------------------------------------------------------------------------

// asgStuckNS builds a namespace stuck in Terminating for `age`,
// carrying one NamespaceContentRemaining condition whose message
// references `groupRef`.
func asgStuckNS(name string, age time.Duration, groupRef string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			DeletionTimestamp: &metav1.Time{Time: time.Now().Add(-age)},
		},
		Status: corev1.NamespaceStatus{
			Phase: corev1.NamespaceTerminating,
			Conditions: []corev1.NamespaceCondition{{
				Type:    corev1.NamespaceContentRemaining,
				Status:  corev1.ConditionTrue,
				Reason:  "ContentRemaining",
				Message: "some resources are remaining: APIservices." + groupRef + " cannot be deleted",
			}},
		},
	}
}

// asgBackendSvc + asgBackendPod build the backing Service and one
// selected pod for a protected-namespace APIService.
func asgBackendSvc(ns, name, app string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": app}},
	}
}

func asgBackendPod(ns, name, app string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, Labels: map[string]string{"app": app},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func asgPodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

// The full wedge signature — protected-namespace APIService
// Available=False >=15m AND a namespace Terminating >=15m whose
// condition names the API group — restarts the backing pods.
func TestAPIServiceGuardUnblockRestartsBackingPods(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 30*time.Minute)
	cs := fake.NewSimpleClientset(
		testutil.Namespace("kube-system"),
		asgStuckNS("dying-ns", 20*time.Minute, "metrics.k8s.io"),
		asgBackendSvc("kube-system", "metrics-server", "metrics-server"),
		asgBackendPod("kube-system", "ms-0", "metrics-server"),
		asgBackendPod("kube-system", "ms-1", "metrics-server"))
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ms-0", "ms-1"} {
		if asgPodExists(t, cs, "kube-system", name) {
			t.Fatalf("backing pod %s not restarted", name)
		}
	}
	if !asgExists(t, dyn, "v1beta1.metrics.k8s.io") {
		t.Fatal("APIService object itself deleted — only pods should restart")
	}
}

// Every gate leg is required: a Terminating namespace younger than
// 15m must not trigger the heal even with a long-dead APIService.
func TestAPIServiceGuardUnblockYoungTerminatingSkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 30*time.Minute)
	cs := fake.NewSimpleClientset(
		testutil.Namespace("kube-system"),
		asgStuckNS("dying-ns", 5*time.Minute, "metrics.k8s.io"),
		asgBackendSvc("kube-system", "metrics-server", "metrics-server"),
		asgBackendPod("kube-system", "ms-0", "metrics-server"))
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("backing pod deleted although the namespace only just started terminating")
	}
}

// A Terminating namespace referencing a DIFFERENT API group does
// not unblock this APIService.
func TestAPIServiceGuardUnblockWrongGroupSkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 30*time.Minute)
	cs := fake.NewSimpleClientset(
		testutil.Namespace("kube-system"),
		asgStuckNS("dying-ns", 20*time.Minute, "other.example.com"),
		asgBackendSvc("kube-system", "metrics-server", "metrics-server"),
		asgBackendPod("kube-system", "ms-0", "metrics-server"))
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("backing pod deleted for an unrelated API group")
	}
}

// The unblock healer is scoped to the protected-namespace set: a
// broken APIService backed in a regular namespace gets the metric
// only — no pod restarts.
func TestAPIServiceGuardUnblockNonProtectedSkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.custom.example.com", "custom-ns", "custom-apiserver")
	asgUnavailable(apiSvc, 30*time.Minute)
	cs := fake.NewSimpleClientset(
		testutil.Namespace("custom-ns"),
		asgStuckNS("dying-ns", 20*time.Minute, "custom.example.com"),
		asgBackendSvc("custom-ns", "custom-apiserver", "custom"),
		asgBackendPod("custom-ns", "custom-0", "custom"))
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "custom-ns", "custom-0") {
		t.Fatal("non-protected APIService backend restarted — scope violated")
	}
}

// A healthy protected-namespace APIService is never touched even
// while a namespace sits Terminating.
func TestAPIServiceGuardUnblockHealthySkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 2*time.Minute) // under the 15m unblock gate
	cs := fake.NewSimpleClientset(
		testutil.Namespace("kube-system"),
		asgStuckNS("dying-ns", 20*time.Minute, "metrics.k8s.io"),
		asgBackendSvc("kube-system", "metrics-server", "metrics-server"),
		asgBackendPod("kube-system", "ms-0", "metrics-server"))
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("backing pod deleted for a sub-threshold APIService failure")
	}
}

// An apiservices list failure inside the watchdog is a real error —
// but the orphan pass must have already run (independence).
func TestAPIServiceGuardListErrorIsolated(t *testing.T) {
	orphan := asgObj("v1alpha1.dead.example.com", "dead-ns", "svc")
	cs := fake.NewSimpleClientset(testutil.Namespace("kube-system"))
	dyn := asgDynFake(orphan)
	g := asgGuard(cs, dyn)

	// Let the orphan pass complete, then break every list: the run
	// errors but the deletion already landed.
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	dyn.PrependReactor("list", "apiservices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when the apiservices list fails")
	}
}

package apiserviceguard

import (
	"context"
	"errors"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders (asg-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

// asgObj builds an APIService unstructured — svcNs/svcName "" renders
// no spec.service at all (the local, non-Service-backed shape).
func asgObj(name, svcNs, svcName string) *unstructured.Unstructured {
	u := testutil.Unstructured(
		apiServiceGVR.GroupVersion().WithKind("APIService"), "", name, nil)
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

// asgDynFake registers APIServiceList (the module's own list) AND
// PlanList — the unblock healer's maintenance mutex lists autopilot
// Plans through the same dyn client, and the fake panics on a List
// whose list kind is not registered.
func asgDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
}

func asgExists(t *testing.T, dyn *dynamicfake.FakeDynamicClient, name string) bool {
	t.Helper()
	_, err := dyn.Resource(apiServiceGVR).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

// asgUnblockCS seeds the unblock-sweep fixture: the protected
// namespace, the Terminating namespace naming `group` (stuck for
// nsAge), and the APIService backend Service plus one Pod per
// podNames entry — every identity an explicit parameter so each
// test shows which object it varies. The clientset emulates the
// pods/eviction contract because the unblock heal evicts through
// policy/v1 (a bare fake records the eviction CREATE without
// deleting the pod).
func asgUnblockCS(ns, group, svcName, svcShort string, nsAge time.Duration, podNames ...string) *fake.Clientset {
	objs := []runtime.Object{
		testutil.Namespace(ns),
		asgStuckNS("dying-ns", nsAge, group),
		asgBackendSvc(ns, svcName, svcShort),
	}
	for _, name := range podNames {
		objs = append(objs, asgBackendPod(ns, name, svcShort))
	}
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	return cs
}

func asgGuard(cs *fake.Clientset, dyn *dynamicfake.FakeDynamicClient) *apiServiceGuard {
	return &apiServiceGuard{cs: cs, dyn: dyn, now: time.Now}
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

	testutil.CleanupMetric(t, metrics.APIServiceUnavailable, "v1beta1.metrics.k8s.io", "kube-system", "metrics-server")

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
// (c) namespace-terminating-wedged — dead-APIService unblocker
// ---------------------------------------------------------------------------

// asgStuckNS builds a namespace stuck in Terminating for `age`,
// carrying one NamespaceContentRemaining condition whose message
// references `groupRef` as a standalone quoted token. The reference
// MUST carry a token boundary (quote/space, not "apiservices."+group)
// because the wedge matcher only accepts whole-token matches since
// the substring false-positive incident — a dot-joined full-name
// reference would never wedge-match, and the fixture must model
// evidence the matcher genuinely fires on.
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
				Message: "some resources are remaining: \"" + groupRef + "\" cannot be deleted",
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
	cs := asgUnblockCS("kube-system", "metrics.k8s.io", "metrics-server", "metrics-server", 20*time.Minute, "ms-0", "ms-1")
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
// The APIService is only 20m dead — under the apiservice-standalone-unblock 30m standalone
// bar — so neither path can fire.
func TestAPIServiceGuardUnblockYoungTerminatingSkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 20*time.Minute)
	cs := asgUnblockCS("kube-system", "metrics.k8s.io", "metrics-server", "metrics-server", 5*time.Minute, "ms-0")
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("backing pod deleted although the namespace only just started terminating")
	}
}

// apiservice-standalone-unblock standalone unblock: a protected-namespace APIService dead
// >=30m gets its backing pods restarted even with NO namespace
// stuck Terminating — the KEDA/cert-manager/prometheus-operator
// adapter deadlock signature.
func TestAPIServiceGuardUnblockStandaloneRestarts(t *testing.T) {
	apiSvc := asgObj("v1beta1.external.metrics.k8s.io", "keda",
		"keda-operator")
	asgUnavailable(apiSvc, 45*time.Minute)
	cs := fake.NewSimpleClientset(
		testutil.Namespace("keda"),
		asgBackendSvc("keda", "keda-operator", "keda-operator"),
		asgBackendPod("keda", "keda-operator-0", "keda-operator"))
	emulateEviction(cs) // the heal evicts through policy/v1
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if asgPodExists(t, cs, "keda", "keda-operator-0") {
		t.Fatal("standalone-unblock: backing pod not restarted")
	}
	if !asgExists(t, dyn, "v1beta1.external.metrics.k8s.io") {
		t.Fatal("APIService object itself deleted — only pods should restart")
	}
}

// The standalone bar is 30m: a protected APIService dead only 20m
// with no Terminating namespace must NOT be restarted.
func TestAPIServiceGuardUnblockStandaloneTooYoungSkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.external.metrics.k8s.io", "keda",
		"keda-operator")
	asgUnavailable(apiSvc, 20*time.Minute)
	cs := fake.NewSimpleClientset(
		testutil.Namespace("keda"),
		asgBackendSvc("keda", "keda-operator", "keda-operator"),
		asgBackendPod("keda", "keda-operator-0", "keda-operator"))
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "keda", "keda-operator-0") {
		t.Fatal("backing pod deleted below the 30m standalone bar")
	}
}

// A Terminating namespace referencing a DIFFERENT API group does
// not unblock this APIService. The APIService is 20m dead — above
// the 15m wedge-evidence bar but below the 30m standalone bar — so
// neither heal path can fire and the wrong-group corpus is the only
// thing under test.
func TestAPIServiceGuardUnblockWrongGroupSkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 20*time.Minute)
	cs := asgUnblockCS("kube-system", "other.example.com", "metrics-server", "metrics-server", 20*time.Minute, "ms-0")
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("backing pod deleted for an unrelated API group")
	}
}

// apiservice-standalone-unblock fallback: a Terminating namespace wedged on an UNRELATED
// API group must not mask the standalone unblock — the dead
// APIService still gets its backing pods restarted once it crosses
// the 30m standalone bar, under the standalone cooldown ledger.
func TestAPIServiceGuardUnblockStandaloneFallbackOnUnrelatedWedge(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 45*time.Minute)
	cs := asgUnblockCS("kube-system", "other.example.com", "metrics-server", "metrics-server", 20*time.Minute, "ms-0")
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if asgPodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("unrelated wedged namespace masked the standalone unblock")
	}
	if _, stamped := g.unblockHealer.standaloneUnblocked.Last("v1beta1.metrics.k8s.io"); !stamped {
		t.Fatal("standalone unblock did not stamp its own cooldown ledger")
	}
	if _, stamped := g.unblockHealer.unblocked.Last("v1beta1.metrics.k8s.io"); stamped {
		t.Fatal("wedge-evidence ledger stamped without wedge evidence")
	}
}

// apiservice-standalone-unblock: KEDA installs via OLM into the "operators" namespace —
// v1beta1.external.metrics.k8s.io's spec.service.namespace is
// "operators", not "keda". The protected-namespace set must cover
// it or the standalone unblock filters the candidate out.
func TestAPIServiceGuardUnblockOperatorsNamespace(t *testing.T) {
	apiSvc := asgObj("v1beta1.external.metrics.k8s.io", "operators",
		"keda-operator-metrics-apiserver")
	asgUnavailable(apiSvc, 45*time.Minute)
	cs := fake.NewSimpleClientset(
		testutil.Namespace("operators"),
		asgBackendSvc("operators", "keda-operator-metrics-apiserver", "keda-operator-metrics-apiserver"),
		asgBackendPod("operators", "keda-metrics-apiserver-0", "keda-operator-metrics-apiserver"))
	emulateEviction(cs) // the heal evicts through policy/v1
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if asgPodExists(t, cs, "operators", "keda-metrics-apiserver-0") {
		t.Fatal("operators-backed APIService skipped — namespace not protected")
	}
}

// The unblock healer is scoped to the protected-namespace set: a
// broken APIService backed in a regular namespace gets the metric
// only — no pod restarts.
func TestAPIServiceGuardUnblockNonProtectedSkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.custom.example.com", "custom-ns", "custom-apiserver")
	asgUnavailable(apiSvc, 30*time.Minute)
	cs := asgUnblockCS("custom-ns", "custom.example.com", "custom-apiserver", "custom", 20*time.Minute, "custom-0")
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
	cs := asgUnblockCS("kube-system", "metrics.k8s.io", "metrics-server", "metrics-server", 20*time.Minute, "ms-0")
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

// The unblock cooldown ledger prunes on EVERY cycle — including the
// apiservices-list-failure cycles that return before any heal: an API
// flap must not keep a decommissioned APIService's expired stamp (and
// its 15m suppression semantics with it) pinned forever.
func TestAPIServiceGuardUnblockCooldownPrunesOnListError(t *testing.T) {
	g := asgGuard(fake.NewSimpleClientset(), asgDynFake())
	u := &unblockHealer{}
	const key = "v1alpha1.dead.example.com"
	t0 := time.Now().Add(-apiServiceUnblockCooldown - time.Minute)
	u.unblocked.Stamp(key, t0)
	snap := &apiServiceSnapshot{g: g, err: errors.New("list apiservices boom")}
	if err := u.sweepUnblock(context.Background(), snap); err == nil {
		t.Fatal("expected the apiservices list error to surface")
	}
	// CooledDown judged AT a point inside the (now-gone) stamp's window:
	// true only if the expired stamp survived the prune.
	if u.unblocked.CooledDown(key, apiServiceUnblockCooldown, t0.Add(30*time.Second)) {
		t.Fatal("expired unblock stamp survived the error cycle — ledger not pruned")
	}
}

// A backing pod already terminating is not a restart target: its
// replacement carries the fix at admission, and a second delete buys
// nothing but still burns a heal-budget grant. When EVERY backing pod
// is terminating the heal is skipped before the heal preamble runs at
// all — no cooldown stamp, no budget grant.
func TestAPIServiceGuardUnblockTerminatingPodsSkipped(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 30*time.Minute)
	objs := []runtime.Object{
		testutil.Namespace("kube-system"),
		asgStuckNS("dying-ns", 20*time.Minute, "metrics.k8s.io"),
		asgBackendSvc("kube-system", "metrics-server", "metrics-server"),
	}
	term := asgBackendPod("kube-system", "ms-term", "metrics-server")
	termTime := metav1.NewTime(time.Now().Add(-time.Minute))
	term.DeletionTimestamp = &termTime
	objs = append(objs, term)
	cs := fake.NewSimpleClientset(objs...)
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-term") {
		t.Fatal("terminating backing pod deleted — must be skipped as a target")
	}
	if _, stamped := g.unblockHealer.unblocked.Last("v1beta1.metrics.k8s.io"); stamped {
		t.Fatal("cooldown stamped although no live target existed — heal preamble must not have run")
	}
}

// Mixed backing pods: the terminating one survives, the live one is
// restarted, and the delivered heal stamps the cooldown.
func TestAPIServiceGuardUnblockDeletesOnlyLivePods(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 30*time.Minute)
	term := asgBackendPod("kube-system", "ms-term", "metrics-server")
	termTime := metav1.NewTime(time.Now().Add(-time.Minute))
	term.DeletionTimestamp = &termTime
	cs := fake.NewSimpleClientset(
		testutil.Namespace("kube-system"),
		asgStuckNS("dying-ns", 20*time.Minute, "metrics.k8s.io"),
		asgBackendSvc("kube-system", "metrics-server", "metrics-server"),
		term,
		asgBackendPod("kube-system", "ms-live", "metrics-server"),
	)
	emulateEviction(cs) // the heal evicts through policy/v1
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-term") {
		t.Fatal("terminating backing pod deleted — must be skipped as a target")
	}
	if asgPodExists(t, cs, "kube-system", "ms-live") {
		t.Fatal("live backing pod not restarted")
	}
	if _, stamped := g.unblockHealer.unblocked.Last("v1beta1.metrics.k8s.io"); !stamped {
		t.Fatal("delivered heal did not stamp the cooldown")
	}
}

// ---------------------------------------------------------------------------
// (d) wedge-evidence matching + PDB-respecting eviction
// ---------------------------------------------------------------------------

// corpusHasToken's whole-token rule, unit-pinned: a dot-joined longer
// name must not match the candidate group inside it; a quoted,
// space-delimited or corpus-leading group must.
func TestCorpusHasTokenBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		corpus string
		want   bool
	}{
		{"full APIService name does not match the group inside it",
			"some resources are remaining: apiservices.v1beta1.metrics.k8s.io cannot be deleted",
			false},
		{"stale webhook event naming a different full name",
			`failed calling webhook "v1beta1.metrics.k8s.io": timed out`,
			false},
		{"quoted bare group matches",
			`failed calling webhook "metrics.k8s.io": timed out`,
			true},
		{"space-delimited group matches",
			"discovery of group metrics.k8s.io failed",
			true},
		{"group at corpus start matches",
			"metrics.k8s.io content remaining",
			true},
		{"unrelated corpus",
			"other.example.com content remaining",
			false},
	} {
		if got := corpusHasToken(tc.corpus, "metrics.k8s.io"); got != tc.want {
			t.Fatalf("%s: corpusHasToken = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The incident: a stale event naming the FULL APIService name
// (v1beta1.metrics.k8s.io) substring-matched the candidate GROUP
// (metrics.k8s.io) under plain strings.Contains and restarted up to
// 10 healthy metric-adapter pods off an unrelated webhooks incident.
// The matcher now requires whole-token references — the dot before
// "metrics" is not a boundary — so the wedge evidence cannot fire,
// and the candidate is only 20m dead (under the 30m standalone bar)
// so nothing else can kill the pod either.
func TestAPIServiceGuardUnblockFullNameReferenceNoMatch(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 20*time.Minute)
	// The stuck namespace's corpus names the full APIService name —
	// the exact false-positive shape.
	cs := asgUnblockCS("kube-system", "v1beta1.metrics.k8s.io",
		"metrics-server", "metrics-server", 20*time.Minute, "ms-0")
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("full-name corpus reference matched the candidate group — pod restarted off stale evidence")
	}
	if _, stamped := g.unblockHealer.unblocked.Last("v1beta1.metrics.k8s.io"); stamped {
		t.Fatal("wedge ledger stamped without whole-token evidence")
	}
}

// A covering PDB with disruptionsAllowed==0 refuses the eviction
// (HTTP 429) — a DEFERRAL, not a failure: the backing pod stays,
// nothing is metered (no IncError) and the wedge cooldown is NOT
// stamped (a refusal must not open the 15m suppression window for a
// heal that never happened).
func TestAPIServiceGuardUnblockPDBRefusalDefers(t *testing.T) {
	apiSvc := asgObj("v1beta1.metrics.k8s.io", "kube-system", "metrics-server")
	asgUnavailable(apiSvc, 30*time.Minute)
	cs := asgUnblockCS("kube-system", "metrics.k8s.io",
		"metrics-server", "metrics-server", 20*time.Minute, "ms-0")
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, apierrors.NewTooManyRequests(
				"pdb allows no disruptions", 0)
		})
	dyn := asgDynFake(apiSvc)
	g := asgGuard(cs, dyn)
	g.queue = "apiservice-guard" // the IncError label the assertion reads

	before := testutil.QueueErrorCount(t, "apiservice-guard")
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !asgPodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("PDB-refused backing pod was evicted anyway")
	}
	if _, stamped := g.unblockHealer.unblocked.Last("v1beta1.metrics.k8s.io"); stamped {
		t.Fatal("PDB refusal stamped the wedge cooldown — deferral must not open the window")
	}
	if got := testutil.QueueErrorCount(t, "apiservice-guard") - before; got != 0 {
		t.Fatalf("PDB refusal metered as an error: delta = %v, want 0", got)
	}
}

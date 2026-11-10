// namespace_terminating_wedged_test.go — coverage for the
// namespace-terminating-wedged check (namespace-terminating-wedged) and the dead-owner
// finalizer sweep.
package nodehealth

import (
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// namespace-terminating-wedged — namespace-terminating-wedged
// ---------------------------------------------------------------------------

// nsStuckDiagnostic — the why-string format pins the exact template:
// name(terminatingFor=Xm,conditions=[...],finalizers=[...]), duration
// truncated to whole minutes, empty lists render [], order preserved.
func TestNsStuckDiagnostic(t *testing.T) {
	now := time.Now()
	build := func(name string, termAge time.Duration,
		conds []corev1.NamespaceCondition, fins []corev1.FinalizerName) *corev1.Namespace {
		return &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:              name,
				DeletionTimestamp: &metav1.Time{Time: now.Add(-termAge)},
			},
			Spec:   corev1.NamespaceSpec{Finalizers: fins},
			Status: corev1.NamespaceStatus{Conditions: conds},
		}
	}
	t.Run("exact format, minutes truncated, order preserved", func(t *testing.T) {
		ns := build("dead-app", 25*time.Minute+40*time.Second,
			[]corev1.NamespaceCondition{
				{Type: corev1.NamespaceDeletionContentFailure, Status: corev1.ConditionTrue},
				{Type: corev1.NamespaceContentRemaining, Status: corev1.ConditionTrue},
			},
			[]corev1.FinalizerName{"kubernetes", "example.com/fx"})
		want := "dead-app(terminatingFor=25m0s,conditions=[" +
			"NamespaceDeletionContentFailure=True,NamespaceContentRemaining=True]," +
			"finalizers=[kubernetes,example.com/fx])"
		if got := nsStuckDiagnostic(ns, now); got != want {
			t.Fatalf("nsStuckDiagnostic =\n%q\nwant\n%q", got, want)
		}
	})
	t.Run("empty lists render []", func(t *testing.T) {
		ns := build("bare", 2*time.Minute, nil, nil)
		if got, want := nsStuckDiagnostic(ns, now),
			"bare(terminatingFor=2m0s,conditions=[],finalizers=[])"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

// protectedFinalizer — the never-strip list: the foreground-deletion
// marker, every kubernetes.io/ finalizer, the external-attacher/
// family; anything else (including the bare "kubernetes.io" prefix
// without the slash) is strippable.
func TestProtectedFinalizer(t *testing.T) {
	cases := []struct {
		f    string
		want bool
	}{
		{"foregroundDeletion", true},
		{"kubernetes.io/pvc-protection", true},
		{"kubernetes.io/pv-protection", true},
		{"external-attacher/csi-driver", true},
		{"example.com/x", false},
		{"kubernetes.io", false}, // HasPrefix("kubernetes.io/") — bare prefix, no slash, not protected
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.f, func(t *testing.T) {
			if got := protectedFinalizer(tc.f); got != tc.want {
				t.Fatalf("protectedFinalizer(%q) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

func TestNamespaceTerminatingWedged(t *testing.T) {
	now := time.Now()
	wedged := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "dead-app",
			DeletionTimestamp: &metav1.Time{Time: now.Add(-25 * time.Minute)},
		},
		Spec: corev1.NamespaceSpec{
			Finalizers: []corev1.FinalizerName{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{
			Phase: corev1.NamespaceTerminating,
			Conditions: []corev1.NamespaceCondition{{
				Type:   corev1.NamespaceContentRemaining,
				Status: corev1.ConditionTrue,
			}},
		},
	}
	fresh := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "fresh-app",
			DeletionTimestamp: &metav1.Time{Time: now.Add(-2 * time.Minute)},
		},
	}
	cs := fake.NewSimpleClientset(wedged, fresh)
	p := testProber(cs)

	res := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("wedged namespace must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "dead-app") ||
		!strings.Contains(res.Why, "NamespaceContentRemaining") {
		t.Fatalf("why missing namespace diagnostics: %q", res.Why)
	}
	if strings.Contains(res.Why, "fresh-app") {
		t.Fatalf("fresh terminating namespace must not be flagged: %q", res.Why)
	}
	if m := probetest.FindMetric(t, "node_automation_namespace_terminating_wedged",
		map[string]string{"namespace": "dead-app"}); m == nil {
		t.Fatal("wedged gauge absent")
	}
}

// maybeStripFinalizers exercises the finalizer sweep's strip path
// directly: a terminating CR owned by a Deployment that no longer
// exists gets its non-protected finalizer removed while
// kubernetes.io/* finalizers stay.
func TestMaybeStripFinalizersDeadOwner(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata": map[string]any{
			"namespace":         "dead-ns",
			"name":              "foo-1",
			"resourceVersion":   "100",
			"finalizers":        []any{"example.com/finalizer", "kubernetes.io/pvc-protection"},
			"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
			"ownerReferences": []any{map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"name":       "gone-deploy",
				"controller": true,
				"uid":        "uid-gone",
			}},
		},
	}}
	cs := fake.NewSimpleClientset() // owner Deployment absent
	kinds := testutil.DynListKinds()
	kinds[gvr] = "FooList" // runtime-discovered CR — outside the table
	dyn := testutil.NewFakeDyn(kinds, obj)
	p := testProberDyn(cs, dyn)

	if !probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).maybeStripFinalizers(ctx, logr.Discard(), gvr, obj) {
		t.Fatal("dead-owner CR should be stripped")
	}
	got, err := dyn.Resource(gvr).Namespace("dead-ns").Get(ctx, "foo-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fins := got.GetFinalizers()
	if len(fins) != 1 || fins[0] != "kubernetes.io/pvc-protection" {
		t.Fatalf("finalizers after strip = %v, want only kubernetes.io/pvc-protection", fins)
	}
}

// A ReplicaSet-owned CR whose controller Rollout (argoproj.io, argo-rollout-gates)
// is gone is the same GC-pending garbage — the Rollout existence
// check rides the dynamic client.
func TestMaybeStripFinalizersDeadRolloutOwner(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "dead-ns", Name: "foo-rs",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout",
				Name: "gone-rollout", UID: "uid-ro", Controller: ptr.To(true),
			}},
		},
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata": map[string]any{
			"namespace":         "dead-ns",
			"name":              "foo-ro",
			"resourceVersion":   "100",
			"finalizers":        []any{"example.com/finalizer"},
			"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
			"ownerReferences": []any{map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "ReplicaSet",
				"name":       "foo-rs",
				"controller": true,
				"uid":        "uid-rs",
			}},
		},
	}}
	cs := fake.NewSimpleClientset(rs)
	kinds := testutil.DynListKinds()
	kinds[gvr] = "FooList"
	kinds[kube.GVRArgoRollout] = "RolloutList"
	dyn := testutil.NewFakeDyn(kinds, obj) // Rollout absent → dead owner
	p := testProberDyn(cs, dyn)

	if !probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).maybeStripFinalizers(ctx, logr.Discard(), gvr, obj) {
		t.Fatal("dead-Rollout-owner CR should be stripped")
	}
	got, err := dyn.Resource(gvr).Namespace("dead-ns").Get(ctx, "foo-ro", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetFinalizers()) != 0 {
		t.Fatalf("finalizers after strip = %v, want none", got.GetFinalizers())
	}
}

// A live Rollout owner must keep the CR — the same fail-closed
// posture as the live Deployment chain.
func TestMaybeStripFinalizersLiveRolloutOwnerSkipped(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "dead-ns", Name: "foo-rs",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout",
				Name: "live-rollout", UID: "uid-ro", Controller: ptr.To(true),
			}},
		},
	}
	ro := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata":   map[string]any{"namespace": "dead-ns", "name": "live-rollout"},
	}}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata": map[string]any{
			"namespace":         "dead-ns",
			"name":              "foo-ro-live",
			"resourceVersion":   "100",
			"finalizers":        []any{"example.com/finalizer"},
			"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
			"ownerReferences": []any{map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "ReplicaSet",
				"name":       "foo-rs",
				"controller": true,
				"uid":        "uid-rs",
			}},
		},
	}}
	cs := fake.NewSimpleClientset(rs)
	kinds := testutil.DynListKinds()
	kinds[gvr] = "FooList"
	kinds[kube.GVRArgoRollout] = "RolloutList"
	dyn := testutil.NewFakeDyn(kinds, obj, ro)
	p := testProberDyn(cs, dyn)

	if probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).maybeStripFinalizers(ctx, logr.Discard(), gvr, obj) {
		t.Fatal("live-Rollout-owner CR must not be stripped")
	}
	got, _ := dyn.Resource(gvr).Namespace("dead-ns").Get(ctx, "foo-ro-live", metav1.GetOptions{})
	if len(got.GetFinalizers()) != 1 {
		t.Fatalf("finalizers = %v, want untouched", got.GetFinalizers())
	}
}

func TestMaybeStripFinalizersLiveOwnerSkipped(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	dep := bareDeployment("dead-ns", "live-deploy")
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata": map[string]any{
			"namespace":         "dead-ns",
			"name":              "foo-2",
			"resourceVersion":   "100",
			"finalizers":        []any{"example.com/finalizer"},
			"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
			"ownerReferences": []any{map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"name":       "live-deploy",
				"controller": true,
			}},
		},
	}}
	cs := fake.NewSimpleClientset(dep)
	kinds := testutil.DynListKinds()
	kinds[gvr] = "FooList" // runtime-discovered CR — outside the table
	dyn := testutil.NewFakeDyn(kinds, obj)
	p := testProberDyn(cs, dyn)

	if probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).maybeStripFinalizers(ctx, logr.Discard(), gvr, obj) {
		t.Fatal("live-owner CR must not be stripped")
	}
	got, _ := dyn.Resource(gvr).Namespace("dead-ns").Get(ctx, "foo-2", metav1.GetOptions{})
	if len(got.GetFinalizers()) != 1 {
		t.Fatalf("finalizers = %v, want untouched", got.GetFinalizers())
	}
}

func TestMaybeStripFinalizersProtectedOnly(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "foos"}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata": map[string]any{
			"namespace":         "dead-ns",
			"name":              "foo-3",
			"resourceVersion":   "100",
			"finalizers":        []any{"kubernetes.io/pvc-protection", "foregroundDeletion"},
			"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}}
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		gvr: "FooList",
	}, obj)
	p := testProberDyn(cs, dyn)

	if probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).maybeStripFinalizers(ctx, logr.Discard(), gvr, obj) {
		t.Fatal("protected-only finalizers must never be stripped")
	}
}

// bareDeployment builds a bare Deployment — the live-owner fixture
// for the finalizer-sweep tests.
func bareDeployment(ns, name string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
}

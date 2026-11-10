// namespace_terminating_wedged_test.go — coverage for the
// namespace-terminating-wedged check (namespace-terminating-wedged) and the dead-owner
// finalizer sweep.
package nodehealth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
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

// ---------------------------------------------------------------------------
// nsFinalizerSweep — the discovery-driven dead-owner sweep
// ---------------------------------------------------------------------------

// sweepDiscovery stubs DiscoveryInterface.ServerPreferredResources —
// the fake clientset's implementation returns nil unconditionally,
// so the sweep's resource census needs this seam. Every other method
// is unreachable from the sweep (embedded nil interface).
type sweepDiscovery struct {
	discovery.DiscoveryInterfaces
	lists []*metav1.APIResourceList
	err   error
}

func (d sweepDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return d.lists, d.err
}

// sweepClientset wraps the fake clientset with a stubbed discovery —
// kubernetes.Interface is embedded so every typed call still lands
// on the tracker; only Discovery() is shadowed.
type sweepClientset struct {
	kubernetes.Interface
	disc discovery.DiscoveryInterfaces
}

func (c sweepClientset) Discovery() discovery.DiscoveryInterfaces { return c.disc }

// nsWedged builds a Namespace Terminating for termAge.
func nsWedged(name string, termAge time.Duration) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			DeletionTimestamp: &metav1.Time{Time: time.Now().Add(-termAge)},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}
}

// fooGVR is the runtime-discovered CR the sweep census reads —
// deliberately outside DynListKinds' table so each test registers
// exactly the GVRs it serves.
var fooGVR = schema.GroupVersionResource{
	Group: "example.com", Version: "v1", Resource: "foos"}

// bazGVR is advertised by the discovery census but its LIST always
// fails — the "no permission / absent — not evidence" continue.
var bazGVR = schema.GroupVersionResource{
	Group: "example.com", Version: "v1", Resource: "bazs"}

// nsSweepDyn builds the dynamic fake serving the sweep census:
// FooList for fooGVR plus a BazList whose every LIST errors — the
// "no permission / absent — not evidence" continue (registered so
// the fake does not panic on the unlisted GVR, erroring via reactor
// instead).
func nsSweepDyn(objs ...runtime.Object) dynamic.Interface {
	kinds := testutil.DynListKinds()
	kinds[fooGVR] = "FooList"
	kinds[bazGVR] = "BazList"
	dyn := testutil.NewFakeDyn(kinds, objs...)
	dyn.PrependReactor("list", "bazs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("bazs not served")
		})
	return dyn
}

// sweepFoo builds a terminating Foo CR in ns carrying finalizers
// and an ownerRef to the named controller kind ("" = no owner).
func sweepFoo(ns, name string, fins []string,
	ownerKind, ownerName string) *unstructured.Unstructured {

	md := map[string]any{
		"namespace":         ns,
		"name":              name,
		"resourceVersion":   "100",
		"deletionTimestamp": time.Now().UTC().Format(time.RFC3339),
	}
	if len(fins) > 0 {
		anyFins := make([]any, len(fins))
		for i, f := range fins {
			anyFins[i] = f
		}
		md["finalizers"] = anyFins
	}
	if ownerKind != "" {
		md["ownerReferences"] = []any{map[string]any{
			"apiVersion": "apps/v1",
			"kind":       ownerKind,
			"name":       ownerName,
			"controller": true,
			"uid":        "uid-" + ownerName,
		}}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata":   md,
	}}
}

// nsSweepLists builds the discovery census the sweep walks: a nil
// entry, an unparseable GroupVersion, a namespaced+subresource pair
// on example.com/v1, a cluster-scoped resource, a list-only resource
// (no patch verb) and a GVR the dynamic fake does not serve.
func nsSweepLists() []*metav1.APIResourceList {
	return []*metav1.APIResourceList{
		nil,                              // skipped outright
		{GroupVersion: "bogus-no-slash"}, // ParseGroupVersion fails
		{
			GroupVersion: "example.com/v1",
			APIResources: []metav1.APIResource{
				{Name: "foos", Namespaced: true, Kind: "Foo",
					Verbs: metav1.Verbs{"get", "list", "patch", "watch"}},
				{Name: "foos/status", Namespaced: true, Kind: "Foo",
					Verbs: metav1.Verbs{"get", "patch"}}, // subresource
				{Name: "bars", Namespaced: true, Kind: "Bar",
					Verbs: metav1.Verbs{"get", "list"}}, // no patch verb
				{Name: "bazs", Namespaced: true, Kind: "Baz",
					Verbs: metav1.Verbs{"get", "list", "patch"}}, // unserved by dyn
				{Name: "clusters", Namespaced: false, Kind: "Cluster",
					Verbs: metav1.Verbs{"get", "list", "patch"}}, // cluster-scoped
			},
		},
	}
}

// The full sweep through Run: a wedged namespace triggers the
// discovery census; the dead-Deployment-owned Foo loses its
// strippable finalizer while protected finalizers stay, and every
// skip branch (wrong namespace, not terminating, no finalizers,
// live owner) leaves its object untouched.
func TestNsFinalizerSweepEndToEnd(t *testing.T) {
	wedged := nsWedged("dead-app", 25*time.Minute)
	cs := fake.NewSimpleClientset(wedged, nsWedged("live-app", time.Minute),
		bareDeployment("dead-app", "live-deploy"))

	dead := sweepFoo("dead-app", "foo-dead",
		[]string{"example.com/finalizer", "kubernetes.io/pvc-protection"},
		"Deployment", "gone-deploy")
	otherNS := sweepFoo("live-app", "foo-other",
		[]string{"example.com/finalizer"}, "Deployment", "gone-deploy")
	alive := sweepFoo("dead-app", "foo-alive",
		[]string{"example.com/finalizer"}, "Deployment", "gone-deploy")
	alive.SetDeletionTimestamp(nil) // not terminating
	noFin := sweepFoo("dead-app", "foo-nofin", nil, "", "")
	liveOwner := sweepFoo("dead-app", "foo-live",
		[]string{"example.com/finalizer"}, "Deployment", "live-deploy")

	dyn := nsSweepDyn(dead, otherNS, alive, noFin, liveOwner)

	scs := sweepClientset{Interface: cs,
		disc: sweepDiscovery{lists: nsSweepLists()}}
	p := probetest.NewCheckProber(scs, dyn, harnessChecks...)

	res := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("wedged namespace must FAIL")
	}
	gvr := fooGVR
	got, err := dyn.Resource(gvr).Namespace("dead-app").
		Get(ctx, "foo-dead", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fins := got.GetFinalizers()
	if len(fins) != 1 || fins[0] != "kubernetes.io/pvc-protection" {
		t.Fatalf("foo-dead finalizers = %v, want only the protected one", fins)
	}
	for _, name := range []string{"foo-other", "foo-alive", "foo-nofin", "foo-live"} {
		var ns string
		if name == "foo-other" {
			ns = "live-app"
		} else {
			ns = "dead-app"
		}
		g, err := dyn.Resource(gvr).Namespace(ns).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if name == "foo-nofin" {
			want = 0
		}
		if len(g.GetFinalizers()) != want {
			t.Fatalf("%s finalizers = %v, want %d", name, g.GetFinalizers(), want)
		}
	}
}

// The 30m per-namespace cooldown throttles the sweep: a stamped
// finalsweep key leaves every finalizer untouched on the next Run.
func TestNsFinalizerSweepCooldown(t *testing.T) {
	wedged := nsWedged("dead-app", 25*time.Minute)
	cs := fake.NewSimpleClientset(wedged)
	dead := sweepFoo("dead-app", "foo-dead",
		[]string{"example.com/finalizer"}, "Deployment", "gone-deploy")
	dyn := nsSweepDyn(dead)
	scs := sweepClientset{Interface: cs,
		disc: sweepDiscovery{lists: nsSweepLists()}}
	p := probetest.NewCheckProber(scs, dyn, harnessChecks...)
	chk := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p)
	chk.Heals.Stamp(
		probefw.SelfHealKey(CheckNameNamespaceWedged, "finalsweep/dead-app"),
		time.Now())

	if res := chk.Run(ctx); res.Pass {
		t.Fatal("wedged namespace must FAIL even inside the sweep cooldown")
	}
	got, err := dyn.Resource(fooGVR).Namespace("dead-app").
		Get(ctx, "foo-dead", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetFinalizers()) != 1 {
		t.Fatalf("cooldown must defer the strip, finalizers = %v",
			got.GetFinalizers())
	}
}

// A full discovery failure skips the sweep entirely — detection
// already FAILed the check, and "cannot enumerate" is not evidence
// any owner is dead.
func TestNsFinalizerSweepDiscoveryFails(t *testing.T) {
	wedged := nsWedged("dead-app", 25*time.Minute)
	cs := fake.NewSimpleClientset(wedged)
	dead := sweepFoo("dead-app", "foo-dead",
		[]string{"example.com/finalizer"}, "Deployment", "gone-deploy")
	dyn := nsSweepDyn(dead)
	scs := sweepClientset{Interface: cs,
		disc: sweepDiscovery{err: errors.New("discovery down")}}
	p := probetest.NewCheckProber(scs, dyn, harnessChecks...)

	if res := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).
		Run(ctx); res.Pass {
		t.Fatal("wedged namespace must FAIL")
	}
	got, err := dyn.Resource(fooGVR).Namespace("dead-app").
		Get(ctx, "foo-dead", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetFinalizers()) != 1 {
		t.Fatalf("discovery failure must skip the sweep, finalizers = %v",
			got.GetFinalizers())
	}
}

// ErrGroupDiscoveryFailed with resolvable groups still sweeps the
// returned lists — an aggregated APIService outage (often the one
// living in THIS terminating namespace) must not paralyze the
// sweep behind an unrelated backend's failure.
func TestNsFinalizerSweepPartialDiscovery(t *testing.T) {
	wedged := nsWedged("dead-app", 25*time.Minute)
	cs := fake.NewSimpleClientset(wedged)
	dead := sweepFoo("dead-app", "foo-dead",
		[]string{"example.com/finalizer"}, "Deployment", "gone-deploy")
	dyn := nsSweepDyn(dead)
	scs := sweepClientset{Interface: cs, disc: sweepDiscovery{
		lists: nsSweepLists(),
		err: &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
			{Group: "broken.example.com", Version: "v1"}: errors.New("apiservice down"),
		}},
	}}
	p := probetest.NewCheckProber(scs, dyn, harnessChecks...)

	if res := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).
		Run(ctx); res.Pass {
		t.Fatal("wedged namespace must FAIL")
	}
	got, err := dyn.Resource(fooGVR).Namespace("dead-app").
		Get(ctx, "foo-dead", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetFinalizers()) != 0 {
		t.Fatalf("partial discovery must still sweep, finalizers = %v",
			got.GetFinalizers())
	}
}

// The 20-strip cap bounds one sweep's blast radius — the 21st
// dead-owner CR keeps its finalizers for the next throttled pass.
func TestNsFinalizerSweepStripCap(t *testing.T) {
	wedged := nsWedged("dead-app", 25*time.Minute)
	cs := fake.NewSimpleClientset(wedged)
	var objs []runtime.Object
	for i := 0; i < nsFinalizerMaxStrips+1; i++ {
		objs = append(objs, sweepFoo("dead-app",
			fmt.Sprintf("foo-%02d", i),
			[]string{"example.com/finalizer"},
			"Deployment", "gone-deploy"))
	}
	dyn := nsSweepDyn(objs...)
	scs := sweepClientset{Interface: cs,
		disc: sweepDiscovery{lists: nsSweepLists()}}
	p := probetest.NewCheckProber(scs, dyn, harnessChecks...)

	if res := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t, p).
		Run(ctx); res.Pass {
		t.Fatal("wedged namespace must FAIL")
	}
	list, err := dyn.Resource(fooGVR).Namespace("dead-app").
		List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stripped, kept := 0, 0
	for i := range list.Items {
		if len(list.Items[i].GetFinalizers()) == 0 {
			stripped++
		} else {
			kept++
		}
	}
	if stripped != nsFinalizerMaxStrips || kept != 1 {
		t.Fatalf("strip cap: %d stripped, %d kept — want %d/1",
			stripped, kept, nsFinalizerMaxStrips)
	}
}

// A nil dynamic client skips the sweep quietly — the wedged
// namespace still FAILs detection, but no census runs.
func TestNsFinalizerSweepNilDyn(t *testing.T) {
	wedged := nsWedged("dead-app", 25*time.Minute)
	cs := fake.NewSimpleClientset(wedged)
	deps := probetest.NewDeps(cs, nil)
	chk := &namespaceTerminatingWedgedCheck{Deps: deps}
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("wedged namespace must FAIL with nil dyn")
	}
}

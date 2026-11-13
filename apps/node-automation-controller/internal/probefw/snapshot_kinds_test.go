// snapshot_kinds_test.go — the extended snapshot censuses: every
// per-resource-kind read (Events/PVCs/StatefulSets/Deployments/
// DaemonSets/unstructured-per-GVR) memoizes ONCE per sweep and
// shares its error with every later caller; InvalidateNodes drops the
// node census AND forces the next AllNodes past the informer cache;
// InvalidateEndpointSlices drops only the slice census. The
// concurrency claim behind the per-kind mutexes is exercised with a
// parallel same-kind reader burst — under -race this is the regression
// for double-LIST / torn-triple memoizes.
package probefw

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

// testUnstructured builds an unstructured seed object for the dynamic
// fake (testhelp.Unstructured with a bare ObjectMeta).
func testUnstructured(gvk schema.GroupVersionKind, ns, name string) *unstructured.Unstructured {
	return testhelp.Unstructured(gvk, ns, name, nil)
}

// countListReactor counts LISTs of one resource on the fake clientset
// and still lets the default tracker serve the objects.
func countListReactor(cs *fake.Clientset, resource string, count *int) {
	cs.PrependReactor("list", resource,
		func(ktesting.Action) (bool, runtime.Object, error) {
			*count++
			return false, nil, nil
		})
}

// sweepOver fixtures for the typed census tests: one object per kind,
// a LIST counter per kind, and the ctx the sweep installed.
type kindCounters struct {
	ctx    context.Context
	d      *Deps
	events int
	pvcs   int
	sts    int
	deps   int
	ds     int
}

func newKindCounters(t *testing.T) *kindCounters {
	t.Helper()
	cs := fake.NewSimpleClientset(
		&corev1.Event{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "ev-1"}, Reason: "ScalingReplicaSet"},
		&corev1.Event{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "ev-2"}, Reason: "Failed"},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "data-1"}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "db"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "web"}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "node-agent"}})
	k := &kindCounters{d: &Deps{CS: cs}}
	countListReactor(cs, "events", &k.events)
	countListReactor(cs, "persistentvolumeclaims", &k.pvcs)
	countListReactor(cs, "statefulsets", &k.sts)
	countListReactor(cs, "deployments", &k.deps)
	countListReactor(cs, "daemonsets", &k.ds)
	k.ctx = WithSweepSnapshot(t.Context())
	return k
}

// Every new census kind memoizes once per sweep: the second All* call
// is served by the snapshot, not a second LIST. EventsWithReason rides
// the same events LIST — the filter is client-side and re-runs free.
func TestSnapshotMemoizesOncePerKind(t *testing.T) {
	k := newKindCounters(t)

	if _, err := k.d.AllEvents(k.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.AllPVCs(k.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.AllStatefulSets(k.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.AllDeployments(k.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.AllDaemonSets(k.ctx); err != nil {
		t.Fatal(err)
	}
	// Reason filter — one match out of the two fixture events.
	failed, err := k.d.EventsWithReason(k.ctx, "Failed")
	if err != nil {
		t.Fatal(err)
	}
	if len(failed) != 1 || failed[0].Name != "ev-2" {
		t.Fatalf("EventsWithReason(Failed) = %v, want ev-2", failed)
	}

	if _, err := k.d.AllEvents(k.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.EventsWithReason(k.ctx, "ScalingReplicaSet"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.AllPVCs(k.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.AllStatefulSets(k.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.AllDeployments(k.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.d.AllDaemonSets(k.ctx); err != nil {
		t.Fatal(err)
	}

	if k.events != 1 || k.pvcs != 1 || k.sts != 1 || k.deps != 1 || k.ds != 1 {
		t.Fatalf("lists events=%d pvcs=%d sts=%d deps=%d ds=%d — "+
			"every kind must memoize to ONE LIST per sweep "+
			"(EventsWithReason included)", k.events, k.pvcs, k.sts,
			k.deps, k.ds)
	}
}

// A transient apiserver failure memoizes with its kind: the SECOND
// caller reads the same error with NO second LIST — the snapshot's
// shared-error contract, now covering the extended kinds.
func TestSnapshotMemoizesErrorPerKind(t *testing.T) {
	cs := fake.NewSimpleClientset()
	boom := errors.New("apiserver wedged")
	for _, resource := range []string{"events", "persistentvolumeclaims"} {
		cs.PrependReactor("list", resource,
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, boom
			})
	}
	d := &Deps{CS: cs}
	ctx := WithSweepSnapshot(t.Context())

	_, err1 := d.AllEvents(ctx)
	_, err2 := d.AllEvents(ctx)
	if !errors.Is(err1, boom) || !errors.Is(err2, boom) || err1 != err2 {
		t.Fatalf("event errors %v/%v — second call must read the memoized error", err1, err2)
	}
	_, err1 = d.AllPVCs(ctx)
	_, err2 = d.AllPVCs(ctx)
	if !errors.Is(err1, boom) || err1 != err2 {
		t.Fatalf("pvc errors %v/%v — second call must read the memoized error", err1, err2)
	}
	var eventLists int
	countListReactor(cs, "events", &eventLists)
	if eventLists != 0 {
		t.Fatalf("memoized error kinds re-LISTed (%d extra)", eventLists)
	}
}

// InvalidateNodes: the node census drops AND the next AllNodes bypasses
// the informer cache — a node patched milliseconds ago must not be
// re-read in its pre-patch shape from the lagging cache. One direct
// read re-arms the memo; nothing reads the cache or the API again.
func TestInvalidateNodesForcesCSRead(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w1"}})
	var nodeLists int
	countListReactor(cs, "nodes", &nodeLists)
	reader := &countingNodeReader{nodes: []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "w1"}}}}
	d := &Deps{CS: cs, NodeReader: reader}
	ctx := WithSweepSnapshot(t.Context())

	// First read goes through the informer cache reader — the normal
	// sweep posture.
	if _, err := d.AllNodes(ctx); err != nil {
		t.Fatal(err)
	}
	if reader.lists != 1 || nodeLists != 0 {
		t.Fatalf("first read: cache lists=%d cs lists=%d, want cache=1 cs=0",
			reader.lists, nodeLists)
	}

	// A node patch lands; InvalidateNodes must drop the memo and arm
	// the direct read.
	d.InvalidateNodes(ctx)
	nodes, err := d.AllNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if nodeLists != 1 || reader.lists != 1 {
		t.Fatalf("post-invalidate: cs lists=%d cache lists=%d — "+
			"the re-read must hit d.CS directly, not the just-patched cache",
			nodeLists, reader.lists)
	}
	if len(nodes) != 1 || nodes[0].Name != "w1" {
		t.Fatalf("re-read census = %v", nodes)
	}

	// The direct read re-armed the memo: later checks pay nothing.
	if _, err := d.AllNodes(ctx); err != nil {
		t.Fatal(err)
	}
	if nodeLists != 1 || reader.lists != 1 {
		t.Fatalf("third read: cs lists=%d cache lists=%d — memo must serve it",
			nodeLists, reader.lists)
	}

	// The node-derived join (NodeZones) drops WITH the census: after
	// an invalidate the next NodeZones must NOT serve the pre-patch
	// map — it rebuilds by triggering the forced direct re-read.
	zones, err := d.NodeZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := zones["w1"]; !ok {
		t.Fatalf("NodeZones = %v — must cover the fresh census", zones)
	}
	if nodeLists != 1 {
		t.Fatalf("node lists=%d — the first join build rides the already-memoized census", nodeLists)
	}
	d.InvalidateNodes(ctx)
	if _, err := d.NodeZones(ctx); err != nil {
		t.Fatal(err)
	}
	if nodeLists != 2 {
		t.Fatalf("node lists=%d — the join rebuild must ride the forced direct re-read, not the stale map", nodeLists)
	}

	// Sibling kinds keep their memoized reads.
	var sliceLists int
	countListReactor(cs, "endpointslices", &sliceLists)
	d.InvalidateNodes(ctx)
	if _, err := d.AllNodes(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllEndpointSlices(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllEndpointSlices(ctx); err != nil {
		t.Fatal(err)
	}
	if sliceLists != 1 {
		t.Fatalf("slice lists=%d — a node invalidate must not drop the slice census", sliceLists)
	}
}

// InvalidateEndpointSlices drops only the slice census: the re-list
// happens, and the sibling kinds (services) stay memoized.
func TestInvalidateEndpointSlices(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "web-abc"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "web"}})
	var sliceLists, svcLists int
	countListReactor(cs, "endpointslices", &sliceLists)
	countListReactor(cs, "services", &svcLists)
	d := &Deps{CS: cs}
	ctx := WithSweepSnapshot(t.Context())

	if _, err := d.AllEndpointSlices(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllServices(ctx); err != nil {
		t.Fatal(err)
	}
	d.InvalidateEndpointSlices(ctx)
	slices, err := d.AllEndpointSlices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(slices) != 1 || slices[0].Name != "web-abc" {
		t.Fatalf("re-listed slices = %v", slices)
	}
	if _, err := d.AllServices(ctx); err != nil {
		t.Fatal(err)
	}
	if sliceLists != 2 || svcLists != 1 {
		t.Fatalf("lists slices=%d services=%d, want 2/1 — "+
			"the slice invalidate must not drop the service census",
			sliceLists, svcLists)
	}
}

// AllUnstructured memoizes per (sweep, GVR) — two GVRs list
// independently, the same GVR twice does not re-LIST, and a nil Dyn
// surfaces as a memoized error.
func TestSnapshotMemoizesDynamicReads(t *testing.T) {
	crdGVR := testhelp.CRDGVR
	scyllaGVR := schema.GroupVersionResource{
		Group: "scylla.scylladb.com", Version: "v1", Resource: "scyllaclusters"}
	fluxGVR := schema.GroupVersionResource{
		Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}

	crd := testUnstructured(crdGVR.GroupVersion().WithKind("CustomResourceDefinition"), "", "scyllaclusters.scylla.scylladb.com")
	scylla := testUnstructured(scyllaGVR.GroupVersion().WithKind("ScyllaCluster"), "data", "s1")
	hr := testUnstructured(fluxGVR.GroupVersion().WithKind("HelmRelease"), "flux-system", "web")

	dyn := testhelp.NewDynamicClient(crd, scylla, hr)
	var crdLists, scyllaLists, fluxLists int
	dyn.PrependReactor("list", crdGVR.Resource,
		func(ktesting.Action) (bool, runtime.Object, error) { crdLists++; return false, nil, nil })
	dyn.PrependReactor("list", scyllaGVR.Resource,
		func(ktesting.Action) (bool, runtime.Object, error) { scyllaLists++; return false, nil, nil })
	dyn.PrependReactor("list", fluxGVR.Resource,
		func(ktesting.Action) (bool, runtime.Object, error) { fluxLists++; return false, nil, nil })

	d := &Deps{CS: fake.NewSimpleClientset(), Dyn: dyn}
	ctx := WithSweepSnapshot(t.Context())

	crdList, err := d.AllUnstructured(ctx, crdGVR)
	if err != nil {
		t.Fatal(err)
	}
	if len(crdList) != 1 || crdList[0].GetName() != "scyllaclusters.scylla.scylladb.com" {
		t.Fatalf("AllUnstructured(crd) = %v", crdList)
	}
	s1, err := d.AllUnstructured(ctx, scyllaGVR)
	if err != nil {
		t.Fatal(err)
	}
	f1, err := d.AllUnstructured(ctx, fluxGVR)
	if err != nil {
		t.Fatal(err)
	}
	// Second calls — same GVR — must be memoized.
	if _, err := d.AllUnstructured(ctx, crdGVR); err != nil {
		t.Fatal(err)
	}
	s2, err := d.AllUnstructured(ctx, scyllaGVR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllUnstructured(ctx, fluxGVR); err != nil {
		t.Fatal(err)
	}
	if crdLists != 1 || scyllaLists != 1 || fluxLists != 1 {
		t.Fatalf("dyn lists crds=%d scylla=%d flux=%d — per-GVR memoization broken",
			crdLists, scyllaLists, fluxLists)
	}
	if len(s1) != 1 || len(s2) != 1 || s1[0].GetName() != "s1" || len(f1) != 1 {
		t.Fatalf("unstructured reads s1=%v s2=%v f1=%v", s1, s2, f1)
	}
}

// A nil Dyn is a wiring bug surfaced as an error — and memoized like
// every snapshot failure, so all CRD-reading checks read ONE failure.
func TestSnapshotNilDynErrors(t *testing.T) {
	d := &Deps{CS: fake.NewSimpleClientset()}
	ctx := WithSweepSnapshot(t.Context())
	if _, err := d.AllUnstructured(ctx, schema.GroupVersionResource{Resource: "plans"}); err == nil {
		t.Fatal("AllUnstructured with nil Dyn must error")
	}
}

// Parallel same-kind readers must serialize on ONE LIST under the
// per-kind mutex — the memoize-once contract the worker pools depend
// on (run with -race).
func TestSnapshotParallelSameKindReadsMemoizeOnce(t *testing.T) {
	k := newKindCounters(t)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			events, err := k.d.AllEvents(k.ctx)
			errs[i] = err
			if err == nil && len(events) != 2 {
				errs[i] = fmt.Errorf("reader %d got %d events, want 2", i, len(events))
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if k.events != 1 {
		t.Fatalf("parallel readers issued %d event LISTs, want 1", k.events)
	}
}

// countingNodeReader records how often the informer-cache path read —
// the observable difference between ListNodesCached and the direct
// ListNodes InvalidateNodes forces.
type countingNodeReader struct {
	nodes []corev1.Node
	lists int
}

func (r *countingNodeReader) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	r.lists++
	nl := list.(*corev1.NodeList)
	nl.Items = append([]corev1.Node(nil), r.nodes...)
	return nil
}

// AllUnstructuredFirst is the multi-served-version census: candidates
// try in order through the same per-GVR memoizer — a NotFound/NoMatch
// GVR is "not served" and falls through to the next, the first
// success wins, and a REAL failure is preferred over benign misses
// when nothing lists (the caller tells "CRD absent" from "API
// broken" off the returned error).
func TestAllUnstructuredFirst(t *testing.T) {
	hrV2 := schema.GroupVersionResource{
		Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}
	hrV2beta2 := schema.GroupVersionResource{
		Group: "helm.toolkit.fluxcd.io", Version: "v2beta2", Resource: "helmreleases"}

	newDeps := func(t *testing.T, objs ...runtime.Object) (*Deps, *int) {
		t.Helper()
		dyn := testhelp.NewDynamicClient(objs...)
		lists := new(int)
		dyn.PrependReactor("list", "helmreleases",
			func(a ktesting.Action) (bool, runtime.Object, error) {
				*lists++
				return false, nil, nil
			})
		return &Deps{CS: fake.NewSimpleClientset(), Dyn: dyn}, lists
	}

	hr := testUnstructured(hrV2.GroupVersion().WithKind("HelmRelease"),
		"flux-system", "web")

	t.Run("first serving GVR wins", func(t *testing.T) {
		d, lists := newDeps(t, hr)
		items, gvr, err := d.AllUnstructuredFirst(
			WithSweepSnapshot(t.Context()), []schema.GroupVersionResource{hrV2, hrV2beta2})
		if err != nil {
			t.Fatal(err)
		}
		if gvr != hrV2 || len(items) != 1 || items[0].GetName() != "web" {
			t.Fatalf("AllUnstructuredFirst = gvr %v items %v, want v2/web", gvr, items)
		}
		if *lists != 1 {
			t.Fatalf("helmrelease lists = %d, want 1 — v2beta2 must not be probed", *lists)
		}
	})

	t.Run("NotFound falls through to the next version", func(t *testing.T) {
		d, _ := newDeps(t, hr)
		// v2beta2 not served on this cluster — the v1beta1-style
		// upgrade shape the fallback exists for. The version-aware
		// reactor sits in FRONT of the shared counter, so count the
		// per-version attempts here.
		attempts := map[string]int{}
		real := d.Dyn.(*dynamicfake.FakeDynamicClient)
		real.PrependReactor("list", "helmreleases",
			func(a ktesting.Action) (bool, runtime.Object, error) {
				attempts[a.GetResource().Version]++
				if a.GetResource().Version == "v2beta2" {
					return true, nil, apierrors.NewNotFound(
						schema.GroupResource{Group: "helm.toolkit.fluxcd.io",
							Resource: "helmreleases"}, "")
				}
				return false, nil, nil
			})
		items, gvr, err := d.AllUnstructuredFirst(
			WithSweepSnapshot(t.Context()), []schema.GroupVersionResource{hrV2beta2, hrV2})
		if err != nil {
			t.Fatal(err)
		}
		if gvr != hrV2 || len(items) != 1 {
			t.Fatalf("fallback = gvr %v items %v, want v2", gvr, items)
		}
		if attempts["v2beta2"] != 1 || attempts["v2"] != 1 {
			t.Fatalf("per-version list attempts = %v, want one each", attempts)
		}
	})

	t.Run("all versions absent surfaces the benign error", func(t *testing.T) {
		d, _ := newDeps(t)
		real := d.Dyn.(*dynamicfake.FakeDynamicClient)
		real.PrependReactor("list", "helmreleases",
			func(a ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewNotFound(
					schema.GroupResource{Group: "helm.toolkit.fluxcd.io",
						Resource: "helmreleases"}, "")
			})
		_, _, err := d.AllUnstructuredFirst(
			WithSweepSnapshot(t.Context()), []schema.GroupVersionResource{hrV2beta2, hrV2})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("all-absent error = %v, want NotFound", err)
		}
	})

	t.Run("a real failure beats benign misses", func(t *testing.T) {
		d, _ := newDeps(t)
		real := d.Dyn.(*dynamicfake.FakeDynamicClient)
		real.PrependReactor("list", "helmreleases",
			func(a ktesting.Action) (bool, runtime.Object, error) {
				switch a.GetResource().Version {
				case "v2beta2":
					return true, nil, apierrors.NewNotFound(
						schema.GroupResource{Group: "helm.toolkit.fluxcd.io",
							Resource: "helmreleases"}, "")
				default:
					return true, nil, errors.New("apiserver blew up")
				}
			})
		_, _, err := d.AllUnstructuredFirst(
			WithSweepSnapshot(t.Context()), []schema.GroupVersionResource{hrV2beta2, hrV2})
		if err == nil || apierrors.IsNotFound(err) {
			t.Fatalf("mixed-failure error = %v, want the real (non-NotFound) error", err)
		}
	})
}

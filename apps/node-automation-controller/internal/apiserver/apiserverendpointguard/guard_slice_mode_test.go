// guard_slice_mode_test.go — the >=v1.33 EndpointSlice SSOT path and
// the hosted mirror-slice discovery regressions.
package apiserverendpointguard

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	discoveryv1client "k8s.io/client-go/kubernetes/typed/discovery/v1"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Same guard on the EndpointSlice SSOT: a Ready=false slice endpoint
// is probed (and could be pulled) but never counts as a healthy peer.
func TestEndpointGuardSliceModeNotReadyPeerCountsAsNoPeer(t *testing.T) {
	eps := kubeEndpointSlice([]string{"10.0.0.1"})
	down := false
	eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
		Addresses:  []string{"10.0.0.2"},
		Conditions: discoveryv1.EndpointConditions{Ready: &down},
	})
	cs := fake.NewSimpleClientset(eps)
	dyn := testutil.NewDynamicClient()
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for range endpointGuardErrCycles {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := getKubeSlice(t, cs)
	if !sliceAddrSet(got)["10.0.0.1"] {
		t.Fatal("last Ready slice endpoint quarantined on a Ready=false peer's health")
	}
	if got.Annotations[endpointGuardAnno] != "" {
		t.Fatalf("annotation = %q, want empty", got.Annotations[endpointGuardAnno])
	}
}

// sliceIPs dedupes/sorts all endpoint addresses including Ready=false.
func TestEndpointGuardSliceIPs(t *testing.T) {
	eps := kubeEndpointSlice([]string{"10.0.0.3", "10.0.0.1"})
	notReady := false
	eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
		Addresses:  []string{"10.0.0.2"},
		Conditions: discoveryv1.EndpointConditions{Ready: &notReady},
	})
	// A second endpoint repeating an IP must dedupe.
	eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
		Addresses: []string{"10.0.0.1"},
	})
	got := sliceIPs(eps)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sliceIPs = %v, want %v", got, want)
	}
}

// >=v1.33: the wedge verdict lands on the EndpointSlice — IP removed,
// annotation recorded — while corev1 Endpoints is never even read.
func TestEndpointGuardSliceModeQuarantine(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for range endpointGuardErrCycles {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	eps := getKubeSlice(t, cs)
	if sliceAddrSet(eps)["10.0.0.1"] {
		t.Fatal("wedged IP still in EndpointSlice")
	}
	if eps.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("slice annotation = %q, want 10.0.0.1",
			eps.Annotations[endpointGuardAnno])
	}
	// The deprecated object must stay untouched — no reads, no writes.
	if acts := actionResources(dyn)["endpoints"]; acts != 0 {
		t.Fatalf("%d endpoints actions on the slice path, want 0", acts)
	}
	ep := getKubeEndpoints(t, dyn)
	if !endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("Endpoints object was mutated on the slice path")
	}
}

// A quarantined slice backend the reconciler still lists (its address
// stayed in the slice while the annotation held) probing healthy for 2
// cycles is dropped from its annotation — the re-add gate requires the
// IP to remain in the slice's endpoint set, since an absent quarantined
// IP is never re-added on streak alone (decommissioned-backend fix).
func TestEndpointGuardSliceModeReaddsRecovered(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeSliceWithQuarantine([]string{"10.0.0.2", "10.0.0.1"}, []string{"10.0.0.1"}))
	dyn := testutil.NewDynamicClient()
	fakeServerVersion(cs, "1", "34")
	probes := probeTable{
		"10.0.0.1": apiHealthyProbe(1000),
		"10.0.0.2": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, dyn, probes)

	// Cycle 1: okStreak = 1 (< 2) -> re-listed quarantined 10.0.0.1 is pulled
	// back out of the slice while the quarantine annotation holds.
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	eps := getKubeSlice(t, cs)
	if sliceAddrSet(eps)["10.0.0.1"] {
		t.Fatalf("re-listed quarantined backend left in slice before recovery: %v", sliceAddrSet(eps))
	}
	if eps.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation dropped early: %q", eps.Annotations[endpointGuardAnno])
	}

	// Simulate the apiserver endpoint reconciler re-listing 10.0.0.1
	// before Cycle 2 reaches endpointGuardRecoverCyc (2).
	eps = eps.DeepCopy()
	ready := true
	eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
		Addresses:  []string{"10.0.0.1"},
		Conditions: discoveryv1.EndpointConditions{Ready: &ready},
	})
	if _, err := cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
		Update(ctx, eps, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	eps = getKubeSlice(t, cs)
	if !sliceAddrSet(eps)["10.0.0.1"] {
		t.Fatalf("recovered backend not re-added to slice: %v", sliceAddrSet(eps))
	}
	if _, ok := eps.Annotations[endpointGuardAnno]; ok {
		t.Fatalf("annotation left after recovery: %q",
			eps.Annotations[endpointGuardAnno])
	}
}

// Neither endpoints object existing fails the cycle — a missing slice
// alone falls back to Endpoints instead (below).
func TestEndpointGuardSliceModeMissingSlice(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient()
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, dyn, probeTable{})
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when neither endpoints object exists")
	}
}

// On >=v1.33 a missing slice drops back to the Endpoints path rather
// than dead-looping — the deprecated object is still writable there.
func TestEndpointGuardSliceModeFallsBackToEndpoints(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for range endpointGuardErrCycles {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("fallback did not run the Endpoints path, annotation = %q",
			ep.GetAnnotations()[endpointGuardAnno])
	}
}

// Slice-path fail-closed: a wedged IP with no healthy peer is never
// pulled — removing it would empty the slice.
func TestEndpointGuardSliceModeKeepsSoleHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeSliceWithQuarantine([]string{"10.0.0.2"}, []string{"10.0.0.1"}))
	dyn := testutil.NewDynamicClient()
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("still down")},
		"10.0.0.2": {err: errors.New("just wedged")},
	})
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sliceAddrSet(getKubeSlice(t, cs)); !got["10.0.0.2"] {
		t.Fatal("sole remaining backend quarantined — slice would be empty")
	}
}

// A slice-update failure is the SSOT write failing — it aborts the
// cycle with an error (unlike the best-effort mirror on the old path).
func TestEndpointGuardSliceModeUpdateError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient()
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	cs.PrependReactor("update", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("update rejected")
		})
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when the EndpointSlice update fails")
	}
}

// ---------------------------------------------------------------------------
// Hosted control planes — the kubernetes slice is a generated-name mirror
// of Endpoints/kubernetes (k0smotron & co.). Regression tests for the
// sweep that hard-failed with `endpointslices "kubernetes" not found`.
// ---------------------------------------------------------------------------

// >=v1.33 hosted plane: the ONLY slice is a generated-name mirror owned
// by the endpointslicemirroring controller. The guard must discover it
// by label and run the Endpoints path — annotation + removal land on
// Endpoints (the mirror's source of truth), the mirror slice converges.
func TestEndpointGuardMirrorSliceEndpointsSSOT(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeMirrorSlice("kubernetes-89b87", []string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	fakeServerVersion(cs, "1", "37")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for range endpointGuardErrCycles {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("wedged IP still in Endpoints")
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation not on the Endpoints SSOT: %q",
			ep.GetAnnotations()[endpointGuardAnno])
	}
	// The mirror slice converges too — the direct write beats the
	// mirror controller's own resync.
	s, err := cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
		Get(ctx, "kubernetes-89b87", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sliceAddrSet(s)["10.0.0.1"] {
		t.Fatal("wedged IP still in the mirror slice")
	}
}

// A generated-name slice that is NOT mirror-managed (exotic hosted
// setup writing slices directly) still runs the slice path on >=1.33 —
// label discovery replaces the fixed-name Get.
func TestEndpointGuardGeneratedNameSliceSSOT(t *testing.T) {
	eps := kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"})
	eps.Name = "kubernetes-xy12z"
	cs := fake.NewSimpleClientset(eps)
	dyn := testutil.NewDynamicClient()
	fakeServerVersion(cs, "1", "34")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for range endpointGuardErrCycles {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got, err := cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
		Get(ctx, "kubernetes-xy12z", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sliceAddrSet(got)["10.0.0.1"] {
		t.Fatal("wedged IP still in the generated-name slice")
	}
	if got.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("slice annotation = %q, want 10.0.0.1",
			got.Annotations[endpointGuardAnno])
	}
}

// Degenerate hosted state: only a mirror slice exists (its owner
// Endpoints already gone). The guard uses what it has — the slice —
// instead of dead-looping on the missing Endpoints.
func TestEndpointGuardSliceOnlyFallback(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeMirrorSlice("kubernetes-89b87", []string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient()
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": apiHealthyProbe(100),
		"10.0.0.2": apiHealthyProbe(100),
	})
	if err := g.run(ctx); err != nil {
		t.Fatalf("slice-only cluster must not error: %v", err)
	}
}

// A mirror slice never becomes the SSOT even on >=1.33 — its edits are
// rebuilt from the Endpoints object on the next mirror reconcile.
func TestEndpointGuardMirrorSliceIgnoredOnNewVersion(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeMirrorSlice("kubernetes-89b87", []string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	fakeServerVersion(cs, "1", "34")
	probed := map[string]int{}
	var probedMu sync.Mutex // probes run in parallel per cycle
	g := &apiServerEndpointGuard{
		cs:  cs,
		dyn: dyn,
		probeFn: func(_ context.Context, ip string) apiProbeResult {
			probedMu.Lock()
			probed[ip]++
			probedMu.Unlock()
			return *apiHealthyProbe(100)
		},
		backends: map[string]*backendProbeState{},
	}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if probed["10.0.0.1"] != 1 || probed["10.0.0.2"] != 1 {
		t.Fatalf("endpoints IPs not probed through the mirror-slice path: %v", probed)
	}
}

func TestEndpointGuardSliceModeRetryOnConflict(t *testing.T) {
	eps := kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"})
	eps.ResourceVersion = "1"
	cs := fake.NewSimpleClientset(eps)
	dyn := testutil.NewDynamicClient()
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for range endpointGuardErrCycles - 1 {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}

	attempts := 0
	cs.PrependReactor("update", "endpointslices",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			attempts++
			if attempts == 1 {
				// Simulate the apiserver endpoint reconciler concurrently
				// adding a 3rd backend and bumping ResourceVersion before retry.
				// Use cs.Tracker().Get directly (calling cs.DiscoveryV1()...Get
				// inside a reactor deadlocks on Fake.Invokes's non-reentrant lock).
				obj, err := cs.Tracker().Get(
					discoveryv1.SchemeGroupVersion.WithResource("endpointslices"),
					endpointGuardNS, eps.Name,
				)
				if err != nil {
					t.Fatalf("tracker get: %v", err)
				}
				cur := obj.(*discoveryv1.EndpointSlice).DeepCopy()
				cur.ResourceVersion = "2"
				ready := true
				cur.Endpoints = append(cur.Endpoints, discoveryv1.Endpoint{
					Addresses:  []string{"10.0.0.3"},
					Conditions: discoveryv1.EndpointConditions{Ready: &ready},
				})
				if err := cs.Tracker().Update(
					discoveryv1.SchemeGroupVersion.WithResource("endpointslices"),
					cur, endpointGuardNS,
				); err != nil {
					t.Fatalf("tracker update: %v", err)
				}
				return true, nil, apierrors.NewConflict(
					schema.GroupResource{Group: "discovery.k8s.io", Resource: "endpointslices"},
					cur.Name, errors.New("resourceVersion mismatch"))
			}
			return false, nil, nil
		})

	if err := g.run(ctx); err != nil {
		t.Fatalf("slice-mode conflict retry failed: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("update attempts = %d, want 2 (initial conflict + retry)", attempts)
	}
	got := getKubeSlice(t, cs)
	addrs := sliceAddrSet(got)
	if addrs["10.0.0.1"] {
		t.Fatal("wedged IP 10.0.0.1 still present after conflict retry")
	}
	if !addrs["10.0.0.2"] || !addrs["10.0.0.3"] {
		t.Fatalf("concurrent/healthy IPs lost after conflict retry: %v", addrs)
	}
	if got.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q, want 10.0.0.1", got.Annotations[endpointGuardAnno])
	}
}

type ssotSliceListRecorder struct {
	kubernetes.Interface
	opts []metav1.ListOptions
}

func (r *ssotSliceListRecorder) DiscoveryV1() discoveryv1client.DiscoveryV1Interface {
	return &recSSOTDiscovery{DiscoveryV1Interface: r.Interface.DiscoveryV1(), r: r}
}

type recSSOTDiscovery struct {
	discoveryv1client.DiscoveryV1Interface
	r *ssotSliceListRecorder
}

func (d *recSSOTDiscovery) EndpointSlices(ns string) discoveryv1client.EndpointSliceInterface {
	return &recSSOTEndpointSlices{EndpointSliceInterface: d.DiscoveryV1Interface.EndpointSlices(ns), r: d.r}
}

type recSSOTEndpointSlices struct {
	discoveryv1client.EndpointSliceInterface
	r *ssotSliceListRecorder
}

func (e *recSSOTEndpointSlices) List(ctx context.Context, opts metav1.ListOptions) (*discoveryv1.EndpointSliceList, error) {
	e.r.opts = append(e.r.opts, opts)
	return e.EndpointSliceInterface.List(ctx, opts)
}

func TestKubernetesSlicesUsesStrongRead(t *testing.T) {
	rec := &ssotSliceListRecorder{Interface: fake.NewSimpleClientset(kubeEndpointSlice([]string{"10.0.0.1"}))}
	g := &apiServerEndpointGuard{cs: rec}
	slices, err := g.kubernetesSlices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(slices) != 1 {
		t.Fatalf("slices = %d, want 1", len(slices))
	}
	if len(rec.opts) != 1 || rec.opts[0].ResourceVersion != "" {
		t.Fatalf("kubernetesSlices ListOptions = %+v, want strong read ResourceVersion=\"\"", rec.opts)
	}
}

package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// apiserver-endpoint-guard
// ---------------------------------------------------------------------------

// kubeEndpoints builds the default/kubernetes Endpoints object the way
// the apiserver's own reconciler writes it: one subset, port 443.
func kubeEndpoints(active, notReady, quarantined []string) *corev1.Endpoints {
	ep := &corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{
		Namespace: endpointGuardNS, Name: endpointGuardName,
		Annotations: map[string]string{},
	}}
	sub := corev1.EndpointSubset{
		Ports: []corev1.EndpointPort{
			{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
		},
	}
	for _, ip := range active {
		sub.Addresses = append(sub.Addresses, corev1.EndpointAddress{IP: ip})
	}
	for _, ip := range notReady {
		sub.NotReadyAddresses = append(sub.NotReadyAddresses,
			corev1.EndpointAddress{IP: ip})
	}
	ep.Subsets = []corev1.EndpointSubset{sub}
	if len(quarantined) > 0 {
		ep.Annotations[endpointGuardAnno] = strings.Join(quarantined, ",")
	}
	return ep
}

// kubeEndpointSlice mirrors the discovery.k8s.io/v1 slice the apiserver
// maintains for the kubernetes service on a self-hosted control plane —
// fixed name, apiserver-managed (not a mirror).
func kubeEndpointSlice(ips []string) *discoveryv1.EndpointSlice {
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: endpointGuardNS, Name: endpointGuardName,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: endpointGuardName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	ready := true
	for _, ip := range ips {
		eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{ip},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		})
	}
	return eps
}

// kubeMirrorSlice builds the generated-name slice the
// endpointslicemirroring controller projects from Endpoints/kubernetes
// on hosted control planes — never the SSOT.
func kubeMirrorSlice(name string, ips []string) *discoveryv1.EndpointSlice {
	eps := kubeEndpointSlice(ips)
	eps.Name = name
	eps.Labels[discoveryv1.LabelManagedBy] = endpointSliceMirrorValue
	owner := true
	eps.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "v1", Kind: "Endpoints", Name: endpointGuardName,
		Controller: &owner,
	}}
	return eps
}

// probeTable is the test seam for g.probeFn — per-IP results the test
// mutates between runs to script multi-cycle wedge/recovery scenarios.
type probeTable map[string]*apiProbeResult

func (pt probeTable) fn(_ context.Context, ip string) apiProbeResult {
	if r, ok := pt[ip]; ok && r != nil {
		return *r
	}
	return apiProbeResult{err: errors.New("no probe result scripted for " + ip)}
}

func newEndpointGuard(cs kubernetes.Interface, probes probeTable) *apiServerEndpointGuard {
	return &apiServerEndpointGuard{
		cs:       cs,
		probeFn:  probes.fn,
		backends: map[string]*backendProbeState{},
	}
}

func getKubeEndpoints(t *testing.T, cs *fake.Clientset) *corev1.Endpoints {
	t.Helper()
	ep, err := cs.CoreV1().Endpoints(endpointGuardNS).
		Get(ctx, endpointGuardName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get endpoints: %v", err)
	}
	return ep
}

func getKubeSlice(t *testing.T, cs *fake.Clientset) *discoveryv1.EndpointSlice {
	t.Helper()
	eps, err := cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
		Get(ctx, endpointGuardName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get endpointslice: %v", err)
	}
	return eps
}

func endpointAddrSet(ep *corev1.Endpoints) map[string]bool {
	set := map[string]bool{}
	for _, sub := range ep.Subsets {
		for _, a := range sub.Addresses {
			set[a.IP] = true
		}
	}
	return set
}

func sliceAddrSet(eps *discoveryv1.EndpointSlice) map[string]bool {
	set := map[string]bool{}
	for _, e := range eps.Endpoints {
		for _, a := range e.Addresses {
			set[a] = true
		}
	}
	return set
}

func apiHealthyProbe(rv int64) *apiProbeResult {
	return &apiProbeResult{liveRV: rv, cacheRV: rv}
}

// A backend holding rv_gap >= threshold for 2 consecutive cycles is
// pulled out of Endpoints AND EndpointSlice and lands in the quarantine
// annotation — the first gapped cycle only arms the streak.
func TestEndpointGuardQuarantineOnRVGap(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}))
	probes := probeTable{
		"10.0.0.1": {liveRV: 1000, cacheRV: 100}, // gap 900 — wedged
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.3": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, probes)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := endpointAddrSet(getKubeEndpoints(t, cs)); !got["10.0.0.1"] {
		t.Fatal("wedged backend removed after a single gapped cycle")
	}

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep := getKubeEndpoints(t, cs)
	if got := endpointAddrSet(ep); got["10.0.0.1"] || !got["10.0.0.2"] || !got["10.0.0.3"] {
		t.Fatalf("wedged backend not quarantined, addresses=%v", got)
	}
	if ann := ep.Annotations[endpointGuardAnno]; ann != "10.0.0.1" {
		t.Fatalf("quarantine annotation = %q, want 10.0.0.1", ann)
	}
	if got := sliceAddrSet(getKubeSlice(t, cs)); got["10.0.0.1"] {
		t.Fatalf("wedged backend still in EndpointSlice: %v", got)
	}
}

// cache_rv frozen for 3 cycles while live_rv keeps advancing is a
// wedge even when the instantaneous gap stays under the threshold.
func TestEndpointGuardQuarantineOnFrozenCache(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	bad := &apiProbeResult{liveRV: 100, cacheRV: 90} // gap 10 < 200
	probes := probeTable{
		"10.0.0.1": bad,
		"10.0.0.2": apiHealthyProbe(100),
	}
	g := newEndpointGuard(cs, probes)

	for cycle := 0; cycle < 3; cycle++ {
		bad.liveRV += 50 // live grows, cache stuck at 90
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
		if endpointAddrSet(getKubeEndpoints(t, cs))["10.0.0.1"] == false {
			t.Fatalf("cycle %d: backend removed before the 3-frozen-cycle latch", cycle)
		}
	}
	bad.liveRV += 50
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if endpointAddrSet(getKubeEndpoints(t, cs))["10.0.0.1"] {
		t.Fatal("frozen-cache backend not quarantined after 3 cycles")
	}
}

// A probe transport error (timeout / 5xx) wedges only after
// endpointGuardErrCycles consecutive failures — a single blip is not
// a verdict.
func TestEndpointGuardQuarantineOnProbeError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("context deadline exceeded")},
		"10.0.0.2": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, probes)
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, cs)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("backend with failed probe kept in endpoints")
	}
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q", ep.Annotations[endpointGuardAnno])
	}
}

// THE guard: with zero healthy backends nothing is ever removed — a
// mass-wedge (or broken probe path) must not empty the endpoint set.
func TestEndpointGuardNeverRemovesLastHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("timeout")},
		"10.0.0.2": {err: errors.New("timeout")},
	}
	g := newEndpointGuard(cs, probes)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep := getKubeEndpoints(t, cs)
	if got := endpointAddrSet(ep); !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("endpoints emptied during mass-wedge: %v", got)
	}
	if ep.Annotations[endpointGuardAnno] != "" {
		t.Fatalf("annotation written with nothing quarantined: %q",
			ep.Annotations[endpointGuardAnno])
	}
}

// Same guard, asymmetric shape: one backend already quarantined, the
// sole remaining active backend wedges — it must stay (removing it
// would leave zero endpoints).
func TestEndpointGuardKeepsSoleRemainingBackend(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.2"}, nil, []string{"10.0.0.1"}),
		kubeEndpointSlice([]string{"10.0.0.2"}))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("still down")},
		"10.0.0.2": {err: errors.New("just wedged")},
	}
	g := newEndpointGuard(cs, probes)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := endpointAddrSet(getKubeEndpoints(t, cs)); !got["10.0.0.2"] {
		t.Fatal("sole remaining backend was quarantined — endpoints would be empty")
	}
}

// A quarantined IP probing healthy for 2 consecutive cycles is put
// back into both objects and dropped from the annotation.
func TestEndpointGuardReaddsRecoveredBackend(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.2", "10.0.0.3"}, nil, []string{"10.0.0.1"}),
		kubeEndpointSlice([]string{"10.0.0.2", "10.0.0.3"}))
	probes := probeTable{
		"10.0.0.1": apiHealthyProbe(1000),
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.3": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, probes)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep := getKubeEndpoints(t, cs)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("backend re-added after a single healthy cycle")
	}
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation dropped too early: %q", ep.Annotations[endpointGuardAnno])
	}

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep = getKubeEndpoints(t, cs)
	if got := endpointAddrSet(ep); !got["10.0.0.1"] {
		t.Fatalf("recovered backend not re-added, addresses=%v", got)
	}
	if _, ok := ep.Annotations[endpointGuardAnno]; ok {
		t.Fatalf("annotation left behind after full recovery: %q",
			ep.Annotations[endpointGuardAnno])
	}
	if got := sliceAddrSet(getKubeSlice(t, cs)); !got["10.0.0.1"] {
		t.Fatalf("recovered backend not back in EndpointSlice: %v", got)
	}
}

// A quarantined backend that is STILL failing keeps its annotation —
// okStreak resets on every failed cycle and recovery never latches.
func TestEndpointGuardKeepsStillWedgedQuarantine(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.2"}, nil, []string{"10.0.0.1"}),
		kubeEndpointSlice([]string{"10.0.0.2"}))
	probes := probeTable{
		"10.0.0.1": {liveRV: 900, cacheRV: 100}, // gap 800 — still wedged
		"10.0.0.2": apiHealthyProbe(900),
	}
	g := newEndpointGuard(cs, probes)
	for i := 0; i < 3; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, cs)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("still-wedged backend re-added")
	}
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q, want 10.0.0.1 kept", ep.Annotations[endpointGuardAnno])
	}
}

// < 2 controller IPs total (production/cicd single-controller):
// probes and streaks still run, but the objects are never touched.
func TestEndpointGuardSingleControllerNeverEdits(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1"}))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
	}
	g := newEndpointGuard(cs, probes)
	for i := 0; i < 3; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, cs)
	if !endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("single-controller endpoints edited")
	}
	if ep.Annotations[endpointGuardAnno] != "" {
		t.Fatalf("annotation written on a single-controller cluster: %q",
			ep.Annotations[endpointGuardAnno])
	}
}

// A wedged IP parked in notReadyAddresses is a controller IP too —
// quarantine must strip it from BOTH address lists.
func TestEndpointGuardRemovesNotReadyAddress(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.2"}, []string{"10.0.0.1"}, nil),
		kubeEndpointSlice([]string{"10.0.0.2"}))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	}
	g := newEndpointGuard(cs, probes)
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, cs)
	for _, sub := range ep.Subsets {
		for _, a := range sub.NotReadyAddresses {
			if a.IP == "10.0.0.1" {
				t.Fatal("wedged IP still in notReadyAddresses")
			}
		}
	}
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q", ep.Annotations[endpointGuardAnno])
	}
}

// ---------------------------------------------------------------------------
// Pure helper coverage — subset/annotation/union mutations.
// ---------------------------------------------------------------------------

// endpointIPs merges addresses + notReadyAddresses, deduped and sorted.
func TestEndpointIPSet(t *testing.T) {
	ep := kubeEndpoints([]string{"10.0.0.3", "10.0.0.1"}, []string{"10.0.0.2"}, nil)
	// Duplicate the IP across subsets to prove dedupe.
	ep.Subsets = append(ep.Subsets, corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}},
	})
	got := endpointIPs(ep)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("endpointIPs = %v, want %v", got, want)
	}
}

// The quarantine annotation tolerates whitespace and empty segments.
func TestParseQuarantineAnnotation(t *testing.T) {
	ep := kubeEndpoints(nil, nil, nil)
	if got := parseQuarantineAnnotation(ep); len(got) != 0 {
		t.Fatalf("absent annotation = %v", got)
	}
	ep.Annotations[endpointGuardAnno] = ""
	if got := parseQuarantineAnnotation(ep); len(got) != 0 {
		t.Fatalf("empty annotation = %v", got)
	}
	ep.Annotations[endpointGuardAnno] = " 10.0.0.1 , ,10.0.0.2 "
	got := parseQuarantineAnnotation(ep)
	if len(got) != 2 || !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("parseQuarantineAnnotation = %v", got)
	}
}

// writeQuarantineAnnotation writes a sorted join and removes the key
// entirely when the set drains.
func TestWriteQuarantineAnnotation(t *testing.T) {
	ep := kubeEndpoints(nil, nil, nil)
	writeQuarantineAnnotation(ep, map[string]bool{"10.0.0.2": true, "10.0.0.1": true})
	if got := ep.Annotations[endpointGuardAnno]; got != "10.0.0.1,10.0.0.2" {
		t.Fatalf("annotation = %q, want sorted join", got)
	}
	writeQuarantineAnnotation(ep, map[string]bool{})
	if _, ok := ep.Annotations[endpointGuardAnno]; ok {
		t.Fatal("empty quarantine set left the annotation behind")
	}
}

// unionIPs merges active + quarantined sources, deduped and sorted.
func TestUnionIPs(t *testing.T) {
	got := unionIPs([]string{"10.0.0.2", "10.0.0.1"},
		map[string]bool{"10.0.0.3": true, "10.0.0.1": true})
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unionIPs = %v, want %v", got, want)
	}
}

// A subset emptied by the removal is dropped entirely — the object
// must never serialize an empty-addresses subset.
func TestRemoveEndpointIPDropsEmptySubset(t *testing.T) {
	ep := kubeEndpoints([]string{"10.0.0.1"}, nil, nil)
	ep.Subsets = append(ep.Subsets, corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{IP: "10.0.0.2"}},
	})
	removeEndpointIP(ep, "10.0.0.1")
	if len(ep.Subsets) != 1 || ep.Subsets[0].Addresses[0].IP != "10.0.0.2" {
		t.Fatalf("emptied subset not dropped: %+v", ep.Subsets)
	}
}

// addEndpointIP placement: existing -> no-op; empty -> fresh subset on
// :6443; named "https" port wins; otherwise the first subset.
func TestAddEndpointIPPlacement(t *testing.T) {
	// Already present — no-op.
	ep := kubeEndpoints([]string{"10.0.0.1"}, nil, nil)
	addEndpointIP(ep, "10.0.0.1")
	if n := len(ep.Subsets[0].Addresses); n != 1 {
		t.Fatalf("duplicate address appended: %d addresses", n)
	}

	// No subsets at all — a fresh subset is seeded with port 6443/https.
	bare := kubeEndpoints(nil, nil, nil)
	bare.Subsets = nil
	addEndpointIP(bare, "10.0.0.9")
	if len(bare.Subsets) != 1 || len(bare.Subsets[0].Addresses) != 1 ||
		bare.Subsets[0].Addresses[0].IP != "10.0.0.9" {
		t.Fatalf("empty endpoints not re-seeded: %+v", bare.Subsets)
	}
	if p := bare.Subsets[0].Ports[0]; p.Port != 6443 || p.Name != "https" {
		t.Fatalf("seeded subset port = %+v, want 6443/https", p)
	}

	// A subset carrying an "https" port (any number) is the target.
	named := &corev1.Endpoints{Subsets: []corev1.EndpointSubset{
		{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}},
			Ports: []corev1.EndpointPort{{Name: "https", Port: 443}},
		},
		{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.2"}},
			Ports: []corev1.EndpointPort{{Name: "other", Port: 1234}},
		},
	}}
	addEndpointIP(named, "10.0.0.7")
	if n := len(named.Subsets[0].Addresses); n != 2 {
		t.Fatalf("IP not appended to the https subset: %+v", named.Subsets)
	}

	// No https/6443 port anywhere — fall back to subset[0].
	fallback := &corev1.Endpoints{Subsets: []corev1.EndpointSubset{
		{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}},
			Ports: []corev1.EndpointPort{{Name: "dns", Port: 53}},
		},
	}}
	addEndpointIP(fallback, "10.0.0.8")
	if n := len(fallback.Subsets[0].Addresses); n != 2 {
		t.Fatalf("IP not appended to subset[0]: %+v", fallback.Subsets)
	}
}

// removeSliceIP reports whether anything changed; addSliceIP refuses
// duplicates.
func TestSliceIPHelpers(t *testing.T) {
	eps := kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"})

	if removeSliceIP(eps, "10.0.0.9") {
		t.Fatal("removeSliceIP reported a change for an absent IP")
	}
	if !removeSliceIP(eps, "10.0.0.1") {
		t.Fatal("removeSliceIP reported no change for a present IP")
	}
	if got := sliceAddrSet(eps); got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("slice after removal = %v", got)
	}

	if addSliceIP(eps, "10.0.0.2") {
		t.Fatal("addSliceIP duplicated an existing IP")
	}
	if !addSliceIP(eps, "10.0.0.3") {
		t.Fatal("addSliceIP refused a new IP")
	}
	if !sliceAddrSet(eps)["10.0.0.3"] {
		t.Fatal("new IP not appended to the slice")
	}
}

// An endpoint whose only address is removed is dropped from the slice.
func TestRemoveSliceIPDropsEmptyEndpoint(t *testing.T) {
	eps := kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"})
	removeSliceIP(eps, "10.0.0.1")
	if len(eps.Endpoints) != 1 {
		t.Fatalf("emptied endpoint kept in slice: %+v", eps.Endpoints)
	}
}

// ---------------------------------------------------------------------------
// run() fetch guards — the objects it cannot read veto the whole sweep.
// ---------------------------------------------------------------------------

// No default/kubernetes Endpoints object at all -> real error.
func TestEndpointGuardMissingEndpoints(t *testing.T) {
	cs := fake.NewSimpleClientset()
	g := newEndpointGuard(cs, probeTable{})
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when the Endpoints object is missing")
	}
}

// An EndpointSlice list failure is a real error — the guard cannot
// decide the SSOT without knowing which slices exist.
func TestEndpointGuardSliceListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	cs.PrependReactor("list", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": apiHealthyProbe(100),
		"10.0.0.2": apiHealthyProbe(100),
	})
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when the EndpointSlice list fails")
	}
}

// EndpointSlice absent entirely (empty list) is tolerated — the guard
// still sweeps the Endpoints object.
func TestEndpointGuardSliceAbsent(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": apiHealthyProbe(100),
		"10.0.0.2": apiHealthyProbe(100),
	})
	if err := g.run(ctx); err != nil {
		t.Fatalf("missing EndpointSlice must not veto the run: %v", err)
	}
}

// Zero controller IPs (empty subsets) -> clean no-op, probes skipped.
func TestEndpointGuardNoControllerIPs(t *testing.T) {
	cs := fake.NewSimpleClientset(kubeEndpoints(nil, nil, nil))
	g := newEndpointGuard(cs, probeTable{}) // any probe call would error
	if err := g.run(ctx); err != nil {
		t.Fatalf("empty controller set must be a no-op: %v", err)
	}
}

// Backend streak state for an IP that left the controller set is
// pruned (and its metric series forgotten) — otherwise a removed
// backend's streak could resurface as stale evidence on re-add.
func TestEndpointGuardPrunesDepartedBackend(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": apiHealthyProbe(100),
		"10.0.0.2": apiHealthyProbe(100),
	})
	g.backends["10.9.9.9"] = &backendProbeState{} // departed controller

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.backends["10.9.9.9"]; ok {
		t.Fatal("streak state for departed backend not pruned")
	}
}

// A wedged backend while ZERO other backends are healthy this cycle
// gets SKIP-QUARANTINE — removing it could leave the Service with no
// routable apiserver at all.
func TestEndpointGuardSkipsQuarantineWithNoHealthyPeer(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("dead")},
		// gapped but under the 2-cycle latch: not wedged AND not
		// healthy — healthyActive stays 0 while 10.0.0.1 wedges.
		"10.0.0.2": {liveRV: 1000, cacheRV: 100},
	}
	g := newEndpointGuard(cs, probes)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep := getKubeEndpoints(t, cs)
	if got := endpointAddrSet(ep); !got["10.0.0.1"] {
		t.Fatalf("backend quarantined with no healthy peer, addresses=%v", got)
	}
	if ep.Annotations[endpointGuardAnno] != "" {
		t.Fatalf("annotation = %q, want empty", ep.Annotations[endpointGuardAnno])
	}
}

// An Endpoints object carrying no annotations at all must still take
// the quarantine annotation — the guard initializes the map instead
// of failing the mutation.
func TestEndpointGuardQuarantinesAnnotationlessEndpoints(t *testing.T) {
	ep := kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil)
	ep.Annotations = nil
	cs := fake.NewSimpleClientset(ep)
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep = getKubeEndpoints(t, cs)
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q, want 10.0.0.1", ep.Annotations[endpointGuardAnno])
	}
}

// The Endpoints update is the SSOT write — its failure aborts the
// sweep so the EndpointSlice can never converge ahead of it.
func TestEndpointGuardEndpointsUpdateError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	cs.PrependReactor("update", "endpoints",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("update rejected")
		})
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when the Endpoints update fails")
	}
}

// A failed EndpointSlice update is logged/metered but NOT returned —
// Endpoints already persisted the verdict and the next cycle
// re-applies the slice diff.
func TestEndpointGuardSliceUpdateErrorTolerated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	cs.PrependReactor("update", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("slice update rejected")
		})
	if err := g.run(ctx); err != nil {
		t.Fatalf("slice update failure must not fail the run: %v", err)
	}
	// Endpoints still converged — the slice retries next cycle.
	ep := getKubeEndpoints(t, cs)
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q", ep.Annotations[endpointGuardAnno])
	}
}

// probe() with no usable transport fails closed (apiProbeResult.err) —
// transport() already covers the InClusterConfig error, this covers
// the probe() early-return on it.
func TestEndpointGuardProbeNoTransport(t *testing.T) {
	g := &apiServerEndpointGuard{}
	if res := g.probe(ctx, "10.0.0.1"); res.err == nil {
		t.Fatal("probe succeeded without any transport")
	}
}

// Start must survive a failing sweep (metered, loop continues) AND
// switch cadence on the quarantine flag: cycle 1 errors with the flag
// pre-armed -> 10s quarantine interval -> cycle 2 succeeds and resets
// to 30s. Real-timer bound: ~40s (the 30s first tick is the code
// under test — the fake's action log is the sync point, not a sleep).
func TestEndpointGuardStartCycles(t *testing.T) {
	cs := fake.NewSimpleClientset() // no Endpoints -> first sweep errors
	// probed receives each backend IP the sweep probes — a probe call
	// is the deterministic sync point for "run() got past the
	// fetch/decide stage" where quarantineActive is (re)assigned; the
	// clientset action count alone can't prove the sweep finished.
	probed := make(chan string, 8)
	g := &apiServerEndpointGuard{
		cs: cs,
		probeFn: func(_ context.Context, ip string) apiProbeResult {
			probed <- ip
			return *apiHealthyProbe(1)
		},
		backends: map[string]*backendProbeState{},
		log:      logr.Discard(),
		// Pre-arm the quarantine cadence so the 10s re-tick is
		// exercised after the erroring sweep.
		quarantineActive: true,
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Start(cctx) }()

	waitActions := func(want int) bool {
		dl := time.Now().Add(endpointGuardInterval + endpointGuardQuarantineInterval + 10*time.Second)
		for time.Now().Before(dl) {
			if len(cs.Actions()) >= want {
				return true
			}
			time.Sleep(25 * time.Millisecond)
		}
		return false
	}

	// Cycle 1 (~30s tick): missing Endpoints -> run errors -> the
	// error is metered/logged and the loop continues on the 10s
	// quarantine cadence.
	if !waitActions(1) {
		t.Fatal("first sweep never ran")
	}
	// Seed a lone-backend Endpoints so the second (10s-cadence) sweep
	// reaches the probe stage — its success clears quarantineActive
	// and resets the interval to 30s (the else branch).
	if _, err := cs.CoreV1().Endpoints(endpointGuardNS).Create(ctx,
		kubeEndpoints([]string{"10.0.0.1"}, nil, nil), metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed endpoints: %v", err)
	}
	select {
	case <-probed:
	case <-time.After(endpointGuardInterval + endpointGuardQuarantineInterval + 10*time.Second):
		t.Fatal("second sweep never ran on the 10s quarantine cadence")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
	// Safe only now: run() writes quarantineActive on the Start
	// goroutine — the done channel gives the happens-before edge.
	if g.quarantineActive {
		t.Fatal("empty controller set left quarantineActive set")
	}
}

// ---------------------------------------------------------------------------
// Endpoint API version gate — >=v1.33 runs the EndpointSlice as SSOT.
// ---------------------------------------------------------------------------

// fakeServerVersion pins the cluster version the guard detects; the
// fake's default (client-go's own v0.0.0-master gitVersion) parses to
// minor 0, which is why every test above exercises the Endpoints path.
func fakeServerVersion(cs *fake.Clientset, major, minor string) {
	cs.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion =
		&version.Info{Major: major, Minor: minor}
}

// kubeSliceWithQuarantine builds the kubernetes EndpointSlice carrying
// the quarantine annotation — the SSOT layout on >=v1.33.
func kubeSliceWithQuarantine(ips, quarantined []string) *discoveryv1.EndpointSlice {
	eps := kubeEndpointSlice(ips)
	if len(quarantined) > 0 {
		eps.Annotations = map[string]string{
			endpointGuardAnno: strings.Join(quarantined, ","),
		}
	}
	return eps
}

// actionResources tallies clientset actions per resource — used to
// prove the slice path never touches corev1 Endpoints.
func actionResources(cs *fake.Clientset) map[string]int {
	out := map[string]int{}
	for _, a := range cs.Actions() {
		out[a.GetResource().Resource]++
	}
	return out
}

// serverMinor parses the fake's pinned version; "33+" (GKE/EKS) and
// GitVersion fallback are the edge cases.
func TestEndpointGuardServerMinor(t *testing.T) {
	cases := []struct {
		name    string
		info    *version.Info
		want    int
		wantErr bool
	}{
		{"plain", &version.Info{Major: "1", Minor: "32"}, 32, false},
		{"new minor", &version.Info{Major: "1", Minor: "33"}, 33, false},
		{"plus suffix", &version.Info{Major: "1", Minor: "33+"}, 33, false},
		{"git fallback", &version.Info{Major: "1", Minor: "", GitVersion: "v1.34.1+k0s.1"}, 34, false},
		{"unparseable", &version.Info{Major: "1", Minor: "", GitVersion: "custom"}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			cs.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = tc.info
			got, err := serverMinor(cs)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("serverMinor(%+v) = %d, want error", tc.info, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("serverMinor(%+v) = %d, %v; want %d", tc.info, got, err, tc.want)
			}
		})
	}
}

// endpointMode caches a successful detection and retries a failed one.
func TestEndpointGuardEndpointModeCache(t *testing.T) {
	calls := 0
	minor := 33
	var fail error
	g := &apiServerEndpointGuard{
		serverMinorFn: func() (int, error) {
			calls++
			return minor, fail
		},
	}
	use, err := g.endpointMode()
	if err != nil || !use {
		t.Fatalf("endpointMode = %v, %v; want true, nil", use, err)
	}
	minor = 20 // flip the source — the cached decision must not move
	use, err = g.endpointMode()
	if err != nil || !use {
		t.Fatalf("cached endpointMode = %v, %v; want true, nil", use, err)
	}
	if calls != 1 {
		t.Fatalf("serverMinorFn called %d times, want 1 (cached)", calls)
	}

	fail = errors.New("discovery down")
	g2 := &apiServerEndpointGuard{
		serverMinorFn: func() (int, error) { calls++; return 0, fail },
	}
	for i := 0; i < 2; i++ {
		if use, err := g2.endpointMode(); use || err == nil {
			t.Fatalf("endpointMode on error = %v, %v; want false, err", use, err)
		}
	}
	if calls != 3 {
		t.Fatalf("detection errors must not be cached, calls = %d", calls)
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
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for i := 0; i < endpointGuardErrCycles; i++ {
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
	if acts := actionResources(cs)["endpoints"]; acts != 0 {
		t.Fatalf("%d endpoints actions on the slice path, want 0", acts)
	}
	ep := getKubeEndpoints(t, cs)
	if !endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("Endpoints object was mutated on the slice path")
	}
}

// A quarantined slice backend probing healthy for 2 cycles is
// re-added to the slice and dropped from its annotation.
func TestEndpointGuardSliceModeReaddsRecovered(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeSliceWithQuarantine([]string{"10.0.0.2"}, []string{"10.0.0.1"}))
	fakeServerVersion(cs, "1", "34")
	probes := probeTable{
		"10.0.0.1": apiHealthyProbe(1000),
		"10.0.0.2": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, probes)
	for i := 0; i < endpointGuardRecoverCyc; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	eps := getKubeSlice(t, cs)
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
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, probeTable{})
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when neither endpoints object exists")
	}
}

// On >=v1.33 a missing slice drops back to the Endpoints path rather
// than dead-looping — the deprecated object is still writable there.
func TestEndpointGuardSliceModeFallsBackToEndpoints(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, cs)
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("fallback did not run the Endpoints path, annotation = %q",
			ep.Annotations[endpointGuardAnno])
	}
}

// Slice-path fail-closed: a wedged IP with no healthy peer is never
// pulled — removing it would empty the slice.
func TestEndpointGuardSliceModeKeepsSoleHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeSliceWithQuarantine([]string{"10.0.0.2"}, []string{"10.0.0.1"}))
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, probeTable{
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
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, probeTable{
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
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeMirrorSlice("kubernetes-89b87", []string{"10.0.0.1", "10.0.0.2"}))
	fakeServerVersion(cs, "1", "37")
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, cs)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("wedged IP still in Endpoints")
	}
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation not on the Endpoints SSOT: %q",
			ep.Annotations[endpointGuardAnno])
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
	fakeServerVersion(cs, "1", "34")
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for i := 0; i < endpointGuardErrCycles; i++ {
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
	g := newEndpointGuard(cs, probeTable{
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
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeMirrorSlice("kubernetes-89b87", []string{"10.0.0.1", "10.0.0.2"}))
	fakeServerVersion(cs, "1", "34")
	probed := map[string]int{}
	g := &apiServerEndpointGuard{
		cs: cs,
		probeFn: func(_ context.Context, ip string) apiProbeResult {
			probed[ip]++
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

// If the reconciler rebuilds the SSOT object and drops the annotation
// mid-incident, the in-memory copy still tracks the quarantined IP —
// it stays probed and quarantineActive stays armed.
func TestEndpointGuardMemQuarantineSurvivesAnnotationLoss(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	probed := map[string]int{}
	probes := probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	}
	g := &apiServerEndpointGuard{
		cs: cs,
		probeFn: func(_ context.Context, ip string) apiProbeResult {
			probed[ip]++
			return probes.fn(context.Background(), ip)
		},
		backends: map[string]*backendProbeState{},
	}
	// +1 cycle: quarantineActive reflects the annotation read at the
	// START of a run, so it only arms on the cycle after the persist.
	for i := 0; i < endpointGuardErrCycles+1; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !g.quarantineActive {
		t.Fatal("quarantine did not arm")
	}
	// Simulate the reconciler rebuilding the object without the
	// annotation (and without re-adding the pulled IP yet).
	ep := getKubeEndpoints(t, cs)
	ep = ep.DeepCopy()
	delete(ep.Annotations, endpointGuardAnno)
	if _, err := cs.CoreV1().Endpoints(endpointGuardNS).
		Update(ctx, ep, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probed = map[string]int{}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !g.quarantineActive {
		t.Fatal("memQuarantine failed to keep the pulled IP tracked")
	}
	if probed["10.0.0.1"] != 1 {
		t.Fatalf("quarantined IP probed %d times, want 1", probed["10.0.0.1"])
	}
	// Still wedged -> the pulled IP stays out of the object.
	if got := endpointAddrSet(getKubeEndpoints(t, cs)); got["10.0.0.1"] {
		t.Fatal("wedged backend back in endpoints while still failing")
	}
}

// endpointMode detection failure falls back to the Endpoints path —
// the sweep still functions on a cluster whose /version is broken.
func TestEndpointGuardVersionUndetectableFallsBack(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil),
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	g := newEndpointGuard(cs, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	g.serverMinorFn = func() (int, error) {
		return 0, errors.New("version endpoint gone")
	}
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, cs)
	if ep.Annotations[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("fallback did not run the Endpoints path, annotation = %q",
			ep.Annotations[endpointGuardAnno])
	}
}

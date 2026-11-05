package apiserverendpointguard

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// apiserver-endpoint-guard
// ---------------------------------------------------------------------------

// kubeEndpoints builds the default/kubernetes Endpoints object the way
// the apiserver's own reconciler writes it: one subset, port 443 —
// unstructured, the shape the dynamic client returns on the wire.
func kubeEndpoints(active, notReady, quarantined []string) *unstructured.Unstructured {
	sub := map[string]any{
		"ports": []any{map[string]any{
			"name": "https", "port": int64(443), "protocol": "TCP"}},
	}
	if len(active) > 0 {
		addrs := make([]any, 0, len(active))
		for _, ip := range active {
			addrs = append(addrs, map[string]any{"ip": ip})
		}
		sub["addresses"] = addrs
	}
	if len(notReady) > 0 {
		nr := make([]any, 0, len(notReady))
		for _, ip := range notReady {
			nr = append(nr, map[string]any{"ip": ip})
		}
		sub["notReadyAddresses"] = nr
	}
	ep := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Endpoints",
		"metadata": map[string]any{
			"namespace": endpointGuardNS, "name": endpointGuardName,
		},
		"subsets": []any{sub},
	}}
	annos := map[string]string{}
	if len(quarantined) > 0 {
		annos[endpointGuardAnno] = strings.Join(quarantined, ",")
	}
	ep.SetAnnotations(annos)
	return ep
}

// subsetAddrs decodes subset[i]'s map-typed list field for assertions.
func subsetAddrs(ep *unstructured.Unstructured, i int, field string) []map[string]any {
	subs := endpointSubsets(ep)
	if i >= len(subs) {
		return nil
	}
	return nestedMaps(subs[i], field)
}

// appendSubset appends a raw subset map to the fixture — the
// unstructured equivalent of ep.Subsets = append(ep.Subsets, ...).
func appendSubset(ep *unstructured.Unstructured, subset map[string]any) {
	subs, _, _ := unstructured.NestedSlice(ep.Object, "subsets")
	subs = append(subs, subset)
	if err := unstructured.SetNestedSlice(ep.Object, subs, "subsets"); err != nil {
		panic(err)
	}
}

// appendAddr appends {"ip": ip} to subset[i]'s field — the test-time
// "reconciler re-added a live IP" mutation.
func appendAddr(ep *unstructured.Unstructured, i int, field, ip string) {
	subs, _, _ := unstructured.NestedSlice(ep.Object, "subsets")
	m, _ := subs[i].(map[string]any)
	addrs, _, _ := unstructured.NestedSlice(m, field)
	addrs = append(addrs, map[string]any{"ip": ip})
	_ = unstructured.SetNestedSlice(m, addrs, field)
	_ = unstructured.SetNestedSlice(ep.Object, subs, "subsets")
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

func newEndpointGuard(cs kubernetes.Interface, dyn dynamic.Interface, probes probeTable) *apiServerEndpointGuard {
	return &apiServerEndpointGuard{
		cs:       cs,
		dyn:      dyn,
		probeFn:  probes.fn,
		backends: map[string]*backendProbeState{},
	}
}

func getKubeEndpoints(t *testing.T, dyn dynamic.Interface) *unstructured.Unstructured {
	t.Helper()
	ep, err := dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).
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

func endpointAddrSet(ep *unstructured.Unstructured) map[string]bool {
	set := map[string]bool{}
	for _, sub := range endpointSubsets(ep) {
		for _, a := range nestedMaps(sub, "addresses") {
			if ip, _ := a["ip"].(string); ip != "" {
				set[ip] = true
			}
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
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil, nil))
	probes := probeTable{
		"10.0.0.1": {liveRV: 1000, cacheRV: 100}, // gap 900 — wedged
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.3": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, dyn, probes)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := endpointAddrSet(getKubeEndpoints(t, dyn)); !got["10.0.0.1"] {
		t.Fatal("wedged backend removed after a single gapped cycle")
	}

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep := getKubeEndpoints(t, dyn)
	if got := endpointAddrSet(ep); got["10.0.0.1"] || !got["10.0.0.2"] || !got["10.0.0.3"] {
		t.Fatalf("wedged backend not quarantined, addresses=%v", got)
	}
	if ann := ep.GetAnnotations()[endpointGuardAnno]; ann != "10.0.0.1" {
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
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	bad := &apiProbeResult{liveRV: 100, cacheRV: 90} // gap 10 < 200
	probes := probeTable{
		"10.0.0.1": bad,
		"10.0.0.2": apiHealthyProbe(100),
	}
	g := newEndpointGuard(cs, dyn, probes)

	for cycle := 0; cycle < 3; cycle++ {
		bad.liveRV += 50 // live grows, cache stuck at 90
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
		if endpointAddrSet(getKubeEndpoints(t, dyn))["10.0.0.1"] == false {
			t.Fatalf("cycle %d: backend removed before the 3-frozen-cycle latch", cycle)
		}
	}
	bad.liveRV += 50
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if endpointAddrSet(getKubeEndpoints(t, dyn))["10.0.0.1"] {
		t.Fatal("frozen-cache backend not quarantined after 3 cycles")
	}
}

// A probe transport error (timeout / 5xx) wedges only after
// endpointGuardErrCycles consecutive failures — a single blip is not
// a verdict.
func TestEndpointGuardQuarantineOnProbeError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("context deadline exceeded")},
		"10.0.0.2": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, dyn, probes)
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("backend with failed probe kept in endpoints")
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q", ep.GetAnnotations()[endpointGuardAnno])
	}
}

// THE guard: with zero healthy backends nothing is ever removed — a
// mass-wedge (or broken probe path) must not empty the endpoint set.
func TestEndpointGuardNeverRemovesLastHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("timeout")},
		"10.0.0.2": {err: errors.New("timeout")},
	}
	g := newEndpointGuard(cs, dyn, probes)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep := getKubeEndpoints(t, dyn)
	if got := endpointAddrSet(ep); !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("endpoints emptied during mass-wedge: %v", got)
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "" {
		t.Fatalf("annotation written with nothing quarantined: %q",
			ep.GetAnnotations()[endpointGuardAnno])
	}
}

// Same guard, asymmetric shape: one backend already quarantined, the
// sole remaining active backend wedges — it must stay (removing it
// would leave zero endpoints).
func TestEndpointGuardKeepsSoleRemainingBackend(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.2"}, nil, []string{"10.0.0.1"}))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("still down")},
		"10.0.0.2": {err: errors.New("just wedged")},
	}
	g := newEndpointGuard(cs, dyn, probes)
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := endpointAddrSet(getKubeEndpoints(t, dyn)); !got["10.0.0.2"] {
		t.Fatal("sole remaining backend was quarantined — endpoints would be empty")
	}
}

// A quarantined IP probing healthy for 2 consecutive cycles is put
// back into both objects and dropped from the annotation.
func TestEndpointGuardReaddsRecoveredBackend(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.2", "10.0.0.3"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.2", "10.0.0.3"}, nil, []string{"10.0.0.1"}))
	probes := probeTable{
		"10.0.0.1": apiHealthyProbe(1000),
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.3": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, dyn, probes)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep := getKubeEndpoints(t, dyn)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("backend re-added after a single healthy cycle")
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation dropped too early: %q", ep.GetAnnotations()[endpointGuardAnno])
	}

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep = getKubeEndpoints(t, dyn)
	if got := endpointAddrSet(ep); !got["10.0.0.1"] {
		t.Fatalf("recovered backend not re-added, addresses=%v", got)
	}
	if _, ok := ep.GetAnnotations()[endpointGuardAnno]; ok {
		t.Fatalf("annotation left behind after full recovery: %q",
			ep.GetAnnotations()[endpointGuardAnno])
	}
	if got := sliceAddrSet(getKubeSlice(t, cs)); !got["10.0.0.1"] {
		t.Fatalf("recovered backend not back in EndpointSlice: %v", got)
	}
}

// A quarantined backend that is STILL failing keeps its annotation —
// okStreak resets on every failed cycle and recovery never latches.
func TestEndpointGuardKeepsStillWedgedQuarantine(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.2"}, nil, []string{"10.0.0.1"}))
	probes := probeTable{
		"10.0.0.1": {liveRV: 900, cacheRV: 100}, // gap 800 — still wedged
		"10.0.0.2": apiHealthyProbe(900),
	}
	g := newEndpointGuard(cs, dyn, probes)
	for i := 0; i < 3; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("still-wedged backend re-added")
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q, want 10.0.0.1 kept", ep.GetAnnotations()[endpointGuardAnno])
	}
}

// < 2 controller IPs total (production/cicd single-controller):
// probes and streaks still run, but the objects are never touched.
func TestEndpointGuardSingleControllerNeverEdits(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1"}, nil, nil))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
	}
	g := newEndpointGuard(cs, dyn, probes)
	for i := 0; i < 3; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if !endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("single-controller endpoints edited")
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "" {
		t.Fatalf("annotation written on a single-controller cluster: %q",
			ep.GetAnnotations()[endpointGuardAnno])
	}
}

// A wedged IP parked in notReadyAddresses is a controller IP too —
// quarantine must strip it from BOTH address lists.
func TestEndpointGuardRemovesNotReadyAddress(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.2"}, []string{"10.0.0.1"}, nil))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	}
	g := newEndpointGuard(cs, dyn, probes)
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	for _, sub := range endpointSubsets(ep) {
		for _, a := range nestedMaps(sub, "notReadyAddresses") {
			if a["ip"] == "10.0.0.1" {
				t.Fatal("wedged IP still in notReadyAddresses")
			}
		}
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q", ep.GetAnnotations()[endpointGuardAnno])
	}
}

// ---------------------------------------------------------------------------
// Pure helper coverage — subset/annotation/union mutations.
// ---------------------------------------------------------------------------

// endpointIPs merges addresses + notReadyAddresses, deduped and sorted.
func TestEndpointIPSet(t *testing.T) {
	ep := kubeEndpoints([]string{"10.0.0.3", "10.0.0.1"}, []string{"10.0.0.2"}, nil)
	// Duplicate the IP across subsets to prove dedupe.
	appendSubset(ep, map[string]any{
		"addresses": []any{map[string]any{"ip": "10.0.0.1"}},
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
	ep.SetAnnotations(map[string]string{endpointGuardAnno: ""})
	if got := parseQuarantineAnnotation(ep); len(got) != 0 {
		t.Fatalf("empty annotation = %v", got)
	}
	ep.SetAnnotations(map[string]string{endpointGuardAnno: " 10.0.0.1 , ,10.0.0.2 "})
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
	if got := ep.GetAnnotations()[endpointGuardAnno]; got != "10.0.0.1,10.0.0.2" {
		t.Fatalf("annotation = %q, want sorted join", got)
	}
	writeQuarantineAnnotation(ep, map[string]bool{})
	if _, ok := ep.GetAnnotations()[endpointGuardAnno]; ok {
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
	appendSubset(ep, map[string]any{
		"addresses": []any{map[string]any{"ip": "10.0.0.2"}},
	})
	removeEndpointIP(ep, "10.0.0.1")
	subs := endpointSubsets(ep)
	if len(subs) != 1 || subsetAddrs(ep, 0, "addresses")[0]["ip"] != "10.0.0.2" {
		t.Fatalf("emptied subset not dropped: %+v", subs)
	}
}

// addEndpointIP placement: existing -> no-op; empty -> fresh subset on
// :6443; named "https" port wins; otherwise the first subset.
func TestAddEndpointIPPlacement(t *testing.T) {
	// Already present — no-op.
	ep := kubeEndpoints([]string{"10.0.0.1"}, nil, nil)
	addEndpointIP(ep, "10.0.0.1")
	if n := len(subsetAddrs(ep, 0, "addresses")); n != 1 {
		t.Fatalf("duplicate address appended: %d addresses", n)
	}

	// No subsets at all — a fresh subset is seeded with port 6443/https.
	bare := kubeEndpoints(nil, nil, nil)
	unstructured.RemoveNestedField(bare.Object, "subsets")
	addEndpointIP(bare, "10.0.0.9")
	bareAddrs := subsetAddrs(bare, 0, "addresses")
	if len(endpointSubsets(bare)) != 1 || len(bareAddrs) != 1 ||
		bareAddrs[0]["ip"] != "10.0.0.9" {
		t.Fatalf("empty endpoints not re-seeded: %+v", endpointSubsets(bare))
	}
	if p := nestedMaps(endpointSubsets(bare)[0], "ports")[0]; num64(p["port"]) != 6443 || p["name"] != "https" {
		t.Fatalf("seeded subset port = %+v, want 6443/https", p)
	}

	// A subset carrying an "https" port (any number) is the target.
	named := &unstructured.Unstructured{Object: map[string]any{
		"subsets": []any{
			map[string]any{
				"addresses": []any{map[string]any{"ip": "10.0.0.1"}},
				"ports":     []any{map[string]any{"name": "https", "port": int64(443)}},
			},
			map[string]any{
				"addresses": []any{map[string]any{"ip": "10.0.0.2"}},
				"ports":     []any{map[string]any{"name": "other", "port": int64(1234)}},
			},
		},
	}}
	addEndpointIP(named, "10.0.0.7")
	if n := len(subsetAddrs(named, 0, "addresses")); n != 2 {
		t.Fatalf("IP not appended to the https subset: %+v", endpointSubsets(named))
	}

	// No https/6443 port anywhere — fall back to subset[0].
	fallback := &unstructured.Unstructured{Object: map[string]any{
		"subsets": []any{
			map[string]any{
				"addresses": []any{map[string]any{"ip": "10.0.0.1"}},
				"ports":     []any{map[string]any{"name": "dns", "port": int64(53)}},
			},
		},
	}}
	addEndpointIP(fallback, "10.0.0.8")
	if n := len(subsetAddrs(fallback, 0, "addresses")); n != 2 {
		t.Fatalf("IP not appended to subset[0]: %+v", endpointSubsets(fallback))
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
	dyn := testutil.NewDynamicClient()
	g := newEndpointGuard(cs, dyn, probeTable{})
	if err := g.run(ctx); err == nil {
		t.Fatal("expected error when the Endpoints object is missing")
	}
}

// An EndpointSlice list failure is a real error — the guard cannot
// decide the SSOT without knowing which slices exist.
func TestEndpointGuardSliceListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	cs.PrependReactor("list", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	g := newEndpointGuard(cs, dyn, probeTable{
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
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": apiHealthyProbe(100),
		"10.0.0.2": apiHealthyProbe(100),
	})
	if err := g.run(ctx); err != nil {
		t.Fatalf("missing EndpointSlice must not veto the run: %v", err)
	}
}

// Zero controller IPs (empty subsets) -> clean no-op, probes skipped.
func TestEndpointGuardNoControllerIPs(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(kubeEndpoints(nil, nil, nil))
	g := newEndpointGuard(cs, dyn, probeTable{}) // any probe call would error
	if err := g.run(ctx); err != nil {
		t.Fatalf("empty controller set must be a no-op: %v", err)
	}
}

// Backend streak state for an IP that left the controller set is
// pruned (and its metric series forgotten) — otherwise a removed
// backend's streak could resurface as stale evidence on re-add.
func TestEndpointGuardPrunesDepartedBackend(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	g := newEndpointGuard(cs, dyn, probeTable{
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
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("dead")},
		// gapped but under the 2-cycle latch: not wedged AND not
		// healthy — healthyActive stays 0 while 10.0.0.1 wedges.
		"10.0.0.2": {liveRV: 1000, cacheRV: 100},
	}
	g := newEndpointGuard(cs, dyn, probes)

	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep := getKubeEndpoints(t, dyn)
	if got := endpointAddrSet(ep); !got["10.0.0.1"] {
		t.Fatalf("backend quarantined with no healthy peer, addresses=%v", got)
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "" {
		t.Fatalf("annotation = %q, want empty", ep.GetAnnotations()[endpointGuardAnno])
	}
}

// THE routable-peer guard: a wedged READY backend whose only
// "healthy" peer sits in notReadyAddresses must NOT be quarantined —
// kube-proxy never routes to notReady addresses, so pulling the last
// routable IP would flap kubernetes.default to zero Ready endpoints.
// (The notReady suspect itself is still probed and could be pulled.)
func TestEndpointGuardNotReadyPeerCountsAsNoPeer(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1"}, []string{"10.0.0.2"}, nil))
	probes := probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500), // healthy probe, but NOT routable
	}
	g := newEndpointGuard(cs, dyn, probes)
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if !endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("last routable backend quarantined on a notReady peer's health")
	}
	if ep.GetAnnotations()[endpointGuardAnno] != "" {
		t.Fatalf("annotation = %q, want empty", ep.GetAnnotations()[endpointGuardAnno])
	}
}

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
	for i := 0; i < endpointGuardErrCycles; i++ {
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

// Quarantine expiry: a quarantined IP that vanishes from the address
// sets AND keeps failing its probe past endpointGuardExpireCyc
// consecutive cycles is declared decommissioned — dropped from the
// annotation, memQuarantine and backend state so the 10s re-apply
// cadence releases (quarantineActive clears).
func TestEndpointGuardQuarantineExpiresForDepartedBackend(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, []string{"10.0.0.9"}))
	probes := probeTable{
		"10.0.0.1": apiHealthyProbe(1000),
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.9": {err: errors.New("connection refused")},
	}
	g := newEndpointGuard(cs, dyn, probes)
	for i := 0; i < endpointGuardExpireCyc-1; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.9" {
		t.Fatalf("quarantine dropped before %d err cycles: %q",
			endpointGuardExpireCyc, ep.GetAnnotations()[endpointGuardAnno])
	}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	ep = getKubeEndpoints(t, dyn)
	if _, ok := ep.GetAnnotations()[endpointGuardAnno]; ok {
		t.Fatalf("dead backend still pinned: %q", ep.GetAnnotations()[endpointGuardAnno])
	}
	if endpointAddrSet(ep)["10.0.0.9"] {
		t.Fatal("expired backend re-added to addresses — expiry must not re-add")
	}
	if g.quarantineActive {
		t.Fatal("quarantineActive still armed after the last IP expired")
	}
	if g.memQuarantine["10.0.0.9"] {
		t.Fatal("memQuarantine still holds the expired IP")
	}
	if _, ok := g.backends["10.0.0.9"]; ok {
		t.Fatal("backend probe state for the expired IP not pruned")
	}
}

// A quarantined IP the endpoints reconciler keeps re-adding (still a
// live backend, e.g. rebuilding after a rebuild-and-rejoin) is never
// expired no matter how long it errors — absence from the address
// sets is the decommissioned tell.
func TestEndpointGuardQuarantineNeverExpiresWhileAddressed(t *testing.T) {
	ep := kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, []string{"10.0.0.9"})
	appendAddr(ep, 0, "addresses", "10.0.0.9") // reconciler re-added it
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(ep)
	probes := probeTable{
		"10.0.0.1": apiHealthyProbe(1000),
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.9": {err: errors.New("connection refused")},
	}
	g := newEndpointGuard(cs, dyn, probes)
	for i := 0; i < endpointGuardExpireCyc+2; i++ {
		// The endpoint reconciler re-adds a pulled LIVE backend every
		// ~10s — simulate that before each sweep (the guard pulls it
		// again each cycle because it still wedges).
		cur := getKubeEndpoints(t, dyn)
		if !endpointAddrSet(cur)["10.0.0.9"] {
			cur = cur.DeepCopy()
			appendAddr(cur, 0, "addresses", "10.0.0.9")
			if _, err := dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).
				Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ep := getKubeEndpoints(t, dyn); ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.9" {
		t.Fatalf("addressed backend expired: %q", ep.GetAnnotations()[endpointGuardAnno])
	}
}

// The <2-backends early-return must not deadlock the expiry
// bookkeeping: a lone quarantined dead IP (zero active addresses)
// still gets its annotation shrink persisted.
func TestEndpointGuardExpiryNotBlockedByMinBackends(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(
		kubeEndpoints(nil, nil, []string{"10.0.0.9"}))
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.9": {err: errors.New("connection refused")},
	})
	for i := 0; i < endpointGuardExpireCyc; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if _, ok := ep.GetAnnotations()[endpointGuardAnno]; ok {
		t.Fatalf("expiry deadlocked behind the min-backends gate: %q",
			ep.GetAnnotations()[endpointGuardAnno])
	}
	if g.quarantineActive {
		t.Fatal("quarantineActive still armed after expiry under min-backends")
	}
}

// An Endpoints object carrying no annotations at all must still take
// the quarantine annotation — the guard initializes the map instead
// of failing the mutation.
func TestEndpointGuardQuarantinesAnnotationlessEndpoints(t *testing.T) {
	ep := kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil)
	unstructured.RemoveNestedField(ep.Object, "metadata", "annotations")
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient(ep)
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	for i := 0; i < endpointGuardErrCycles; i++ {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep = getKubeEndpoints(t, dyn)
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q, want 10.0.0.1", ep.GetAnnotations()[endpointGuardAnno])
	}
}

// The Endpoints update is the SSOT write — its failure aborts the
// sweep so the EndpointSlice can never converge ahead of it.
func TestEndpointGuardEndpointsUpdateError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	})
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	dyn.PrependReactor("update", "endpoints",
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
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	g := newEndpointGuard(cs, dyn, probeTable{
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
	ep := getKubeEndpoints(t, dyn)
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q", ep.GetAnnotations()[endpointGuardAnno])
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
	cs := fake.NewSimpleClientset()    // no EndpointSlice -> read-through falls to Endpoints
	dyn := testutil.NewDynamicClient() // no Endpoints -> first sweep errors
	// probed receives each backend IP the sweep probes — a probe call
	// is the deterministic sync point for "run() got past the
	// fetch/decide stage" where quarantineActive is (re)assigned; the
	// clientset action count alone can't prove the sweep finished.
	probed := make(chan string, 8)
	g := &apiServerEndpointGuard{
		cs:  cs,
		dyn: dyn,
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
	if _, err := dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).Create(ctx,
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

// actionResources tallies fake-client actions per resource — used to
// prove the slice path never touches the deprecated Endpoints object.
type actionLogger interface {
	Actions() []ktesting.Action
}

func actionResources(f actionLogger) map[string]int {
	out := map[string]int{}
	for _, a := range f.Actions() {
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
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	fakeServerVersion(cs, "1", "33")
	g := newEndpointGuard(cs, dyn, probeTable{
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
	if acts := actionResources(dyn)["endpoints"]; acts != 0 {
		t.Fatalf("%d endpoints actions on the slice path, want 0", acts)
	}
	ep := getKubeEndpoints(t, dyn)
	if !endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("Endpoints object was mutated on the slice path")
	}
}

// A quarantined slice backend probing healthy for 2 cycles is
// re-added to the slice and dropped from its annotation.
func TestEndpointGuardSliceModeReaddsRecovered(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeSliceWithQuarantine([]string{"10.0.0.2"}, []string{"10.0.0.1"}))
	dyn := testutil.NewDynamicClient()
	fakeServerVersion(cs, "1", "34")
	probes := probeTable{
		"10.0.0.1": apiHealthyProbe(1000),
		"10.0.0.2": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, dyn, probes)
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
	for i := 0; i < endpointGuardErrCycles; i++ {
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
	for i := 0; i < endpointGuardErrCycles; i++ {
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
	g := &apiServerEndpointGuard{
		cs:  cs,
		dyn: dyn,
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
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	probed := map[string]int{}
	probes := probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	}
	g := &apiServerEndpointGuard{
		cs:  cs,
		dyn: dyn,
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
	ep := getKubeEndpoints(t, dyn)
	ep = ep.DeepCopy()
	annos := ep.GetAnnotations()
	delete(annos, endpointGuardAnno)
	ep.SetAnnotations(annos)
	if _, err := dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).
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
	if got := endpointAddrSet(getKubeEndpoints(t, dyn)); got["10.0.0.1"] {
		t.Fatal("wedged backend back in endpoints while still failing")
	}
}

// The dedicated clientset's WarningHandler drops ONLY the Endpoints
// deprecation header — deliberate writes must stay silent, everything
// else delegates to the default logger.
func TestEndpointGuardWarningFilter(t *testing.T) {
	var forwarded []string
	filter := endpointGuardWarnings{delegate: recordingWarnings{&forwarded}}
	filter.HandleWarningHeader(299, "",
		"v1 Endpoints is deprecated in v1.33+; use discovery.k8s.io/v1 EndpointSlice")
	if len(forwarded) != 0 {
		t.Fatalf("deprecation warning leaked to delegate: %v", forwarded)
	}
	filter.HandleWarningHeader(299, "", "some other deprecation")
	filter.HandleWarningHeader(299, "", "v1 Secrets is deprecated")
	if len(forwarded) != 2 {
		t.Fatalf("unrelated warnings swallowed: %v", forwarded)
	}
}

// recordingWarnings captures delegated warnings for the filter test.
type recordingWarnings struct{ got *[]string }

func (r recordingWarnings) HandleWarningHeader(_ int, _ string, message string) {
	*r.got = append(*r.got, message)
}

func (r recordingWarnings) HandleWarningHeaderWithContext(_ context.Context, _ int, _ string, message string) {
	*r.got = append(*r.got, message)
}

// endpointMode detection failure falls back to the Endpoints path —
// the sweep still functions on a cluster whose /version is broken.
func TestEndpointGuardVersionUndetectableFallsBack(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2"}, nil, nil))
	g := newEndpointGuard(cs, dyn, probeTable{
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
	ep := getKubeEndpoints(t, dyn)
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("fallback did not run the Endpoints path, annotation = %q",
			ep.GetAnnotations()[endpointGuardAnno])
	}
}

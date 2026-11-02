package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
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
// maintains for the kubernetes service.
func kubeEndpointSlice(ips []string) *discoveryv1.EndpointSlice {
	eps := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
		Namespace: endpointGuardNS, Name: endpointGuardName,
	}}
	ready := true
	for _, ip := range ips {
		eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{ip},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		})
	}
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

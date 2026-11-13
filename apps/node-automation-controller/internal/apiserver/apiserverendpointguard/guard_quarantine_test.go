// guard_quarantine_test.go — the quarantine lifecycle scenarios:
// wedge detection (frozen cache, probe errors), the never-remove-last
// guards, re-add/recovery gates, hosted-plane peer discovery and
// quarantine expiry.
package apiserverendpointguard

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// P0-3: a large STATIC live-cache gap is NOT a wedge signal — the gap
// counts every unrelated cluster write since the last lease renewal,
// so it stays inflated on a perfectly healthy backend under ordinary
// write storms. Only a cache_rv frozen across cycles while live_rv
// grows (TestEndpointGuardQuarantineOnFrozenCache) or consecutive
// probe errors may quarantine.
func TestEndpointGuardStaticGapDoesNotWedge(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil, nil))
	probes := probeTable{
		"10.0.0.1": {liveRV: 1000, cacheRV: 100}, // gap 900 but live_rv flat
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.3": apiHealthyProbe(1000),
	}
	g := newEndpointGuard(cs, dyn, probes)

	for range endpointGuardFrozenCyc + 2 {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if got := endpointAddrSet(ep); !got["10.0.0.1"] {
		t.Fatalf("static-gap backend quarantined on storm noise, addresses=%v", got)
	}
	if ann := ep.GetAnnotations()[endpointGuardAnno]; ann != "" {
		t.Fatalf("quarantine annotation = %q, want empty", ann)
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

	for cycle := range 3 {
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
	for range endpointGuardErrCycles {
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

// A quarantined IP the reconciler still lists (notReady copy) probing
// healthy for 2 consecutive cycles is put back into both objects and
// dropped from the annotation. The IP must stay visible to activeIPs —
// since the re-add gate, a quarantined IP absent from the current
// endpoints is never re-added on streak alone (it would fight the
// reconciler; see the absent-IP regression test below).
func TestEndpointGuardReaddsRecoveredBackend(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.2", "10.0.0.3"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.2", "10.0.0.3"}, []string{"10.0.0.1"}, []string{"10.0.0.1"}))
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

// A quarantined backend whose okStreak is sufficient is re-added ONLY
// while the reconciler still lists it — the decommissioned-backend
// flapping fix. 10.0.0.1 stays in the Endpoints object (notReady copy,
// as the reconciler leaves behind) so it recovers back into both
// objects; 10.0.0.3's host still answers :6443 (healthy probes,
// okStreak climbs) but the reconciler dropped it everywhere — re-adding
// on streak alone made the guard fight the reconciler every cycle and
// kube-proxy flapped kubernetes.default. It must stay quarantined (and
// must NOT expire either — a live host never accumulates errStreak).
func TestEndpointGuardSkipsReaddOfAbsentQuarantinedBackend(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeEndpointSlice([]string{"10.0.0.2"}))
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.2"}, []string{"10.0.0.1"}, []string{"10.0.0.1", "10.0.0.3"}))
	probes := probeTable{
		"10.0.0.1": apiHealthyProbe(1000), // decommissioned twin: healthy host
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.3": apiHealthyProbe(1000), // quarantined AND absent
	}
	g := newEndpointGuard(cs, dyn, probes)

	for i := range endpointGuardRecoverCyc + 1 { // +1: stability after re-add
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
		ep := getKubeEndpoints(t, dyn)
		got := endpointAddrSet(ep)
		slice := sliceAddrSet(getKubeSlice(t, cs))
		if got["10.0.0.3"] || slice["10.0.0.3"] {
			t.Fatalf("cycle %d: absent quarantined backend re-added — reconciler fight (ep=%v slice=%v)",
				i+1, got, slice)
		}
		if ann := ep.GetAnnotations()[endpointGuardAnno]; !strings.Contains(ann, "10.0.0.3") {
			t.Fatalf("cycle %d: absent backend dropped from annotation early: %q", i+1, ann)
		}
		if i+1 < endpointGuardRecoverCyc {
			// Latch not reached: the listed twin must also stay out.
			if got["10.0.0.1"] {
				t.Fatalf("cycle %d: listed backend re-added after a single healthy cycle", i+1)
			}
			continue
		}
		if !got["10.0.0.1"] || !slice["10.0.0.1"] {
			t.Fatalf("cycle %d: listed recovered backend not re-added (ep=%v slice=%v)", i+1, got, slice)
		}
		if ann := ep.GetAnnotations()[endpointGuardAnno]; ann != "10.0.0.3" {
			t.Fatalf("cycle %d: annotation = %q, want only absent 10.0.0.3", i+1, ann)
		}
	}
}

// P0-3 hosted-plane re-add: on a mirror-slice (hosted) plane NO
// endpoint reconciler re-lists a pulled IP — activeIPs can never
// contain it again, so the reconciler-listing rule alone deadlocked
// every recovered backend out of the set forever. Membership is
// instead proven against ssotPeerIPs (control-plane node
// InternalIPs): 10.0.0.1 stays a CP node address and must come
// back; 10.0.0.3 is quarantined, absent, and NOT a node address —
// decommissioned evidence — so it stays out.
func TestEndpointGuardHostedReaddViaPeerDiscovery(t *testing.T) {
	cpNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "cp-0",
			Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
		},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			{Type: corev1.NodeInternalIP, Address: "10.0.0.2"},
		}},
	}
	cs := fake.NewSimpleClientset(
		kubeMirrorSlice("kubernetes-89b87", []string{"10.0.0.2"}),
		cpNode)
	dyn := testutil.NewDynamicClient(
		// 10.0.0.1 + 10.0.0.3 quarantined and absent from the
		// address lists — the guard pulled them and nothing
		// re-lists them on a hosted plane.
		kubeEndpoints([]string{"10.0.0.2"}, nil, []string{"10.0.0.1", "10.0.0.3"}))
	fakeServerVersion(cs, "1", "37")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": apiHealthyProbe(1000), // CP node IP — recovers back
		"10.0.0.2": apiHealthyProbe(1000),
		"10.0.0.3": apiHealthyProbe(1000), // absent AND not a peer — stays out
	})

	for range endpointGuardRecoverCyc + 1 {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	got := endpointAddrSet(ep)
	if !got["10.0.0.1"] {
		t.Fatal("recovered CP backend not re-added — SKIP-RE-ADD deadlock on hosted plane")
	}
	if got["10.0.0.3"] {
		t.Fatal("non-peer quarantined backend re-added — decommissioned evidence ignored")
	}
	if ann := ep.GetAnnotations()[endpointGuardAnno]; ann != "10.0.0.3" {
		t.Fatalf("quarantine annotation = %q, want only 10.0.0.3", ann)
	}
	// The mirror slice converges to the same post-decision set.
	s, err := cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
		Get(ctx, "kubernetes-89b87", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	slice := sliceAddrSet(s)
	if !slice["10.0.0.1"] || slice["10.0.0.3"] {
		t.Fatalf("mirror slice not converged: %v", slice)
	}
}

// Same hosted shape but peer discovery finds NO control-plane nodes
// (managed plane / list failure shape): with no independent peer
// evidence the strict rule stays — an absent quarantined IP is never
// re-added on streak alone.
func TestEndpointGuardHostedReaddFailsClosedWithoutPeers(t *testing.T) {
	cs := fake.NewSimpleClientset(
		kubeMirrorSlice("kubernetes-89b87", []string{"10.0.0.2"})) // no nodes at all
	dyn := testutil.NewDynamicClient(
		kubeEndpoints([]string{"10.0.0.2"}, nil, []string{"10.0.0.1"}))
	fakeServerVersion(cs, "1", "37")
	g := newEndpointGuard(cs, dyn, probeTable{
		"10.0.0.1": apiHealthyProbe(1000),
		"10.0.0.2": apiHealthyProbe(1000),
	})
	for range endpointGuardRecoverCyc + 1 {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep := getKubeEndpoints(t, dyn)
	if endpointAddrSet(ep)["10.0.0.1"] {
		t.Fatal("absent backend re-added with zero peer evidence — fail closed violated")
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
		"10.0.0.1": {err: errors.New("still wedged")}, // keeps failing — stays out
		"10.0.0.2": apiHealthyProbe(900),
	}
	g := newEndpointGuard(cs, dyn, probes)
	for range 3 {
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
		// also failing: neither backend is a healthy peer, so the
		// last-healthy guard vetoes every removal.
		"10.0.0.2": {err: errors.New("dead too")},
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
	for range endpointGuardErrCycles {
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
	for range endpointGuardExpireCyc - 1 {
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
	for range endpointGuardExpireCyc + 2 {
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
	for range endpointGuardExpireCyc {
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
	for range endpointGuardErrCycles {
		if err := g.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ep = getKubeEndpoints(t, dyn)
	if ep.GetAnnotations()[endpointGuardAnno] != "10.0.0.1" {
		t.Fatalf("annotation = %q, want 10.0.0.1", ep.GetAnnotations()[endpointGuardAnno])
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
	var probedMu sync.Mutex // probes run in parallel per cycle
	probes := probeTable{
		"10.0.0.1": {err: errors.New("wedged")},
		"10.0.0.2": apiHealthyProbe(500),
	}
	g := &apiServerEndpointGuard{
		cs:  cs,
		dyn: dyn,
		probeFn: func(_ context.Context, ip string) apiProbeResult {
			probedMu.Lock()
			probed[ip]++
			probedMu.Unlock()
			return probes.fn(t.Context(), ip)
		},
		backends: map[string]*backendProbeState{},
	}
	// +1 cycle: quarantineActive reflects the annotation read at the
	// START of a run, so it only arms on the cycle after the persist.
	for range endpointGuardErrCycles + 1 {
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

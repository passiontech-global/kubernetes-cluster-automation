// guard_cycle_test.go — the run/Start loop scenarios: fetch-guard
// errors, SSOT write failures, the Start cadence switch, the
// >=v1.33 server-version gate, warning filtering, JWKS kid skew and
// panic recovery.
package apiserverendpointguard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

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
	for range 3 {
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
	for range endpointGuardErrCycles {
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
		// Pre-arm the quarantine cadence so the fast re-tick is
		// exercised after the erroring sweep. The injected
		// millisecond intervals keep the whole cycle test in the
		// ~100ms range instead of ~40s of real timers.
		quarantineActive:   true,
		interval:           20 * time.Millisecond,
		quarantineInterval: 10 * time.Millisecond,
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Start(cctx) }()

	waitActions := func(want int) bool {
		dl := time.Now().Add(10 * time.Second)
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
	case <-time.After(10 * time.Second):
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
	for range 2 {
		if use, err := g2.endpointMode(); use || err == nil {
			t.Fatalf("endpointMode on error = %v, %v; want false, err", use, err)
		}
	}
	if calls != 3 {
		t.Fatalf("detection errors must not be cached, calls = %d", calls)
	}
}

// The dedicated clientset's WarningHandler drops ONLY the Endpoints
// deprecation header — deliberate writes must stay silent, everything
// else delegates to the default logger.
func TestEndpointGuardWarningFilter(t *testing.T) {
	var forwarded []string
	filter := kube.EndpointGuardWarnings{Delegate: recordingWarnings{&forwarded}}
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

// jwks-kid-skew: a backend whose JWKS kid set dissents from the healthy
// majority for 3 consecutive cycles is flagged (gauge+log) — the
// sa.pub/sa.key rotation skew surfaces as random 401s through the LB.
func TestEndpointGuardJWKSKIDSkew(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient()
	probes := probeTable{
		"10.0.0.1": {liveRV: 1000, cacheRV: 1000, jwksKIDs: "k1 k2"},
		"10.0.0.2": {liveRV: 1000, cacheRV: 1000, jwksKIDs: "k1 k2"},
		"10.0.0.3": {liveRV: 1000, cacheRV: 1000, jwksKIDs: "k3"}, // skewed
	}
	g := newEndpointGuard(cs, dyn, probes)
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for range endpointGuardKidSkewCycles {
		g.evaluateBackends(ctx, ips, ips, map[string]bool{})
	}
	if got := g.backends["10.0.0.3"].kidSkewStreak; got != endpointGuardKidSkewCycles {
		t.Fatalf("skewed backend kidSkewStreak = %d, want %d", got, endpointGuardKidSkewCycles)
	}
	if got := g.backends["10.0.0.1"].kidSkewStreak; got != 0 {
		t.Fatalf("majority backend kidSkewStreak = %d, want 0", got)
	}
	// Recovery: the odd backend rejoins the majority — streak resets.
	probes["10.0.0.3"] = &apiProbeResult{liveRV: 1000, cacheRV: 1000, jwksKIDs: "k1 k2"}
	g.evaluateBackends(ctx, ips, ips, map[string]bool{})
	if got := g.backends["10.0.0.3"].kidSkewStreak; got != 0 {
		t.Fatalf("recovered backend kidSkewStreak = %d, want 0", got)
	}
}

// A lone dissent voter can't skew itself: empty/missing JWKS sets
// abstain, and a 2-backend tie never flags a minority.
func TestEndpointGuardJWKSTieNeverFlags(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient()
	probes := probeTable{
		"10.0.0.1": {liveRV: 1000, cacheRV: 1000, jwksKIDs: "k1"},
		"10.0.0.2": {liveRV: 1000, cacheRV: 1000, jwksKIDs: "k2"},
	}
	g := newEndpointGuard(cs, dyn, probes)
	ips := []string{"10.0.0.1", "10.0.0.2"}
	for range endpointGuardKidSkewCycles + 1 {
		g.evaluateBackends(ctx, ips, ips, map[string]bool{})
	}
	for _, ip := range ips {
		if got := g.backends[ip].kidSkewStreak; got != 0 {
			t.Fatalf("tied backend %s kidSkewStreak = %d, want 0", ip, got)
		}
	}
}

// runCycle contains a panicking sweep: a panic anywhere in the run
// path (here: the version-probe seam) is recovered, metered and
// logged, and the Start loop keeps its cadence — a wedged dependency
// or a malformed unstructured object must not kill the whole
// controller process. (This runnable bypasses shared.Periodic, which
// is where every other module's panic recovery lives.)
func TestEndpointGuardCycleRecoversPanics(t *testing.T) {
	cs := fake.NewSimpleClientset()
	dyn := testutil.NewDynamicClient()
	g := newEndpointGuard(cs, dyn, probeTable{})
	g.serverMinorFn = func() (int, error) { panic("version probe exploded") }
	if got := g.runCycle(ctx, logr.Discard(), endpointGuardInterval); got != endpointGuardInterval {
		t.Fatalf("cadence after a panicking sweep = %v, want the passed-in interval", got)
	}
	// The recover must not wedge the loop: the passed-in cadence is
	// retained through panicking cycles too.
	if got := g.runCycle(ctx, logr.Discard(), endpointGuardQuarantineInterval); got != endpointGuardQuarantineInterval {
		t.Fatalf("cadence after the recovered cycle = %v, want the passed-in quarantine interval", got)
	}
	// And a healthy cycle still applies the quarantine fast-cadence
	// switch.
	g.serverMinorFn = nil
	g.quarantineActive = true
	if got := g.runCycle(ctx, logr.Discard(), endpointGuardInterval); got != endpointGuardQuarantineInterval {
		t.Fatalf("healthy sweep after recovery = %v, want the quarantine fast cadence", got)
	}
	g.quarantineActive = false
	if got := g.runCycle(ctx, logr.Discard(), endpointGuardQuarantineInterval); got != endpointGuardInterval {
		t.Fatalf("healthy sweep with quarantine disarmed = %v, want the steady interval", got)
	}
}

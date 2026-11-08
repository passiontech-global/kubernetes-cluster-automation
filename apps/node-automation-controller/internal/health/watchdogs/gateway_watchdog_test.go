// gateway_watchdog_test.go — regression coverage for the gateway-API
// signature + ownership fix in the operator-workqueue watchdog
// (W5.8). The fix landed three corrections:
//
//  1. Gateway-API types carry NO top-level status.observedGeneration —
//     generation lag is judged inside the per-condition
//     observedGeneration fields of status.parents[] /
//     status.listeners[] (gatewayStatusStuck / gatewayObjectStuck /
//     condMaxObservedGeneration). A signature that read the top-level
//     field would flag every healthy route/Gateway forever.
//  2. The Gateway kind is judged on status.listeners (routes use
//     status.parents): a spec.listeners->status.listeners programming
//     gap means the controller never programmed it, while a Gateway
//     without spec.listeners is nothing to reconcile and never stuck.
//  3. gateway-api resources on this cluster are shared between
//     cilium-operator and foreign gateway controllers (e.g.
//     cloudflare-tunnel): the owns filter drops a stuck object from
//     cilium's set — and from its heal path — only when attribution to
//     another controller is PROVEN; unresolvable class/parent data
//     keeps the object, because an unattributable gateway-API object
//     is still a gateway-plane problem worth flagging.
package watchdogs

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// foreignGatewayController is a non-cilium spec.controllerName — the
// value the cloudflare-tunnel gateway class carries on this cluster.
const foreignGatewayController = "cf.k8s.lex.la/tunnel-controller"

// gwClassFixture builds a GatewayClass fixture carrying a
// spec.controllerName — the ownership key the owns filters resolve —
// plus a healthy status.conditions[Accepted] stamped at the object's
// generation: gatewayclasses is a watched resource too, so a
// conditionless class would read as never-accepted and pollute
// opFirstSeen inside the operator sweep tests.
func gwClassFixture(name, controller string) *unstructured.Unstructured {
	obj := probetest.UnstructuredObj("gateway.networking.k8s.io/v1", "GatewayClass", "", name, 1, 0)
	_ = unstructured.SetNestedField(obj.Object, controller, "spec", "controllerName")
	_ = unstructured.SetNestedSlice(obj.Object, []any{map[string]any{
		"type": "Accepted", "status": "True", "observedGeneration": int64(1)}},
		"status", "conditions")
	return obj
}

// gwFixture builds a Gateway bound to a class. spec.listeners is left
// absent on purpose unless the caller adds it — a listener-less spec
// never reads as stuck, keeping parentRef-resolution fixtures inert
// inside the operator sweep's own gateways scan.
func gwFixture(ns, name, class string, gen int64) *unstructured.Unstructured {
	obj := probetest.UnstructuredObj("gateway.networking.k8s.io/v1", "Gateway", ns, name, gen, 0)
	_ = unstructured.SetNestedField(obj.Object, class, "spec", "gatewayClassName")
	return obj
}

// routeFixture builds an HTTPRoute with optional spec.parentRefs
// entries (map[string]any values: name/namespace/kind/group).
func routeFixture(ns, name string, gen int64, refs []any) *unstructured.Unstructured {
	obj := probetest.UnstructuredObj("gateway.networking.k8s.io/v1", "HTTPRoute", ns, name, gen, 0)
	if refs != nil {
		_ = unstructured.SetNestedSlice(obj.Object, refs, "spec", "parentRefs")
	}
	return obj
}

// parentStatus builds one status.parents entry as the gateway
// controller writes it: conditions carrying the last processed
// observedGeneration.
func parentStatus(og int64) map[string]any {
	return map[string]any{
		"parentRef": map[string]any{"name": "gw"},
		"conditions": []any{map[string]any{
			"type": "Accepted", "status": "True", "observedGeneration": og}},
	}
}

// putGateway seeds a Gateway THROUGH the client instead of the fake
// tracker's object list: NewSimpleDynamicClient guesses plurals and
// stores kind=Gateway under "gatewaies" (the y→ies rule), so a
// seeded object would be invisible to Get/List on the real
// "gateways" GVR the ownership filter queries.
func putGateway(t *testing.T, dyn dynamic.Interface, o *unstructured.Unstructured) {
	t.Helper()
	if _, err := dyn.Resource(kube.GVRGateway).Namespace(o.GetNamespace()).
		Create(ctx, o, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed gateway %s/%s: %v", o.GetNamespace(), o.GetName(), err)
	}
}

// newGatewayClassAwareProber builds a prober whose dyn fake knows the
// four gateway.networking.k8s.io/v1 GVRs (including gatewayclasses)
// plus the autopilot Plan the maintenance mutex reads if a heal ever
// fires — all covered by testutil.NewDynamicClient's table.
func newGatewayClassAwareProber(objs ...runtime.Object) *probetest.Prober {
	return testProberDyn(fake.NewSimpleClientset(),
		testutil.NewDynamicClient(objs...))
}

// ---------------------------------------------------------------------------
// gatewayStatusStuck — the route-kind signature
// ---------------------------------------------------------------------------

// The controller attaches a status.parents entry when it programs the
// route; its absence is the never-attached signature, and parents
// whose conditions only saw an older generation mean the last spec
// write was never reconciled.
func TestGatewayStatusStuck(t *testing.T) {
	// Never attached → stuck.
	route := routeFixture("apps", "r", 1, nil)
	if !gatewayStatusStuck(route) {
		t.Fatal("route without status.parents must read as stuck")
	}

	// Attached and reporting the current generation → healthy.
	_ = unstructured.SetNestedSlice(route.Object,
		[]any{parentStatus(int64(1))}, "status", "parents")
	if gatewayStatusStuck(route) {
		t.Fatal("route attached at the current generation must not read as stuck")
	}

	// Attached once but the last spec write (gen 5) unseen → stuck.
	stale := routeFixture("apps", "r", 5, nil)
	_ = unstructured.SetNestedSlice(stale.Object,
		[]any{parentStatus(int64(3))}, "status", "parents")
	if !gatewayStatusStuck(stale) {
		t.Fatal("route whose parents only saw gen 3 must read as stuck at gen 5")
	}

	// A parent entry without conditions carries no generation signal
	// at all — the controller attached nothing usable → stuck.
	bare := routeFixture("apps", "r", 2, nil)
	_ = unstructured.SetNestedSlice(bare.Object,
		[]any{map[string]any{"parentRef": map[string]any{"name": "gw"}}},
		"status", "parents")
	if !gatewayStatusStuck(bare) {
		t.Fatal("parent without conditions must read as stuck")
	}
	empty := routeFixture("apps", "r", 2, nil)
	_ = unstructured.SetNestedSlice(empty.Object,
		[]any{map[string]any{
			"parentRef":  map[string]any{"name": "gw"},
			"conditions": []any{},
		}},
		"status", "parents")
	if !gatewayStatusStuck(empty) {
		t.Fatal("parent with empty conditions must read as stuck")
	}

	// Multi-parent: ANY parent reporting the current generation
	// proves the controller saw the last spec write → healthy.
	mixed := routeFixture("apps", "r", 4, nil)
	_ = unstructured.SetNestedSlice(mixed.Object,
		[]any{parentStatus(int64(2)), parentStatus(int64(4))},
		"status", "parents")
	if gatewayStatusStuck(mixed) {
		t.Fatal("one fresh parent among stale ones must not read as stuck")
	}
}

// ---------------------------------------------------------------------------
// gatewayObjectStuck — the Gateway-kind signature
// ---------------------------------------------------------------------------

// Gateways carry status.listeners, not status.parents. Nothing in
// spec.listeners means nothing to program; spec listeners without
// matching status.listeners means never programmed; otherwise the
// max observedGeneration across top-level + per-listener conditions
// decides whether the last spec write was seen.
func TestGatewayObjectStuck(t *testing.T) {
	listeners := []any{map[string]any{"name": "http", "port": int64(80), "protocol": "HTTP"}}

	// No listeners declared — nothing to reconcile → never stuck.
	bare := probetest.UnstructuredObj("gateway.networking.k8s.io/v1", "Gateway", "apps", "gw", 3, 0)
	if gatewayObjectStuck(bare) {
		t.Fatal("Gateway without spec.listeners must not read as stuck")
	}

	// Declared listeners but the controller never wrote
	// status.listeners → never programmed → stuck.
	unprogrammed := gwFixture("apps", "gw", "cilium", 3)
	_ = unstructured.SetNestedSlice(unprogrammed.Object, listeners, "spec", "listeners")
	if !gatewayObjectStuck(unprogrammed) {
		t.Fatal("spec.listeners without status.listeners must read as stuck")
	}

	// Programmed listeners reporting the current generation inside
	// their own conditions → healthy.
	fresh := gwFixture("apps", "gw", "cilium", 4)
	_ = unstructured.SetNestedSlice(fresh.Object, listeners, "spec", "listeners")
	_ = unstructured.SetNestedSlice(fresh.Object,
		[]any{map[string]any{
			"name": "http",
			"conditions": []any{map[string]any{
				"type": "Programmed", "status": "True", "observedGeneration": int64(4)}},
		}},
		"status", "listeners")
	if gatewayObjectStuck(fresh) {
		t.Fatal("listener conditions at the current generation must not read as stuck")
	}

	// The current generation may appear ONLY in top-level
	// status.conditions — per-listener conditions lag legitimately
	// while the Gateway-level Accepted condition is fresh.
	topOnly := gwFixture("apps", "gw", "cilium", 3)
	_ = unstructured.SetNestedSlice(topOnly.Object, listeners, "spec", "listeners")
	_ = unstructured.SetNestedSlice(topOnly.Object,
		[]any{map[string]any{
			"name": "http",
			"conditions": []any{map[string]any{
				"type": "Programmed", "status": "True", "observedGeneration": int64(1)}},
		}},
		"status", "listeners")
	_ = unstructured.SetNestedSlice(topOnly.Object,
		[]any{map[string]any{
			"type": "Accepted", "status": "True", "observedGeneration": int64(3)}},
		"status", "conditions")
	if gatewayObjectStuck(topOnly) {
		t.Fatal("fresh top-level conditions must not read as stuck")
	}

	// Every condition (top-level + listener) behind metadata.generation
	// → the last spec write was never seen → stuck.
	stale := gwFixture("apps", "gw", "cilium", 5)
	_ = unstructured.SetNestedSlice(stale.Object, listeners, "spec", "listeners")
	_ = unstructured.SetNestedSlice(stale.Object,
		[]any{map[string]any{
			"name": "http",
			"conditions": []any{map[string]any{
				"type": "Programmed", "status": "True", "observedGeneration": int64(4)}},
		}},
		"status", "listeners")
	_ = unstructured.SetNestedSlice(stale.Object,
		[]any{map[string]any{
			"type": "Accepted", "status": "True", "observedGeneration": int64(2)}},
		"status", "conditions")
	if !gatewayObjectStuck(stale) {
		t.Fatal("all conditions behind generation must read as stuck")
	}
}

// ---------------------------------------------------------------------------
// condMaxObservedGeneration — the conditions-slice max helper
// ---------------------------------------------------------------------------

// 0 is the "no generation ever reported" reading: nil/empty slices
// and generation-less entries must not poison the max — the caller
// compares it against metadata.generation which is always >= 1.
// (Malformed serialized conditions are skipped one layer down, by
// kube.Conditions — covered in the shared package's tests.)
func TestCondMaxObservedGeneration(t *testing.T) {
	if got := condMaxObservedGeneration(nil); got != 0 {
		t.Fatalf("nil conditions = %v, want 0", got)
	}
	if got := condMaxObservedGeneration([]kube.Condition{}); got != 0 {
		t.Fatalf("empty conditions = %v, want 0", got)
	}
	// Entries that never reported a generation read as 0 and are
	// skipped by the max — the largest real observedGeneration wins.
	got := condMaxObservedGeneration([]kube.Condition{
		{Type: "Accepted", ObservedGeneration: 2},
		{Type: "ResolvedRefs", ObservedGeneration: 7},
		{Type: "Orphan"}, // no observedGeneration at all
	})
	if got != 7 {
		t.Fatalf("condMaxObservedGeneration = %v, want 7", got)
	}
}

// ---------------------------------------------------------------------------
// ciliumOwnsGatewayObject — class→controller attribution for Gateways
// ---------------------------------------------------------------------------

// Only a Gateway whose class resolves to cilium's controllerName is
// cilium-operator's responsibility. An unresolvable class keeps the
// object in the stuck set — ownership cannot be disproven.
func TestCiliumOwnsGatewayObject(t *testing.T) {
	classes := []runtime.Object{
		gwClassFixture("cilium", ciliumGatewayController),
		gwClassFixture("cloudflare-tunnel", foreignGatewayController),
	}

	p := newGatewayClassAwareProber(classes...)
	if !ciliumOwnsGatewayObject(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p), gwFixture("apps", "gw", "cilium", 1)) {
		t.Fatal("cilium-class Gateway must be owned by cilium-operator")
	}
	if ciliumOwnsGatewayObject(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p), gwFixture("apps", "gw", "cloudflare-tunnel", 1)) {
		t.Fatal("foreign-class Gateway must NOT be owned by cilium-operator")
	}
	if !ciliumOwnsGatewayObject(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p), gwFixture("apps", "gw", "no-such-class", 1)) {
		t.Fatal("unresolvable class must keep the object (cannot disprove ownership)")
	}
}

// ---------------------------------------------------------------------------
// ciliumOwnsRouteParent — parentRef→Gateway→class attribution for routes
// ---------------------------------------------------------------------------

// The route filter resolves spec.parentRefs to their Gateways. false
// requires at least one resolved parent AND none of them cilium's —
// every failure mode (no refs, missing Gateway, unknown class) keeps
// the route in the stuck set.
func TestCiliumOwnsRouteParent(t *testing.T) {
	classes := []runtime.Object{
		gwClassFixture("cilium", ciliumGatewayController),
		gwClassFixture("cloudflare-tunnel", foreignGatewayController),
	}

	// Parent resolves to a cilium-class Gateway → cilium's problem.
	p := newGatewayClassAwareProber(classes...)
	putGateway(t, p.Dyn, gwFixture("apps", "gw-cilium", "cilium", 1))
	if !ciliumOwnsRouteParent(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p),
		routeFixture("apps", "r", 1, []any{map[string]any{"name": "gw-cilium"}})) {
		t.Fatal("route attached to a cilium-class Gateway must be owned by cilium")
	}

	// Parent resolves to a foreign-class Gateway → proven foreign.
	p = newGatewayClassAwareProber(classes...)
	putGateway(t, p.Dyn, gwFixture("apps", "gw-foreign", "cloudflare-tunnel", 1))
	if ciliumOwnsRouteParent(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p),
		routeFixture("apps", "r", 1, []any{map[string]any{"name": "gw-foreign"}})) {
		t.Fatal("route attached to a foreign-class Gateway must NOT be owned by cilium")
	}

	// ParentRef names a Gateway that does not exist — attribution
	// unresolvable → kept.
	p = newGatewayClassAwareProber(classes...)
	if !ciliumOwnsRouteParent(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p),
		routeFixture("apps", "r", 1, []any{map[string]any{"name": "missing-gw"}})) {
		t.Fatal("unresolvable parent Gateway must keep the route")
	}

	// No parentRefs at all → nothing to attribute → kept.
	if !ciliumOwnsRouteParent(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p), routeFixture("apps", "r", 1, nil)) {
		t.Fatal("route without parentRefs must keep the route")
	}

	// A parentRef may point across namespaces — the ref's own
	// namespace field is honored over the route's.
	p = newGatewayClassAwareProber(classes...)
	putGateway(t, p.Dyn, gwFixture("infra", "gw-foreign", "cloudflare-tunnel", 1))
	if ciliumOwnsRouteParent(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p),
		routeFixture("apps", "r", 1,
			[]any{map[string]any{"name": "gw-foreign", "namespace": "infra"}})) {
		t.Fatal("cross-namespace foreign parent must NOT be owned by cilium")
	}

	// Mixed parents — a foreign parent resolved first must not
	// short-circuit: one cilium parent anywhere wins ownership.
	p = newGatewayClassAwareProber(classes...)
	putGateway(t, p.Dyn, gwFixture("apps", "gw-foreign", "cloudflare-tunnel", 1))
	putGateway(t, p.Dyn, gwFixture("apps", "gw-cilium", "cilium", 1))
	if !ciliumOwnsRouteParent(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p),
		routeFixture("apps", "r", 1, []any{
			map[string]any{"name": "gw-foreign"},
			map[string]any{"name": "gw-cilium"},
		})) {
		t.Fatal("one cilium parent among resolved parents must keep the route")
	}

	// Non-Gateway parent kinds (kind/group filters) are skipped
	// entirely — a Service-only parentRef proves nothing → kept.
	if !ciliumOwnsRouteParent(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p),
		routeFixture("apps", "r", 1, []any{
			map[string]any{"name": "backend", "kind": "Service"},
			map[string]any{"name": "other", "group": "example.io"},
		})) {
		t.Fatal("non-Gateway parentRefs must not disprove cilium ownership")
	}
}

// ---------------------------------------------------------------------------
// gatewayClassStuck — the GatewayClass-kind signature
// ---------------------------------------------------------------------------

// The class kind carries no top-level status.observedGeneration: the
// serving controller reports the last reconciled generation inside
// status.conditions[type=Accepted].observedGeneration. No Accepted
// entry means never picked up; a lagging one means the last spec
// write was never seen.
func TestGatewayClassStuck(t *testing.T) {
	accepted := func(og int64, status string) map[string]any {
		return map[string]any{
			"type": "Accepted", "status": status, "observedGeneration": og}
	}

	// Never accepted → the controller never picked the class up.
	bare := gwClassFixtureBare("cilium", ciliumGatewayController, 1)
	if !gatewayClassStuck(bare) {
		t.Fatal("GatewayClass without status.conditions must read as stuck")
	}

	// Accepted at the current generation → healthy.
	fresh := gwClassFixtureBare("cilium", ciliumGatewayController, 3)
	_ = unstructured.SetNestedSlice(fresh.Object,
		[]any{accepted(int64(3), "True")}, "status", "conditions")
	if gatewayClassStuck(fresh) {
		t.Fatal("Accepted at the current generation must not read as stuck")
	}

	// Accepted once but behind the last spec write (gen 5) → stuck.
	stale := gwClassFixtureBare("cilium", ciliumGatewayController, 5)
	_ = unstructured.SetNestedSlice(stale.Object,
		[]any{accepted(int64(4), "True")}, "status", "conditions")
	if !gatewayClassStuck(stale) {
		t.Fatal("Accepted og 4 behind generation 5 must read as stuck")
	}

	// The Accepted VALUE is irrelevant — a fresh False verdict still
	// proves the controller read the current generation.
	rejected := gwClassFixtureBare("cilium", ciliumGatewayController, 2)
	_ = unstructured.SetNestedSlice(rejected.Object,
		[]any{accepted(int64(2), "False")}, "status", "conditions")
	if gatewayClassStuck(rejected) {
		t.Fatal("Accepted=False at the current generation must not read as stuck")
	}

	// Conditions exist but none of them is Accepted → never
	// accepted (other condition types prove nothing on their own).
	noAccepted := gwClassFixtureBare("cilium", ciliumGatewayController, 2)
	_ = unstructured.SetNestedSlice(noAccepted.Object, []any{map[string]any{
		"type": "SupportedVersion", "status": "True", "observedGeneration": int64(2)}},
		"status", "conditions")
	if !gatewayClassStuck(noAccepted) {
		t.Fatal("conditions without an Accepted entry must read as stuck")
	}

	// An Accepted entry with no observedGeneration field reports no
	// generation signal — reads as 0 < generation → stuck.
	noOG := gwClassFixtureBare("cilium", ciliumGatewayController, 1)
	_ = unstructured.SetNestedSlice(noOG.Object, []any{map[string]any{
		"type": "Accepted", "status": "True"}},
		"status", "conditions")
	if !gatewayClassStuck(noOG) {
		t.Fatal("Accepted without observedGeneration must read as stuck")
	}

	// Malformed entries are skipped without poisoning the verdict:
	// the real Accepted condition still decides.
	mixed := gwClassFixtureBare("cilium", ciliumGatewayController, 2)
	_ = unstructured.SetNestedSlice(mixed.Object, []any{
		"not-a-map",
		accepted(int64(2), "True"),
	}, "status", "conditions")
	if gatewayClassStuck(mixed) {
		t.Fatal("non-map entries must not poison a fresh Accepted verdict")
	}
}

// gwClassFixtureBare is gwClassFixture without the status half — the
// building block for gatewayClassStuck cases that shape their own
// conditions. Generation is set explicitly (a real class bumps it on
// every spec write).
func gwClassFixtureBare(name, controller string, gen int64) *unstructured.Unstructured {
	obj := probetest.UnstructuredObj("gateway.networking.k8s.io/v1", "GatewayClass", "", name, gen, 0)
	_ = unstructured.SetNestedField(obj.Object, controller, "spec", "controllerName")
	return obj
}

// ---------------------------------------------------------------------------
// ciliumOwnsGatewayClass — direct controllerName attribution
// ---------------------------------------------------------------------------

// The class object carries its own spec.controllerName — no lookup.
// Only a PROVEN foreign controller drops it from cilium's stuck set;
// an absent controllerName cannot disprove ownership.
func TestCiliumOwnsGatewayClass(t *testing.T) {
	p := newGatewayClassAwareProber()
	if !ciliumOwnsGatewayClass(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p),
		gwClassFixtureBare("cilium", ciliumGatewayController, 1)) {
		t.Fatal("cilium-controller class must be owned by cilium-operator")
	}
	if ciliumOwnsGatewayClass(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p),
		gwClassFixtureBare("cloudflare-tunnel", foreignGatewayController, 1)) {
		t.Fatal("foreign-controller class must NOT be owned by cilium-operator")
	}
	if !ciliumOwnsGatewayClass(ctx, probetest.MustCheck[*operatorWorkqueueCheck](t, p), gwClassFixtureBare("orphan", "", 1)) {
		t.Fatal("absent controllerName must keep the class (cannot disprove)")
	}
}

// ---------------------------------------------------------------------------
// gatewayClassController — class list caching
// ---------------------------------------------------------------------------

// The class set is cached ~1 minute so a stuck sweep doesn't LIST
// GatewayClasses once per object: a second resolution inside the
// window must answer from the check's gwClassCtlr cache even if the
// class objects disappear from the apiserver underneath.
func TestGatewayClassControllerCache(t *testing.T) {
	base := time.Now()
	p := newGatewayClassAwareProber(
		gwClassFixture("cilium", ciliumGatewayController))
	probetest.FreezeNow(p.Deps, base)

	ctlr, ok := probetest.MustCheck[*operatorWorkqueueCheck](t, p).gatewayClassController(ctx, "cilium")
	if !ok || ctlr != ciliumGatewayController {
		t.Fatalf("first resolve = %q,%v want %q,true", ctlr, ok, ciliumGatewayController)
	}
	if probetest.MustCheck[*operatorWorkqueueCheck](t, p).gwClassCtlr == nil {
		t.Fatal("class map not cached after first resolve")
	}

	// Delete the class object — inside the cache window the answer
	// must come from the gwClassCtlr cache, not a fresh LIST (which
	// would now return an empty set and ok=false).
	if err := p.Dyn.Resource(kube.GVRGatewayClass).
		Delete(ctx, "cilium", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete class: %v", err)
	}
	ctlr, ok = probetest.MustCheck[*operatorWorkqueueCheck](t, p).gatewayClassController(ctx, "cilium")
	if !ok || ctlr != ciliumGatewayController {
		t.Fatalf("cached resolve = %q,%v want %q,true", ctlr, ok, ciliumGatewayController)
	}
}

// ---------------------------------------------------------------------------
// checkOperatorWorkqueues — the owns filter end-to-end
// ---------------------------------------------------------------------------

// A stuck HTTPRoute whose parent resolves to a foreign-class Gateway
// must never enter cilium-operator's stuck set: no first-seen entry,
// no gauge, and — most importantly — a heal would never bounce
// cilium's leader over someone else's queue.
func TestCheckOperatorWorkqueuesForeignGatewaySkipped(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "cilium-operator", opReasonStaleGWStatus)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("kube-system", "cilium-operator-resource-lock",
			"cilium-operator-aa_uid", 2*time.Second, base))
	// Route is stuck (no status.parents) but provably foreign-owned.
	route := routeFixture("apps", "r-foreign", 1,
		[]any{map[string]any{"name": "gw-foreign"}})
	dyn := testutil.NewDynamicClient(route,
		gwClassFixture("cilium", ciliumGatewayController),
		gwClassFixture("cloudflare-tunnel", foreignGatewayController))
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)
	putGateway(t, p.Dyn, gwFixture("apps", "gw-foreign", "cloudflare-tunnel", 1))

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("foreign-owned stuck route must pass quietly: %+v", res)
	}
	for _, k := range probetest.LedgerKeys(&probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen) {
		t.Fatalf("foreign-owned route entered cilium's stuck set: %s", k)
	}
}

// The mirror: the same stuck route attached to a cilium-class Gateway
// IS tracked — first-seen lands under the
// "cilium-operator/httproutes/<ns>/<name>" signature key.
func TestCheckOperatorWorkqueuesCiliumGatewayTracked(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "cilium-operator", opReasonStaleGWStatus)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("kube-system", "cilium-operator-resource-lock",
			"cilium-operator-aa_uid", 2*time.Second, base))
	route := routeFixture("apps", "r-cilium", 1,
		[]any{map[string]any{"name": "gw-cilium"}})
	dyn := testutil.NewDynamicClient(route,
		gwClassFixture("cilium", ciliumGatewayController),
		gwClassFixture("cloudflare-tunnel", foreignGatewayController))
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)
	putGateway(t, p.Dyn, gwFixture("apps", "gw-cilium", "cilium", 1))

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	want := "cilium-operator/httproutes/apps/r-cilium"
	if _, ok := probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen.Seen(want, base); !ok {
		t.Fatalf("cilium-owned stuck route not tracked under %q: %v",
			want, probetest.LedgerKeys(&probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen))
	}
}

// ---------------------------------------------------------------------------
// checkOperatorWorkqueues — the gatewayclasses entry end-to-end
// ---------------------------------------------------------------------------

// A never-accepted GatewayClass served by cilium's controller is
// tracked under "cilium-operator/gatewayclasses//<name>" — while the
// same never-accepted class owned by a foreign controller must NOT
// enter the stuck set: proven foreign ownership applies to the class
// kind exactly as it does to Gateways and routes.
func TestCheckOperatorWorkqueuesGatewayClassOwnership(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "cilium-operator", opReasonStaleGWStatus)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("kube-system", "cilium-operator-resource-lock",
			"cilium-operator-aa_uid", 2*time.Second, base))
	dyn := testutil.NewDynamicClient( // Never accepted (no status.conditions) — stuck by signature.
		gwClassFixtureBare("cilium", ciliumGatewayController, 1),
		gwClassFixtureBare("cloudflare-tunnel", foreignGatewayController, 1))
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	if _, ok := probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen.
		Seen("cilium-operator/gatewayclasses//cilium", base); !ok {
		t.Fatalf("never-accepted cilium class not tracked: %v",
			probetest.LedgerKeys(&probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen))
	}
	for _, k := range probetest.LedgerKeys(&probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen) {
		if strings.Contains(k, "cloudflare-tunnel") {
			t.Fatalf("foreign-owned class entered cilium's stuck set: %s", k)
		}
	}
}

// The genuinely-stale case: a cilium class whose Accepted condition
// still reports an older generation past the stuck window freezes the
// check and lifts the stale_gateway_status gauge — the real signal
// the signature exists for.
func TestCheckOperatorWorkqueuesGatewayClassStaleFreezes(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "cilium-operator", opReasonStaleGWStatus)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("kube-system", "cilium-operator-resource-lock",
			"cilium-operator-aa_uid", 2*time.Second, base))
	stale := gwClassFixtureBare("cilium", ciliumGatewayController, 5)
	_ = unstructured.SetNestedSlice(stale.Object, []any{map[string]any{
		"type": "Accepted", "status": "True", "observedGeneration": int64(4)}},
		"status", "conditions")
	dyn := testutil.NewDynamicClient(stale)
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)
	probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen.
		Observe("cilium-operator/gatewayclasses//cilium", base.Add(-time.Hour))

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stale cilium GatewayClass past the window must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "cilium-operator", opReasonStaleGWStatus); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}

// The healthy mirror: a class Accepted at its current generation is
// not even tracked — no first-seen, no gauge.
func TestCheckOperatorWorkqueuesGatewayClassHealthyQuiet(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "cilium-operator", opReasonStaleGWStatus)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("kube-system", "cilium-operator-resource-lock",
			"cilium-operator-aa_uid", 2*time.Second, base))
	dyn := testutil.NewDynamicClient(gwClassFixture("cilium", ciliumGatewayController))
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, base)

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("healthy accepted class must keep the check quiet: %+v", res)
	}
	for _, k := range probetest.LedgerKeys(&probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen) {
		t.Fatalf("healthy class entered the stuck set: %s", k)
	}
}

// gateway_route_health_verdicts_test.go — coverage for the
// gateway-route-health verdict helpers: the lazy ReferenceGrant
// census (loadGrants) — its inconclusive-error contract, the
// per-census memoization, and tolerating a ReferenceGrant version
// the cluster does not serve.
package nethealth

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// grantObj builds a ReferenceGrant at the served apiVersion —
// from front-ns HTTPRoutes to Services in its own (backend) ns.
func grantObj(apiVersion, ns, name, fromNS string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion, "kind": "ReferenceGrant",
		"metadata": map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"from": []any{map[string]any{
				"group": "gateway.networking.k8s.io",
				"kind":  "HTTPRoute", "namespace": fromNS}},
			"to": []any{map[string]any{
				"group": "", "kind": "Service"}},
		},
	}}
}

// A ReferenceGrant LIST failure marks the census inconclusive — the
// route verdicts flag nothing on a partial grant picture (a missed
// grant would false-positive every cross-namespace backend in the
// cluster). The load is tried ONCE per census: the second call
// short-circuits on grantsTried instead of re-listing.
func TestGatewayLoadGrantsListErrorInconclusive(t *testing.T) {
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false))
	dyn := probetest.OpDyn()
	lists := 0
	dyn.PrependReactor("list", "referencegrants",
		func(ktesting.Action) (bool, runtime.Object, error) {
			lists++
			return true, nil, errors.New("api down")
		})
	p := probetest.NewCheckProber(cs, dyn, NewGatewayRouteHealthCheck)
	chk := p.Checks[0].(*gatewayRouteHealthCheck)

	before := testutil.QueueErrorCount(t, p.Name)
	c := newGatewayRouteCensus()
	chk.loadGrants(ctx, logr.Discard(), c)
	if !c.grantsErr {
		t.Fatal("list error did not mark the grant census inconclusive")
	}
	if got := testutil.QueueErrorCount(t, p.Name) - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1 — the list failure is counted", got)
	}

	chk.loadGrants(ctx, logr.Discard(), c) // memoized — no re-list
	if lists != 1 {
		t.Fatalf("referencegrants listed %d times, want 1 — grantsTried must memoize the failure", lists)
	}
}

// A version the cluster does not serve (NotFound) is tolerated —
// the served versions still merge into the census, decoded down to
// the from/to tuples the backendRefGranted check matches on.
func TestGatewayLoadGrantsToleratesUnservedVersion(t *testing.T) {
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false))
	dyn := probetest.OpDyn(
		grantObj("gateway.networking.k8s.io/v1alpha2", "backend-ns", "g1", "front-ns"))
	dyn.PrependReactor("list", "referencegrants",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			gvr := a.(ktesting.ListAction).GetResource()
			if gvr.Version == "v1beta1" {
				return true, nil, apierrors.NewNotFound(gvr.GroupResource(), "")
			}
			return false, nil, nil // v1alpha2 falls through to the tracker
		})
	p := probetest.NewCheckProber(cs, dyn, NewGatewayRouteHealthCheck)
	chk := p.Checks[0].(*gatewayRouteHealthCheck)

	c := newGatewayRouteCensus()
	chk.loadGrants(ctx, logr.Discard(), c)
	if c.grantsErr {
		t.Fatal("unserved version marked the census inconclusive — must read as 'not served', not an error")
	}
	if len(c.grants) != 1 {
		t.Fatalf("grants = %d, want 1 — the v1alpha2 grant must still load", len(c.grants))
	}
	g := c.grants[0]
	if g.ns != "backend-ns" || len(g.from) != 1 || g.from[0].namespace != "front-ns" {
		t.Fatalf("decoded grant = %+v, want backend-ns grant from front-ns", g)
	}
}

// With no errors the load lists each served version exactly once —
// the census memoizes, so a second loadGrants pays nothing.
func TestGatewayLoadGrantsMemoizesPerCensus(t *testing.T) {
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false))
	dyn := probetest.OpDyn()
	lists := 0
	dyn.PrependReactor("list", "referencegrants",
		func(ktesting.Action) (bool, runtime.Object, error) {
			lists++
			return false, nil, nil
		})
	p := probetest.NewCheckProber(cs, dyn, NewGatewayRouteHealthCheck)
	chk := p.Checks[0].(*gatewayRouteHealthCheck)

	c := newGatewayRouteCensus()
	chk.loadGrants(ctx, logr.Discard(), c)
	chk.loadGrants(ctx, logr.Discard(), c)
	if lists != len(referenceGrantGVRs) {
		t.Fatalf("referencegrants listed %d times, want %d — once per served version", lists, len(referenceGrantGVRs))
	}
}

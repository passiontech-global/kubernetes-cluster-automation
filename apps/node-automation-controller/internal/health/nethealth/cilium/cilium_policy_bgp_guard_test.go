// cilium_policy_bgp_guard_test.go — coverage for cilium-policy-bgp-guard (#70):
// CNP/CCNP status.nodes.ok=false, Cilium 1.17+ Valid=False / derivativePolicies,
// CiliumBGPNodeConfig v2 & v2alpha1 peer states, 10m/5m persistence hysteresis,
// 404/NoMatch prune vs 403 Forbidden carry-forward, and GaugeLedger cleanup.
package cilium

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func makeCNP(ns, name string, status map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"namespace": ns,
			"name":      name,
		},
		"status": status,
	}}
}

func makeCCNP(name string, status map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumClusterwideNetworkPolicy",
		"metadata": map[string]any{
			"name": name,
		},
		"status": status,
	}}
}

func makeBGPNodeConfig(apiVersion, node string, instances []any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       "CiliumBGPNodeConfig",
		"metadata": map[string]any{
			"name": node,
		},
		"status": map[string]any{
			"bgpInstances": instances,
		},
	}}
}

func policyErrorSeries(t *testing.T, kind, ns, name string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_cilium_policy_error",
		map[string]string{"kind": kind, "namespace": ns, "name": name})
}

func bgpPeerDownSeries(t *testing.T, node, asn, peer string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_cilium_bgp_peer_down",
		map[string]string{"node": node, "asn": asn, "peer": peer})
}

func TestCiliumPolicyErrorPersistenceAndRecovery(t *testing.T) {
	now := time.Now()
	badCNP := makeCNP("apps", "bad-fqdn", map[string]any{
		"nodes": map[string]any{
			"worker-1": map[string]any{"ok": false, "error": "invalid toFQDNs regex"},
		},
	})
	badCCNPValid := makeCCNP("bad-valid", map[string]any{
		"conditions": []any{
			map[string]any{"type": "Valid", "status": "False", "message": "selector invalid"},
		},
	})
	badCCNPDeriv := makeCCNP("bad-deriv", map[string]any{
		"derivativePolicies": map[string]any{
			"deriv-1": map[string]any{"ok": false, "error": "compile error"},
		},
	})
	healthyCNP := makeCNP("apps", "ok-pol", map[string]any{
		"nodes": map[string]any{
			"worker-1": map[string]any{"ok": true},
		},
		"conditions": []any{
			map[string]any{"type": "Valid", "status": "True"},
		},
	})

	dyn := probetest.OpDyn(badCNP, badCCNPValid, badCCNPDeriv, healthyCNP)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*ciliumPolicyBGPGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("t=0s must arm inside 10m window, got %+v", res)
	}
	if _, ok := policyErrorSeries(t, "CiliumNetworkPolicy", "apps", "bad-fqdn"); ok {
		t.Fatal("policy error gauge emitted before 10m window")
	}

	probetest.FreezeNow(p.Deps, now.Add(9*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("t=9m must still pass inside 10m window, got %+v", res)
	}

	probetest.FreezeNow(p.Deps, now.Add(11*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=11m expected failure after 10m persistence")
	}
	for _, tc := range [][3]string{
		{"CiliumNetworkPolicy", "apps", "bad-fqdn"},
		{"CiliumClusterwideNetworkPolicy", "", "bad-valid"},
		{"CiliumClusterwideNetworkPolicy", "", "bad-deriv"},
	} {
		if v, ok := policyErrorSeries(t, tc[0], tc[1], tc[2]); !ok || v != 1 {
			t.Fatalf("missing policy error series for %v: v=%v ok=%v", tc, v, ok)
		}
	}
	if _, ok := policyErrorSeries(t, "CiliumNetworkPolicy", "apps", "ok-pol"); ok {
		t.Fatal("healthy CNP should not emit gauge")
	}

	// Recover all policies -> stale gauge tuples must be deleted.
	cleanDyn := probetest.OpDyn(healthyCNP)
	chk.Dyn = cleanDyn
	probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered sweep must pass: %+v", res)
	}
	for _, tc := range [][3]string{
		{"CiliumNetworkPolicy", "apps", "bad-fqdn"},
		{"CiliumClusterwideNetworkPolicy", "", "bad-valid"},
		{"CiliumClusterwideNetworkPolicy", "", "bad-deriv"},
	} {
		if _, ok := policyErrorSeries(t, tc[0], tc[1], tc[2]); ok {
			t.Fatalf("stale policy error series not deleted for %v", tc)
		}
	}
}

func TestCiliumBGPPeerDownV2AndV2Alpha1Fallback(t *testing.T) {
	now := time.Now()
	// v2alpha1 object; simulate v2 CRD absent so AllUnstructuredFirst falls back to v2alpha1.
	cfgDown := makeBGPNodeConfig("cilium.io/v2alpha1", "worker-bgp-1", []any{
		map[string]any{
			"localASN": int64(65001),
			"peers": []any{
				map[string]any{"peerAddress": "10.0.0.1", "sessionState": "Established"},
				map[string]any{"peerAddress": "10.0.0.2", "sessionState": "active"},
				map[string]any{"name": "tor-b", "sessionState": "idle"},
				map[string]any{"sessionState": ""},
			},
		},
	})

	dyn := probetest.OpDyn(cfgDown)
	dyn.PrependReactor("list", "ciliumbgpnodeconfigs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Version == "v2" {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "cilium.io", Resource: "ciliumbgpnodeconfigs"}, "")
		}
		return false, nil, nil
	})

	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*ciliumPolicyBGPGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("t=0s must arm inside 5m window, got %+v", res)
	}

	probetest.FreezeNow(p.Deps, now.Add(6*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=6m expected failure for non-established BGP peers")
	}
	if _, ok := bgpPeerDownSeries(t, "worker-bgp-1", "65001", "10.0.0.1"); ok {
		t.Fatal("Established peer must not emit down series")
	}
	for _, peer := range []string{"10.0.0.2", "tor-b", "unknown"} {
		if v, ok := bgpPeerDownSeries(t, "worker-bgp-1", "65001", peer); !ok || v != 1 {
			t.Fatalf("missing BGP peer down series for peer=%q: v=%v ok=%v", peer, v, ok)
		}
	}

	// Recover peers -> stale series pruned.
	cfgUp := makeBGPNodeConfig("cilium.io/v2alpha1", "worker-bgp-1", []any{
		map[string]any{
			"localASN": int64(65001),
			"peers": []any{
				map[string]any{"peerAddress": "10.0.0.1", "sessionState": "established"},
				map[string]any{"peerAddress": "10.0.0.2", "sessionState": "Established"},
				map[string]any{"name": "tor-b", "sessionState": "established"},
			},
		},
	})
	dyn2 := probetest.OpDyn(cfgUp)
	dyn2.PrependReactor("list", "ciliumbgpnodeconfigs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Version == "v2" {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "cilium.io", Resource: "ciliumbgpnodeconfigs"}, "")
		}
		return false, nil, nil
	})
	chk.Dyn = dyn2
	probetest.FreezeNow(p.Deps, now.Add(10*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered BGP sweep must pass: %+v", res)
	}
	for _, peer := range []string{"10.0.0.2", "tor-b", "unknown"} {
		if _, ok := bgpPeerDownSeries(t, "worker-bgp-1", "65001", peer); ok {
			t.Fatalf("stale BGP peer down series not deleted for peer=%q", peer)
		}
	}
}

func TestCiliumPolicyBGPGuard404PrunesAnd403CarriesWithoutFail(t *testing.T) {
	now := time.Now()
	badCNP := makeCNP("apps", "cnp-held", map[string]any{
		"nodes": map[string]any{"w1": map[string]any{"ok": false}},
	})
	badCCNP := makeCCNP("ccnp-gone", map[string]any{
		"conditions": []any{map[string]any{"type": "Valid", "status": "False"}},
	})
	badBGP := makeBGPNodeConfig("cilium.io/v2", "w1", []any{
		map[string]any{
			"localASN": int64(65010),
			"peers":    []any{map[string]any{"peerAddress": "10.1.1.1", "sessionState": "connect"}},
		},
	})

	dyn := probetest.OpDyn(badCNP, badCCNP, badBGP)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*ciliumPolicyBGPGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, now.Add(11*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatal("expected initial failure to populate held tuples")
	}

	// Next sweep: CNP is 403 Forbidden (must carry held tuple, no Infra/Fail),
	// CCNP is 404 NotFound (CRD removed -> must prune its held tuple),
	// BGP is 403 Forbidden (must carry held tuple, no Infra/Fail).
	dynBlocked := probetest.OpDyn()
	dynBlocked.PrependReactor("list", "ciliumnetworkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: apierrors.NewForbidden(
			schema.GroupResource{Group: "cilium.io", Resource: "ciliumnetworkpolicies"}, "", errors.New("forbidden")).Status()}
	})
	dynBlocked.PrependReactor("list", "ciliumclusterwidenetworkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(
			schema.GroupResource{Group: "cilium.io", Resource: "ciliumclusterwidenetworkpolicies"}, "")
	})
	dynBlocked.PrependReactor("list", "ciliumbgpnodeconfigs", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "cilium.io", Resource: "ciliumbgpnodeconfigs"}, "", errors.New("forbidden"))
	})
	chk.Dyn = dynBlocked
	probetest.FreezeNow(p.Deps, now.Add(15*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass || res.Infra != nil {
		t.Fatalf("403/404 sweep must pass with nil Infra, got %+v", res)
	}
	if _, ok := policyErrorSeries(t, "CiliumNetworkPolicy", "apps", "cnp-held"); !ok {
		t.Fatal("403 Forbidden on CNP should carry held tuple")
	}
	if _, ok := policyErrorSeries(t, "CiliumClusterwideNetworkPolicy", "", "ccnp-gone"); ok {
		t.Fatal("404 NotFound on CCNP must prune stale tuple")
	}
	if _, ok := bgpPeerDownSeries(t, "w1", "65010", "10.1.1.1"); !ok {
		t.Fatal("403 Forbidden on BGP must carry held tuple")
	}

	// Verify 403 status code constant sanity (avoid unused import).
	_ = http.StatusForbidden
	// Verify non-403/404 error returns Infra.
	dynErr := probetest.OpDyn()
	dynErr.PrependReactor("list", "ciliumnetworkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver timeout")
	})
	chk.Dyn = dynErr
	resErr := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if resErr.Infra == nil || !strings.Contains(resErr.Infra.Error(), "apiserver timeout") {
		t.Fatalf("expected Infra error on transient failure, got %+v", resErr)
	}
	// Clean up gauges for subsequent tests in package.
	ciliumPolicyErrorGauge.DeleteLabelValues("CiliumNetworkPolicy", "apps", "cnp-held")
	ciliumBGPPeerDownGauge.DeleteLabelValues("w1", "65010", "10.1.1.1")
}

func TestCiliumPolicyBGPGuardPreExistingTimestampsAndRecovery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ts15m := now.Add(-15 * time.Minute).Format(time.RFC3339)
	ts10m := now.Add(-10 * time.Minute).Format(time.RFC3339)
	ts5m := now.Add(-5 * time.Minute).Format(time.RFC3339)
	ts2m := now.Add(-2 * time.Minute).Format(time.RFC3339)
	ts30m := now.Add(-30 * time.Minute).Format(time.RFC3339)

	cnpOld := makeCNP("apps", "cnp-old", map[string]any{
		"nodes": map[string]any{
			"w1": map[string]any{"ok": false, "error": "bad rule", "lastUpdated": ts15m},
		},
	})
	ccnpOld := makeCCNP("ccnp-old", map[string]any{
		"conditions": []any{
			map[string]any{"type": "Valid", "status": "False", "message": "selector invalid", "lastTransitionTime": ts15m},
		},
	})
	cnpMultiOld := makeCNP("apps", "cnp-multi", map[string]any{
		"nodes": map[string]any{
			"w1": map[string]any{"ok": false, "error": "node err", "lastUpdated": ts5m},
		},
		"conditions": []any{
			map[string]any{"type": "Valid", "status": "False", "lastTransitionTime": ts15m},
		},
	})
	cnpRecent := makeCNP("apps", "cnp-recent", map[string]any{
		"nodes": map[string]any{
			"w1": map[string]any{"ok": false, "error": "recent err", "lastUpdated": ts5m},
		},
	})
	cnpRecent.Object["metadata"].(map[string]any)["creationTimestamp"] = ts30m

	cnpNoTS := makeCNP("apps", "cnp-no-ts", map[string]any{
		"nodes": map[string]any{
			"w1": map[string]any{"ok": false, "error": "untimestamped err"},
		},
	})
	cnpNoTS.Object["metadata"].(map[string]any)["creationTimestamp"] = ts30m

	bgpCfg := makeBGPNodeConfig("cilium.io/v2", "worker-1", []any{
		map[string]any{
			"localASN": int64(65001),
			"peers": []any{
				map[string]any{"peerAddress": "10.0.0.1", "sessionState": "active", "lastTransitionTime": ts10m},
				map[string]any{"peerAddress": "10.0.0.2", "sessionState": "active", "lastTransitionTime": ts2m},
				map[string]any{"peerAddress": "10.0.0.3", "sessionState": "idle"},
			},
		},
	})
	bgpCfg.Object["metadata"].(map[string]any)["creationTimestamp"] = ts30m
	bgpCfg.Object["status"].(map[string]any)["conditions"] = []any{
		map[string]any{"type": "BGPPeerDown", "status": "True", "lastTransitionTime": ts10m},
	}

	bgpNoTS := makeBGPNodeConfig("cilium.io/v2", "worker-2", []any{
		map[string]any{
			"localASN": int64(65001),
			"peers": []any{
				map[string]any{"peerAddress": "10.0.0.4", "sessionState": "connect"},
			},
		},
	})
	bgpNoTS.Object["metadata"].(map[string]any)["creationTimestamp"] = ts30m

	dyn := probetest.OpDyn(cnpOld, ccnpOld, cnpMultiOld, cnpRecent, cnpNoTS, bgpCfg, bgpNoTS)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*ciliumPolicyBGPGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=0s expected failure for pre-existing >=10m policy and >=5m BGP errors")
	}

	for _, tc := range [][3]string{
		{"CiliumNetworkPolicy", "apps", "cnp-old"},
		{"CiliumClusterwideNetworkPolicy", "", "ccnp-old"},
		{"CiliumNetworkPolicy", "apps", "cnp-multi"},
	} {
		if v, ok := policyErrorSeries(t, tc[0], tc[1], tc[2]); !ok || v != 1 {
			t.Fatalf("t=0s missing pre-existing policy series for %v: v=%v ok=%v", tc, v, ok)
		}
	}
	for _, tc := range [][3]string{
		{"CiliumNetworkPolicy", "apps", "cnp-recent"},
		{"CiliumNetworkPolicy", "apps", "cnp-no-ts"},
	} {
		if _, ok := policyErrorSeries(t, tc[0], tc[1], tc[2]); ok {
			t.Fatalf("t=0s unexpected policy series for %v", tc)
		}
	}

	for _, peer := range []string{"10.0.0.1", "10.0.0.3"} {
		if v, ok := bgpPeerDownSeries(t, "worker-1", "65001", peer); !ok || v != 1 {
			t.Fatalf("t=0s missing pre-existing BGP series for peer=%q: v=%v ok=%v", peer, v, ok)
		}
	}
	if _, ok := bgpPeerDownSeries(t, "worker-1", "65001", "10.0.0.2"); ok {
		t.Fatal("t=0s recent peer 10.0.0.2 must not flag even when node BGPPeerDown=True is 10m old")
	}
	if _, ok := bgpPeerDownSeries(t, "worker-2", "65001", "10.0.0.4"); ok {
		t.Fatal("t=0s untimestamped peer 10.0.0.4 must not fall back to creationTimestamp")
	}

	// Timestamped items must stay out of FirstSeenLedger; only untimestamped items enter.
	for _, k := range []string{
		"CiliumNetworkPolicy/apps/cnp-old",
		"CiliumClusterwideNetworkPolicy//ccnp-old",
		"CiliumNetworkPolicy/apps/cnp-multi",
		"CiliumNetworkPolicy/apps/cnp-recent",
	} {
		if _, tracked := chk.policySeen.Seen(k, now); tracked {
			t.Fatalf("timestamped policy %s must not enter policySeen", k)
		}
	}
	if _, tracked := chk.policySeen.Seen("CiliumNetworkPolicy/apps/cnp-no-ts", now); !tracked {
		t.Fatal("untimestamped policy cnp-no-ts must enter policySeen fallback")
	}
	for _, k := range []string{
		"worker-1/65001/10.0.0.1",
		"worker-1/65001/10.0.0.2",
		"worker-1/65001/10.0.0.3",
	} {
		if _, tracked := chk.bgpSeen.Seen(k, now); tracked {
			t.Fatalf("timestamped BGP peer %s must not enter bgpSeen", k)
		}
	}
	if _, tracked := chk.bgpSeen.Seen("worker-2/65001/10.0.0.4", now); !tracked {
		t.Fatal("untimestamped BGP peer worker-2/65001/10.0.0.4 must enter bgpSeen fallback")
	}

	// Advance +6m: recent timestamped entries (cnp-recent=11m, 10.0.0.2=8m) and
	// untimestamped BGP peer (6m) now flag, while cnp-no-ts (6m < 10m) still holds.
	probetest.FreezeNow(p.Deps, now.Add(6*time.Minute))
	res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=6m expected failure")
	}
	if v, ok := policyErrorSeries(t, "CiliumNetworkPolicy", "apps", "cnp-recent"); !ok || v != 1 {
		t.Fatalf("t=6m expected cnp-recent to flag: v=%v ok=%v", v, ok)
	}
	if _, ok := policyErrorSeries(t, "CiliumNetworkPolicy", "apps", "cnp-no-ts"); ok {
		t.Fatal("t=6m cnp-no-ts must remain inside 10m FirstSeenLedger window")
	}
	if v, ok := bgpPeerDownSeries(t, "worker-1", "65001", "10.0.0.2"); !ok || v != 1 {
		t.Fatalf("t=6m expected peer 10.0.0.2 to flag: v=%v ok=%v", v, ok)
	}
	if v, ok := bgpPeerDownSeries(t, "worker-2", "65001", "10.0.0.4"); !ok || v != 1 {
		t.Fatalf("t=6m expected peer 10.0.0.4 to flag via bgpSeen: v=%v ok=%v", v, ok)
	}

	// Recover all -> Pass=true and all GaugeLedger series deleted.
	healthyCNP := makeCNP("apps", "cnp-old", map[string]any{
		"nodes": map[string]any{"w1": map[string]any{"ok": true}},
	})
	healthyBGP := makeBGPNodeConfig("cilium.io/v2", "worker-1", []any{
		map[string]any{
			"localASN": int64(65001),
			"peers": []any{
				map[string]any{"peerAddress": "10.0.0.1", "sessionState": "established"},
				map[string]any{"peerAddress": "10.0.0.2", "sessionState": "established"},
				map[string]any{"peerAddress": "10.0.0.3", "sessionState": "established"},
			},
		},
	})
	chk.Dyn = probetest.OpDyn(healthyCNP, healthyBGP)
	probetest.FreezeNow(p.Deps, now.Add(8*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered sweep must pass: %+v", res)
	}
	for _, tc := range [][3]string{
		{"CiliumNetworkPolicy", "apps", "cnp-old"},
		{"CiliumClusterwideNetworkPolicy", "", "ccnp-old"},
		{"CiliumNetworkPolicy", "apps", "cnp-multi"},
		{"CiliumNetworkPolicy", "apps", "cnp-recent"},
	} {
		if _, ok := policyErrorSeries(t, tc[0], tc[1], tc[2]); ok {
			t.Fatalf("stale policy series not deleted for %v", tc)
		}
	}
	for _, tc := range [][3]string{
		{"worker-1", "65001", "10.0.0.1"},
		{"worker-1", "65001", "10.0.0.2"},
		{"worker-1", "65001", "10.0.0.3"},
		{"worker-2", "65001", "10.0.0.4"},
	} {
		if _, ok := bgpPeerDownSeries(t, tc[0], tc[1], tc[2]); ok {
			t.Fatalf("stale BGP series not deleted for %v", tc)
		}
	}
}

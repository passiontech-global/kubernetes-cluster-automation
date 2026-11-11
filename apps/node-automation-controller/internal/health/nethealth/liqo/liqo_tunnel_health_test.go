// liqo_tunnel_health_test.go — coverage for the liqo-tunnel-health
// check: dead-peer gateway bounces, peer identity resolution and the
// disconnected-window reader. Split from the former
// cloudflared_liqo_tunnel_health_test.go; the cloudflared half lives
// in nethealth/cloudflared.
package liqo

import (
	"strings"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// liqoObj builds a minimal unstructured liqo object with the given
// labels and a status.conditions list.
func liqoObj(name string, labels map[string]string,
	conds ...map[string]any) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.liqo.io/v1", "kind": "VirtualNode",
		"metadata": map[string]any{"name": name, "namespace": "liqo"},
	}}
	if labels != nil {
		obj.SetLabels(labels)
	}
	if len(conds) > 0 {
		_ = unstructured.SetNestedSlice(obj.Object, condsToAny(conds),
			"status", "conditions")
	}
	return obj
}

func condsToAny(conds []map[string]any) []any {
	out := make([]any, len(conds))
	for i, c := range conds {
		out[i] = c
	}
	return out
}

// liqoConnection builds a networking.liqo.io Connection whose
// Connected condition transitioned to the given status `age` ago.
func liqoConnection(ns, name, status string, age time.Duration) *unstructured.Unstructured {
	obj := testutil.Unstructured(
		kube.GVRLiqoConnection.GroupVersion().WithKind("Connection"), ns, name,
		map[string]any{
			"metadata": map[string]any{
				"namespace": ns, "name": name,
				"labels": map[string]any{
					"networking.liqo.io/remote-cluster-id": "peer-b"},
			},
			"status": map[string]any{
				"conditions": []any{map[string]any{
					"type":   "Connected",
					"status": status,
					"lastTransitionTime": time.Now().
						Add(-age).UTC().Format(time.RFC3339)}},
			}})
	return obj
}

func TestLiqoDeadPeerBouncesGateway(t *testing.T) {
	conn := liqoConnection("liqo-tenant", "conn-peer-b", "False", 20*time.Minute)
	gw := probetest.PodWithPhase("liqo-tenant", "liqo-gateway-wireguard-0",
		corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(gw)
	p := testProberDyn(cs, probetest.OpDyn(conn))
	res := probetest.MustCheck[*liqoTunnelHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("dead peer must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "peer-b") {
		t.Fatalf("why missing peer: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods("liqo-tenant").Get(ctx, "liqo-gateway-wireguard-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("liqo-gateway pod should be bounced, err=%v", err)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_liqo_peer_unhealthy",
		map[string]string{"peer": "peer-b", "reason": "connection_disconnected"}); !ok || v != 1 {
		t.Fatalf("peer gauge = %v,%v want 1,true", v, ok)
	}
}

// A multi-peer cluster runs one gateway pod per peer — the bounce must
// hit the failing peer's own gateway (matched by the remote-cluster-id
// label or the pod name), never a healthy peer's.
func TestLiqoBounceMatchesFailingPeer(t *testing.T) {
	conn := liqoConnection("liqo-tenant", "conn-peer-b", "False", 20*time.Minute)
	healthy := probetest.PodWithPhase("liqo-tenant",
		"liqo-gateway-wireguard-peer-a-0", corev1.PodRunning, true, 2*time.Hour)
	failing := probetest.PodWithPhase("liqo-tenant",
		"liqo-gateway-wireguard-peer-b-0", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(healthy, failing)
	p := testProberDyn(cs, probetest.OpDyn(conn))
	if res := probetest.MustCheck[*liqoTunnelHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("dead peer must fail")
	}
	if _, err := cs.CoreV1().Pods("liqo-tenant").
		Get(ctx, healthy.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy peer's gateway must survive: %v", err)
	}
	if _, err := cs.CoreV1().Pods("liqo-tenant").
		Get(ctx, failing.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("failing peer's gateway should be bounced, err=%v", err)
	}
}

// A cluster-scoped virtual-node finding (no namespace) refuses to
// bounce a gateway it cannot tie to the failing peer — an
// unattributable bounce heals nothing and can kill a healthy tunnel.
func TestLiqoVirtualNodeNoPeerMatchSkipsBounce(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "virtual-node-peer-x",
			Labels: map[string]string{"liqo.io/type": "virtual-node"},
		},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(
				time.Now().Add(-20 * time.Minute)),
		}}},
	}
	gw := probetest.PodWithPhase("liqo-tenant",
		"liqo-gateway-wireguard-peer-a-0", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(gw, node)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*liqoTunnelHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("dead virtual node must fail (finding)")
	}
	if _, err := cs.CoreV1().Pods("liqo-tenant").
		Get(ctx, gw.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("gateway not tied to the failing peer must survive: %v", err)
	}
}

// A virtual node whose Ready condition carries a zero
// LastTransitionTime falls back to the node's creation age — a
// just-created virtual node never reads as a 10m-dead peer.
func TestLiqoVirtualNodeZeroTransitionTimeUsesAge(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "virtual-node-peer-fresh",
			Labels:            map[string]string{"liqo.io/type": "virtual-node"},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Minute)),
		},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionFalse,
		}}},
	}
	cs := fake.NewSimpleClientset(node)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*liqoTunnelHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatal("a 1m-old virtual node must not read as a dead peer")
	}
	if m := probetest.FindMetric(t, "node_automation_liqo_peer_unhealthy",
		map[string]string{"peer": "virtual-node-peer-fresh",
			"reason": "virtual_node_not_ready"}); m != nil {
		t.Fatal("fresh virtual node must not raise the peer gauge")
	}
}

func TestLiqoConnectedPeerPasses(t *testing.T) {
	conn := liqoConnection("liqo-tenant", "conn-peer-b", "True", time.Hour)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(conn))
	if res := probetest.MustCheck[*liqoTunnelHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("connected peer must pass: %+v", res)
	}
}

// A CR finding that matches no gateway in a namespace holding SEVERAL
// gateways (multi-peer topology) must not fall back to bouncing any
// of them — an unattributable bounce kills a healthy peer's tunnel.
// Fallback to the namespace gateway is allowed only when the
// namespace holds exactly one gateway.
func TestLiqoCRNoPeerMatchMultiGatewaySkipsBounce(t *testing.T) {
	// Connection CR carries remote-cluster-id label peer-x — matches
	// neither gateway pod (peer-a / peer-b names and labels).
	conn := testutil.Unstructured(
		kube.GVRLiqoConnection.GroupVersion().WithKind("Connection"),
		"liqo-tenant", "conn-peer-x",
		map[string]any{
			"metadata": map[string]any{
				"namespace": "liqo-tenant", "name": "conn-peer-x",
				"labels": map[string]any{
					"networking.liqo.io/remote-cluster-id": "peer-x"},
			},
			"status": map[string]any{
				"conditions": []any{map[string]any{
					"type":   "Connected",
					"status": "False",
					"lastTransitionTime": time.Now().
						Add(-20 * time.Minute).UTC().Format(time.RFC3339)}},
			}})
	gwA := probetest.PodWithPhase("liqo-tenant",
		"liqo-gateway-wireguard-peer-a-0", corev1.PodRunning, true, 2*time.Hour)
	gwB := probetest.PodWithPhase("liqo-tenant",
		"liqo-gateway-wireguard-peer-b-0", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(gwA, gwB)
	p := testProberDyn(cs, probetest.OpDyn(conn))
	if res := probetest.MustCheck[*liqoTunnelHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("dead peer with no matching gateway must fail (finding)")
	}
	for _, gw := range []*corev1.Pod{gwA, gwB} {
		if _, err := cs.CoreV1().Pods("liqo-tenant").
			Get(ctx, gw.Name, metav1.GetOptions{}); err != nil {
			t.Fatalf("unattributable finding must not bounce gateway %s: %v", gw.Name, err)
		}
	}
}

func TestLiqoPeerName(t *testing.T) {
	cases := []struct {
		name string
		obj  *unstructured.Unstructured
		want string
	}{
		{"remote-cluster-id label",
			liqoObj("vn", map[string]string{
				"networking.liqo.io/remote-cluster-id": "edge-1"}), "edge-1"},
		{"discovery cluster-id label",
			liqoObj("vn", map[string]string{
				"discovery.liqo.io/cluster-id": "edge-2"}), "edge-2"},
		{"liqo.io label",
			liqoObj("vn", map[string]string{
				"liqo.io/remote-cluster-id": "edge-3"}), "edge-3"},
		{"status.remoteClusterID",
			func() *unstructured.Unstructured {
				o := liqoObj("vn", nil)
				_ = unstructured.SetNestedField(o.Object, "edge-4", "status", "remoteClusterID")
				return o
			}(), "edge-4"},
		{"status.clusterID",
			func() *unstructured.Unstructured {
				o := liqoObj("vn", nil)
				_ = unstructured.SetNestedField(o.Object, "edge-5", "status", "clusterID")
				return o
			}(), "edge-5"},
		{"spec.clusterID",
			func() *unstructured.Unstructured {
				o := liqoObj("vn", nil)
				_ = unstructured.SetNestedField(o.Object, "edge-6", "spec", "clusterID")
				return o
			}(), "edge-6"},
		{"first label spelling wins",
			liqoObj("vn", map[string]string{
				"networking.liqo.io/remote-cluster-id": "edge-7",
				"discovery.liqo.io/cluster-id":         "edge-8"}), "edge-7"},
		{"object name fallback",
			liqoObj("vn-edge-9", nil), "vn-edge-9"},
	}
	for _, tc := range cases {
		if got := liqoPeerName(tc.obj); got != tc.want {
			t.Errorf("%s: liqoPeerName=%q, want %q", tc.name, got, tc.want)
		}
	}
}

// liqoDisconnectedFor reports the Connected/Established=False age —
// (duration, true) only while a condition actively reports False;
// absent conditions and True statuses are not evidence of a dead
// peer. A zero transition time falls back to the object's creation
// age, and a fully unverifiable clock reads as the minimum age.
func TestLiqoDisconnectedFor(t *testing.T) {
	now := time.Now()
	transition := now.Add(-15 * time.Minute).UTC().Format(time.RFC3339)
	mkCond := func(status, ts string) map[string]any {
		c := map[string]any{"type": "Connected", "status": status}
		if ts != "" {
			c["lastTransitionTime"] = ts
		}
		return c
	}
	cases := []struct {
		name string
		obj  *unstructured.Unstructured
		want time.Duration
		ok   bool
	}{
		{"no conditions is not evidence",
			liqoObj("vn", nil), 0, false},
		{"connected true is healthy",
			liqoObj("vn", nil, mkCond("True", transition)), 0, false},
		{"connected false with transition time",
			liqoObj("vn", nil, mkCond("False", transition)), 15 * time.Minute, true},
		{"established false counts too",
			liqoObj("vn", nil, map[string]any{
				"type": "Established", "status": "False",
				"lastTransitionTime": transition}), 15 * time.Minute, true},
		{"connected true wins over a later established false",
			liqoObj("vn", nil,
				mkCond("True", transition),
				map[string]any{"type": "Established", "status": "False",
					"lastTransitionTime": transition}), 0, false},
		{"zero transition falls back to creation age",
			func() *unstructured.Unstructured {
				o := liqoObj("vn", nil, mkCond("False", ""))
				o.SetCreationTimestamp(metav1.NewTime(now.Add(-20 * time.Minute)))
				return o
			}(), 20 * time.Minute, true},
		{"fully unverifiable clock reads as minimum age",
			liqoObj("vn", nil, mkCond("False", "")), liqoPeerDisconnectMinAge, true},
	}
	for _, tc := range cases {
		got, ok := liqoDisconnectedFor(tc.obj, now)
		// Creation/transition times are second-granular — allow a
		// small skew around the exact minute.
		if ok != tc.ok || (ok && (got < tc.want-time.Second || got > tc.want+time.Second)) {
			t.Errorf("%s: liqoDisconnectedFor=(%v,%v), want ~(%v,%v)",
				tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// TestLiqoEndpointChangeBouncesGateway covers the A3 stale-conntrack
// trigger: a gatewayclient whose WireGuard endpoint MOVED between
// sweeps (peer re-anchored) bounces the peer's gateway even though
// the Connected condition never dropped — the first sighting arms
// the ledger, the move fires the bounce + the endpoint counter.
func TestLiqoEndpointChangeBouncesGateway(t *testing.T) {
	connected := map[string]any{
		"type": "Connected", "status": "True",
		"lastTransitionTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	buildCR := func(addr string) *unstructured.Unstructured {
		return testutil.Unstructured(
			kube.GVRLiqoGatewayClient.GroupVersion().WithKind("GatewayClient"),
			"liqo-tenant", "gwclient-peer-b",
			map[string]any{
				"metadata": map[string]any{
					"namespace": "liqo-tenant", "name": "gwclient-peer-b",
					"labels": map[string]any{
						"networking.liqo.io/remote-cluster-id": "peer-b"},
				},
				"status": map[string]any{
					"remoteEndpoint": map[string]any{"addr": addr, "port": int64(51871)},
					"conditions":     []any{connected},
				}})
	}
	gw := probetest.PodWithPhase("liqo-tenant", "liqo-gateway-peer-b-0",
		corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(gw)
	dyn := probetest.OpDyn(buildCR("10.9.0.1"))
	p := testProberDyn(cs, dyn)
	check := probetest.MustCheck[*liqoTunnelHealthCheck](t, p)

	// Sweep 1: endpoint arms the ledger — connected peer, no bounce.
	if res := check.Run(ctx); !res.Pass {
		t.Fatalf("first sighting must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("liqo-tenant").Get(ctx, "liqo-gateway-peer-b-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("gateway bounced on the arming sweep: %v", err)
	}
	if v := ptestutil.ToFloat64(liqoEndpointChangedTotal.WithLabelValues("peer-b")); v != 0 {
		t.Fatalf("endpoint counter armed before any move: %v", v)
	}

	// Sweep 2: the endpoint moved (a real reconcile writes the new
	// endpoint through the API — the fake tracker mirrors that) —
	// bounce + counter, Connected or not.
	moved := buildCR("10.9.0.9")
	if _, err := dyn.Resource(kube.GVRLiqoGatewayClient).
		Namespace("liqo-tenant").Update(ctx, moved, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update gatewayclient: %v", err)
	}
	if res := check.Run(ctx); res.Pass {
		t.Fatalf("endpoint move must be a finding: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("liqo-tenant").Get(ctx, "liqo-gateway-peer-b-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("gateway should be bounced after the endpoint move, err=%v", err)
	}
	if v := ptestutil.ToFloat64(liqoEndpointChangedTotal.WithLabelValues("peer-b")); v != 1 {
		t.Fatalf("endpoint counter = %v, want 1", v)
	}

	// Sweep 3: the ledger now holds the new endpoint — no repeat
	// bounce (the cooldown key would suppress it anyway, but the
	// finding must not re-fire either).
	if res := check.Run(ctx); !res.Pass {
		t.Fatalf("unchanged endpoint must pass: %+v", res)
	}
	if v := ptestutil.ToFloat64(liqoEndpointChangedTotal.WithLabelValues("peer-b")); v != 1 {
		t.Fatalf("unchanged endpoint re-fired the counter: %v", v)
	}
}

// TestLiqoEndpointOf pins the endpoint-shape resolution the change
// detector diffs against.
func TestLiqoEndpointOf(t *testing.T) {
	nested := testutil.Unstructured(
		kube.GVRLiqoGatewayServer.GroupVersion().WithKind("GatewayServer"),
		"liqo", "gws", map[string]any{
			"spec": map[string]any{
				"endpoint": map[string]any{"addr": "203.0.113.7", "port": int64(51820)}}})
	if got := liqoEndpointOf(nested); got != "203.0.113.7" {
		t.Fatalf("nested spec.endpoint.addr = %q", got)
	}
	bare := testutil.Unstructured(
		kube.GVRLiqoGatewayClient.GroupVersion().WithKind("GatewayClient"),
		"liqo", "gwc", map[string]any{
			"status": map[string]any{"remoteEndpoint": "gw.example.net"}})
	if got := liqoEndpointOf(bare); got != "gw.example.net" {
		t.Fatalf("bare status.remoteEndpoint = %q", got)
	}
	none := liqoConnection("liqo", "conn", "True", time.Minute)
	if got := liqoEndpointOf(none); got != "" {
		t.Fatalf("connection without endpoint = %q, want empty", got)
	}
}

// cloudflared_liqo_tunnel_health_test.go — coverage for the
// cloudflared-tunnel-health and liqo-tunnel-health checks: ha-0
// metrics persistence + sibling-gated delete, and dead-peer
// gateway bounces.
package nethealth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// cfPod builds a Running+Ready cloudflared pod owned by `owner` with
// the given podIP.
func cfPod(ns, name, ip string, owner types.UID) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	pod.Status.PodIP = ip
	pod.Spec.Containers = []corev1.Container{{Name: "cloudflared"}}
	pod.OwnerReferences = []metav1.OwnerReference{{
		Kind: "ReplicaSet", Name: "rs-cf",
		UID: owner, Controller: ptr.To(true)}}
	return pod
}

// cfMetricsTransport answers pod :2000/metrics scrapes per podIP.
func cfMetricsTransport(bodies map[string]string) *testutil.StubTransport {
	return &testutil.StubTransport{Fn: func(r *http.Request) (*http.Response, error) {
		ip := strings.Split(r.URL.Host, ":")[0]
		if body, ok := bodies[ip]; ok {
			return testutil.ProbeResponse(200, body), nil
		}
		return testutil.ProbeResponse(500, ""), nil
	}}
}

func TestCloudflaredZeroHAConnectionsDeletesWithSibling(t *testing.T) {
	owner := types.UID("rs-cf")
	bad := cfPod("cf", "cf-1", "10.0.0.1", owner)
	good := cfPod("cf", "cf-2", "10.0.0.2", owner)
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs)
	p.HTTPClient = &http.Client{Transport: cfMetricsTransport(map[string]string{
		"10.0.0.1": "cloudflared_tunnel_ha_connections 0\n",
		"10.0.0.2": "cloudflared_tunnel_ha_connections 4\n",
	})}
	chk := probetest.MustCheck[*cloudflaredTunnelHealthCheck](t, p)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first degraded sighting inside streak must pass: %+v", res)
	}
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatalf("persistent ha_connections=0 must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("cf").Get(ctx, "cf-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("dead-tunnel pod should be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("cf").Get(ctx, "cf-2", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy sibling must survive: %v", err)
	}
}

func TestCloudflaredHealthyHAConnectionsPass(t *testing.T) {
	pod := cfPod("cf", "cf-1", "10.0.0.1", types.UID("rs-cf"))
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	p.HTTPClient = &http.Client{Transport: cfMetricsTransport(map[string]string{
		"10.0.0.1": "cloudflared_tunnel_ha_connections 4\n",
	})}
	chk := probetest.MustCheck[*cloudflaredTunnelHealthCheck](t, p)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("healthy tunnel must pass: %+v", res)
	}
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

// ---------------------------------------------------------------------------
// cfTunnelLogQUICStorm — the log-tail fallback when :2000/metrics is
// unreachable: QUIC edge-dial markers mean a dead tunnel behind a
// live Ready gate; a clean tail or a fetch error is not a storm.
// ---------------------------------------------------------------------------

func TestCfTunnelLogQUICStorm(t *testing.T) {
	pod := cfPod("cf", "cf-1", "10.0.0.1", types.UID("rs-cf"))

	t.Run("QUIC edge-dial marker hits", func(t *testing.T) {
		cs := fake.NewSimpleClientset(pod)
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"2026-11-10T00:00:00Z ERR failed to dial to edge with quic: timeout\n", nil))
		p := testProber(cs)
		storm, err := probetest.MustCheck[*cloudflaredTunnelHealthCheck](t, p).
			cfTunnelLogQUICStorm(ctx, pod)
		if err != nil || !storm {
			t.Fatalf("cfTunnelLogQUICStorm = (%v,%v), want (true,nil)", storm, err)
		}
	})

	t.Run("clean tail is not a storm", func(t *testing.T) {
		cs := fake.NewSimpleClientset(pod)
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"2026-11-10T00:00:00Z INF tunnel registered\n", nil))
		p := testProber(cs)
		storm, err := probetest.MustCheck[*cloudflaredTunnelHealthCheck](t, p).
			cfTunnelLogQUICStorm(ctx, pod)
		if err != nil || storm {
			t.Fatalf("cfTunnelLogQUICStorm = (%v,%v), want (false,nil)", storm, err)
		}
	})

	t.Run("fetch failure is inconclusive", func(t *testing.T) {
		cs := fake.NewSimpleClientset(pod)
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"", errors.New("kubelet log read boom")))
		p := testProber(cs)
		storm, err := probetest.MustCheck[*cloudflaredTunnelHealthCheck](t, p).
			cfTunnelLogQUICStorm(ctx, pod)
		if err == nil || storm {
			t.Fatalf("cfTunnelLogQUICStorm = (%v,%v), want (false,err)", storm, err)
		}
	})
}

// The benign UDP-buffer warning ("failed to sufficiently increase
// receive buffer" — present on virtually every host with stock
// net.core.rmem_max) is NOT a dead-tunnel signature: on the
// metrics-unreachable path it must never degrade the connector, let
// alone delete it.
func TestCfTunnelBufferWarningIsNotADeadTunnel(t *testing.T) {
	pod := cfPod("cf", "cf-1", "10.0.0.1", types.UID("rs-cf"))
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"2026-11-10T00:00:00Z WRN failed to sufficiently increase "+
			"receive buffer size (expected: 7168, got: 2129)\n", nil))
	p := testProber(cs)
	// Metrics unreachable — the transport 500s every scrape, forcing
	// the log-tail fallback.
	p.HTTPClient = &http.Client{Transport: cfMetricsTransport(nil)}
	chk := probetest.MustCheck[*cloudflaredTunnelHealthCheck](t, p)

	for i := 0; i <= cfTunnelMinStreak; i++ {
		if res := chk.Run(ctx); !res.Pass {
			t.Fatalf("benign buffer warning must not degrade the connector (sweep %d): %+v", i, res)
		}
	}
	if _, err := cs.CoreV1().Pods("cf").Get(ctx, "cf-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy connector must never be deleted on a benign warning: %v", err)
	}
}

// Inconclusive sweeps (metrics + logs both unreadable) must carry the
// pod's streak through the keep-set — Prune may not wipe a streak the
// sweep could not evaluate, or a dead tunnel with flaky evidence
// never reaches cfTunnelMinStreak and never heals.
func TestCfTunnelInconclusiveSweepKeepsStreak(t *testing.T) {
	owner := types.UID("rs-cf")
	bad := cfPod("cf", "cf-1", "10.0.0.1", owner)
	good := cfPod("cf", "cf-2", "10.0.0.2", owner)
	cs := fake.NewSimpleClientset(bad, good)
	// Metrics channel: sweep 1 reads ha=0 for cf-1; then the channel
	// dies for one sweep and revives.
	metrics := map[string]string{"10.0.0.1": "cloudflared_tunnel_ha_connections 0\n"}
	p := testProber(cs)
	p.HTTPClient = &http.Client{Transport: cfMetricsTransport(metrics)}
	chk := probetest.MustCheck[*cloudflaredTunnelHealthCheck](t, p)

	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first degraded sighting inside streak must pass: %+v", res)
	}
	// Both channels die: the transport drops the body and the kubelet
	// log read errors — inconclusive, not clean.
	delete(metrics, "10.0.0.1")
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"", errors.New("kubelet log read boom")))
	_ = chk.Run(ctx)
	// Metrics revive: the second degraded sighting rides the
	// preserved streak straight to cfTunnelMinStreak.
	metrics["10.0.0.1"] = "cloudflared_tunnel_ha_connections 0\n"
	chk.Run(ctx)
	if _, err := cs.CoreV1().Pods("cf").Get(ctx, "cf-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("flaky-evidence dead tunnel must still reach the streak threshold, err=%v", err)
	}
}

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

// liqoPeerName resolves the remote cluster's identity across the
// label spellings and status/spec fields the liqo versions carry —
// first match wins, the object name is the fallback.
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

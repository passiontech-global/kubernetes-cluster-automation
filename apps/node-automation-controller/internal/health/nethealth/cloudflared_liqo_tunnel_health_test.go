// cloudflared_liqo_tunnel_health_test.go — coverage for the
// cloudflared-tunnel-health and liqo-tunnel-health checks: ha-0
// metrics persistence + sibling-gated delete, and dead-peer
// gateway bounces.
package nethealth

import (
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

func TestLiqoConnectedPeerPasses(t *testing.T) {
	conn := liqoConnection("liqo-tenant", "conn-peer-b", "True", time.Hour)
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn(conn))
	if res := probetest.MustCheck[*liqoTunnelHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("connected peer must pass: %+v", res)
	}
}

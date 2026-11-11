// cloudflared_tunnel_health_test.go — coverage for the
// cloudflared-tunnel-health check: ha-0 metrics persistence +
// sibling-gated delete, the QUIC log-tail fallback and the buffer-
// warning false-positive guard. Split from the former
// cloudflared_liqo_tunnel_health_test.go; the liqo half lives in
// nethealth/liqo.
package cloudflared

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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

// TestCloudflaredEndpointBounceDetected covers the A3 bounce
// detector: a connector REPLACED under the same pod key (new UID)
// opens the stale-conntrack window — the first sighting arms the
// ledger, the replacement counts once, a stable UID re-fires
// nothing, and the wedge evaluation re-arms on the fresh UID.
func TestCloudflaredEndpointBounceDetected(t *testing.T) {
	pod := cfPod("cf", "cf-1", "10.0.0.1", types.UID("rs-cf"))
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	p.HTTPClient = &http.Client{Transport: cfMetricsTransport(map[string]string{
		"10.0.0.1": "cloudflared_tunnel_ha_connections 4\n",
	})}
	chk := probetest.MustCheck[*cloudflaredTunnelHealthCheck](t, p)

	// Sweep 1: the connector arms the ledger — healthy, no bounce.
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("arming sweep must pass: %+v", res)
	}
	if v := ptestutil.ToFloat64(cloudflaredEndpointBouncedTotal.WithLabelValues("cf")); v != 0 {
		t.Fatalf("bounce counter armed before any replacement: %v", v)
	}

	// Sweep 2: the connector was REPLACED (same key, new UID — what
	// a rollout leaves behind). Counted, and the tunnel stays
	// healthy so no delete fires.
	replaced := cfPod("cf", "cf-1", "10.0.0.1", types.UID("rs-cf"))
	replaced.UID = "uid-replaced"
	if _, err := cs.CoreV1().Pods("cf").Update(ctx, replaced, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("replace connector: %v", err)
	}
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("healthy replacement must pass: %+v", res)
	}
	if v := ptestutil.ToFloat64(cloudflaredEndpointBouncedTotal.WithLabelValues("cf")); v != 1 {
		t.Fatalf("bounce counter = %v, want 1", v)
	}

	// Sweep 3: same UID — no repeat count.
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("stable connector must pass: %+v", res)
	}
	if v := ptestutil.ToFloat64(cloudflaredEndpointBouncedTotal.WithLabelValues("cf")); v != 1 {
		t.Fatalf("stable connector re-fired the counter: %v", v)
	}
}

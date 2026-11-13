// konnectivity_tunnel_health_test.go — coverage for the
// konnectivity-tunnel-health check (konnectivity-tunnel-health): the half-open deficit
// persisting past the window heals the agent, an all-agents-down
// shape never heals (server-side outage), the CP-less hub-spoke
// peer-max fallback, and the no-Prometheus inconclusive pass.
package nethealth

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// konnCPNode builds a Ready control-plane node — the expectedCPCount
// census member.
func konnCPNode(name string) *corev1.Node {
	n := probetest.ReadyWorkerNode(name, "", 0, false)
	n.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
	return n
}

// konnAgentPod builds a Running konnectivity-agent member pod —
// name-prefix matched like the DaemonSet's own pod names.
func konnAgentPod(name, node string) *corev1.Pod {
	pod := probetest.PodWithPhase("kube-system", name,
		corev1.PodRunning, true, time.Hour)
	pod.Spec.NodeName = node
	return pod
}

// konnPromServer answers only the open_server_connections query —
// every other series reads empty.
func konnPromServer(t *testing.T,
	byPod map[string]float64) *httptest.Server {
	t.Helper()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if !strings.Contains(query, "open_server_connections") {
			return nil
		}
		var out []probetest.PromTestSample
		for pod, v := range byPod {
			out = append(out, probetest.PromTestSample{
				Labels: map[string]string{
					"namespace": "kube-system", "pod": pod},
				Value: v})
		}
		return out
	})
	return srv
}

// konnProber wires the prom endpoint + client into the test prober —
// the seam the production PromQuery reads per call.
func konnProber(cs *fake.Clientset, srv *httptest.Server) *probetest.Prober {
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	return p
}

// A half-open agent persists the deficit past the 10m window while a
// sibling holds the full count: the gauge fires and the wedged agent
// is deleted so it re-dials every konnectivity-server.
func TestKonnectivityHalfOpenHealsPastWindow(t *testing.T) {
	base := time.Now()
	srv := konnPromServer(t, map[string]float64{
		"konnectivity-agent-a": 1, // expected 2 — half-open
		"konnectivity-agent-b": 2,
	})
	cs := fake.NewSimpleClientset([]runtime.Object{
		konnCPNode("cp-1"), konnCPNode("cp-2"),
		konnAgentPod("konnectivity-agent-a", "w1"),
		konnAgentPod("konnectivity-agent-b", "w2"),
	}...)
	p := konnProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p)
	if res := check.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("first sight is inside the window — must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("half-open tunnel past the window must FAIL")
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "konnectivity-agent-a", metav1.GetOptions{}); err == nil {
		t.Fatal("half-open agent must be deleted while a sibling is fully connected")
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "konnectivity-agent-b", metav1.GetOptions{}); err != nil {
		t.Fatalf("fully-connected sibling must survive: %v", err)
	}
	m := probetest.FindMetric(t, "node_automation_konnectivity_agent_half_open",
		map[string]string{"pod": "konnectivity-agent-a", "node": "w1"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("half-open gauge must emit {pod,node}")
	}
}

// EVERY agent below the expected count is a server-side outage, not
// a per-pod wedge — the gauge fires (alerting is the contract) but
// no pod is deleted: bouncing agents during a konnectivity-server
// outage only prolongs it.
func TestKonnectivityAllHalfOpenNeverHeals(t *testing.T) {
	base := time.Now()
	srv := konnPromServer(t, map[string]float64{
		"konnectivity-agent-a": 0,
		"konnectivity-agent-b": 1,
	})
	cs := fake.NewSimpleClientset([]runtime.Object{
		konnCPNode("cp-1"), konnCPNode("cp-2"),
		konnAgentPod("konnectivity-agent-a", "w1"),
		konnAgentPod("konnectivity-agent-b", "w2"),
	}...)
	p := konnProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p)
	_ = check.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("all-agents half-open must still FAIL the check")
	}
	for _, name := range []string{"konnectivity-agent-a", "konnectivity-agent-b"} {
		if _, err := cs.CoreV1().Pods("kube-system").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("no healthy peer — %s must not be deleted: %v", name, err)
		}
	}
}

// Every agent at the full connection count is healthy — the
// early-exit never even lists pods.
func TestKonnectivityFullyConnectedPasses(t *testing.T) {
	srv := konnPromServer(t, map[string]float64{
		"konnectivity-agent-a": 2, "konnectivity-agent-b": 2})
	cs := fake.NewSimpleClientset([]runtime.Object{
		konnCPNode("cp-1"), konnCPNode("cp-2"),
		konnAgentPod("konnectivity-agent-a", "w1"),
		konnAgentPod("konnectivity-agent-b", "w2"),
	}...)
	p := konnProber(cs, srv)
	if res := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p).
		Run(ctx); !res.Pass {
		t.Fatalf("fully-connected agents must pass: %+v", res)
	}
}

// Zero Ready control-plane nodes on a cluster WITH a Prometheus
// endpoint no longer skips the check — the hub-spoke fallback
// derives the expectation from live agents (covered below). Here
// the evidence source itself is offline, so the check has nothing
// to evaluate and passes inconclusively.
func TestKonnectivityNoReadyControlPlanePasses(t *testing.T) {
	p := testProber(fake.NewSimpleClientset(
		konnAgentPod("konnectivity-agent-a", "w1")))
	if res := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p).
		Run(ctx); !res.Pass {
		t.Fatalf("no ready CP must pass: %+v", res)
	}
}

// Hub-spoke (zero in-cluster CP nodes — the k0s nonprod shape): the
// expected count derives from the healthiest LIVE agent, so a
// half-open agent still heals once the deficit persists. This is
// the regression pin for the 2026-11-13 vacuous-check incident.
func TestKonnectivityHubSpokePeerMaxHeals(t *testing.T) {
	base := time.Now()
	srv := konnPromServer(t, map[string]float64{
		"konnectivity-agent-a": 0, // peer max is 1 — half-open
		"konnectivity-agent-b": 1,
	})
	cs := fake.NewSimpleClientset([]runtime.Object{
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		konnAgentPod("konnectivity-agent-a", "w1"),
		konnAgentPod("konnectivity-agent-b", "w2"),
	}...)
	p := konnProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p)
	if res := check.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("first sight is inside the window — must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("hub-spoke half-open tunnel past the window must FAIL")
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "konnectivity-agent-a", metav1.GetOptions{}); err == nil {
		t.Fatal("half-open agent must be deleted while a sibling is fully connected")
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "konnectivity-agent-b", metav1.GetOptions{}); err != nil {
		t.Fatalf("fully-connected sibling must survive: %v", err)
	}
}

// Hub-spoke all-agents-at-zero: peerMax floors the expectation at
// 1, so a TOTAL tunnel loss still fires the gauge — alerting is the
// contract — but with no live agent at the expected count nothing
// is deleted (the server-side outage posture).
func TestKonnectivityHubSpokeAllZeroFiresGaugeNoHeal(t *testing.T) {
	base := time.Now()
	srv := konnPromServer(t, map[string]float64{
		"konnectivity-agent-a": 0,
		"konnectivity-agent-b": 0,
	})
	cs := fake.NewSimpleClientset([]runtime.Object{
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		konnAgentPod("konnectivity-agent-a", "w1"),
		konnAgentPod("konnectivity-agent-b", "w2"),
	}...)
	p := konnProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p)
	_ = check.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("all-agents-at-zero tunnel loss must FAIL — the gauge is the alerting contract")
	}
	for _, name := range []string{"konnectivity-agent-a", "konnectivity-agent-b"} {
		if _, err := cs.CoreV1().Pods("kube-system").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("no healthy peer — %s must not be deleted: %v", name, err)
		}
	}
}

// No resolvable Prometheus endpoint: the only evidence source is
// offline — the check has nothing to evaluate and passes.
func TestKonnectivityNoPrometheusPasses(t *testing.T) {
	cs := fake.NewSimpleClientset([]runtime.Object{
		konnCPNode("cp-1"),
		konnAgentPod("konnectivity-agent-a", "w1"),
	}...)
	p := testProber(cs) // HTTPContent.URL points at a dead address
	if res := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p).
		Run(ctx); !res.Pass {
		t.Fatalf("no prometheus endpoint must pass: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// isKonnectivityAgentPod — DaemonSet membership signatures
// ---------------------------------------------------------------------------

// Membership is the kube-system namespace plus EITHER chart label
// (k8s-app or app.kubernetes.io/name — the chart has stamped both
// across versions) or, when labels drift, the konnectivity-agent-
// pod name shape — the same posture isDNSPod takes for coredns.
func TestIsKonnectivityAgentPod(t *testing.T) {
	mk := func(ns, name string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Labels: labels}}
	}
	cases := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"right labels outside kube-system do not count",
			mk("monitoring", "konnectivity-agent-x", map[string]string{
				"k8s-app": "konnectivity-agent"}), false},
		{"k8s-app label member",
			mk("kube-system", "pod-x", map[string]string{
				"k8s-app": "konnectivity-agent"}), true},
		{"app.kubernetes.io/name label member",
			mk("kube-system", "pod-x", map[string]string{
				"app.kubernetes.io/name": "konnectivity-agent"}), true},
		{"name shape is the label-drift fallback",
			mk("kube-system", "konnectivity-agent-7d4f9-abcde", nil), true},
		{"unrelated kube-system pod",
			mk("kube-system", "coredns-abc", nil), false},
		{"prefix look-alike is not a member",
			mk("kube-system", "konnectivity-agent", nil), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isKonnectivityAgentPod(tc.pod); got != tc.want {
				t.Fatalf("isKonnectivityAgentPod = %v, want %v", got, tc.want)
			}
		})
	}
}

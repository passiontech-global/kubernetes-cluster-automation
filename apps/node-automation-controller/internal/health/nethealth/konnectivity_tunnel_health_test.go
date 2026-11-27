// konnectivity_tunnel_health_test.go — coverage for the
// konnectivity-tunnel-health check (konnectivity-tunnel-health): the half-open deficit
// persisting past the window heals the agent, an all-agents-down
// shape never heals (server-side outage), the CP-less hub-spoke
// peer-max fallback, and the no-Prometheus inconclusive pass.
package nethealth

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

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
	if res := check.Run(probetest.SweepCtx(ctx, check.Deps)); !res.Pass {
		t.Fatalf("first sight is inside the window — must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
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
	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
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

// The heal is capped per sweep AND keyed per node: three half-open
// DaemonSet agents with one healthy peer lose at most two per sweep,
// and a third agent on its own node is still healable on the next
// sweep (a shared DaemonSet cooldown key would suppress it for 30m).
func TestKonnectivityHealCapAndPerNodeCooldown(t *testing.T) {
	base := time.Now()
	srv := konnPromServer(t, map[string]float64{
		"konnectivity-agent-a": 1,
		"konnectivity-agent-b": 1,
		"konnectivity-agent-d": 1,
		"konnectivity-agent-c": 2, // the sole healthy peer
	})
	cs := fake.NewSimpleClientset([]runtime.Object{
		konnCPNode("cp-1"), konnCPNode("cp-2"),
		konnAgentPod("konnectivity-agent-a", "w1"),
		konnAgentPod("konnectivity-agent-b", "w2"),
		konnAgentPod("konnectivity-agent-c", "w3"),
		konnAgentPod("konnectivity-agent-d", "w4"),
	}...)
	p := konnProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)
	check := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p)

	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))

	candidates := []string{"konnectivity-agent-a", "konnectivity-agent-b", "konnectivity-agent-d"}
	deleted, leftover := 0, ""
	for _, name := range candidates {
		if _, err := cs.CoreV1().Pods("kube-system").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			deleted++
		} else {
			leftover = name
		}
	}
	if deleted != konnHealCapPerSweep || leftover == "" {
		t.Fatalf("first sweep deleted %d agents (leftover %q), want the cap of %d",
			deleted, leftover, konnHealCapPerSweep)
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "konnectivity-agent-c", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy peer must survive: %v", err)
	}

	// Next sweep is still inside the 30m cooldown of the two
	// delivered deletes. The remaining agent is on a DIFFERENT node
	// and must not inherit their per-node cooldown stamps.
	probetest.FreezeNow(p.Deps, base.Add(12*time.Minute))
	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, leftover, metav1.GetOptions{}); err == nil {
		t.Fatalf("remaining agent %s must heal next sweep — per-node cooldown key", leftover)
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
	if res := check.Run(probetest.SweepCtx(ctx, check.Deps)); !res.Pass {
		t.Fatalf("first sight is inside the window — must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
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
	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
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

// konnPromServerWithBackends answers both open_server_connections and
// konnectivity_network_proxy_server_ready_backend_connections.
func konnPromServerWithBackends(t *testing.T,
	byPod map[string]float64,
	byServer map[string]float64) *httptest.Server {
	t.Helper()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "open_server_connections"):
			var out []probetest.PromTestSample
			for pod, v := range byPod {
				out = append(out, probetest.PromTestSample{
					Labels: map[string]string{
						"namespace": "kube-system", "pod": pod},
					Value: v})
			}
			return out
		case strings.Contains(query, "server_ready_backend_connections"):
			var out []probetest.PromTestSample
			for inst, v := range byServer {
				out = append(out, probetest.PromTestSample{
					Labels: map[string]string{"instance": inst},
					Value:  v})
			}
			return out
		default:
			return nil
		}
	})
	return srv
}

// Split-brain detection via server imbalance + agent logs containing
// >=5 "duplicate server connection attempt" lines: deletes pods with
// UID preconditions, respects per-sweep cap (2), skips pods with <5
// matches, and heals remaining pods on the next sweep.
func TestKonnectivitySplitBrainRollingDeleteCapCooldownAndUID(t *testing.T) {
	base := time.Now()
	// All agents report 2 open connections, but cp-2 has 0 ready backends
	// while cp-1 has 4 — server imbalance triggers the log scan.
	srv := konnPromServerWithBackends(t,
		map[string]float64{
			"konnectivity-agent-a": 2,
			"konnectivity-agent-b": 2,
			"konnectivity-agent-c": 2,
			"konnectivity-agent-d": 2,
		},
		map[string]float64{
			"cp-1:8133": 4,
			"cp-2:8133": 0,
		},
	)
	mkPod := func(name, node string) *corev1.Pod {
		p := konnAgentPod(name, node)
		p.UID = types.UID("uid-" + name)
		return p
	}
	cs := fake.NewSimpleClientset([]runtime.Object{
		konnCPNode("cp-1"), konnCPNode("cp-2"),
		mkPod("konnectivity-agent-a", "w1"),
		mkPod("konnectivity-agent-b", "w2"),
		mkPod("konnectivity-agent-c", "w3"),
		mkPod("konnectivity-agent-d", "w4"),
	}...)

	deletedUIDs := map[string]types.UID{}
	cs.PrependReactor("delete", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		da := action.(ktesting.DeleteAction)
		opts := da.GetDeleteOptions()
		if opts.Preconditions == nil || opts.Preconditions.UID == nil {
			t.Errorf("pod %s deleted without UID precondition", da.GetName())
		} else {
			deletedUIDs[da.GetName()] = *opts.Preconditions.UID
		}
		return false, nil, nil
	})

	p := konnProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)
	check := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p)

	dup5 := strings.Repeat("E1127 duplicate server connection attempt from agent\n", 5)
	dup4 := strings.Repeat("E1127 duplicate server connection attempt from agent\n", 4)
	check.podLogFn = func(_ context.Context, pod *corev1.Pod) (string, error) {
		if pod.Name == "konnectivity-agent-d" {
			return dup4, nil // below threshold
		}
		return dup5, nil
	}

	// Sweep 1: 3 split-brain pods (a, b, c) — cap 2 deletes exactly 2.
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if res.Pass {
		t.Fatal("split-brain agents must FAIL the sweep")
	}
	if len(deletedUIDs) != konnHealCapPerSweep {
		t.Fatalf("sweep 1 deleted %d pods (%v), want cap %d",
			len(deletedUIDs), deletedUIDs, konnHealCapPerSweep)
	}
	for name, uid := range deletedUIDs {
		if want := types.UID("uid-" + name); uid != want {
			t.Fatalf("pod %s deleted with UID %q, want %q", name, uid, want)
		}
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "konnectivity-agent-d", metav1.GetOptions{}); err != nil {
		t.Fatalf("agent with only 4 duplicate lines must survive: %v", err)
	}

	var leftover string
	for _, name := range []string{"konnectivity-agent-a", "konnectivity-agent-b", "konnectivity-agent-c"} {
		if _, wasDeleted := deletedUIDs[name]; !wasDeleted {
			leftover = name
		}
	}

	// Sweep 2 (5m later): leftover 3rd pod heals on its own node.
	probetest.FreezeNow(p.Deps, base.Add(5*time.Minute))
	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, leftover, metav1.GetOptions{}); err == nil {
		t.Fatalf("remaining split-brain pod %s must be healed on next sweep", leftover)
	}
}

// Per-node 30m cooldown prevents re-deleting a DaemonSet-recreated
// split-brain pod on the same node inside the window, then allows
// healing once the cooldown expires.
func TestKonnectivitySplitBrainPerNodeCooldown(t *testing.T) {
	base := time.Now()
	srv := konnPromServerWithBackends(t,
		map[string]float64{"konnectivity-agent-a": 2},
		map[string]float64{"cp-1:8133": 2, "cp-2:8133": 0},
	)
	mkDSPod := func(name, node string) *corev1.Pod {
		p := konnAgentPod(name, node)
		p.UID = types.UID("uid-" + name)
		ctrl := true
		p.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       "DaemonSet",
			Name:       "konnectivity-agent",
			Controller: &ctrl,
		}}
		return p
	}
	cs := fake.NewSimpleClientset([]runtime.Object{
		konnCPNode("cp-1"), konnCPNode("cp-2"),
		mkDSPod("konnectivity-agent-a", "w1"),
	}...)
	p := konnProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)
	check := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p)
	check.podLogFn = func(_ context.Context, _ *corev1.Pod) (string, error) {
		return strings.Repeat("duplicate server connection attempt\n", 5), nil
	}

	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "konnectivity-agent-a", metav1.GetOptions{}); err == nil {
		t.Fatal("sweep 1 must delete split-brain DaemonSet pod")
	}

	// DaemonSet recreates pod on w1 5m later (inside 30m cooldown) -> must survive.
	reborn := mkDSPod("konnectivity-agent-a-new", "w1")
	if _, err := cs.CoreV1().Pods("kube-system").Create(ctx, reborn, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create replacement pod: %v", err)
	}
	probetest.FreezeNow(p.Deps, base.Add(5*time.Minute))
	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, reborn.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("replacement pod on w1 must not be deleted inside 30m cooldown: %v", err)
	}

	// Past 30m cooldown -> allowed to delete again.
	probetest.FreezeNow(p.Deps, base.Add(31*time.Minute))
	_ = check.Run(probetest.SweepCtx(ctx, check.Deps))
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, reborn.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("replacement pod on w1 must be healed after 30m cooldown expires")
	}
}

// Deficit-triggered split-brain heals even without waiting 10m or having
// a healthy peer when agent logs prove >=5 duplicate server connection attempts.
func TestKonnectivitySplitBrainTriggeredByDeficit(t *testing.T) {
	base := time.Now()
	srv := konnPromServer(t, map[string]float64{
		"konnectivity-agent-a": 1,
		"konnectivity-agent-b": 1,
	})
	podA := konnAgentPod("konnectivity-agent-a", "w1")
	podA.UID = "uid-a"
	podB := konnAgentPod("konnectivity-agent-b", "w2")
	podB.UID = "uid-b"
	cs := fake.NewSimpleClientset([]runtime.Object{
		konnCPNode("cp-1"), konnCPNode("cp-2"),
		podA, podB,
	}...)
	p := konnProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)
	check := probetest.MustCheck[*konnectivityTunnelHealthCheck](t, p)
	check.podLogFn = func(_ context.Context, pod *corev1.Pod) (string, error) {
		if pod.Name == "konnectivity-agent-a" {
			return strings.Repeat("duplicate server connection attempt\n", 5), nil
		}
		return "normal log\n", nil
	}

	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if res.Pass {
		t.Fatal("split-brain agent must fail sweep")
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "konnectivity-agent-a", metav1.GetOptions{}); err == nil {
		t.Fatal("split-brain agent with >=5 duplicate server connection attempts must be deleted")
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "konnectivity-agent-b", metav1.GetOptions{}); err != nil {
		t.Fatalf("non-split-brain agent must survive: %v", err)
	}
}

// konnectivity_tunnel_health.go — the konnectivity-tunnel-health
// check (konnectivity-tunnel-health): the konnectivity-agent half-open tunnel watchdog.
// A konnectivity-agent pod can keep a "connected" gRPC session to
// FEWER konnectivity-servers than there are Ready control-plane
// nodes — a stale HTTP/2 stream pinned in conntrack, or a CP whose
// konnectivity-server restarted while the agent's other streams
// stayed up. kube-apiserver on the unserved CP then hangs ~30s and
// 502s on every tunnel-routed call (ValidatingWebhooks,
// kubectl logs/exec, kubelet /healthz) — exactly the cross-DC
// flap shape the brainstorm calls out. The check reads each agent's
// open_server_connections from Prometheus; once a deficit persists
// 10m while a sibling agent demonstrably holds full connections
// (proving the servers are reachable), the agent pod is deleted so
// it re-dials every server.
package nethealth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// konnectivityTunnelHealthCheck is the konnectivity-tunnel-health half-open tunnel
// watchdog.
type konnectivityTunnelHealthCheck struct {
	*probefw.Deps

	// seen: "ns/pod" → first sweep the agent's open server
	// connections read below the Ready control-plane count — the
	// 10m persistence window before the deficit counts. In-RAM by
	// contract (state.FirstSeenLedger): a restart re-arms the
	// window and delays the heal, the safe direction.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
}

// NewKonnectivityTunnelHealthCheck builds the konnectivity-tunnel-health check — its
// state is the seen/emitted ledgers (zero value usable); pod-delete
// cooldowns ride the shared Deps.Heals set via DeletePodHeal.
func NewKonnectivityTunnelHealthCheck(d *probefw.Deps) probefw.Check {
	return &konnectivityTunnelHealthCheck{Deps: d}
}

const (
	CheckNameKonnectivityTunnelHealth = "konnectivity-tunnel-health"

	// konnectivity-tunnel-health — konnectivity-tunnel-health knobs.
	konnHalfOpenMinAge = 10 * time.Minute
	konnHealCool       = 30 * time.Minute
	konnAgentNS        = "kube-system"
	konnAgentPodPrefix = "konnectivity-agent-"
)

var (
	// konnectivity-tunnel-health — a konnectivity-agent pod holding fewer open server
	// connections than there are Ready control-plane nodes past the
	// persistence window.
	konnAgentHalfOpenGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_konnectivity_agent_half_open",
		Help: "1 while a konnectivity-agent pod holds fewer open server connections than Ready control-plane nodes for >=10m — konnectivity-tunnel-health.",
	}, []string{"pod", "node"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		konnAgentHalfOpenGauge)
}

// isKonnectivityAgentPod reports whether the pod is a member of the
// kube-system/konnectivity-agent DaemonSet — the k8s-app or
// app.kubernetes.io/name label where the chart stamps it, else the
// konnectivity-agent-<hash> name shape (label-drift fallback, the
// isDNSPod posture).
func isKonnectivityAgentPod(pod *corev1.Pod) bool {
	if pod.Namespace != konnAgentNS {
		return false
	}
	if pod.Labels["k8s-app"] == "konnectivity-agent" ||
		pod.Labels["app.kubernetes.io/name"] == "konnectivity-agent" {
		return true
	}
	return strings.HasPrefix(pod.Name, konnAgentPodPrefix)
}

// checkKonnectivityTunnelHealth compares every live
// konnectivity-agent pod's open server connections against the
// Ready control-plane count. The deficit must persist
// konnHalfOpenMinAge before the gauge fires and the pod is deleted
// (30m shared cooldown, maintenance-gated, UID-preconditioned) —
// konnectivity-server rollouts legitimately flap per-agent counts
// for seconds at a time. The heal ALSO requires a sibling agent
// holding the full count: if no live agent reaches expectedCPCount,
// the konnectivity-servers themselves are the outage and bouncing
// agents only prolongs it.
func (p *konnectivityTunnelHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	// expectedCPCount — every agent should hold one open server
	// connection per Ready control-plane node. A cluster reporting
	// zero Ready CP has bigger problems than tunnel health, and 0
	// would make the "sibling holds the full count" proof vacuous:
	// skip rather than flag the whole DaemonSet.
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	expectedCP := 0
	for i := range nodes {
		if kube.IsControlPlane(&nodes[i]) && kube.NodeReady(&nodes[i]) {
			expectedCP++
		}
	}
	if expectedCP == 0 {
		return probefw.Result{Pass: true}
	}

	// The connection counts only exist where a Prometheus endpoint
	// resolves — same "no endpoint configured, skip" gate the other
	// metrics-backed checks use. An unreadable endpoint or failed
	// query is "can't tell", NOT "resolved": every tuple the last
	// sweep fired Carries + re-Finds (the imagepull_secret_auditor
	// pattern) so a monitoring flap cannot prune live half-open
	// series — and the seen ledger stays untouched so the 10m
	// persistence windows do not re-arm on a Prometheus outage.
	var rep probefw.SweepReport
	carry := func(what string, err error) probefw.Result {
		log.Info("WARN: "+what+" — half-open signal carried, not evaluated",
			"error", err)
		for k, lv := range p.emitted.Last() {
			rep.Carry(k, lv)
			rep.Find(k + "(prometheus unreadable — carried)")
		}
		return rep.Result(&p.emitted, konnAgentHalfOpenGauge.DeleteLabelValues,
			"konnectivity-agent pods with half-open tunnels: ", ", ")
	}
	if _, err := p.PromEndpoint(); err != nil {
		return carry("konnectivity prometheus endpoint unavailable", err)
	}
	series, err := p.PromQuery(ctx,
		`konnectivity_network_proxy_agent_open_server_connections`)
	if err != nil {
		// An unreachable Prometheus is inconclusive, not a clean
		// bill — warn and pass rather than fail the sweep on a
		// monitoring outage (the coredns/rabbitmq posture), but the
		// previously-firing tuples still carry forward.
		return carry("konnectivity agent connections query failed", err)
	}
	conns := map[string]float64{}
	for _, s := range series {
		if podName := s.Label("pod", "pod_name"); podName != "" {
			conns[podName] = s.Value
		}
	}
	// Cheap exit first: with no series below the expected count
	// there is nothing to evaluate — the pods List (needed only to
	// map a deficit onto live pods for the node label, the peer
	// proof and the heal target) is skipped on the common path. A
	// wholly empty result reads as healthy here: konnectivity-agent
	// never scraped is a monitoring gap, not tunnel evidence.
	// (rep was declared above for the Prometheus-error carry path —
	// this sweep's emits reuse it.)
	deficit := false
	for _, v := range conns {
		if v < float64(expectedCP) {
			deficit = true
			break
		}
	}
	if !deficit && len(p.emitted.Last()) == 0 {
		// Healthy AND nothing held from last sweep — but the
		// reconcile still owes the ledgers: seen entries must drop
		// so a recovering agent re-arms the window. (Returning Pass
		// without the reconcile would leak series pinned at 1.)
		// The cheap exit only applies when the emitted ledger is
		// empty: with held tuples a pod whose series VANISHED this
		// sweep is indistinguishable from a resolved one until the
		// pod census runs — "can't tell" must carry, not prune.
		p.seen.Prune(func(string) bool { return false })
		return rep.Result(&p.emitted, konnAgentHalfOpenGauge.DeleteLabelValues,
			"konnectivity-agent pods with half-open tunnels: ", ", ")
	}
	pods, err := p.PodsIn(ctx, konnAgentNS)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list %s pods: %w", konnAgentNS, err)}
	}

	halfOpen := map[string]bool{} // live-key set for the seen prune
	var targets []*corev1.Pod
	healthyPeer := false
	for i := range pods {
		pod := pods[i]
		if !isKonnectivityAgentPod(pod) || pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning {
			continue
		}
		v, ok := conns[pod.Name]
		if !ok {
			// The pod has no series — inconclusive, never evidence:
			// it cannot count as the "servers are reachable" peer
			// and it is not flagged either. But "can't tell" is not
			// "resolved": keep its first-seen stamp and carry any
			// emitted tuple, or a one-sweep metrics gap would prune
			// a live half-open series and re-arm the 10m window.
			key := pod.Namespace + "/" + pod.Name
			halfOpen[key] = true
			if lv, held := p.emitted.Last()[key]; held {
				rep.Carry(key, lv)
				rep.Find(key + "(connections series missing — carried)")
			}
			continue
		}
		if v >= float64(expectedCP) {
			// A LIVE agent holding the full count is the only
			// admissible proof the konnectivity-servers are up —
			// a stale series on a dead pod must not author it.
			healthyPeer = true
			continue
		}
		halfOpen[pod.Namespace+"/"+pod.Name] = true
		targets = append(targets, pod)
	}

	for _, pod := range targets {
		key := pod.Namespace + "/" + pod.Name
		if !probefw.Persisted(&p.seen, key, now, konnHalfOpenMinAge, log) {
			continue
		}
		rep.Emit(konnAgentHalfOpenGauge, key,
			[]string{pod.Name, pod.Spec.NodeName},
			fmt.Sprintf("%s(connections=%.0f/%d node=%s)",
				key, conns[pod.Name], expectedCP, pod.Spec.NodeName))
		if !healthyPeer {
			log.Info("skip konnectivity heal: no live agent reports full "+
				"connections — a server-side outage, not a half-open tunnel",
				"pod", key)
			continue
		}
		// The cooldown keys on the pod's CONTROLLER, not its name —
		// a deleted agent pod is recreated by the DaemonSet under a
		// fresh suffix, so a pod-name stamp never suppressed the
		// re-heal of the same wedge.
		p.DeletePodHeal(ctx, log, CheckNameKonnectivityTunnelHealth,
			kube.PodControllerKey(pod), pod, konnHealCool, now)
	}
	p.seen.Prune(func(k string) bool { return halfOpen[k] })
	return rep.Result(&p.emitted, konnAgentHalfOpenGauge.DeleteLabelValues,
		"konnectivity-agent pods with half-open tunnels: ", ", ")
}

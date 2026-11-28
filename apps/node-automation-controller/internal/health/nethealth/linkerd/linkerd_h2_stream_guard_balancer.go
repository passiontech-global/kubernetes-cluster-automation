// linkerd_h2_stream_guard_balancer.go — the linkerd-h2-stream-guard half of the
// linkerd-h2-stream-guard check: the outbound failure-accrual lockout
// (a client proxy holding pending endpoints or active fail-fast shutups
// with NONE in endpoint_state="ready" / legacy state="ready" long after
// the destination recovered) and the proxy-OOMKilled wedge seed —
// Prometheus signals cross-checked against live EndpointSlices, healed
// by the shared Ready-sibling-gated pod delete.
package linkerd

import (
	"context"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// linkerd-h2-stream-guard — pods whose linkerd-proxy holds pending
// endpoints (or active fail-fast queue-gate shutups) for a target with
// ZERO in endpoint_state="ready" (or legacy state="ready") past the
// persistence window, while the destination Service still has Ready
// endpoints: the client-side failure-accrual / dead-channel lockout.
var linkerdOutboundBalancerWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_linkerd_outbound_balancer_wedged",
	Help: "1 while the meshed pod's outbound balancer holds pending endpoints or active fail-fast for a target with none in endpoint_state=ready for >=10m and the destination healthy.",
}, []string{"namespace", "pod"})

func init() {
	ctrlmetrics.Registry.MustRegister(linkerdOutboundBalancerWedgedGauge)
}

// ---------------------------------------------------------------------------
// linkerd-h2-stream-guard — outbound balancer lockout & proxy OOM detection
// ---------------------------------------------------------------------------

// linkerdProxyOOMWindow bounds how recent the OOM termination must
// be — a FinishedAt older than the window describes a proxy that
// already restarted clean (empty connection table but a rebuilt,
// healthy balancer view), not the wedge seed.
const linkerdProxyOOMWindow = 30 * time.Minute

// linkerdProxyOOMKill is the ONE linkerd-proxy OOM scan both checks
// share (check-specific windows): it walks the proxy's status in BOTH
// maps — current State AND LastTerminationState, regular containers
// AND init containers (an init OOM leaves the pod un-Ready with a
// proxy that never started) — and reports whether the freshest
// OOMKilled termination lands inside window of now, plus the proxy's
// restart count for the event dedup key (a fresh kill bumps it,
// re-arming the event). A zero FinishedAt is unverifiable — not
// evidence. linkerd-h2-stream-guard uses it as the wedge seed, the
// sidecar-oom-guard as its whole signature; container names are
// unique across a pod, so the map order cannot change the verdict.
func linkerdProxyOOMKill(pod *corev1.Pod, now time.Time,
	window time.Duration) (int, bool) {

	for _, statuses := range [][]corev1.ContainerStatus{
		pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses,
	} {
		for i := range statuses {
			cs := &statuses[i]
			if cs.Name != kube.LinkerdProxyContainer {
				continue
			}
			fresh := func(t *corev1.ContainerStateTerminated) bool {
				return t != nil && t.Reason == "OOMKilled" &&
					!t.FinishedAt.IsZero() &&
					now.Sub(t.FinishedAt.Time) <= window
			}
			if fresh(cs.State.Terminated) ||
				fresh(cs.LastTerminationState.Terminated) {
				return int(cs.RestartCount), true
			}
			return 0, false
		}
	}
	return 0, false
}

// linkerdProxyOOMKilled is the h2 guard's boolean view of the shared
// scan: the pod's proxy terminated OOMKilled within
// linkerdProxyOOMWindow. An OOM'd proxy restarts with an empty
// connection table and re-learns its balancer view, which is exactly
// how a client-side dead-channel lockout starts.
func linkerdProxyOOMKilled(pod *corev1.Pod, now time.Time) bool {
	_, ok := linkerdProxyOOMKill(pod, now, linkerdProxyOOMWindow)
	return ok
}

// linkerdTargetService parses a linkerd target_addr label back to the
// Service it fronts — svc.ns.svc.cluster.local[:port] or the short
// svc.ns.svc[:port] shape — so the wedge candidate can be
// cross-checked against the live EndpointSlices. Unresolvable
// targets (IP literals, external authorities) report ok=false so
// callers fail closed.
func linkerdTargetService(targetAddr string) (ns, name string, ok bool) {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr // port-less or unparseable — try as-is
	}
	// DNS-1123 names carry no dots, so the first two labels are
	// always <name>.<ns> on the standard cluster suffixes.
	parts := strings.Split(host, ".")
	if len(parts) == 5 && parts[0] != "" && parts[1] != "" &&
		parts[2] == "svc" && parts[3] == "cluster" && parts[4] == "local" {
		return parts[1], parts[0], true
	}
	if len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] == "svc" {
		return parts[1], parts[0], true
	}
	return "", "", false
}

// linkerdBalancerTarget resolves the destination Kubernetes Service and
// canonical target identifier from a Prometheus balancer sample.
// Linkerd edge-26.x exports backend_* and parent_* labels (and drops
// target_addr); legacy Linkerd exports target_addr. Non-Service kinds
// and unresolvable targets return ok=false so callers fail closed.
func linkerdBalancerTarget(s promq.Sample) (targetID, svcNS, svcName string, ok bool) {
	if bk := s.Label("backend_kind"); bk != "" && bk != "Service" {
		return "", "", "", false
	}
	if bns, bn := s.Label("backend_namespace"), s.Label("backend_name"); bns != "" && bn != "" {
		id := bns + "/" + bn
		if bp := s.Label("backend_port"); bp != "" {
			id += ":" + bp
		}
		return id, bns, bn, true
	}
	if pk := s.Label("parent_kind"); pk != "" && pk != "Service" {
		return "", "", "", false
	}
	if pns, pn := s.Label("parent_namespace"), s.Label("parent_name"); pns != "" && pn != "" {
		id := pns + "/" + pn
		if pp := s.Label("parent_port"); pp != "" {
			id += ":" + pp
		}
		return id, pns, pn, true
	}
	if ta := s.Label("target_addr"); ta != "" {
		ns, name, ok := linkerdTargetService(ta)
		if !ok {
			return "", "", "", false
		}
		return ta, ns, name, true
	}
	return "", "", "", false
}

// readyEndpointsByService counts Ready endpoints per "ns/svc" across
// the live EndpointSlices — the wedge cross-check's ground truth,
// on the shared ReadyEndpointsByService rollup (nil Ready counts as
// ready, the convention every slice census in this package uses).
// A list failure returns nil so callers can tell "census
// unverifiable" from "genuinely zero endpoints".
func (p *linkerdH2StreamGuardCheck) readyEndpointsByService(
	ctx context.Context) (map[string]int, error) {

	ready := map[string]int{}
	slices, err := p.AllEndpointSlices(ctx)
	if err != nil {
		return nil, err
	}
	for key, eps := range kube.ReadyEndpointsByService(slices) {
		for _, e := range eps {
			// An addressless endpoint serves nothing — the wedge
			// cross-check counts only routable endpoints.
			if len(e.Addresses) > 0 {
				ready[key]++
			}
		}
	}
	return ready, nil
}

// nebulaPartitionActive reports whether any node currently carries a live
// NebulaIsolated=True condition (inter-DC overlay partition). Deleting meshed
// pods whose outbound balancer lost cross-DC endpoints during a live partition
// cannot restore reachability and triggers a destructive pod-recreation +
// cardinality storm (nonprod 2026-11-26: 39 pods deleted while 3/3 DataHub
// workers were NebulaIsolated=True).
const linkerdPartitionHeartbeatMaxAge = 15 * time.Minute

func (p *linkerdH2StreamGuardCheck) nebulaPartitionActive(
	ctx context.Context, log logr.Logger, now time.Time) (string, bool) {

	nodes, err := p.AllNodes(ctx)
	if err != nil {
		log.V(1).Info("WARN: list nodes for NebulaIsolated partition gate failed", "error", err)
		return "", false
	}
	for i := range nodes {
		n := &nodes[i]
		for _, c := range n.Status.Conditions {
			if c.Type != corev1.NodeConditionType(nodecond.NebulaIsolated) ||
				c.Status != corev1.ConditionTrue {
				continue
			}
			if !kube.CondHeartbeatLive(&c, linkerdPartitionHeartbeatMaxAge, now) {
				continue
			}
			return n.Name, true
		}
	}
	return "", false
}

const (
	linkerdBalancerPendingQuery = `sum by (namespace, pod, backend_kind, backend_namespace, backend_name, backend_port, parent_kind, parent_namespace, parent_name, parent_port, target_addr) (outbound_http_balancer_endpoints{endpoint_state="pending"} or outbound_http_balancer_endpoints{state="pending"})`
	linkerdBalancerReadyQuery   = `sum by (namespace, pod, backend_kind, backend_namespace, backend_name, backend_port, parent_kind, parent_namespace, parent_name, parent_port, target_addr) (outbound_http_balancer_endpoints{endpoint_state="ready"} or outbound_http_balancer_endpoints{state="ready"})`
	linkerdBalancerFailfastQ    = `sum by (namespace, pod, backend_kind, backend_namespace, backend_name, backend_port, parent_kind, parent_namespace, parent_name, parent_port) (increase(outbound_http_balancer_queue_gate_shut_total[5m])) > 0`
)

type balancerCandidate struct {
	ns       string
	podName  string
	targetID string
	svcNS    string
	svcName  string
}

func (p *linkerdH2StreamGuardCheck) carryBalancerEmitted(
	rep, balancerRep *probefw.SweepReport) {

	// Inconclusive, not clean — carry the held wedge series so the Close
	// below cannot read a Prometheus/API flap as recovery and prune live
	// alerts. Find lands on rep (the report Verdict reads), not
	// balancerRep: a carried series is still a live finding.
	for k, lv := range p.balancerEmitted.Last() {
		balancerRep.Carry(k, lv)
		rep.Find(k)
	}
}

func (p *linkerdH2StreamGuardCheck) queryBalancerSeries(
	ctx context.Context, log logr.Logger) (pending, ready, failfast []promq.Sample, ok bool) {

	var err error
	pending, err = p.PromQuery(ctx, linkerdBalancerPendingQuery)
	if err != nil {
		log.Info("WARN: linkerd balancer pending-endpoints query failed — wedge signal skipped",
			"error", err)
		return nil, nil, nil, false
	}
	ready, err = p.PromQuery(ctx, linkerdBalancerReadyQuery)
	if err != nil {
		log.Info("WARN: linkerd balancer ready-endpoints query failed — wedge signal skipped",
			"error", err)
		return nil, nil, nil, false
	}
	failfast, err = p.PromQuery(ctx, linkerdBalancerFailfastQ)
	if err != nil {
		log.Info("WARN: linkerd balancer queue-gate-shut query failed — fail-fast fallback skipped",
			"error", err)
		failfast = nil
	}
	return pending, ready, failfast, true
}

func buildReadyByTarget(readySeries []promq.Sample) map[string]float64 {
	readyByTarget := map[string]float64{}
	for _, s := range readySeries {
		ns, podName := s.Label("namespace"), s.Label("pod")
		if ns == "" || podName == "" {
			continue
		}
		targetID, _, _, ok := linkerdBalancerTarget(s)
		if !ok {
			continue
		}
		readyByTarget[ns+"/"+podName+"/"+targetID] += s.Value
	}
	return readyByTarget
}

func collectBalancerCandidates(pending, failfast []promq.Sample) map[string]balancerCandidate {
	candidates := map[string]balancerCandidate{}
	add := func(samples []promq.Sample) {
		for _, s := range samples {
			if s.Value <= 0 {
				continue
			}
			ns, podName := s.Label("namespace"), s.Label("pod")
			if ns == "" || podName == "" {
				continue
			}
			targetID, svcNS, svcName, ok := linkerdBalancerTarget(s)
			if !ok || svcNS == "" || svcName == "" {
				continue
			}
			key := ns + "/" + podName + "/" + targetID
			candidates[key] = balancerCandidate{
				ns:       ns,
				podName:  podName,
				targetID: targetID,
				svcNS:    svcNS,
				svcName:  svcName,
			}
		}
	}
	add(pending)
	add(failfast)
	return candidates
}

// scanOutboundBalancers implements the linkerd-h2-stream-guard outbound
// failure-accrual lockout detection: a meshed client pod whose
// linkerd-proxy holds pending endpoints (or active fail-fast queue-gate
// shutups) for a target with ZERO in endpoint_state="ready" (or legacy
// state="ready") is circuit-broken — idle/boot-only targets with
// ready==0 && pending==0 and no active fail-fast are excluded. The signal
// must persist linkerdBalancerWedgeMinAge (probefw.Persisted on the in-RAM
// balancerSeen ledger) and is cross-checked against live EndpointSlices:
// unresolvable targets or EndpointSlice list failures fail closed, and a
// target Service that genuinely has 0 ready endpoints cluster-wide is a
// real outage rather than a wedge. Confirmed wedges emit
// node_automation_linkerd_outbound_balancer_wedged and get the same
// Ready-sibling-gated SafePodDelete as the storm path (shared 30m
// cooldown key) when LINKERD_H2_STREAM_GUARD_EVICT_ENABLED is enabled.
func (p *linkerdH2StreamGuardCheck) scanOutboundBalancers(
	ctx context.Context, log logr.Logger, now time.Time,
	pods []corev1.Pod, readyByOwner map[types.UID]int,
	rep, balancerRep *probefw.SweepReport) {

	// The balancer series only exists where a Prometheus endpoint
	// resolves — same "no endpoint configured, skip" gate the other
	// metrics-backed signals use (PromQuery would resolve-and-fail
	// the same way, this just skips the noise).
	if _, err := p.PromEndpointCtx(ctx); err != nil {
		return
	}

	pendingSeries, readySeries, failfastSeries, ok := p.queryBalancerSeries(ctx, log)
	if !ok {
		p.carryBalancerEmitted(rep, balancerRep)
		return
	}
	readyByTarget := buildReadyByTarget(readySeries)
	candidates := collectBalancerCandidates(pendingSeries, failfastSeries)

	podByKey := map[string]*corev1.Pod{}
	for i := range pods {
		podByKey[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}

	// The EndpointSlice cross-check census is lazy — one
	// cluster-wide read happens only when a wedge candidate needs
	// disambiguating from a genuine outage.
	var svcReady map[string]int
	svcReadyOK, svcReadyLoaded := false, false
	serviceReadyEndpoints := func(ns, svc string) (int, bool) {
		if !svcReadyLoaded {
			svcReadyLoaded = true
			var err error
			svcReady, err = p.readyEndpointsByService(ctx)
			if err != nil {
				log.Info("WARN: endpointslices list failed — balancer-wedge cross-check failed closed",
					"error", err)
			} else {
				svcReadyOK = true
			}
		}
		return svcReady[ns+"/"+svc], svcReadyOK
	}

	// Lazy inter-DC partition check: evaluated at most once per sweep only
	// when a persisted wedged pod is actually eligible for deletion.
	partitionChecked, partitionActive := false, false
	partitionNode := ""
	checkPartition := func() (string, bool) {
		if !partitionChecked {
			partitionChecked = true
			partitionNode, partitionActive = p.nebulaPartitionActive(ctx, log, now)
		}
		return partitionNode, partitionActive
	}

	keys := make([]string, 0, len(candidates))
	for k := range candidates {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	keep := map[string]bool{}
	for _, key := range keys {
		cand := candidates[key]
		podKey := cand.ns + "/" + cand.podName
		pod := podByKey[podKey]
		if pod == nil || pod.DeletionTimestamp != nil {
			continue
		}
		if readyByTarget[key] > 0 {
			continue // balancer still has a live ready endpoint — healthy
		}
		n, censusOK := serviceReadyEndpoints(cand.svcNS, cand.svcName)
		if !censusOK {
			// Fail closed on EndpointSlice census failure: preserve
			// held gauges and balancerSeen without deleting pods.
			p.carryBalancerEmitted(rep, balancerRep)
			return
		}
		if n == 0 {
			// The target Service genuinely has zero ready
			// endpoints cluster-wide — a real outage, not a
			// wedge. The proxy is reporting honestly. The
			// first-seen entry is NOT kept: a scaled-to-zero
			// backend must not bank wedge age it never proved.
			continue
		}
		// Only now does the tuple count as wedge evidence — keep
		// marks it for the balancerSeen prune below.
		keep[key] = true
		if !probefw.Persisted(&p.balancerSeen, key, now,
			linkerdBalancerWedgeMinAge, log) {
			continue
		}
		lv := []string{cand.ns, cand.podName}
		// The emitted ledger keys one entry per LABEL TUPLE
		// (ns/pod), not per wedged target: the gauge declares only
		// (namespace, pod), so a target-qualified key would make
		// Reconcile delete the still-wedged series the moment any
		// ONE of the pod's targets recovered (key vanished →
		// DeleteLabelValues(ns, pod)). balancerSeen keeps the
		// per-target granularity — only the emitted key collapses.
		balancerRep.Flag(linkerdOutboundBalancerWedgedGauge, podKey, lv)
		rep.Find(podKey + "(outbound balancer wedged: " + cand.targetID + ")")
		if !p.evictEnabled {
			continue
		}
		if partNode, active := checkPartition(); active {
			log.Info("DEFER: outbound balancer pod heal suppressed during active inter-DC Nebula partition",
				"pod", podKey, "target", cand.targetID, "isolatedNode", partNode)
			continue
		}
		p.maybeSafePodDelete(ctx, log, pod, readyByOwner, now)
	}
	p.balancerSeen.Prune(func(k string) bool { return keep[k] })
}

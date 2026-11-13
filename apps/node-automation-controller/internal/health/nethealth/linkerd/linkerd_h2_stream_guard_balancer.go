// linkerd_h2_stream_guard_balancer.go — the linkerd-h2-stream-guard half of the
// linkerd-h2-stream-guard check: the outbound failure-accrual lockout
// (a client proxy holding balancer endpoints with NONE state="ready"
// long after the destination recovered) and the proxy-OOMKilled wedge
// seed — Prometheus signals cross-checked against live EndpointSlices,
// healed by the shared Ready-sibling-gated pod delete.
package linkerd

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// linkerd-h2-stream-guard — pods whose linkerd-proxy keeps endpoints for a
// target but ZERO in state="ready" past the persistence window,
// while the destination Service still has Ready endpoints: the
// client-side failure-accrual / dead-channel lockout.
var linkerdOutboundBalancerWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_linkerd_outbound_balancer_wedged",
	Help: "1 while the meshed pod's outbound balancer holds endpoints for a target but none in state=ready for >=10m with the destination healthy.",
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
// targets (IP literals, external authorities) report ok=false — the
// wedge cannot be disproven and stands.
func linkerdTargetService(targetAddr string) (ns, name string, ok bool) {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr // port-less or unparseable — try as-is
	}
	// DNS-1123 names carry no dots, so the first two labels are
	// always <name>.<ns> on the standard cluster suffixes.
	parts := strings.Split(host, ".")
	if len(parts) == 5 && parts[2] == "svc" &&
		parts[3] == "cluster" && parts[4] == "local" {
		return parts[1], parts[0], true
	}
	if len(parts) == 3 && parts[2] == "svc" {
		return parts[1], parts[0], true
	}
	return "", "", false
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

// scanOutboundBalancers implements the linkerd-h2-stream-guard outbound
// failure-accrual lockout detection: a meshed client pod whose
// linkerd-proxy holds balancer endpoints for a target but reports
// ZERO in state="ready" is circuit-broken — the destination
// recovered, the client never did. The signal must persist
// linkerdBalancerWedgeMinAge (probefw.Persisted on the in-RAM
// balancerSeen ledger) and is cross-checked against live
// EndpointSlices: a target Service that genuinely has 0 ready
// endpoints cluster-wide is a real outage the proxy is reporting
// honestly — bouncing it heals nothing. Confirmed wedges emit
// node_automation_linkerd_outbound_balancer_wedged and get the same
// Ready-sibling-gated DeletePodHeal as the storm path (shared 30m
// cooldown key).
func (p *linkerdH2StreamGuardCheck) scanOutboundBalancers(
	ctx context.Context, log logr.Logger, now time.Time,
	pods []corev1.Pod, readyByOwner map[types.UID]int,
	rep, balancerRep *probefw.SweepReport) {

	// The balancer series only exists where a Prometheus endpoint
	// resolves — same "no endpoint configured, skip" gate the other
	// metrics-backed signals use (PromQuery would resolve-and-fail
	// the same way, this just skips the noise).
	if _, err := p.PromEndpoint(); err != nil {
		return
	}

	// "total > 0 AND ready == 0" per (namespace, pod, target_addr)
	// is diffed client-side across two instant queries: the literal
	// `> 0 and == 0` single query never matches — the
	// sum(...{state="ready"}) side produces an EMPTY vector for the
	// wedged tuple, and PromQL's `and` intersects it away.
	totals, err := p.PromQuery(ctx,
		`sum by (namespace, pod, target_addr) (outbound_http_balancer_endpoints)`)
	if err != nil {
		log.Info("WARN: linkerd balancer endpoints query failed — wedge signal skipped",
			"error", err)
		return
	}
	readySeries, err := p.PromQuery(ctx,
		`sum by (namespace, pod, target_addr) (outbound_http_balancer_endpoints{state="ready"})`)
	if err != nil {
		log.Info("WARN: linkerd balancer ready-endpoints query failed — wedge signal skipped",
			"error", err)
		return
	}
	readyByTarget := map[string]float64{}
	for _, s := range readySeries {
		readyByTarget[s.Label("namespace")+"/"+s.Label("pod")+
			"/"+s.Label("target_addr")] = s.Value
	}
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
			svcReady, err = p.readyEndpointsByService(ctx)
			if err != nil {
				// Can't tell — a failed census must not skip every
				// candidate (can't disprove the wedge), but must not
				// fail the sweep either.
				log.Info("WARN: endpointslices list failed — balancer-wedge cross-check disabled",
					"error", err)
			} else {
				svcReadyOK = true
			}
		}
		return svcReady[ns+"/"+svc], svcReadyOK
	}

	keep := map[string]bool{}
	for _, s := range totals {
		ns, podName, target := s.Label("namespace"), s.Label("pod"),
			s.Label("target_addr")
		if ns == "" || podName == "" || s.Value <= 0 {
			continue
		}
		if readyByTarget[ns+"/"+podName+"/"+target] > 0 {
			continue // balancer still has a live endpoint — healthy
		}
		key := ns + "/" + podName + "/" + target
		keep[key] = true
		if svcNS, svcName, ok := linkerdTargetService(target); ok {
			if n, censusOK := serviceReadyEndpoints(svcNS, svcName); censusOK && n == 0 {
				// The target Service genuinely has zero ready
				// endpoints cluster-wide — a real outage, not a
				// wedge. The proxy is reporting honestly.
				continue
			}
		}
		if !probefw.Persisted(&p.balancerSeen, key, now,
			linkerdBalancerWedgeMinAge, log) {
			continue
		}
		podKey := ns + "/" + podName
		lv := []string{ns, podName}
		// The emitted ledger keys one entry per LABEL TUPLE
		// (ns/pod), not per wedged target: the gauge declares only
		// (namespace, pod), so a target-qualified key would make
		// Reconcile delete the still-wedged series the moment any
		// ONE of the pod's targets recovered (key vanished →
		// DeleteLabelValues(ns, pod)). balancerSeen keeps the
		// per-target granularity — only the emitted key collapses.
		balancerRep.Flag(linkerdOutboundBalancerWedgedGauge, podKey, lv)
		rep.Find(podKey + "(outbound balancer wedged: " + target + ")")
		pod := podByKey[podKey]
		if pod != nil {
			// Gone or going is nothing to bounce — SafePodDelete
			// skips a terminating pod (the replacement proxy
			// rebuilds its balancer view anyway) and fails closed
			// on the sibling gate before the delete.
			p.SafePodDelete(ctx, log, CheckNameLinkerdH2StreamGuard,
				pod, readyByOwner, 1, linkerdH2HealCool, now)
		}
	}
	p.balancerSeen.Prune(func(k string) bool { return keep[k] })
}

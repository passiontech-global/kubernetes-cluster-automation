// cloudflared_tunnel_health.go — the cloudflared-tunnel-health
// check: the edge-tunnel gray-failure watchdog. cloudflared pods
// report Ready=True on a dead tunnel (the readiness gate is local,
// not edge-reachability), so the check scrapes :2000/metrics for
// ha_connections==0 and the logs for QUIC edge-dial failures.
// Split from the former cloudflared_liqo_tunnel_health.go of the
// flat nethealth package; its peer half lives in nethealth/liqo.
package cloudflared

import (
	"context"
	"fmt"
	"strconv"
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

// ---------------------------------------------------------------------------
// cloudflared-tunnel-health
// ---------------------------------------------------------------------------

// cloudflaredTunnelHealthCheck is the cloudflared tunnel wedge
// watchdog.
type cloudflaredTunnelHealthCheck struct {
	*probefw.Deps

	// streak counts consecutive sweeps each pod read as degraded —
	// the 2-cycle persistence before a delete fires (UID-keyed so a
	// recreate re-arms).
	streak state.StreakLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; one goroutine runs a given check
	// per sweep).
	emitted state.GaugeLedger[string]
	// podsSeen carries each Running connector's last-seen UID
	// ("ns/name" → UID) — the A3 bounce detector: a UID change on
	// the same key means the tunnel endpoint was REPLACED, and the
	// host's conntrack entries toward the old edge tuples stay
	// stale (the UDP blackhole window) until the flush or the fresh
	// connector's re-dial clears them. One goroutine touches a
	// given check per sweep.
	podsSeen map[string]string
}

// NewCloudflaredTunnelHealthCheck builds the cloudflared check — its
// state is the streak/emitted ledgers; pod-delete cooldowns ride the
// shared Deps.Heals set.
func NewCloudflaredTunnelHealthCheck(d *probefw.Deps) probefw.Check {
	return &cloudflaredTunnelHealthCheck{Deps: d}
}

const (
	CheckNameCloudflaredTunnelHealth = "cloudflared-tunnel-health"

	// cloudflared-tunnel-health knobs.
	cfTunnelPodMinAge      = 5 * time.Minute
	cfTunnelMinStreak      = 2
	cfTunnelHealCool       = 30 * time.Minute
	cfTunnelMetricsPort    = 2000
	cfTunnelHTTPTimeout    = 8 * time.Second
	cfTunnelMetricsMaxByte = int64(1 << 20)
)

// cfTunnelQUICMarkers are the log signatures of a cloudflared
// connector whose QUIC path to the edge is dead — the pod stays
// Ready (its /ready endpoint answers locally) while every edge
// dial times out. "failed to sufficiently increase receive buffer"
// is deliberately absent: that cloudflared UDP-buffer warning is
// benign and ships on virtually every host with stock
// net.core.rmem_max — consulted on the metrics-unreachable path it
// turned healthy connectors into repeatedly deleted pods.
var cfTunnelQUICMarkers = []string{
	"failed to dial to edge with quic",
	"timeout: no recent network activity",
}

var (
	// cloudflared pods running a dead tunnel.
	cloudflaredTunnelDegradedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cloudflared_tunnel_degraded",
		Help: "1 while the cloudflared pod reports zero tunnel ha_connections or QUIC edge-dial failures across sweeps.",
	}, []string{"namespace", "pod"})

	// cloudflaredEndpointBouncedTotal counts connector endpoint
	// replacements detected between sweeps (UID change on the same
	// pod key) — each one opens the A3 stale-conntrack window toward
	// the old QUIC edge tuples, so the counter is the flush audit
	// the host-agent nethealth flush keys alongside.
	cloudflaredEndpointBouncedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_cloudflared_endpoint_bounced_total",
		Help: "Cloudflared connector endpoint replacements detected between sweeps (stale conntrack window).",
	}, []string{"namespace"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(cloudflaredTunnelDegradedGauge, cloudflaredEndpointBouncedTotal)
}

// isCloudflaredPod reports whether the pod runs the cloudflared
// connector — a container literally named cloudflared or whose image
// reference contains it (the ingress-controller and gateway releases
// name the container differently but ship the same binary).
func isCloudflaredPod(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == "cloudflared" || strings.Contains(c.Image, "cloudflared") {
			return true
		}
	}
	return false
}

// cfTunnelHAConnections scrapes the pod's :2000/metrics and returns
// the maximum cloudflared_tunnel_ha_connections value — 0 means the
// connector holds no edge connections (a dead tunnel behind a live
// Ready gate). ok=false when the endpoint is unreachable or the
// metric is absent — inconclusive, not healthy (FetchPodMetrics
// folds every failure shape — no client, no IP, transport error,
// non-200 — into the same inconclusive err).
func (p *cloudflaredTunnelHealthCheck) cfTunnelHAConnections(ctx context.Context,
	pod *corev1.Pod) (float64, bool) {

	body, err := probefw.FetchPodMetrics(ctx, p.HTTPClient, pod.Status.PodIP,
		cfTunnelMetricsPort, cfTunnelHTTPTimeout, cfTunnelMetricsMaxByte)
	if err != nil {
		return 0, false
	}
	found := false
	maxV := 0.0
	for _, v := range probefw.ParseMetricValues(
		string(body), "cloudflared_tunnel_ha_connections") {
		found = true
		if v > maxV {
			maxV = v
		}
	}
	return maxV, found
}

// cfTunnelLogQUICStorm fetches the pod's log tail and reports
// whether a QUIC edge-dial failure signature is present. The
// default-container rule applies (no container name — cloudflared
// pods carry a single workload container); a fetch/read failure is
// inconclusive, not healthy.
func (p *cloudflaredTunnelHealthCheck) cfTunnelLogQUICStorm(ctx context.Context,
	pod *corev1.Pod) (bool, error) {

	return kube.ReadPodLogTail(ctx, p.CS, pod, kube.PodLogOpts{
		TailLines:    probefw.DefaultTailLines,
		SinceSeconds: 900,
		MaxBytes:     probefw.LogMaxBytes,
		Timeout:      probefw.LogTimeout,
	}, func(line string) bool {
		l := strings.ToLower(line)
		for _, marker := range cfTunnelQUICMarkers {
			if strings.Contains(l, marker) {
				return true
			}
		}
		return false
	})
}

// checkCloudflaredTunnelHealth scans Running cloudflared pods older
// than 5m — Ready included, the wedge is invisible to readiness. A
// pod reads degraded when :2000/metrics reports ha_connections==0,
// or (metrics unreachable) its log tail carries a QUIC edge-dial
// failure. The signature must persist 2 sweeps and a Ready sibling
// replica must exist before the pod is deleted — a tunnel edge
// outage hits every replica, and bouncing the whole population
// during a real Cloudflare incident is worse than the wedge.
//
// Alongside the wedge audit, the A3 bounce detector watches every
// Running connector's UID: a replacement under the same pod key is a
// tunnel endpoint bounce — the host's conntrack entries toward the
// old QUIC edge tuples stay stale (the UDP blackhole window) until
// the flush or the fresh connector's re-dial clears them — counted
// on cloudflared_endpoint_bounced_total so the host-side flush has
// an audit trail to pair with.
func (p *cloudflaredTunnelHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	// Ready siblings per controller UID — the heal's "someone can
	// absorb the traffic" proof.
	readyByOwner := probefw.ReadyByOwner(pods)

	var rep probefw.SweepReport
	streakKeep := map[string]bool{}
	seenKeep := map[string]bool{} // podsSeen rebuild set — Running connectors only
	var degraded []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			!isCloudflaredPod(pod) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		// A3 bounce detection runs on EVERY Running connector (not
		// just the age-eligible ones — a replacement minutes old has
		// already opened the stale-conntrack window): a UID change
		// under the same key is a tunnel endpoint bounce. The fresh
		// connector's own sockets are clean; the count is the audit
		// the host-side flush pairs with. The streak signature is
		// UID-keyed, so a bounce re-arms the wedge evaluation.
		if prev, ok := p.podsSeen[key]; ok && prev != string(pod.UID) {
			cloudflaredEndpointBouncedTotal.WithLabelValues(pod.Namespace).Inc()
			log.Info("cloudflared connector endpoint bounced — conntrack toward the old QUIC edge is stale until flushed",
				"pod", key, "oldUID", prev, "newUID", pod.UID)
		}
		if p.podsSeen == nil {
			p.podsSeen = map[string]string{} // lazy: zero value usable
		}
		p.podsSeen[key] = string(pod.UID)
		seenKeep[key] = true
		sig := key + "/" + string(pod.UID)
		if now.Sub(pod.CreationTimestamp.Time) < cfTunnelPodMinAge {
			continue // young pod — the wedge evaluation waits it out
		}
		bad := false
		if ha, ok := p.cfTunnelHAConnections(ctx, pod); ok {
			bad = ha == 0
		} else if storm, lerr := p.cfTunnelLogQUICStorm(ctx, pod); lerr == nil {
			bad = storm
		} else {
			// Both evidence paths failed — inconclusive, not clean.
			// Carry the key through the keep-set so the Prune below
			// cannot wipe a streak the sweep could not evaluate —
			// a dead tunnel with flaky evidence would otherwise
			// never reach cfTunnelMinStreak. The emitted tuple
			// carries too: "can't tell" is not "resolved", or one
			// metrics+logs flap would prune a live degraded series.
			log.Info("WARN: cloudflared metrics + logs both unreadable — wedge unverifiable",
				"pod", key, "error", lerr)
			streakKeep[sig] = true
			if lv, held := p.emitted.Last()[key]; held {
				rep.Carry(key, lv)
				rep.Find(key + "(evidence unverifiable — carried)")
			}
			continue
		}
		if !bad {
			p.streak.Reset(sig) // fresh evidence of health — re-arm
			continue
		}
		streakKeep[sig] = true
		if p.streak.Hit(sig) < cfTunnelMinStreak {
			continue
		}
		rep.Emit(cloudflaredTunnelDegradedGauge, key,
			[]string{pod.Namespace, pod.Name}, key)
		degraded = append(degraded, pod)
	}
	p.streak.Prune(func(k string) bool { return streakKeep[k] })
	for k := range p.podsSeen {
		if !seenKeep[k] {
			delete(p.podsSeen, k) // connector gone — a future key re-arms cold
		}
	}
	rep.Close(&p.emitted, cloudflaredTunnelDegradedGauge.DeleteLabelValues)

	for _, pod := range degraded {
		// The degraded pod can still report Ready (the gray-failure
		// shape) — the SafePodDelete gate uses ReadySiblings, which
		// discounts the pod itself so the guard requires a GENUINELY
		// separate sibling (an edge outage vs a wedge unverifiable
		// without one); the cooldown keys on the pod's controller.
		p.SafePodDelete(ctx, log, CheckNameCloudflaredTunnelHealth,
			pod, readyByOwner, 1, cfTunnelHealCool, now)
	}
	return rep.Verdict("cloudflared pods with a dead tunnel across "+
		strconv.Itoa(cfTunnelMinStreak)+" sweeps: ", ", ")
}

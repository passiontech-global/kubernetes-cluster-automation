// cloudflared_liqo_tunnel_health.go — the cloudflared-tunnel-health
// and liqo-tunnel-health checks: the edge-tunnel gray-failure pair.
// cloudflared pods report Ready=True on a dead tunnel (the readiness
// gate is local, not edge-reachability), so the check scrapes
// :2000/metrics for ha_connections==0 and the logs for QUIC
// edge-dial failures. Liqo peers disconnect without the virtual
// node or the gateway pod noticing, so the check reads the
// networking.liqo.io CR status and bounces the liqo-gateway pod.
package nethealth

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
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
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
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
	cfTunnelTailLines      = int64(200)
	cfTunnelLogMaxByte     = int64(256 * 1024)
	cfTunnelMetricsMaxByte = int64(1 << 20)
)

// cfTunnelQUICMarkers are the log signatures of a cloudflared
// connector whose QUIC path to the edge is dead — the pod stays
// Ready (its /ready endpoint answers locally) while every edge
// dial times out.
var cfTunnelQUICMarkers = []string{
	"failed to dial to edge with quic",
	"timeout: no recent network activity",
	"failed to sufficiently increase receive buffer",
}

var (
	// cloudflared pods running a dead tunnel.
	cloudflaredTunnelDegradedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cloudflared_tunnel_degraded",
		Help: "1 while the cloudflared pod reports zero tunnel ha_connections or QUIC edge-dial failures across sweeps.",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		cloudflaredTunnelDegradedGauge,
		liqoPeerUnhealthyGauge)
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

	return probefw.PodLogTail(ctx, p.CS, pod, "",
		cfTunnelTailLines, cfTunnelLogMaxByte, cfTunnelHTTPTimeout,
		func(line string) bool {
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
func (p *cloudflaredTunnelHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	// Ready siblings per controller UID — the heal's "someone can
	// absorb the traffic" proof.
	readyByOwner := probefw.ReadyByOwner(pods.Items)

	var rep probefw.SweepReport
	streakKeep := map[string]bool{}
	var degraded []*corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			now.Sub(pod.CreationTimestamp.Time) < cfTunnelPodMinAge ||
			!isCloudflaredPod(pod) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		bad := false
		if ha, ok := p.cfTunnelHAConnections(ctx, pod); ok {
			bad = ha == 0
		} else if storm, lerr := p.cfTunnelLogQUICStorm(ctx, pod); lerr == nil {
			bad = storm
		} else {
			// Both evidence paths failed — inconclusive, not clean.
			log.Info("WARN: cloudflared metrics + logs both unreadable — wedge unverifiable",
				"pod", key, "error", lerr)
			continue
		}
		if !bad {
			p.streak.Reset(key + "/" + string(pod.UID)) // fresh evidence of health — re-arm
			continue
		}
		sig := key + "/" + string(pod.UID)
		streakKeep[sig] = true
		if p.streak.Hit(sig) < cfTunnelMinStreak {
			continue
		}
		rep.Emit(cloudflaredTunnelDegradedGauge, key,
			[]string{pod.Namespace, pod.Name}, key)
		degraded = append(degraded, pod)
	}
	p.streak.Prune(func(k string) bool { return streakKeep[k] })
	rep.Close(&p.emitted, cloudflaredTunnelDegradedGauge.DeleteLabelValues)

	for _, pod := range degraded {
		key := pod.Namespace + "/" + pod.Name
		ref := metav1.GetControllerOf(pod)
		if ref == nil {
			log.Info("skip heal: unowned cloudflared pod", "pod", key)
			continue
		}
		// The degraded pod can still report Ready (the gray-failure
		// shape) — ReadySiblings discounts it so the guard requires
		// a GENUINELY separate sibling.
		if probefw.ReadySiblings(readyByOwner, pod) < 1 {
			log.Info("skip heal: no healthy cloudflared sibling — edge outage vs wedge unverifiable",
				"pod", key)
			continue
		}
		p.DeletePodHeal(ctx, log, CheckNameCloudflaredTunnelHealth,
			key, pod, cfTunnelHealCool, now)
	}
	return rep.Verdict("cloudflared pods with a dead tunnel across "+
		strconv.Itoa(cfTunnelMinStreak)+" sweeps: ", ", ")
}

// ---------------------------------------------------------------------------
// liqo-tunnel-health
// ---------------------------------------------------------------------------

// liqoTunnelHealthCheck is the liqo peering watchdog.
type liqoTunnelHealthCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
}

// NewLiqoTunnelHealthCheck builds the liqo check — its only state is
// the emitted-gauge ledger; gateway-bounce cooldowns ride the shared
// Deps.Heals set.
func NewLiqoTunnelHealthCheck(d *probefw.Deps) probefw.Check {
	return &liqoTunnelHealthCheck{Deps: d}
}

const (
	CheckNameLiqoTunnelHealth = "liqo-tunnel-health"

	// liqo-tunnel-health knobs.
	liqoPeerDisconnectMinAge = 10 * time.Minute
	liqoGatewayHealCool      = 30 * time.Minute

	// liqoVirtualNodeLabel marks virtual-kubelet node objects —
	// a peer whose virtual node drops Ready is unreachable even
	// while its gateway pods keep running.
	liqoVirtualNodeLabel = "liqo.io/type"
	liqoVirtualNodeValue = "virtual-node"
	// liqoGatewayPodPrefix is the pod-name prefix of the liqo
	// wireguard gateway — the bounce target for a dead peer.
	liqoGatewayPodPrefix = "liqo-gateway"
)

var (
	// Peers whose tunnel/connection is down past the window.
	liqoPeerUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_liqo_peer_unhealthy",
		Help: "1 while the liqo peer is disconnected or its virtual node unready past the window.",
	}, []string{"peer", "reason"})
)

// liqoPeerName resolves the remote cluster's identity for a
// networking.liqo.io object — the remote-cluster-id labels and the
// status/spec clusterID fields cover the shapes across liqo
// versions; the object name is the fallback.
func liqoPeerName(obj *unstructured.Unstructured) string {
	for _, key := range []string{
		"networking.liqo.io/remote-cluster-id",
		"discovery.liqo.io/cluster-id",
		"liqo.io/remote-cluster-id",
	} {
		if v := obj.GetLabels()[key]; v != "" {
			return v
		}
	}
	for _, path := range [][]string{
		{"status", "remoteClusterID"},
		{"status", "clusterID"},
		{"spec", "clusterID"},
	} {
		if v, _ := kube.NestedString(obj.Object, path...); v != "" {
			return v
		}
	}
	return obj.GetName()
}

// liqoDisconnectedFor reports how long the object's
// Connected/Established condition has been False — (age, true) when
// disconnected, false otherwise. A condition absent entirely is not
// evidence (the object may predate status reporting).
func liqoDisconnectedFor(obj *unstructured.Unstructured, now time.Time) (time.Duration, bool) {
	for _, typ := range []string{"Connected", "Established"} {
		c, ok := kube.ConditionOf(obj.Object, typ)
		if !ok {
			continue
		}
		if c.Status != "False" {
			return 0, false // connected — healthy
		}
		if c.LastTransitionTime.IsZero() {
			return 0, true // disconnected, age unverifiable — counts
		}
		return now.Sub(c.LastTransitionTime), true
	}
	return 0, false
}

// liqoPeerFinding is one dead peer resolved to its gauge labels plus
// the namespace its gateway pods live in ("" for virtual-node
// findings — virtual nodes are cluster-scoped, so the gateway pod is
// located by name prefix across all namespaces).
type liqoPeerFinding struct {
	peer, reason, ns string
}

// checkLiqoTunnelHealth audits the liqo peering stack: virtual nodes
// (liqo.io/type=virtual-node) that dropped Ready >=10m ago, plus
// connections/gatewayclients/gatewayservers whose
// Connected/Established condition reads False for the same window.
// Each dead peer bounces the tenant's liqo-gateway pod (30m
// cooldown) — a wedged wireguard re-handshake is the only fix a pod
// restart can force.
func (p *liqoTunnelHealthCheck) Run(ctx context.Context) probefw.Result {
	// The CR scan needs dyn — a missing client is a wiring bug, not
	// "no signal" (same posture as the scylla check).
	if r := p.RequireDyn("liqo tunnel check"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()

	var found []liqoPeerFinding

	// Virtual nodes — Ready False/absent past the window.
	nodes, err := kube.ListNodes(ctx, p.CS)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	for i := range nodes {
		n := &nodes[i]
		if n.Labels[liqoVirtualNodeLabel] != liqoVirtualNodeValue {
			continue
		}
		c := kube.NodeCondition(n, corev1.NodeReady)
		if c != nil && c.Status == corev1.ConditionTrue {
			continue
		}
		var age time.Duration
		if c != nil && !c.LastTransitionTime.IsZero() {
			age = now.Sub(c.LastTransitionTime.Time)
			if age < liqoPeerDisconnectMinAge {
				continue
			}
		}
		peer := n.Labels["liqo.io/remote-cluster-id"]
		if peer == "" {
			peer = n.Name
		}
		found = append(found, liqoPeerFinding{
			peer: peer, reason: "virtual_node_not_ready"})
	}

	// networking.liqo.io CRs — Connected/Established False past the
	// window. An absent CRD family means no liqo on this cluster and
	// that family's scan is skipped, matching the report-GC posture.
	for _, g := range liqoTunnelCRs {
		items, lerr := p.Dyn.Resource(g.gvr).List(ctx, metav1.ListOptions{})
		switch {
		case apierrors.IsNotFound(lerr) || meta.IsNoMatchError(lerr):
			continue
		case lerr != nil:
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", g.gvr.Resource, lerr)}
		}
		for i := range items.Items {
			obj := &items.Items[i]
			age, disconnected := liqoDisconnectedFor(obj, now)
			if !disconnected || age < liqoPeerDisconnectMinAge {
				continue
			}
			found = append(found, liqoPeerFinding{
				peer: liqoPeerName(obj), reason: g.reason,
				ns: obj.GetNamespace()})
		}
	}

	var rep probefw.SweepReport
	for _, f := range found {
		rep.Emit(liqoPeerUnhealthyGauge, f.peer+"/"+f.reason,
			[]string{f.peer, f.reason}, f.peer+"("+f.reason+")")
	}
	rep.Close(&p.emitted, liqoPeerUnhealthyGauge.DeleteLabelValues)

	if len(found) > 0 {
		if err := p.bounceLiqoGateways(ctx, log, found, now); err != nil {
			return probefw.Result{Infra: err}
		}
	}
	return rep.Verdict(fmt.Sprintf(
		"liqo peers disconnected >=%s: ", liqoPeerDisconnectMinAge), ", ")
}

// liqoTunnelCRs is the networking.liqo.io family the peer scan
// reads — connections are the tunnel state, gatewayclients/servers
// the wireguard endpoints on either side.
var liqoTunnelCRs = []struct {
	reason string
	gvr    schema.GroupVersionResource
}{
	{"connection_disconnected", kube.GVRLiqoConnection},
	{"gateway_client_disconnected", kube.GVRLiqoGatewayClient},
	{"gateway_server_disconnected", kube.GVRLiqoGatewayServer},
}

// bounceLiqoGateways deletes one Running liqo-gateway pod per dead
// peer — the wireguard endpoint whose restart forces a re-handshake.
// The pod lives in the CR's namespace (tenant namespace); a
// cluster-scoped virtual-node finding searches every namespace.
// DeletePodHeal carries the cooldown + maintenance gate per peer.
func (p *liqoTunnelHealthCheck) bounceLiqoGateways(ctx context.Context,
	log logr.Logger, found []liqoPeerFinding, now time.Time) error {

	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list pods for liqo gateway bounce: %w", err)
	}
	for _, f := range found {
		var target *corev1.Pod
		for i := range pods.Items {
			pod := &pods.Items[i]
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase != corev1.PodRunning ||
				!strings.HasPrefix(pod.Name, liqoGatewayPodPrefix) {
				continue
			}
			if f.ns != "" && pod.Namespace != f.ns {
				continue
			}
			target = pod
			break
		}
		if target == nil {
			log.Info("no running liqo-gateway pod found for dead peer — bounce skipped",
				"peer", f.peer, "reason", f.reason)
			continue
		}
		p.DeletePodHeal(ctx, log, CheckNameLiqoTunnelHealth,
			"peer/"+f.peer, target, liqoGatewayHealCool, now)
	}
	return nil
}

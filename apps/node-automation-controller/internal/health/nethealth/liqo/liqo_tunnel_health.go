// liqo_tunnel_health.go — the liqo-tunnel-health check: the edge-
// tunnel gray-failure watchdog on the other end of the pair
// (nethealth/cloudflared). Liqo peers disconnect without the virtual
// node or the gateway pod noticing, so the check reads the
// networking.liqo.io CR status and bounces the liqo-gateway pod.
// Split from the former cloudflared_liqo_tunnel_health.go of the
// flat nethealth package.
package liqo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// ---------------------------------------------------------------------------
// liqo-tunnel-health
// ---------------------------------------------------------------------------

// liqoTunnelHealthCheck is the liqo peering watchdog.
type liqoTunnelHealthCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; one goroutine runs a given check
	// per sweep).
	emitted state.GaugeLedger[string]
	// endpoints carries each scanned CR's last-seen tunnel endpoint
	// ("<ns>/<name>" → addr/fqdn) — the A3 stale-conntrack detector:
	// when a peer's WireGuard endpoint moves (remote re-anchored to a
	// new gateway/NAT), the node's conntrack entries toward the OLD
	// ip:port stay UNREPLIED and blackhole the tunnel until flushed
	// or the local gateway rebuilds its sockets. A change (vs the
	// previous sweep's resolution) is a bounce trigger exactly like a
	// dead peer. One goroutine touches a given check per sweep.
	endpoints map[string]string
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

	// liqoEndpointChangedTotal counts peer WireGuard endpoint moves
	// detected between sweeps — each one leaves the host's conntrack
	// entries toward the OLD endpoint stale (the A3 UDP blackhole
	// window) and triggers the peer's gateway bounce (fresh sockets
	// + re-handshake), so the counter doubles as the flush audit.
	liqoEndpointChangedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_liqo_endpoint_changed_total",
		Help: "Liqo peer WireGuard endpoint moves detected between sweeps (stale conntrack window, gateway bounced).",
	}, []string{"peer"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(liqoPeerUnhealthyGauge, liqoEndpointChangedTotal)
}

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
			// Zero condition time falls back to the object's
			// creation age — the same read the virtual-node scan
			// applies (a just-created object never reads as a
			// 10m-dead peer; only a fully unverifiable clock counts).
			if obj.GetCreationTimestamp().Time.IsZero() {
				return liqoPeerDisconnectMinAge, true
			}
			return now.Sub(obj.GetCreationTimestamp().Time), true
		}
		return now.Sub(c.LastTransitionTime), true
	}
	return 0, false
}

// liqoEndpointPaths are the nested paths a liqo tunnel CR carries
// its WireGuard endpoint address under — gatewayclients read the
// remote endpoint from status, gatewayservers advertise theirs in
// spec, and the field spelling drifted across liqo versions
// (addr/address/fqdn, object or bare-string shapes). The first
// non-empty string wins; "" means this object carries no resolvable
// endpoint (connections, pre-status objects) and never joins the
// endpoint ledger.
var liqoEndpointPaths = [][]string{
	{"status", "remoteEndpoint", "addr"},
	{"status", "remoteEndpoint", "address"},
	{"status", "remoteEndpoint", "fqdn"},
	{"spec", "endpoint", "addr"},
	{"spec", "endpoint", "address"},
	{"spec", "endpoint", "fqdn"},
	{"status", "localEndpoint", "addr"},
	{"status", "remoteEndpoint"}, // bare-string shapes
	{"spec", "endpoint"},
}

// liqoEndpointOf resolves a tunnel CR's WireGuard endpoint address
// ("" when none of the known shapes carries one).
func liqoEndpointOf(obj *unstructured.Unstructured) string {
	for _, path := range liqoEndpointPaths {
		if v, _ := kube.NestedString(obj.Object, path...); v != "" {
			return v
		}
	}
	return ""
}

// liqoPeerFinding is one dead peer resolved to its gauge labels plus
// the namespace its gateway pods live in ("" for virtual-node
// findings — virtual nodes are cluster-scoped, so the gateway pod is
// located by name prefix across all namespaces). reason covers both
// the dead-peer signatures and the A3 endpoint_changed trigger.
type liqoPeerFinding struct {
	peer, reason, ns string
}

// checkLiqoTunnelHealth audits the liqo peering stack: virtual nodes
// (liqo.io/type=virtual-node) that dropped Ready >=10m ago,
// connections/gatewayclients/gatewayservers whose
// Connected/Established condition reads False for the same window,
// and — the A3 stale-conntrack trigger — gatewayclients/servers
// whose WireGuard endpoint MOVED between sweeps (the host's
// conntrack entries toward the old endpoint stay UNREPLIED and
// blackhole the tunnel until the gateway rebuilds its sockets).
// Each finding bounces the tenant's liqo-gateway pod (30m cooldown,
// one key per peer — the endpoint bounce and a disconnect bounce
// share it) — a wedged wireguard re-handshake is the only fix a pod
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
	nodes, err := p.AllNodes(ctx)
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
		// Age since the Ready flip; a zero LastTransitionTime falls
		// back to the node's creation age (consistent with the CR
		// path, where an unverifiable condition time counts) — a
		// just-created virtual node never reads as a 10m-dead peer.
		var age time.Duration
		switch {
		case c != nil && !c.LastTransitionTime.IsZero():
			age = now.Sub(c.LastTransitionTime.Time)
		case !n.CreationTimestamp.IsZero():
			age = now.Sub(n.CreationTimestamp.Time)
		default:
			// No verifiable clock at all — counts (consistent with
			// the CR path's unverifiable-condition posture).
			age = liqoPeerDisconnectMinAge
		}
		if age < liqoPeerDisconnectMinAge {
			continue
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
	// endpointKeep is the ledger rebuild set — a CR gone (peer left,
	// object recreated) drops its endpoint entry so a future object
	// reusing the key re-arms cold.
	endpointKeep := map[string]bool{}
	for _, g := range liqoTunnelCRs {
		// The per-sweep unstructured snapshot memoizes one LIST per
		// GVR; the raw error keeps the NoMatch/NotFound = "family
		// absent on this cluster" interpretation.
		items, lerr := p.AllUnstructured(ctx, g.gvr)
		switch {
		case kube.IsCRDAbsent(lerr):
			continue
		case lerr != nil:
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", g.gvr.Resource, lerr)}
		}
		for i := range items {
			obj := &items[i]
			age, disconnected := liqoDisconnectedFor(obj, now)
			if !disconnected || age < liqoPeerDisconnectMinAge {
				continue
			}
			found = append(found, liqoPeerFinding{
				peer: liqoPeerName(obj), reason: g.reason,
				ns: obj.GetNamespace()})
		}
		// A3 stale-conntrack detection: resolve each CR's tunnel
		// endpoint and diff against the previous sweep. Only
		// gatewayclients/gatewayservers carry endpoint shapes —
		// connections resolve to "" and never join the ledger. The
		// ledger key carries the RESOURCE: a gatewayclient and a
		// gatewayserver sharing ns/name must not diff against each
		// other's endpoint.
		for i := range items {
			obj := &items[i]
			key := g.gvr.Resource + "/" + obj.GetNamespace() + "/" + obj.GetName()
			ep := liqoEndpointOf(obj)
			if ep == "" {
				continue
			}
			endpointKeep[key] = true
			prev, seen := p.endpoints[key]
			if p.endpoints == nil {
				p.endpoints = map[string]string{}
			}
			p.endpoints[key] = ep
			if !seen || prev == ep {
				continue
			}
			peer := liqoPeerName(obj)
			liqoEndpointChangedTotal.WithLabelValues(peer).Inc()
			log.Info("liqo WireGuard endpoint moved — conntrack toward the old endpoint is stale, bouncing the gateway",
				"peer", peer, "object", key, "old", prev, "new", ep)
			found = append(found, liqoPeerFinding{
				peer: peer, reason: "endpoint_changed",
				ns: obj.GetNamespace()})
		}
	}
	for k := range p.endpoints {
		if !endpointKeep[k] {
			delete(p.endpoints, k)
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
// cluster-scoped virtual-node finding matches by peer id (the
// remote-cluster-id labels or the pod name) and refuses to bounce a
// gateway it cannot tie to the failing peer. DeletePodHeal carries
// the cooldown + maintenance gate per peer.
func (p *liqoTunnelHealthCheck) bounceLiqoGateways(ctx context.Context,
	log logr.Logger, found []liqoPeerFinding, now time.Time) error {

	pods, err := p.AllPods(ctx)
	if err != nil {
		return fmt.Errorf("list pods for liqo gateway bounce: %w", err)
	}
	for _, f := range found {
		// Candidates: the gateway prefix, live, and (for CR findings)
		// inside the CR's namespace. Peer scoping runs on top: a
		// multi-peer liqo deployment runs one gateway pod per peer,
		// so bouncing a HEALTHY peer's gateway heals nothing.
		var nsCands, peerCands []*corev1.Pod
		for i := range pods {
			pod := &pods[i]
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase != corev1.PodRunning ||
				!strings.HasPrefix(pod.Name, liqoGatewayPodPrefix) {
				continue
			}
			if f.ns != "" && pod.Namespace != f.ns {
				continue
			}
			nsCands = append(nsCands, pod)
			if liqoPodMatchesPeer(pod, f.peer) {
				peerCands = append(peerCands, pod)
			}
		}
		// Prefer the peer-matched gateway. Fallback to the namespace's
		// gateway ONLY when that namespace holds a single gateway pod
		// — then the namespace itself is the peer scope. With several
		// gateways (multi-peer topology) an unattributable finding
		// must not bounce a HEALTHY peer's gateway; keep the finding
		// only. A namespace-less virtual-node finding needs an
		// explicit peer match — an unattributable bounce skips.
		target := liqoOldestPod(peerCands)
		if target == nil && f.ns != "" && len(nsCands) == 1 {
			target = nsCands[0]
		}
		if target == nil {
			log.Info("no liqo-gateway pod matched the dead peer — bounce skipped",
				"peer", f.peer, "reason", f.reason, "namespace", f.ns)
			continue
		}
		p.DeletePodHeal(ctx, log, CheckNameLiqoTunnelHealth,
			"peer/"+f.peer, target, liqoGatewayHealCool, now)
	}
	return nil
}

// liqoPodMatchesPeer reports whether the gateway pod carries the
// failing peer's identity — one of the remote-cluster-id labels, or
// the peer id inside the pod name (liqo names gateways
// liqo-gateway-<peer-suffix>-<hash>).
func liqoPodMatchesPeer(pod *corev1.Pod, peer string) bool {
	if peer == "" {
		return false
	}
	for _, key := range []string{
		"networking.liqo.io/remote-cluster-id",
		"discovery.liqo.io/cluster-id",
		"liqo.io/remote-cluster-id",
	} {
		if pod.Labels[key] == peer {
			return true
		}
	}
	return strings.Contains(strings.ToLower(pod.Name), strings.ToLower(peer))
}

// liqoOldestPod returns the oldest candidate — the least-recently
// restarted gateway takes the bounce.
func liqoOldestPod(cands []*corev1.Pod) *corev1.Pod {
	var oldest *corev1.Pod
	for _, pod := range cands {
		if oldest == nil ||
			pod.CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = pod
		}
	}
	return oldest
}

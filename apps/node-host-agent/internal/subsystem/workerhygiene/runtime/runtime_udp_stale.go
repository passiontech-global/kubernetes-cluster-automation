// runtime_udp_stale.go — Wave-3 #3: Connected-UDP dead-backend socket
// destroyer (NETLINK_SOCK_DIAG + SOCK_DESTROY).
//
// In Kubernetes, a pod holding a connected UDP socket (e.g. Go net.Dial("udp")
// to a ClusterIP Service or backend Pod IP) keeps sending packets into a
// conntrack/eBPF blackhole forever after the backend Pod terminates and its IP
// disappears. This check scans each K8s pod netns (pause tasks from the
// node-scoped task map), filters connected UDP sockets whose DstIP lies in
// the merged cluster Pod CIDR, and only then treats them as dead-Service
// backends when the DstPort is managed by an existing UDP EndpointSlice
// and the IP has vanished from every slice for that port. Direct
// Pod-to-Pod UDP on any other port is never a candidate (Wave-5 P0).
// The API read is fail-closed and a verdict needs >= 2 cycles before
// SOCK_DESTROY.
//
// Wave-5 P0: the old version listed ALL Pods and ALL Services cluster-wide
// every 60s from a DaemonSet (guaranteed 403 on services + 512Mi OOM risk),
// and used the node's own /24 PodCIDR with localPodIPs only. It now uses
// node-scoped pods from e.Pods, the shared task map for pause PIDs, Node
// PodCIDRs merged with ResourceVersion:"0", and EndpointSlices (already in
// NHA's RBAC) as the live-backend authority. Cilium health AND host IPs
// advertised on node annotations are explicitly excluded from kill
// candidates, including when the CIDR list is operator-overridden.
package runtime

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/ledger"
)

const (
	udpStaleMinStreak  = 2
	udpPodCIDRCacheTTL = 5 * time.Minute

	// Cilium advertises its per-node health AND host endpoint IPs on
	// these Node annotations. Both live inside the pod CIDR but are
	// NOT pod backends — a stale-socket verdict against either would
	// kill a healthy cilium-health / cilium-host endpoint (Wave-5 P0).
	ciliumIPv4HealthAnno = "io.cilium.network.ipv4-health-ip"
	ciliumIPv6HealthAnno = "io.cilium.network.ipv6-health-ip"
	ciliumIPv4HostAnno   = "io.cilium.network.ipv4-cilium-host"
	ciliumIPv6HostAnno   = "io.cilium.network.ipv6-cilium-host"
)

// UDPStaleCheck is the Wave-3 #3 connected-UDP dead-backend socket destroyer.
type UDPStaleCheck struct {
	d              *wdeps.Deps
	streaks        ledger.StreakLedger
	cachedCIDR     []*net.IPNet
	cachedHealth   map[string]bool
	cidrCachedAt   time.Time
	healthCachedAt time.Time
	// everSeenUDP remembers every (ip, port) that has EVER appeared as
	// a UDP EndpointSlice endpoint — including endpoints with
	// Serving=false/Terminating and endpoints on a Node that has
	// since vanished or gone NotReady. A socket is a dead-Service
	// backend only if its exact dst ip:port was once an endpoint:
	// a direct Pod-to-Pod UDP flow that merely reuses a Service's
	// port was never an endpoint and must never be destroyed.
	everSeenUDP ledger.SeenSet
	// everSeenSeeded marks the one-time backfill of local Pod IPs into
	// the ledger — a backend on this very node is excluded from the
	// candidate scan while alive, so its ip:port would otherwise never
	// enter everSeenUDP and a later blackhole could not be recognised.
	everSeenSeeded bool
}

// ipPort is the destination identity a Socket points at. A port being
// managed by some EndpointSlice is NOT enough — the specific IP must
// have been an endpoint of that port at some point (everSeenUDP).
type ipPort struct {
	ip   string
	port uint16
}

func (p ipPort) key() string { return p.ip + ":" + strconv.Itoa(int(p.port)) }

// NewUDPStale builds the check.
func NewUDPStale(d *wdeps.Deps) *UDPStaleCheck {
	return &UDPStaleCheck{d: d}
}

// Name returns the check label / WD_SIG key.
func (c *UDPStaleCheck) Name() string { return wdeps.CheckUDPStale }

type udpNetnsRep struct {
	pid  int
	link string
}

type udpCandidate struct {
	repPID    int
	netnsLink string
	sock      netlinkx.ConnectedUDPSocket
	dstIPStr  string
	key       string
}

// pausePIDs returns the PIDs of LIVE pause (sandbox infra) tasks from
// the once-per-cycle containerd task map — i.e. only K8s pod netns.
// The old code used every host PID (or PidsOnce), which swept host and
// Concourse container netns and could destroy unrelated sockets.
func (c *UDPStaleCheck) pausePIDs(e *wdeps.CycleEnv) ([]int, bool) {
	tasks, complete := c.d.CycleTasks(e)
	if !complete {
		return nil, false
	}
	seen := map[int]bool{}
	var pids []int
	for _, ts := range tasks {
		for _, t := range ts {
			if !t.Live || t.PID <= 0 || (t.Name != "pause" && t.Name != "POD") {
				continue
			}
			if seen[t.PID] {
				continue
			}
			seen[t.PID] = true
			pids = append(pids, t.PID)
		}
	}
	return pids, true
}

func (c *UDPStaleCheck) podNetnsReps(pids []int) ([]udpNetnsRep, bool) {
	hostLink, _ := os.Readlink(c.d.Proc.File(1, "ns", "net"))
	seen := map[string]bool{}
	if hostLink != "" {
		seen[hostLink] = true
	}
	var reps []udpNetnsRep
	readErr := false
	for _, pid := range pids {
		if pid == 1 {
			continue
		}
		link, err := os.Readlink(c.d.Proc.File(pid, "ns", "net"))
		if err != nil {
			if !os.IsNotExist(err) {
				readErr = true
			}
			continue
		}
		if seen[link] {
			continue
		}
		seen[link] = true
		reps = append(reps, udpNetnsRep{pid: pid, link: link})
	}
	return reps, readErr
}

// resolvePodCIDRs merges every Node's PodCIDR/PodCIDRs (one cached
// watch LIST at RV=0) and records the cilium-health AND cilium-host IPs
// advertised on node annotations so they can be subtracted from kill
// candidates. The annotation read is NEVER skipped by a
// UDPStalePodCIDRs override: overriding the CIDR list must not expose
// cilium-host as a dead backend.
func (c *UDPStaleCheck) resolvePodCIDRs(ctx context.Context) []*net.IPNet {
	raw := strings.TrimSpace(c.d.Cfg.Wave3.UDPStalePodCIDRs)
	// Base.Clock may be nil (the live clock is Seams.Host.Clock) —
	// always read the armed seam, never the promoted fallback.
	now := c.d.Cfg.Seams.Host.Clock.Now()

	var nets []*net.IPNet
	if raw != "" {
		// Operator override supplies the CIDRs, but NOT the exempt IPs.
		for part := range strings.SplitSeq(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ipNet, err := net.ParseCIDR(part); err == nil {
				nets = append(nets, ipNet)
			}
		}
	} else if len(c.cachedCIDR) > 0 && now.Sub(c.cidrCachedAt) < udpPodCIDRCacheTTL {
		nets = c.cachedCIDR
	}

	refreshHealth := c.healthCachedAt.IsZero() || now.Sub(c.healthCachedAt) >= udpPodCIDRCacheTTL
	refreshCIDRs := raw == "" && !(len(c.cachedCIDR) > 0 && now.Sub(c.cidrCachedAt) < udpPodCIDRCacheTTL)
	if (refreshHealth || refreshCIDRs) && c.d.Cfg.Client != nil {
		nodes, err := c.d.Cfg.Client.CoreV1().Nodes().List(ctx,
			metav1.ListOptions{ResourceVersion: "0"})
		if err == nil {
			seen := map[string]bool{}
			health := map[string]bool{}
			var nodeNets []*net.IPNet
			for i := range nodes.Items {
				node := &nodes.Items[i]
				for _, anno := range []string{ciliumIPv4HealthAnno, ciliumIPv6HealthAnno,
					ciliumIPv4HostAnno, ciliumIPv6HostAnno} {
					if s := canonicalIP(node.Annotations[anno]); s != "" {
						health[s] = true
					}
				}
				rawCIDRs := node.Spec.PodCIDRs
				if len(rawCIDRs) == 0 && node.Spec.PodCIDR != "" {
					rawCIDRs = []string{node.Spec.PodCIDR}
				}
				for _, cidr := range rawCIDRs {
					cidr = strings.TrimSpace(cidr)
					if cidr == "" || seen[cidr] {
						continue
					}
					if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
						seen[cidr] = true
						nodeNets = append(nodeNets, ipNet)
					}
				}
			}
			// Keep the annotation set even under a CIDR override —
			// the health/host IPs are exempt on EVERY port.
			c.cachedHealth = health
			c.healthCachedAt = now
			if raw == "" && len(nodeNets) > 0 {
				c.cachedCIDR = nodeNets
				c.cidrCachedAt = now
				nets = nodeNets
			}
		}
	}
	if raw == "" && len(nets) == 0 {
		nets = c.cachedCIDR // keep the last good view on a failed LIST
	}
	return nets
}

func ipInAnyCIDR(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func canonicalIP(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// Run executes one connected-UDP dead-backend sweep.
func (c *UDPStaleCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckUDPStale) {
		return
	}

	// Fail closed FIRST: an unhealthy API cycle may hand us a stale
	// or empty Pod list, so no API-backed verdict — and above all no
	// socket sweep or SOCK_DESTROY — may run on it.
	if e != nil && !e.APIOK {
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}

	// Acquire the Node snapshot BEFORE sweeping sockets: it produces
	// both the PodCIDRs and the cilium health/host exemptions. The
	// guard below applies even under a UDPStalePodCIDRs override —
	// an override supplies CIDRs, not a trustworthy cluster view.
	podCIDRs := c.resolvePodCIDRs(ctx)
	if len(podCIDRs) == 0 || c.healthCachedAt.IsZero() {
		// No healthy-node snapshot: never scan or destroy sockets.
		c.streaks.Prune(func(string) bool { return false })
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}

	// Only K8s pause PIDs — never the host or a Concourse container.
	pids, complete := c.pausePIDs(e)
	if !complete {
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}
	if len(pids) == 0 {
		c.streaks.Prune(func(string) bool { return false })
		c.d.CycleResult(wdeps.CheckUDPStale, "ok")
		return
	}

	// Node-scoped pod IPs from the shared Cycle env (NOT a cluster-wide
	// Pods().List — NHA has no such RBAC and it is an OOM bomb).
	localPodIPs := map[string]bool{}
	if e != nil {
		for i := range e.Pods {
			p := &e.Pods[i]
			// A terminal local pod's IP is no longer a live local
			// endpoint — a socket still pointed at it is exactly
			// the dead-backend case this check owns.
			if p.Status.Phase == corev1.PodSucceeded ||
				p.Status.Phase == corev1.PodFailed {
				continue
			}
			if s := canonicalIP(p.Status.PodIP); s != "" {
				localPodIPs[s] = true
			}
			for _, pip := range p.Status.PodIPs {
				if s := canonicalIP(pip.IP); s != "" {
					localPodIPs[s] = true
				}
			}
		}
	}

	var rawCandidates []udpCandidate
	reps, dumpErr := c.podNetnsReps(pids)
	for _, rep := range reps {
		socks, err := c.d.Cfg.Seams.Host.DumpConnectedUDPFn(rep.pid)
		if err != nil {
			dumpErr = true
			continue
		}
		for _, s := range socks {
			dstStr := s.DstIP.String()
			if localPodIPs[dstStr] || c.cachedHealth[dstStr] {
				continue
			}
			key := rep.link + ":" + hex.EncodeToString(s.ID[:])
			rawCandidates = append(rawCandidates, udpCandidate{
				repPID:    rep.pid,
				netnsLink: rep.link,
				sock:      s,
				dstIPStr:  dstStr,
				key:       key,
			})
		}
	}
	if len(rawCandidates) == 0 {
		if dumpErr {
			c.d.CycleResult(wdeps.CheckUDPStale, "abort")
			return
		}
		c.streaks.Prune(func(string) bool { return false })
		c.d.CycleResult(wdeps.CheckUDPStale, "ok")
		return
	}

	var candidates []udpCandidate
	for _, cand := range rawCandidates {
		if !ipInAnyCIDR(cand.sock.DstIP, podCIDRs) {
			continue
		}
		candidates = append(candidates, cand)
	}

	if len(candidates) == 0 {
		if dumpErr {
			c.d.CycleResult(wdeps.CheckUDPStale, "abort")
			return
		}
		c.streaks.Prune(func(string) bool { return false })
		c.d.CycleResult(wdeps.CheckUDPStale, "ok")
		return
	}

	// Lazy API verification: EndpointSlices only (lightweight, in NHA's
	// RBAC), fail closed on any error. Services/Pods cluster-wide lists
	// were removed — 403 on services and 512Mi OOM on pods.
	if c.d.Cfg.Client == nil {
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}
	listOpts := metav1.ListOptions{ResourceVersion: "0"}
	sliceList, err := c.d.Cfg.Client.DiscoveryV1().EndpointSlices("").List(ctx, listOpts)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: udp-stale-socket lazy EndpointSlices list failed (fail closed): %v", err))
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}

	// The P0 fix: a DstIP is a dead-Service-backend ONLY when its
	// DstPort is managed by an existing UDP EndpointSlice (i.e. a
	// Service currently exposes that UDP port), the exact ip:port
	// was once an EndpointSlice endpoint, and it has since vanished
	// from every slice for that port. A connected UDP flow to any
	// other ip:port is a direct Pod-to-Pod conversation (P2P gossip,
	// headless StatefulSet peers, reply sockets to a client Pod IP)
	// — it is inside podCIDRs but NOT a Service backend and must
	// never be SOCK_DESTROY'd.
	// liveUDPSet (udpPorts) is the set of (port -> addresses) present
	// in the current UDP EndpointSlices. everSeenUDP is the RAM ledger
	// of every (ip, port) that has EVER been an endpoint, including
	// non-serving/terminating ones and ones on vanished/NotReady nodes.
	// A socket may only be destroyed when its exact dst ip:port is in
	// the ledger but no longer live — that is a dead Service backend,
	// not a direct Pod-to-Pod flow reusing the port.
	udpPorts := make(map[uint16]map[string]bool)
	sliceEndpoints := map[string]bool{}
	for i := range sliceList.Items {
		sl := &sliceList.Items[i]
		hasUDPPort := false
		for _, p := range sl.Ports {
			if p.Port != nil && *p.Port > 0 && *p.Port <= 65535 &&
				p.Protocol != nil && *p.Protocol == corev1.ProtocolUDP {
				hasUDPPort = true
				break
			}
		}
		if !hasUDPPort {
			continue
		}
		// liveByAddr distinguishes a genuinely serving endpoint from one
		// that merely still appears in a slice while Terminating /
		// Serving=false, scoped strictly to this slice.
		liveByAddr := map[string]bool{}
		for _, ep := range sl.Endpoints {
			serving := ep.Conditions.Serving != nil && *ep.Conditions.Serving
			if ep.Conditions.Serving == nil &&
				(ep.Conditions.Ready == nil || *ep.Conditions.Ready) {
				serving = true
			}
			for _, addr := range ep.Addresses {
				if s := canonicalIP(addr); s != "" {
					if _, seen := liveByAddr[s]; !seen || serving {
						liveByAddr[s] = serving
					}
				}
			}
		}
		for _, p := range sl.Ports {
			// Port 0 is never a Service port; negative/out-of-range
			// would wrap the uint16 cast. Nil protocol means the
			// Kubernetes TCP default — NOT UDP.
			if p.Port == nil || *p.Port <= 0 || *p.Port > 65535 {
				continue
			}
			if p.Protocol == nil || *p.Protocol != corev1.ProtocolUDP {
				continue
			}
			port := uint16(*p.Port)
			active := udpPorts[port]
			if active == nil {
				active = map[string]bool{}
				udpPorts[port] = active
			}
			for s, serving := range liveByAddr {
				epKey := ipPort{ip: s, port: port}.key()
				c.everSeenUDP.Add(epKey)
				sliceEndpoints[epKey] = true
				if serving {
					active[s] = true // liveUDPSet — only serving endpoints
				}
			}
			// One-time backfill: a backend on THIS node is excluded
			// from rawCandidates while it lives, so without this its
			// ip:port would never enter the ledger and a later
			// blackhole to it could not be recognised (P0 F.1.2).
			if !c.everSeenSeeded {
				for ip := range localPodIPs {
					epKey := ipPort{ip: ip, port: port}.key()
					c.everSeenUDP.Add(epKey)
					sliceEndpoints[epKey] = true
				}
			}
		}
	}
	c.everSeenSeeded = true

	// A connected socket whose SrcPort is locally bound in the same
	// netns is a server replying to a client, not a blackhole. One
	// low-level dump per implicated netns, cached across candidates;
	// an inconclusive dump suppresses every kill in that netns.
	boundByPID := map[int]map[uint16]bool{}
	boundOK := map[int]bool{}
	boundPortsFor := func(pid int) (map[uint16]bool, bool) {
		if ports, ok := boundByPID[pid]; ok {
			return ports, boundOK[pid]
		}
		fn := c.d.Cfg.Seams.Host.UDPBoundPortsFn
		if fn == nil {
			return nil, false
		}
		ports, err := fn(pid)
		boundByPID[pid] = ports
		boundOK[pid] = err == nil
		return ports, err == nil
	}

	seenKeys := make(map[string]bool, len(candidates))
	candKeys := make(map[string]bool, len(candidates))
	var confirmed []udpCandidate
	for _, cand := range candidates {
		active, managed := udpPorts[cand.sock.DstPort]
		epKey := ipPort{ip: cand.dstIPStr, port: cand.sock.DstPort}.key()
		if managed && c.everSeenUDP.Has(epKey) {
			candKeys[epKey] = true
		}
		if !managed || active[cand.dstIPStr] ||
			!c.everSeenUDP.Has(epKey) {
			// Unmanaged port (a nil protocol is Kubernetes' TCP
			// default, never UDP), a still-live endpoint, or an
			// IP:port that was never a Service endpoint (direct
			// Pod-to-Pod UDP reusing a managed port): drop the
			// streak, never arm a kill.
			c.streaks.Reset(cand.key)
			continue
		}
		bound, ok := boundPortsFor(cand.repPID)
		if !ok || bound[cand.sock.SrcPort] {
			// A locally bound SrcPort is a UDP server's reply socket.
			c.streaks.Reset(cand.key)
			continue
		}
		seenKeys[cand.key] = true
		if c.streaks.Hit(cand.key) >= udpStaleMinStreak {
			confirmed = append(confirmed, cand)
		}
	}
	if !dumpErr {
		c.streaks.Prune(func(k string) bool { return seenKeys[k] })
		c.everSeenUDP.Prune(func(k string) bool {
			return sliceEndpoints[k] || candKeys[k]
		})
	}

	if len(confirmed) > 0 && c.d.Cfg.Wave3.UDPStaleDestroyEnabled {
		if c.d.HoldLocalAction(ctx) {
			// "ok" is the contract label for a validly-gated cycle —
			// "held" was never a declared cycles{check,result} value.
			c.d.CycleResult(wdeps.CheckUDPStale, "ok")
			return
		}
		maxKills := c.d.Cfg.Wave3.UDPStaleMaxKills
		if maxKills <= 0 {
			maxKills = 16
		}
		killed := 0
		for _, cand := range confirmed {
			if killed >= maxKills {
				break
			}
			destroyed, err := c.d.Cfg.Seams.Host.DestroyUDPSocketFn(
				cand.repPID, cand.sock.Family, cand.sock.ID)
			if err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: udp-stale-socket SOCK_DESTROY pid=%d dst=%s:%d failed: %v",
					cand.repPID, cand.dstIPStr, cand.sock.DstPort, err))
				continue
			}
			if !destroyed {
				// Kernel answered ENOENT — the socket was already
				// gone. Idempotent success, but NOT a kill we did.
				c.streaks.Reset(cand.key)
				continue
			}
			killed++
			c.streaks.Reset(cand.key)
			c.d.Series.UDPStaleDestroyed++
			c.d.Actions.WithLabelValues(wdeps.CheckUDPStale, "sock_destroy").Inc()
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: udp-stale-socket SOCK_DESTROY netns=%s pid=%d src_port=%d dst=%s:%d",
				cand.netnsLink, cand.repPID, cand.sock.SrcPort, cand.dstIPStr, cand.sock.DstPort))
		}
	}

	c.d.CycleResult(wdeps.CheckUDPStale, "ok")
}

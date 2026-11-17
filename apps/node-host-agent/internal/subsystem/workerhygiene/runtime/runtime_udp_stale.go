// runtime_udp_stale.go — Wave-3 #3: Connected-UDP dead-backend socket
// destroyer (NETLINK_SOCK_DIAG + SOCK_DESTROY).
//
// In Kubernetes, a pod holding a connected UDP socket (e.g. Go net.Dial("udp")
// to a ClusterIP Service or backend Pod IP) keeps sending packets into a
// conntrack/eBPF blackhole forever after the backend Pod terminates and its IP
// disappears. This check scans each pod netns, filters connected UDP sockets
// whose DstIP lies in the cluster Pod CIDR and isn't on this node, lazily
// verifies against watch-cached Pods/EndpointSlices/Services (fail-closed on
// any API error), confirms over >= 2 consecutive cycles, and issues SOCK_DESTROY.
package runtime

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
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
)

// UDPStaleCheck is the Wave-3 #3 connected-UDP dead-backend socket destroyer.
type UDPStaleCheck struct {
	d            *wdeps.Deps
	streaks      ledger.StreakLedger
	cachedCIDR   []*net.IPNet
	cidrCachedAt time.Time
}

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

func (c *UDPStaleCheck) podNetnsReps(pids []int) []udpNetnsRep {
	hostLink, _ := os.Readlink(c.d.Proc.File(1, "ns", "net"))
	seen := map[string]bool{}
	if hostLink != "" {
		seen[hostLink] = true
	}
	var reps []udpNetnsRep
	for _, pid := range pids {
		if pid == 1 {
			continue
		}
		link, err := os.Readlink(c.d.Proc.File(pid, "ns", "net"))
		if err != nil || seen[link] {
			continue
		}
		seen[link] = true
		reps = append(reps, udpNetnsRep{pid: pid, link: link})
	}
	return reps
}

func (c *UDPStaleCheck) resolvePodCIDRs(ctx context.Context) []*net.IPNet {
	if raw := strings.TrimSpace(c.d.Cfg.Wave3.UDPStalePodCIDRs); raw != "" {
		var nets []*net.IPNet
		for part := range strings.SplitSeq(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ipNet, err := net.ParseCIDR(part); err == nil {
				nets = append(nets, ipNet)
			}
		}
		return nets
	}
	now := c.d.Cfg.Clock.Now()
	if len(c.cachedCIDR) > 0 && now.Sub(c.cidrCachedAt) < udpPodCIDRCacheTTL {
		return c.cachedCIDR
	}
	if c.d.Cfg.Client == nil {
		return c.cachedCIDR
	}
	nodes, err := c.d.Cfg.Client.CoreV1().Nodes().List(ctx,
		metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return c.cachedCIDR
	}
	seen := map[string]bool{}
	var nets []*net.IPNet
	for i := range nodes.Items {
		node := &nodes.Items[i]
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
				nets = append(nets, ipNet)
			}
		}
	}
	if len(nets) > 0 {
		c.cachedCIDR = nets
		c.cidrCachedAt = now
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

	var pids []int
	if e != nil && e.PidsOnce != nil {
		pids = e.PidsOnce()
	} else {
		var err error
		pids, err = c.d.Proc.PIDs()
		if err != nil {
			c.d.CycleResult(wdeps.CheckUDPStale, "abort")
			return
		}
	}

	localPodIPs := map[string]bool{}
	if e != nil {
		for i := range e.Pods {
			p := &e.Pods[i]
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
	for _, rep := range c.podNetnsReps(pids) {
		socks, err := c.d.Cfg.Seams.Host.DumpConnectedUDPFn(rep.pid)
		if err != nil {
			continue
		}
		for _, s := range socks {
			dstStr := s.DstIP.String()
			if localPodIPs[dstStr] {
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
		c.streaks.Prune(func(string) bool { return false })
		c.d.CycleResult(wdeps.CheckUDPStale, "ok")
		return
	}

	podCIDRs := c.resolvePodCIDRs(ctx)
	if len(podCIDRs) == 0 {
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
		c.streaks.Prune(func(string) bool { return false })
		c.d.CycleResult(wdeps.CheckUDPStale, "ok")
		return
	}

	// Lazy API Verification: only called when candidates exist; fail closed on any error.
	if c.d.Cfg.Client == nil {
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}
	listOpts := metav1.ListOptions{ResourceVersion: "0"}
	podList, err := c.d.Cfg.Client.CoreV1().Pods("").List(ctx, listOpts)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: udp-stale-socket lazy Pods list failed (fail closed): %v", err))
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}
	sliceList, err := c.d.Cfg.Client.DiscoveryV1().EndpointSlices("").List(ctx, listOpts)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: udp-stale-socket lazy EndpointSlices list failed (fail closed): %v", err))
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}
	svcList, err := c.d.Cfg.Client.CoreV1().Services("").List(ctx, listOpts)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: udp-stale-socket lazy Services list failed (fail closed): %v", err))
		c.d.CycleResult(wdeps.CheckUDPStale, "abort")
		return
	}

	liveIPs := make(map[string]bool, len(podList.Items)+len(svcList.Items))
	for i := range svcList.Items {
		sv := &svcList.Items[i]
		if s := canonicalIP(sv.Spec.ClusterIP); s != "" {
			liveIPs[s] = true
		}
		for _, cip := range sv.Spec.ClusterIPs {
			if s := canonicalIP(cip); s != "" {
				liveIPs[s] = true
			}
		}
		for _, eip := range sv.Spec.ExternalIPs {
			if s := canonicalIP(eip); s != "" {
				liveIPs[s] = true
			}
		}
	}
	for i := range sliceList.Items {
		sl := &sliceList.Items[i]
		for _, ep := range sl.Endpoints {
			for _, addr := range ep.Addresses {
				if s := canonicalIP(addr); s != "" {
					liveIPs[s] = true
				}
			}
		}
	}
	for i := range podList.Items {
		p := &podList.Items[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if s := canonicalIP(p.Status.PodIP); s != "" {
			liveIPs[s] = true
		}
		for _, pip := range p.Status.PodIPs {
			if s := canonicalIP(pip.IP); s != "" {
				liveIPs[s] = true
			}
		}
	}

	seenKeys := make(map[string]bool, len(candidates))
	var confirmed []udpCandidate
	for _, cand := range candidates {
		if liveIPs[cand.dstIPStr] {
			c.streaks.Reset(cand.key)
			continue
		}
		seenKeys[cand.key] = true
		if c.streaks.Hit(cand.key) >= udpStaleMinStreak {
			confirmed = append(confirmed, cand)
		}
	}
	c.streaks.Prune(func(k string) bool { return seenKeys[k] })

	if len(confirmed) > 0 && c.d.Cfg.Wave3.UDPStaleDestroyEnabled {
		if c.d.HoldLocalAction(ctx) {
			c.d.CycleResult(wdeps.CheckUDPStale, "held")
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
			if err := c.d.Cfg.Seams.Host.DestroyUDPSocketFn(
				cand.repPID, cand.sock.Family, cand.sock.ID); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: udp-stale-socket SOCK_DESTROY pid=%d dst=%s:%d failed: %v",
					cand.repPID, cand.dstIPStr, cand.sock.DstPort, err))
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

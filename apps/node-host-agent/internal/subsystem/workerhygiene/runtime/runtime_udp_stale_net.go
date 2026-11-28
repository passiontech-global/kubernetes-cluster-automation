// runtime_udp_stale_net.go — netns representative resolution, PodCIDR/Cilium-IP
// resolution, and TTL-cached EndpointSlice listing for UDPStaleCheck.
// Split out of runtime_udp_stale.go.
package runtime

import (
	"context"
	"net"
	"os"
	"strings"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

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

func (c *UDPStaleCheck) listEndpointSlices(ctx context.Context) (*discoveryv1.EndpointSliceList, error) {
	now := c.d.Cfg.Seams.Host.Clock.Now()
	if c.cachedSlices != nil && now.Sub(c.slicesCachedAt) < udpEndpointSliceCacheTTL {
		return c.cachedSlices, nil
	}
	listOpts := metav1.ListOptions{ResourceVersion: "0"}
	sliceList, err := c.d.Cfg.Client.DiscoveryV1().EndpointSlices("").List(ctx, listOpts)
	if err != nil {
		return nil, err
	}
	c.cachedSlices = sliceList
	c.slicesCachedAt = now
	return sliceList, nil
}

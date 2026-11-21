// cilium_ipam_reap.go — L1 zombie Cilium endpoint reaper for
// CiliumIPAMCheck: parses GET /v1/endpoint, confirms dead-netdev /
// unowned-IP pod endpoints across two consecutive cycles after IPAM
// exhaustion is latched, and deletes them via DELETE /v1/endpoint/{id}.
package cilium

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// maxReapPerCycle bounds per-cycle endpoint deletions so a huge
	// zombie backlog drains cleanly without overwhelming cilium-agent.
	maxReapPerCycle = 50
	// ipamReapBudgetFile is the hoststate rate-limit budget file for
	// zombie endpoint reaping.
	ipamReapBudgetFile = "last-cilium-ipam-reap"
)

// CiliumEndpoint is the parsed subset of one Cilium agent GET
// /v1/endpoint entry needed to identify dead-netdev zombie pod
// endpoints.
type CiliumEndpoint struct {
	ID            int64
	TopState      string
	State         string
	InterfaceName string
	IPs           []string
}

// ParseCiliumEndpoints decodes a Cilium agent GET /v1/endpoint JSON
// array into CiliumEndpoint records.
func ParseCiliumEndpoints(body []byte) ([]CiliumEndpoint, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty /v1/endpoint body")
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var raw []struct {
		ID     int64  `json:"id"`
		State  string `json:"state"`
		Status struct {
			State      string `json:"state"`
			Networking struct {
				InterfaceName string `json:"interface-name"`
				Addressing    []struct {
					IPv4 string `json:"ipv4"`
					IPv6 string `json:"ipv6"`
				} `json:"addressing"`
			} `json:"networking"`
		} `json:"status"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, err
	}
	out := make([]CiliumEndpoint, 0, len(raw))
	for i := range raw {
		r := &raw[i]
		ep := CiliumEndpoint{
			ID:            r.ID,
			TopState:      strings.TrimSpace(r.State),
			State:         strings.TrimSpace(r.Status.State),
			InterfaceName: strings.TrimSpace(r.Status.Networking.InterfaceName),
		}
		for _, addr := range r.Status.Networking.Addressing {
			if v4 := strings.TrimSpace(addr.IPv4); v4 != "" {
				ep.IPs = append(ep.IPs, v4)
			}
			if v6 := strings.TrimSpace(addr.IPv6); v6 != "" {
				ep.IPs = append(ep.IPs, v6)
			}
		}
		out = append(out, ep)
	}
	return out, nil
}

func isTransitionalEndpointState(topState, statusState string) bool {
	for _, s := range []string{topState, statusState} {
		if strings.EqualFold(s, "creating") || strings.EqualFold(s, "restoring") {
			return true
		}
	}
	return false
}

func normalizeIP(raw string) string {
	s := strings.TrimSpace(raw)
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.String()
	}
	return s
}

func livePodIPSet(pods []corev1.Pod) map[string]struct{} {
	live := make(map[string]struct{}, len(pods)*2)
	for i := range pods {
		p := &pods[i]
		if p.Spec.HostNetwork ||
			p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		if ip := normalizeIP(p.Status.PodIP); ip != "" {
			live[ip] = struct{}{}
		}
		for _, pip := range p.Status.PodIPs {
			if ip := normalizeIP(pip.IP); ip != "" {
				live[ip] = struct{}{}
			}
		}
	}
	return live
}

func (c *CiliumIPAMCheck) reapZombieEndpoints(ctx context.Context, e *wdeps.CycleEnv) {
	if !c.d.Cfg.Cilium.IPAMReapEnabled {
		c.seenZombies = nil
		return
	}
	if !e.APIOK {
		return
	}
	if c.d.Cfg.Seams.Cilium.UnixGet == nil || c.d.Cfg.Seams.Cilium.UnixDelete == nil {
		return
	}
	epBody, err := c.d.Cfg.Seams.Cilium.UnixGet(ctx, c.d.Cfg.Cilium.Socket, "/v1/endpoint")
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-ipam endpoint query on %s failed: %v — skip reap",
			c.d.Cfg.Cilium.Socket, err))
		return
	}
	eps, err := ParseCiliumEndpoints(epBody)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-ipam /v1/endpoint unparseable: %v — skip reap", err))
		return
	}
	statFn := c.d.Cfg.Seams.Host.StatFn
	if statFn == nil {
		statFn = os.Stat
	}
	// Fail closed if SysClassNet itself is absent/unreadable: otherwise
	// every live pod interface stat would return ENOENT.
	if fi, err := statFn(c.d.Cfg.SysClassNet); err != nil || !fi.IsDir() {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-ipam SysClassNet %s unavailable (err=%v) — fail-closed, skip reap",
			c.d.Cfg.SysClassNet, err))
		return
	}

	liveIPs := livePodIPSet(e.Pods)
	var candidates []int64
	for i := range eps {
		ep := &eps[i]
		if ep.ID <= 0 {
			continue
		}
		if !isPodLxcIface(ep.InterfaceName) {
			continue
		}
		if isTransitionalEndpointState(ep.TopState, ep.State) {
			continue
		}
		ifacePath := filepath.Join(c.d.Cfg.SysClassNet, ep.InterfaceName)
		if _, err := statFn(ifacePath); err == nil {
			// Host netdev still exists — live endpoint, never a zombie.
			continue
		} else if !os.IsNotExist(err) {
			// Unexpected stat error (e.g. EACCES/EIO) — fail closed.
			continue
		}
		ipOwned := false
		for _, ip := range ep.IPs {
			if _, ok := liveIPs[normalizeIP(ip)]; ok {
				ipOwned = true
				break
			}
		}
		if ipOwned {
			continue
		}
		candidates = append(candidates, ep.ID)
	}

	// 2-cycle confirmation: prune disappeared endpoints and only confirm
	// IDs already observed as zombie candidates on the previous cycle.
	nextSeen := make(map[int64]bool, len(candidates))
	var confirmed []int64
	for _, id := range candidates {
		if nextSeen[id] {
			continue
		}
		nextSeen[id] = true
		if c.seenZombies[id] {
			confirmed = append(confirmed, id)
		}
	}
	c.seenZombies = nextSeen
	if len(confirmed) == 0 {
		return
	}

	if c.d.HoldEmergencyHeal(ctx) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-ipam-reap %d confirmed zombie endpoints — held by maintenance window, skip",
			len(confirmed)))
		return
	}
	if !c.d.State.RateTrySpend(ipamReapBudgetFile, c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-ipam-reap %d confirmed zombie endpoints — cooldown active, skip",
			len(confirmed)))
		return
	}

	slices.Sort(confirmed)
	toReap := confirmed
	if len(toReap) > maxReapPerCycle {
		toReap = toReap[:maxReapPerCycle]
	}

	c.d.StampLocalRemediation(ctx)
	deleted, failed := 0, 0
	for _, id := range toReap {
		path := fmt.Sprintf("/v1/endpoint/%d", id)
		if err := c.d.Cfg.Seams.Cilium.UnixDelete(ctx, c.d.Cfg.Cilium.Socket, path); err != nil {
			failed++
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cilium-ipam-reap DELETE %s failed: %v", path, err))
			continue
		}
		deleted++
		delete(c.seenZombies, id)
	}
	if deleted > 0 && c.d.Actions != nil {
		c.d.Actions.WithLabelValues(wdeps.CheckCiliumIPAM, "endpoint-delete").Add(float64(deleted))
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION cilium-ipam-reap: deleted=%d failed=%d confirmed=%d remaining=%d",
		deleted, failed, len(confirmed), len(confirmed)-deleted))
}

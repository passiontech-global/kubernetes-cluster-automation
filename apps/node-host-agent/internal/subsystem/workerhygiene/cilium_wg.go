// cilium_wg.go — W5.6 WireGuard peer-gc drift healer
// (ciliumWGCheck): cilium_wg0 alive but allowed-ips peers below the
// expected count → latch + agent restart — plus the wg/encrypt-
// status/healthz peer-count parsers and the ReadyNodes fallback.
package workerhygiene

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// --- Check: cilium WireGuard peer-gc drift healer (W5.6) ---
// A cilium WireGuard node can lose its wg0 peer table (kernel-side
// peer GC racing agent bookkeeping): cilium_wg0 exists, the agent's
// healthz stays green, but every peer's allowed-ips reads "(none)"
// — the node encrypts nothing while cross-node pod traffic
// blackholes. The healer compares live allowed-ips peers against the
// expected count (cilium-dbg encrypt status, falling back to
// ReadyNodes-1) and restarts the agent through the shared cilium
// budget.

// parseWGAllowedIPs counts peers carrying a real allowed-ips set —
// `wg show <iface> allowed-ips` prints "<pubkey>\t<ip,ip,...>" per
// line, "(none)" for a peer whose routes were wiped.
func parseWGAllowedIPs(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] == "(none)" {
			continue
		}
		n++
	}
	return n
}

// encryptPeersRe matches a textual "num-peers"-style field inside
// `cilium-dbg encrypt status` — versions that print a table instead
// of JSON (e.g. "NumPeers: 5", "num_peers=5").
var encryptPeersRe = regexp.MustCompile(`(?i)num.?peers[^0-9]*([0-9]+)`)

// parseCiliumEncryptPeers extracts the expected WireGuard peer count
// from `cilium-dbg encrypt status`. JSON bodies are searched for a
// num-peers-ish key (the largest match wins — interfaces may repeat
// the field); a non-JSON body falls back to a text regex. ok=false
// means no usable number (non-wireguard mode, older agent).
func parseCiliumEncryptPeers(out string) (int, bool) {
	var v any
	if json.Unmarshal([]byte(out), &v) == nil {
		var vals []int64
		hostutil.JSONFindInts(v, &vals, "num-peers", "numpeers", "num_peers")
		if len(vals) > 0 {
			return int(slices.Max(vals)), true
		}
		return 0, false
	}
	if m := encryptPeersRe.FindStringSubmatch(out); m != nil {
		n, err := strconv.Atoi(m[1])
		return n, err == nil
	}
	return 0, false
}

// parseCiliumHealthNodes counts remote cluster members in the
// agent's /v1/healthz payload ({"cluster":{"nodes":[...]}} — the
// same source `cilium status` reports "Cluster health: N/M"). Every
// entry is a remote node running cilium-agent, i.e. one WireGuard
// peer this node should hold; virtual/liqo nodes run no agent and
// never appear. ok=false when the section is absent or empty — the
// caller then falls back to the node-list heuristic.
func parseCiliumHealthNodes(body []byte) (int, bool) {
	var resp struct {
		Cluster *struct {
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(body, &resp); err != nil ||
		resp.Cluster == nil || len(resp.Cluster.Nodes) == 0 {
		return 0, false
	}
	return len(resp.Cluster.Nodes), true
}

// readyNodeCount lists Ready, REAL nodes — the expected-peers
// fallback (every other real Ready node should be a WireGuard
// peer). Virtual nodes (Liqo/virtual-kubelet) are excluded — they
// run no cilium-agent so they never become peers; control-plane
// members are excluded too: undercounting expected is the
// fail-safe direction (it can only blunt a partial-drift signal,
// never produce the repeated false kill an overcount causes).
func (h *Hygiene) readyNodeCount(ctx context.Context) int {
	list, err := h.cfg.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}
	n := 0
	for i := range list.Items {
		node := &list.Items[i]
		// Virtual nodes run no cilium-agent — never peers.
		if _, ok := node.Labels["liqo.io/type"]; ok {
			continue
		}
		if _, ok := node.Labels["virtual-kubelet.io/provider"]; ok {
			continue
		}
		if node.Labels["type"] == "virtual-kubelet" {
			continue
		}
		// Control-plane members may or may not run the agent —
		// excluding them can only undercount (fail safe).
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			continue
		}
		if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
			continue
		}
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				n++
				break
			}
		}
	}
	return n
}

// ciliumWGCheck detects the wiped peer table: it runs only on
// nodes where cilium_wg0 exists, the API answered, and a
// cilium-agent task is running — every other shape is another
// check's signal. actual < expected for ConsecNeeded consecutive
// cycles latches state-cilium-wg-peer-wipe and SIGKILLs the agent
// (kubelet restarts it; the shared last-cilium-restart 30m budget
// and the node-overloaded gate apply like sig9). The streak stays
// on Hygiene (ciliumWGFails) — pre-Check tests poke it directly.
type ciliumWGCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *ciliumWGCheck) Name() string { return checkCiliumWG }

// Run executes one cilium-wg-peers round.
func (c *ciliumWGCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumWG, "gated").Inc()
		return
	}
	if !e.apiOK {
		// Inconclusive — keep counters/latch exactly like the other
		// API-dependent checks.
		c.h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.h.cfg.Net.SysClassNet, "cilium_wg0")); err != nil {
		// No WireGuard datapath on this node (calico, tunnel mode,
		// hub) — nothing to heal; drop stale evidence.
		c.h.ciliumWGFails = 0
		c.h.state.Exit(hoststate.LatchCiliumWGPeerWipe, nil)
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	tasks, reachable := c.h.ciliumAgentTasks()
	if !reachable {
		c.h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	running := false
	for _, t := range tasks {
		if t.live && t.pid > 0 {
			running = true
			break
		}
	}
	if !running {
		// No live cilium-agent — sig9 owns agent-down; killing
		// nothing here is correct, not a miss.
		c.h.ciliumWGFails = 0
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	actual, err := c.h.cfg.Seams.wgAllowedIPsFn(ctx)
	if err != nil {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers wg allowed-ips probe failed: %v — inconclusive, keeping state", err))
		c.h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	expected, err := c.h.cfg.Seams.ciliumEncryptPeersFn(ctx)
	if err != nil || expected <= 0 {
		// encrypt status unreadable or carries no count — fall back
		// to ReadyNodes-1 (every OTHER Ready node is a peer).
		if n := c.h.readyNodeCount(ctx); n > 1 {
			expected = n - 1
		} else {
			expected = 0
		}
	}
	if expected <= 0 {
		// No expectation available — inconclusive but not harmful:
		// neither count nor clear a streak we cannot verify.
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	if actual >= expected {
		c.h.ciliumWGFails = 0
		c.h.state.Exit(hoststate.LatchCiliumWGPeerWipe, nil)
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	c.h.ciliumWGFails++
	if c.h.ciliumWGFails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d (check %d/%d)",
			actual, expected, c.h.ciliumWGFails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	c.h.state.Enter(hoststate.LatchCiliumWGPeerWipe,
		fmt.Sprintf("allowed_ips=%d expected=%d", actual, expected))
	switch {
	case c.h.state.Exists(hoststate.LatchNodeOverloaded):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d %dx but node overloaded — skip kill",
			actual, expected, c.h.ciliumWGFails))
	case !c.h.state.RateTrySpend("last-cilium-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d %dx but restart cooldown — skip kill",
			actual, expected, c.h.ciliumWGFails))
	default:
		// Budget already spent atomically by the rateTrySpend case.
		if c.h.killCiliumAgent(tasks) {
			// NPD contract: the cilium_wg0 line feeds
			// CiliumWireGuardPeerDrift (events.go).
			c.h.state.AppendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - cilium_wg0 has %d allowed-ip peers while expected %d (kubelet will restart -> wireguard peer resync)",
				actual, expected))
			c.h.ciliumWGFails = 0
			c.h.actions.WithLabelValues(checkCiliumWG, "sigkill").Inc()
		} else {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: cilium-wg-peers allowed_ips=%d expected=%d, no running task to kill",
				actual, expected))
		}
	}
	c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
}

// checkCiliumWGPeers forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumWGPeers(ctx context.Context, apiOK, workerActive bool) {
	h.ciliumWG.Run(ctx, &cycleEnv{apiOK: apiOK, workerActive: workerActive})
}

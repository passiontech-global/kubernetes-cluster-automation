// cilium_wg.go — cilium-wg-peer-gc WireGuard peer-gc drift healer
// (CiliumWGCheck): cilium_wg0 alive but allowed-ips peers below the
// expected count → latch + agent restart — plus the wg/encrypt-
// status/healthz peer-count parsers and the ReadyNodes fallback.
package cilium

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// --- Check: cilium WireGuard peer-gc drift healer (cilium-wg-peer-gc) ---
// A cilium WireGuard node can lose its wg0 peer table (kernel-side
// peer GC racing agent bookkeeping): cilium_wg0 exists, the agent's
// healthz stays green, but every peer's allowed-ips reads "(none)"
// — the node encrypts nothing while cross-node pod traffic
// blackholes. The healer compares live allowed-ips peers against the
// expected count (cilium-dbg encrypt status, falling back to
// ReadyNodes-1) and restarts the agent through the shared cilium
// budget.

// encryptPeersRe matches a textual "num-peers"-style field inside
// `cilium-dbg encrypt status` — versions that print a table instead
// of JSON (e.g. "NumPeers: 5", "num_peers=5").
var encryptPeersRe = regexp.MustCompile(`(?i)num.?peers[^0-9]*([0-9]+)`)

// ParseCiliumEncryptPeers extracts the expected WireGuard peer count
// from `cilium-dbg encrypt status`. JSON bodies are searched for a
// num-peers-ish key (the largest match wins — interfaces may repeat
// the field); a non-JSON body falls back to a text regex. ok=false
// means no usable number (non-wireguard mode, older agent).
func ParseCiliumEncryptPeers(out string) (int, bool) {
	var v any
	if json.Unmarshal([]byte(out), &v) == nil {
		var vals []int64
		procfs.JSONFindInts(v, &vals, "num-peers", "numpeers", "num_peers")
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

// readyNodeCount lists Ready, REAL nodes — the expected-peers
// fallback (every other real Ready node should be a WireGuard
// peer). Virtual nodes (Liqo/virtual-kubelet) are excluded — they
// run no cilium-agent so they never become peers; control-plane
// members are excluded too: undercounting expected is the
// fail-safe direction (it can only blunt a partial-drift signal,
// never produce the repeated false kill an overcount causes).
func readyNodeCount(d *wdeps.Deps, ctx context.Context) int {
	// ResourceVersion "0": serve the LIST from the apiserver's watch
	// cache — expected-peer counting is a best-effort scan the drift
	// guard re-evaluates every cycle (verdicts ride confirm windows,
	// so a cache-lag view moves nothing on its own), and the
	// per-cycle quorum read + etcd fan-out is skipped.
	list, err := d.Cfg.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		ResourceVersion: "0",
	})
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

// CiliumWGCheck detects the wiped peer table: it runs only on
// nodes where cilium_wg0 exists, the API answered, and a
// cilium-agent task is running — every other shape is another
// check's signal. actual < expected for ConsecNeeded consecutive
// cycles latches state-cilium-wg-peer-wipe and SIGKILLs the agent
// (kubelet restarts it; the shared last-cilium-restart 30m budget
// and the node-overloaded gate apply like sig9). Fails is the
// consecutive peer-deficit streak (ex-Deps.CiliumWGFails) — tests
// poke it via the named Hygiene field.
type CiliumWGCheck struct {
	d     *wdeps.Deps
	Fails int
	// peerStats — the per-peer zombie state held across Run
	// cycles: last transfer counters, when tx first flowed with a
	// zero handshake, and the consecutive stalled-cycle streak.
	peerStats map[string]wgPeerSample
}

// Zombie-peer thresholds.
const (
	// wgZombieHandshakeStale — a peer whose latest handshake is
	// older than this while its tx grows but rx never does.
	wgZombieHandshakeStale = 10 * time.Minute
	// wgZombieZeroFlowMin — with handshake==0, tx must have been
	// flowing at least this long to classify the peer.
	wgZombieZeroFlowMin = 5 * time.Minute
	// wgZombieConsecNeeded — consecutive stalled cycles (tx up,
	// rx flat) before a peer classifies as a zombie.
	wgZombieConsecNeeded = 3
)

// wgPeerSample is one peer's cross-cycle state.
type wgPeerSample struct {
	txBytes, rxBytes     int64
	firstZeroHandshakeAt time.Time
	stalledCycles        int
	seen                 bool // sampled at least once before
}

// peerSample merges one dump row into the cross-cycle state and
// returns whether the peer is a zombie: tx increased AND rx stayed
// flat for ConsecNeeded consecutive cycles, AND the handshake is
// stale (>10m) or has never happened while tx has been flowing
// >5m. State for peers that vanished is pruned by the caller.
func (c *CiliumWGCheck) peerSample(p wdeps.WGDumpPeer, now time.Time) bool {
	if c.peerStats == nil {
		c.peerStats = make(map[string]wgPeerSample)
	}
	st := c.peerStats[p.Pub]
	seen := st.seen
	txUp := seen && p.TX > st.txBytes
	rxFlat := seen && p.RX == st.rxBytes
	if txUp && rxFlat {
		st.stalledCycles++
	} else {
		st.stalledCycles = 0
	}
	if p.Handshake == 0 && p.TX > 0 {
		if st.firstZeroHandshakeAt.IsZero() {
			st.firstZeroHandshakeAt = now
		}
	} else {
		st.firstZeroHandshakeAt = time.Time{}
	}
	st.txBytes, st.rxBytes = p.TX, p.RX
	st.seen = true
	c.peerStats[p.Pub] = st
	stale := p.Handshake > 0 &&
		now.Sub(time.Unix(p.Handshake, 0)) > wgZombieHandshakeStale
	never := p.Handshake == 0 && !st.firstZeroHandshakeAt.IsZero() &&
		now.Sub(st.firstZeroHandshakeAt) > wgZombieZeroFlowMin
	return st.stalledCycles >= wgZombieConsecNeeded && (stale || never)
}

// prunePeers drops state for peers no longer in the dump.
func (c *CiliumWGCheck) prunePeers(seen map[string]bool) {
	for k := range c.peerStats {
		if !seen[k] {
			delete(c.peerStats, k)
		}
	}
}

// Name returns the check label / WD_SIG key.
func (c *CiliumWGCheck) Name() string { return wdeps.CheckCiliumWG }

// Run executes one cilium-wg-peers round.
func (c *CiliumWGCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCiliumWG) {
		return
	}
	if !e.APIOK {
		// Inconclusive — keep counters/latch exactly like the other
		// API-dependent checks.
		c.d.CycleResult(wdeps.CheckCiliumWG, "abort")
		return
	}
	if _, err := os.Stat(filepath.Join(c.d.Cfg.SysClassNet, "cilium_wg0")); err != nil {
		// No WireGuard datapath on this node (calico, tunnel mode,
		// hub) — nothing to heal; drop stale evidence (incl. the
		// per-peer zombie state).
		c.Fails = 0
		c.peerStats = nil
		c.d.State.Exit(latchdefs.LatchCiliumWGPeerWipe, nil)
		c.d.CycleResult(wdeps.CheckCiliumWG, "ok")
		return
	}
	tasks, reachable := ciliumAgentTasks(c.d, e)
	if !reachable {
		c.d.CycleResult(wdeps.CheckCiliumWG, "abort")
		return
	}
	running := false
	for _, t := range tasks {
		if t.Live && t.PID > 0 {
			running = true
			break
		}
	}
	if !running {
		// No live cilium-agent — sig9 owns agent-down; killing
		// nothing here is correct, not a miss.
		c.Fails = 0
		c.d.CycleResult(wdeps.CheckCiliumWG, "ok")
		return
	}
	// Prefer the full `wg show cilium_wg0 dump` evidence —
	// it carries per-peer transfer counters and handshakes, so
	// zombie peers (tx flowing, rx dead, stale/no handshake) can be
	// excluded from the healthy count. The dump exec failing keeps
	// the cilium-wg-peer-gc allowed-ips count path (backward compatibility).
	peers, dumpErr := c.d.Cfg.Seams.Cilium.WGDumpPeers(ctx, c.d.Cfg.Systemd)
	if dumpErr != nil {
		peers = nil
	}
	actual, err := 0, error(nil)
	if peers != nil {
		now := c.d.Cfg.Seams.Cilium.MonotonicNow()
		seen := make(map[string]bool, len(peers))
		actual = 0
		for _, p := range peers {
			seen[p.Pub] = true
			// Wiped peers are the original peer-wipe signal — the
			// zombie state machine only classifies live peers.
			if p.AllowedIPs == "(none)" || p.AllowedIPs == "" {
				continue
			}
			if c.peerSample(p, now) {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: cilium-wg-peers zombie peer %.16s… tx=%d rx=%d handshake=%d — excluded from healthy count",
					p.Pub, p.TX, p.RX, p.Handshake))
				continue
			}
			actual++
		}
		c.prunePeers(seen)
	} else {
		actual, err = c.d.Cfg.Seams.Cilium.WGAllowedIPs(ctx, c.d.Cfg.Systemd)
	}
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers wg allowed-ips probe failed: %v — inconclusive, keeping state", err))
		c.d.CycleResult(wdeps.CheckCiliumWG, "abort")
		return
	}
	expected, err := c.d.Cfg.Seams.Cilium.EncryptPeers(ctx, c.d.Cfg.Cilium.Socket)
	if err != nil || expected <= 0 {
		// encrypt status unreadable or carries no count — fall back
		// to ReadyNodes-1 (every OTHER Ready node is a peer).
		if n := readyNodeCount(c.d, ctx); n > 1 {
			expected = n - 1
		} else {
			expected = 0
		}
	}
	if expected <= 0 {
		// No expectation available — inconclusive but not harmful:
		// neither count nor clear a streak we cannot verify.
		c.d.CycleResult(wdeps.CheckCiliumWG, "ok")
		return
	}
	if actual >= expected {
		c.Fails = 0
		c.d.State.Exit(latchdefs.LatchCiliumWGPeerWipe, nil)
		c.d.CycleResult(wdeps.CheckCiliumWG, "ok")
		return
	}
	if c.d.StreakPending(&c.Fails, fmt.Sprintf(
		"suspect: cilium-wg-peers allowed_ips=%d expected=%d",
		actual, expected)) {
		c.d.CycleResult(wdeps.CheckCiliumWG, "ok")
		return
	}
	c.d.State.Enter(latchdefs.LatchCiliumWGPeerWipe,
		fmt.Sprintf("allowed_ips=%d expected=%d", actual, expected))
	switch {
	case c.d.State.Exists(latchdefs.LatchNodeOverloaded):
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d %dx but node overloaded — skip kill",
			actual, expected, c.Fails))
	case !c.d.State.RateTrySpend("last-cilium-restart", c.d.Cfg.MinRestartInterval):
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d %dx but restart cooldown — skip kill",
			actual, expected, c.Fails))
	default:
		// Budget already spent atomically by the rateTrySpend case.
		if killCiliumAgent(c.d, tasks) {
			// NPD contract: the cilium_wg0 line feeds
			// CiliumWireGuardPeerDrift (events.go).
			c.d.State.AppendLog(fmt.Sprintf(latchdefs.ActionCiliumWGKill+
				" has %d allowed-ip peers while expected %d (kubelet will restart -> wireguard peer resync)",
				actual, expected))
			c.Fails = 0
			c.d.Actions.WithLabelValues(wdeps.CheckCiliumWG, "sigkill").Inc()
			// This check runs after CiliumEnvoyCheck in the dispatch —
			// bounce envoy inline for the xDS resync (the shared flag
			// would only be seen next cycle).
			restartEnvoyAfterAgentKill(c.d, e, wdeps.CheckCiliumWG,
				"cilium-agent restarted for wireguard peer drift")
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cilium-wg-peers allowed_ips=%d expected=%d, no running task to kill",
				actual, expected))
		}
	}
	c.d.CycleResult(wdeps.CheckCiliumWG, "ok")
}

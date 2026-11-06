package nethealth

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	yaml3 "go.yaml.in/yaml/v3"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

const (
	// nebulaDegradedCTFlushInterval is the W12-NM2 dead-peer
	// conntrack flush budget — often enough to unstick a
	// recovered underlay promptly, rare enough that a permanently
	// dead peer can't make `conntrack -D` spam the table every
	// cycle.
	nebulaDegradedCTFlushInterval = 5 * time.Minute
	// nebulaNTPRestartInterval is the timesyncd restart budget when
	// a clock latch accompanies a Nebula failure — tighter than
	// checkClockSync's own 30m because the broken handshake is the
	// live outage; the latch just explains it.
	nebulaNTPRestartInterval = 10 * time.Minute
)

// checkNebulaDirectTCP enforces the pref-1499 Direct-Underlay TCP
// bypass rules (ipproto tcp dport <port> lookup main) for every
// nebula_direct_tcp_ports entry — hostconfig installs them via
// nebula-up.sh + the T5b converge; this guard re-adds a rule the
// kernel lost between converges (same failure mode the netlink route
// guard covers for the overlay tables). Only runs where the nebula
// dataplane is actually deployed.
func (n *NetHealth) checkNebulaDirectTCP(ctx context.Context) {
	wd := n.watchdogConf()
	if wd == nil || !n.nebulaUpExists(wd) {
		n.cycles.WithLabelValues(checkNebTCP, "gated").Inc()
		return
	}
	// The pref-1499 rule table is one kernel object — listing it
	// per port ran the identical `ip rule list` (nsenter fork)
	// once per configured port every cycle.
	out, err := n.ip(ctx, "rule", "list", "pref", "1499")
	if err != nil {
		n.cycles.WithLabelValues(checkNebTCP, "open_error").Inc()
		return
	}
	for _, port := range n.cfg.NebulaDirectTCPPorts {
		if port <= 0 || port > 65535 {
			continue
		}
		p := strconv.Itoa(port)
		if strings.Contains(out, "dport "+p+" ") ||
			strings.Contains(out, "dport "+p+"\n") ||
			strings.HasSuffix(strings.TrimSpace(out), "dport "+p) {
			continue
		}
		if _, err := n.ip(ctx, "rule", "add", "pref", "1499",
			"ipproto", "tcp", "dport", p, "lookup", "main"); err != nil {
			n.state.AppendLog(fmt.Sprintf(
				"nebula-direct-tcp: ip rule add pref 1499 dport %s failed: %v",
				p, err))
			n.cycles.WithLabelValues(checkNebTCP, "restore_error").Inc()
			continue
		}
		n.actions.WithLabelValues(checkNebTCP, "rule_add").Inc()
		n.state.AppendLog(fmt.Sprintf(
			"ACTION: re-added pref-1499 direct-underlay tcp dport %s rule", p))
		// Fold the new rule into the snapshot — a duplicated port
		// entry in the list must not attempt a second add (the old
		// per-iteration re-list saw it for free).
		out += "dport " + p + " "
	}
	n.cycles.WithLabelValues(checkNebTCP, "ok").Inc()
}

// --- Check: nebula-health (13-nebula-health.sh) ---

// udpSocketBound parses /proc/net/udp[6] for a socket bound to port —
// `ss -uHln "sport = :PORT"` parity (UNCONN sockets included — a raw
// parse of the hex local_address field).
func (n *NetHealth) udpSocketBound(port int) bool {
	want := fmt.Sprintf(":%04X", port)
	for _, f := range []string{n.cfg.ProcNetUDP, n.cfg.ProcNetUDP6} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasSuffix(fields[1], want) {
				return true
			}
		}
	}
	return false
}

// hasIPv4Addr mirrors `ip -4 -o addr show dev <dev> | grep .` — a
// tun that failed to init has no address.
func (n *NetHealth) hasIPv4Addr(ctx context.Context, dev string) bool {
	out, err := n.ip(ctx, "-4", "-o", "addr", "show", "dev", dev)
	return err == nil && strings.TrimSpace(out) != ""
}

// nebulaRestarts restarts nebula@<net> through the shared
// last-nebula-restart budget.
func (n *NetHealth) nebulaRestart(ctx context.Context) {
	net := n.cfg.Watchdog.NebulaNet
	if n.cfg.Systemd == nil {
		n.state.SuspectLog("nebula-no-systemd",
			"nebula restart skipped — no systemd client", suspectLogCadence)
		return
	}
	if err := n.cfg.Systemd.Restart(ctx, "nebula@"+net); err != nil {
		n.state.AppendLog(fmt.Sprintf("nebula@%s restart failed: %v", net, err))
		return
	}
	n.actions.WithLabelValues(checkNebula, "restart").Inc()
	// DNS flows pinned to conntrack entries through the dead tunnel
	// stay blackholed until expiry — flush them now.
	n.flushStaleUDPConntrack(ctx, checkNebula)
}

// rmFiles removes every state-dir file matching glob — the module's
// `rm -f $STATE_DIR/<pattern>` cleanup when its unit is inactive.
func (n *NetHealth) rmFiles(pattern string) {
	for _, f := range n.egressFiles(pattern) {
		_ = os.Remove(f)
	}
}

// pingResult bundles the per-target fanout output.
type pingResult struct {
	ok  bool
	rtt float64
}

// checkNebulaHealth — module 13: socket bound, tun addressed, stats
// answering, dataplane probes (only while nebula is the ACTIVE
// overlay — probing over tinc rules would misjudge the warm standby).
func (n *NetHealth) checkNebulaHealth(ctx context.Context) {
	wd := n.cfg.Watchdog
	net := wd.NebulaNet
	if !n.unitEnabledActive(ctx, "nebula@"+net) {
		// Nebula disabled/left mesh → drop this module's states
		// (stale files feed phantom gauges). Egress state is module
		// 12's own business.
		n.rmFiles(hoststate.LatchFilePrefix + "nebula-")
		n.nebulaFails, n.nebulaDpFail, n.nebulaDeg = 0, 0, 0
		n.pmtuFails = 0
		n.nebulaSiteedgeRun = 0
		n.cycles.WithLabelValues(checkNebula, "gated").Inc()
		return
	}
	reason := ""
	dpFail := false // dataplane-dead counts its own counter
	switch {
	case !n.udpSocketBound(wd.NebulaPort):
		reason = fmt.Sprintf("nebula-no-socket udp/%d not bound", wd.NebulaPort)
	case !n.hasIPv4Addr(ctx, wd.NebulaDev):
		reason = "nebula-no-tun-addr dev=" + wd.NebulaDev
	case wd.NebulaStatsURL != "":
		if err := n.cfg.probeHTTP(ctx, wd.NebulaStatsURL, 5*time.Second); err != nil {
			reason = fmt.Sprintf("nebula-stats-dead %s: %v",
				wd.NebulaStatsURL, err)
		}
	}

	// Dataplane probes — ONLY while nebula is the active overlay.
	if reason == "" && wd.OverlayActive == "nebula" &&
		(len(wd.OverlayProbeTargets)+len(wd.OverlayProbeMarkers)) > 0 {
		count := wd.OverlayProbeCount
		if count <= 0 {
			count = 3
		}
		wait := wd.OverlayProbeWait
		if wait <= 0 {
			wait = 4
		}
		// Parallel fanout like wd_ping_fanout — serial pings would
		// blow the check budget on a large mesh.
		targets := append(append(append([]string{},
			wd.OverlayProbeTargets...),
			wd.OverlayProbeMarkers...),
			wd.OverlaySiteMarkers...)
		results := map[string]pingResult{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, rtt := n.cfg.ping(ctx, t, count, wait, false)
				mu.Lock()
				results[t] = pingResult{ok, rtt}
				mu.Unlock()
			}()
		}
		wg.Wait()

		dpAlive, dpTotal := 0, 0
		// W12-NM2: record WHICH peers failed this round — the
		// degraded/siteedge remediation needs the dead set to evict
		// only their conntrack tuples, never a live peer's.
		var deadUnderlay, deadOverlay []string
		for _, t := range wd.OverlayProbeTargets {
			dpTotal++
			if results[t].ok {
				dpAlive++
			} else {
				deadUnderlay = append(deadUnderlay, t)
			}
		}
		mkAlive, mkTotal := 0, 0
		var slowpath []string
		slowSet := map[string]bool{}
		for _, t := range wd.OverlaySlowpathMarkers {
			slowSet[t] = true
		}
		for _, t := range wd.OverlayProbeMarkers {
			mkTotal++
			r := results[t]
			if !r.ok {
				deadOverlay = append(deadOverlay, t)
				continue
			}
			mkAlive++
			if slowSet[t] && r.rtt >= 0 && r.rtt > wd.OverlaySlowpathRTTms {
				slowpath = append(slowpath, fmt.Sprintf("%s=%.1fms", t, r.rtt))
			}
		}
		if len(slowpath) > 0 {
			n.state.SuspectLog(hoststate.LatchNebulaSlowpath, "suspect: nebula-dataplane-slowpath (reroute via remote site) "+
				strings.Join(slowpath, " "), suspectLogCadence)
			n.state.Enter(hoststate.LatchNebulaSlowpath, strings.Join(slowpath, " "))
		} else {
			n.stateExit(hoststate.LatchNebulaSlowpath)
		}
		if len(wd.OverlaySiteMarkers) > 0 {
			var siteedge []string
			for _, t := range wd.OverlaySiteMarkers {
				r := results[t]
				if !r.ok {
					siteedge = append(siteedge, t+"=dead")
					deadOverlay = append(deadOverlay, t)
					continue
				}
				if r.rtt >= 0 && r.rtt > wd.OverlaySiteedgeRTTms {
					siteedge = append(siteedge, fmt.Sprintf("%s=%.1fms", t, r.rtt))
				}
			}
			if len(siteedge) > 0 {
				// The siteedge latch still arms on the first
				// detection (a lost site edge is urgent evidence);
				// nebulaSiteedgeRun is the W12-NM2 confirmation
				// counter the per-peer flush waits on — same
				// ConsecNeeded gate the degraded path carries.
				n.nebulaSiteedgeRun++
				n.state.SuspectLog(hoststate.LatchNebulaSiteedge, "suspect: nebula-siteedge-degraded (site-mesh edge lost) "+
					strings.Join(siteedge, " "), suspectLogCadence)
				n.state.Enter(hoststate.LatchNebulaSiteedge, strings.Join(siteedge, " "))
			} else {
				n.nebulaSiteedgeRun = 0
				n.stateExit(hoststate.LatchNebulaSiteedge)
			}
		} else {
			n.nebulaSiteedgeRun = 0
		}
		switch {
		case (dpTotal > 0 && dpAlive == 0) || (mkTotal > 0 && mkAlive == 0):
			reason = fmt.Sprintf("nebula-dataplane-dead pub=%d/%d marker=%d/%d",
				dpAlive, dpTotal, mkAlive, mkTotal)
			dpFail = true
			n.nebulaDeg = 0
			n.stateExit(hoststate.LatchNebulaDegraded)
			if !n.state.Exists(hoststate.LatchNebulaIsolated) {
				// B3: on the isolation edge the conntrack entries
				// learned on the dead path keep the tunnel blackholed
				// — drop each affected peer's udp/<nebula-port>
				// entries to force re-handshake immediately. The peer
				// set is the FULL known set on purpose: whole-node
				// isolation means every peer's conntrack is stale.
				// NB: the disk latch means the edge won't refire
				// after an agent restart while already isolated —
				// acceptable (restart clears in-memory state but the
				// stale flows have long expired by then).
				n.flushPeerNebulaConntrack(ctx, checkNebula, nebulaPeerUnderlayIPs(wd)...)
			}
			n.state.Enter(hoststate.LatchNebulaIsolated, "dataplane dead")
		case dpTotal-dpAlive >= 2 || mkTotal-mkAlive >= 2:
			n.nebulaDeg++
			need := wd.NebulaDegradedConsec
			if need <= 0 {
				need = 2
			}
			n.state.SuspectLog(hoststate.LatchNebulaDegraded, fmt.Sprintf(
				"suspect: nebula-dataplane-degraded pub=%d/%d marker=%d/%d (run %d/%d)",
				dpAlive, dpTotal, mkAlive, mkTotal, n.nebulaDeg, need),
				suspectLogCadence)
			if n.nebulaDeg >= need {
				n.state.Enter(hoststate.LatchNebulaDegraded, fmt.Sprintf(
					"pub=%d/%d marker=%d/%d", dpAlive, dpTotal, mkAlive, mkTotal))
			}
		default:
			n.nebulaDeg = 0
			n.stateExit(hoststate.LatchNebulaDegraded)
			n.stateExit(hoststate.LatchNebulaIsolated)
		}
		// W12-NM2: a partially-dead dataplane leaves the dead
		// peers' udp/<nebula-port> conntrack pinning the tunnel
		// long after the underlay recovers — the old code only
		// latched and waited for full isolation before any flush.
		// Only the degraded/siteedge (partial death) case applies
		// here — the dataplane-dead branch above owns the
		// all-dead full-set flush already.
		isolated := (dpTotal > 0 && dpAlive == 0) ||
			(mkTotal > 0 && mkAlive == 0)
		if !isolated {
			n.flushDeadNebulaPeers(ctx, wd, deadUnderlay, deadOverlay)
		}
		// W9-NM1: small-packet pings can pass while a DF probe at
		// near-MTU size blackholes — the double-encap path MTU
		// sits below the overlay's. Only evaluated when at least
		// one overlay target answered the small pings; total
		// overlay failure belongs to the isolated/degraded
		// verdicts above, not to a PMTU latch.
		n.checkNebulaPMTU(ctx, targets, results)
	} else {
		// overlay != nebula (or no probe config): don't probe through
		// the other overlay — clear leftover dataplane states.
		n.nebulaDeg = 0
		n.pmtuFails = 0
		n.nebulaSiteedgeRun = 0
		n.stateExit(hoststate.LatchNebulaDegraded)
		n.stateExit(hoststate.LatchNebulaSlowpath)
		n.stateExit(hoststate.LatchNebulaSiteedge)
		n.stateExit(hoststate.LatchNebulaIsolated)
		n.stateExit(hoststate.LatchNebulaPMTUBlackhole)
	}

	if reason == "" {
		n.nebulaFails, n.nebulaDpFail = 0, 0
		n.cycles.WithLabelValues(checkNebula, "ok").Inc()
		return
	}
	// W12-NM2: a skewed/unsynced clock wedges the Nebula handshake
	// (cert not-yet-valid / replay window) — when a clock latch is
	// armed and Nebula is failing, bounce timesyncd under the
	// shared last-ntp-restart budget rather than only cycling
	// nebula.service.
	n.restartTimesyncdOnClockLatch(ctx)
	fails := &n.nebulaFails
	if dpFail {
		fails = &n.nebulaDpFail
	}
	*fails++
	if *fails >= n.cfg.ConsecNeeded &&
		n.state.RateOK("last-nebula-restart", n.cfg.MinRestart) {
		n.state.AppendLog(fmt.Sprintf("ACTION: restarting nebula@%s - %s (persisted %dx)",
			net, reason, *fails))
		n.state.RateSpend("last-nebula-restart")
		n.nebulaFails, n.nebulaDpFail = 0, 0
		n.nebulaRestart(ctx)
	} else {
		// Key on the reason's leading token so a persisting cause
		// throttles to the cadence while a NEW cause still logs at
		// once.
		n.state.SuspectLog(strings.SplitN(reason, " ", 2)[0], fmt.Sprintf(
			"suspect: %s (check %d/%d)",
			reason, *fails, n.cfg.ConsecNeeded), suspectLogCadence)
	}
	n.cycles.WithLabelValues(checkNebula, "ok").Inc()
}

// checkNebulaPMTU is the W9-NM1 double-encapsulation PMTU probe:
// small-packet overlay pings keep passing while a 1200-byte
// don't-fragment probe blackholes — the signature of a path MTU
// below the overlay's (nebula-in-nebula / wg-in-overlay double
// encapsulation leaves less headroom than the overlay MTU
// advertises). The probe only runs when at least one overlay
// target answered the normal small pings — total overlay failure
// is the isolated/degraded verdict's job, not a PMTU latch.
// ConsecNeeded consecutive DF failures latch
// state-nebula-pmtu-blackhole; a passing probe (or no alive
// target) clears it.
func (n *NetHealth) checkNebulaPMTU(ctx context.Context,
	targets []string, results map[string]pingResult) {
	target := ""
	for _, t := range targets {
		if results[t].ok {
			target = t
			break
		}
	}
	if target == "" {
		// No alive overlay peer this cycle — the isolation /
		// degraded verdicts own the diagnosis; a PMTU streak
		// cannot be measured without a reachable target.
		n.pmtuFails = 0
		n.stateExit(hoststate.LatchNebulaPMTUBlackhole)
		return
	}
	out, err := n.cfg.runHostCmd(ctx, []string{
		"ping", "-c", "1", "-W", "2", "-M", "do", "-s", "1200", target})
	if err != nil {
		n.pmtuFails++
		n.state.SuspectLog(hoststate.LatchNebulaPMTUBlackhole, fmt.Sprintf(
			"suspect: nebula-pmtu-blackhole df_probe_failed target=%s size=1200 (check %d/%d): %v (%s)",
			target, n.pmtuFails, n.cfg.ConsecNeeded, err,
			trimRunErr(out)), suspectLogCadence)
		if n.pmtuFails >= n.cfg.ConsecNeeded {
			n.state.Enter(hoststate.LatchNebulaPMTUBlackhole,
				fmt.Sprintf("target=%s df_size=1200", target))
		}
		return
	}
	n.pmtuFails = 0
	n.stateExit(hoststate.LatchNebulaPMTUBlackhole)
}

// flushDeadNebulaPeers — W12-NM2: the targeted per-peer conntrack
// eviction for the degraded/siteedge verdicts. Dead
// OVERLAY_PROBE_TARGETS are already underlay/public IPs (the -d/-s
// tuples conntrack records); dead markers are overlay addresses
// conntrack never sees — they must be resolved through the
// static_host_map before eviction, and an unresolvable marker is
// skipped rather than guessed (flushing an overlay IP would hit
// nothing anyway, but guessing wrong could evict a LIVE peer's
// flows — the exact harm this remediation exists to avoid).
//
// The flush only fires on a CONFIRMED verdict — the degraded latch
// (which carries its own NebulaDegradedConsec gate) or
// nebulaSiteedgeRun >= ConsecNeeded — under the 5m
// last-nebula-degraded-ct-flush budget. nebula.service is never
// restarted here: a half-alive mesh must not lose its working
// tunnels.
func (n *NetHealth) flushDeadNebulaPeers(ctx context.Context,
	wd *watchdogconf.Config, deadUnderlay, deadOverlay []string) {
	confirmed := n.state.Exists(hoststate.LatchNebulaDegraded) ||
		n.nebulaSiteedgeRun >= n.cfg.ConsecNeeded
	if !confirmed || (len(deadUnderlay) == 0 && len(deadOverlay) == 0) {
		return
	}
	peers := append([]string{}, deadUnderlay...)
	staticMap := n.nebulaUnderlayPeers(wd.NebulaNet)
	var unresolved []string
	for _, ov := range deadOverlay {
		if under, ok := staticMap[ov]; ok && len(under) > 0 {
			peers = append(peers, under...)
		} else {
			unresolved = append(unresolved, ov)
		}
	}
	if len(unresolved) > 0 {
		n.state.SuspectLog("nebula-dead-peer-resolve", fmt.Sprintf(
			"suspect: dead overlay peers %s have no static_host_map underlay — conntrack flush skipped for them",
			strings.Join(unresolved, " ")), suspectLogCadence)
	}
	if len(peers) == 0 {
		return
	}
	if !n.state.RateTrySpend("last-nebula-degraded-ct-flush",
		nebulaDegradedCTFlushInterval) {
		n.state.SuspectLog("nebula-degraded-ct-flush",
			"suspect: dead-peer conntrack flush in cooldown (<5m), skip",
			suspectLogCadence)
		return
	}
	// flushPeerNebulaConntrack does the per-peer -d AND -s delete
	// and logs the ACTION line per peer.
	n.flushPeerNebulaConntrack(ctx, checkNebula, peers...)
}

// nebulaUnderlayPeers maps overlay marker IPs to the underlay IPs
// declared for them in /etc/nebula/<net>/*.yaml static_host_map —
// the '"10.8.x.y": ["1.2.3.4:45670"]' entries. Conntrack records only
// the underlay tuple, so a dead overlay peer must be resolved
// through this table before its udp/<port> entries can be evicted.
// Unreadable/missing files yield an empty map — markers stay
// unresolved, never guessed.
func (n *NetHealth) nebulaUnderlayPeers(netName string) map[string][]string {
	out := map[string][]string{}
	if netName == "" {
		return out
	}
	files, err := filepath.Glob(filepath.Join(
		n.cfg.HostRoot, "etc/nebula", netName, "*.yaml"))
	if err != nil {
		return out
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var doc struct {
			StaticHostMap map[string][]string `yaml:"static_host_map"`
		}
		if err := yaml3.Unmarshal(data, &doc); err != nil {
			n.state.SuspectLog("nebula-staticmap-parse", fmt.Sprintf(
				"nebula-health: %s static_host_map parse failed: %v — dead-marker conntrack flush partially blind",
				f, err), suspectLogCadence)
			continue
		}
		for overlay, addrs := range doc.StaticHostMap {
			for _, a := range addrs {
				if ip := underlayHost(a); ip != "" {
					out[overlay] = append(out[overlay], ip)
				}
			}
		}
	}
	return out
}

// underlayHost extracts the IP half of a static_host_map endpoint
// ("1.2.3.4:45670", "[v6]:port", or a bare IP) — the host part is
// all the conntrack -d/-s selectors need.
func underlayHost(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	// No port (or an unbracketed IPv6): treat the token as the
	// host itself.
	return strings.Trim(a, "[]")
}

// restartTimesyncdOnClockLatch — W12-NM2: when the Nebula check is
// failing AND a clock latch (clock-unsync from the H1 check or the
// hostmetrics clock-skew latch) is armed, the handshake's
// not-before/replay-window math is a prime suspect. Restart
// systemd-timesyncd under the 10m last-ntp-restart budget — the
// budget file is shared with checkClockSync so the two remedies
// can't double-fire.
func (n *NetHealth) restartTimesyncdOnClockLatch(ctx context.Context) {
	if !n.state.Exists(hoststate.LatchClockUnsync) &&
		!n.state.Exists(hoststate.LatchClockSkew) {
		return
	}
	if n.cfg.Systemd == nil {
		return
	}
	if !n.state.RateTrySpend("last-ntp-restart", nebulaNTPRestartInterval) {
		return
	}
	n.state.AppendLog(
		"ACTION: restarting systemd-timesyncd.service — clock latch active while nebula unhealthy")
	if err := n.cfg.Systemd.Restart(ctx, "systemd-timesyncd.service"); err != nil {
		n.state.AppendLog(fmt.Sprintf(
			"systemd-timesyncd.service restart failed: %v", err))
		return
	}
	n.actions.WithLabelValues(checkNebula, "ntp_restart").Inc()
}

// minRTT parses the smallest "time=<ms>" from ping output — the
// shell's wd_probe_rtt (first sample is inflated by ARP/tunnel setup).
var rttRe = regexp.MustCompile(`time=([0-9.]+)`)

func minRTT(out string) float64 {
	best := -1.0
	for _, m := range rttRe.FindAllStringSubmatch(out, -1) {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil && (best < 0 || v < best) {
			best = v
		}
	}
	return best
}

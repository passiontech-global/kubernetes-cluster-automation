package nethealth

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

const (
	// Conntrack pressure hysteresis: the latch arms above 0.90 of
	// the table used and only clears below 0.80 — a hovering
	// counter must not flap the state file every cycle.
	conntrackEnterRatio = 0.90
	conntrackExitRatio  = 0.80
)

// --- Check: conntrack-guard (H2) ---

// checkConntrack — H2: nf_conntrack table pressure. Once the table
// fills, the NAT path drops NEW connections silently (nf_conntrack:
// table full, dropping packet) — a classic gray failure: established
// flows keep working while everything new blackholes. The latch arms
// above 0.90 used and only clears below 0.80 so a hovering counter
// can't flap it. Missing /proc entries mean the module isn't loaded
// → no table to pressure, drop any stale latch.
func (n *NetHealth) checkConntrack(ctx context.Context) {
	usedStr := hostutil.ReadTrimmed(n.cfg.ConntrackCountFile)
	maxStr := hostutil.ReadTrimmed(n.cfg.ConntrackMaxFile)
	if usedStr == "" || maxStr == "" {
		n.stateExit(hoststate.LatchConntrackPressure)
		n.cycles.WithLabelValues(checkCT, "gated").Inc()
		return
	}
	used, errU := strconv.ParseFloat(usedStr, 64)
	max, errM := strconv.ParseFloat(maxStr, 64)
	if errU != nil || errM != nil || max <= 0 {
		n.state.SuspectLog("conntrack-parse", fmt.Sprintf(
			"conntrack-guard: unparseable conntrack values count=%q max=%q — cycle aborted",
			usedStr, maxStr), suspectLogCadence)
		n.cycles.WithLabelValues(checkCT, "abort").Inc()
		return
	}
	ratio := used / max
	if n.state.Exists(hoststate.LatchConntrackPressure) {
		if ratio < conntrackExitRatio {
			n.state.AppendLog(fmt.Sprintf(
				"conntrack-pressure cleared (used=%.0f max=%.0f ratio=%.2f)",
				used, max, ratio))
			n.stateExit(hoststate.LatchConntrackPressure)
		}
	} else if ratio > conntrackEnterRatio {
		n.state.AppendLog(fmt.Sprintf(
			"suspect: conntrack-pressure used=%.0f max=%.0f ratio=%.2f > %.2f",
			used, max, ratio, conntrackEnterRatio))
		n.state.Enter(hoststate.LatchConntrackPressure,
			fmt.Sprintf("used=%.0f max=%.0f ratio=%.2f", used, max, ratio))
	}
	n.cycles.WithLabelValues(checkCT, "ok").Inc()
}

// flushPeerNebulaConntrack drops stale udp/<nebula-port> conntrack
// entries bound to specific peer underlay IPs — B3: after a peer
// becomes isolated (state-nebula-isolated) or its egress path just
// switched (overlay-egress direct↔relay), conntrack entries learned
// on the dead path pin the tunnel until expiry. Deleting only the
// affected peers' entries forces an immediate Nebula re-handshake on
// the new path without touching healthy peers' flows.
// Best-effort like flushStaleUDPConntrack — a missing conntrack
// binary or a denied delete logs and moves on, never fails a cycle.
// check attributes the flush to the calling check (conntrack-guard
// is only the table-pressure probe).
func (n *NetHealth) flushPeerNebulaConntrack(ctx context.Context, check string, peers ...string) {
	port := n.cfg.Watchdog.NebulaPort
	if port <= 0 {
		port = 45670
	}
	dport := strconv.Itoa(port)
	seen := map[string]bool{}
	for _, p := range peers {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		// Both tuple directions must go: `-d <peer>` evicts flows WE
		// initiated toward the peer; `-s <peer>` evicts peer-initiated
		// flows (orig src=peer -> our IP:<port>) whose surviving reply
		// direction would otherwise keep our outbound packets pinned
		// on the dead path. Same runMountCmd seam as
		// flushStaleUDPConntrack — the host's conntrack binary on the
		// real conntrack table; each delete is independently
		// best-effort (no-match is a fine "failure").
		for _, sel := range [][]string{{"-d", p}, {"-s", p}} {
			args := append([]string{"conntrack", "-D", "-p", "udp",
				"--dport", dport}, sel...)
			out, err := n.cfg.runMountCmd(ctx, args)
			if err != nil {
				n.state.AppendLog(fmt.Sprintf("conntrack nebula-peer flush %s skipped: %v (%s) [%s]",
					p, err, trimRunErr(out), sel[0]))
				continue
			}
			n.actions.WithLabelValues(check, "flush_peer").Inc()
		}
		n.state.AppendLog(fmt.Sprintf(
			"ACTION: flushed stale udp/%d conntrack entries for peer %s", port, p))
	}
}

// nebulaPeerUnderlayIPs returns the peer underlay IPs the watchdog
// conf knows about — OVERLAY_PROBE_TARGETS (remote public IPs probed
// through the tunnel) plus OVERLAY_EGRESS_RELAYS (relay peers). These
// are the -d destinations conntrack records for udp/<nebula-port>
// flows; marker IPs are overlay addresses conntrack never sees.
func nebulaPeerUnderlayIPs(wd *watchdogconf.Config) []string {
	out := append([]string{}, wd.OverlayProbeTargets...)
	return append(out, wd.OverlayEgressRelays...)
}

// flushStaleUDPConntrack drops stale udp/53 conntrack entries after
// a DNS-path transition (dns-fallback pins written, coredns-stub or
// nebula@ just restarted). NATed DNS replies bound to a now-dead
// endpoint's conntrack entry keep blackholing lookups until the
// entry expires — deleting them makes the fix effective immediately.
// Best-effort only: a missing conntrack binary or a denied delete
// logs and moves on, it never fails the cycle. check attributes the
// flush to the calling check.
func (n *NetHealth) flushStaleUDPConntrack(ctx context.Context, check string) {
	// runMountCmd (nsenter -t 1 -m -n) is required — runHostCmd only
	// joins the host NET namespace, so `conntrack` would resolve
	// against the container image (which does not ship
	// conntrack-tools). The host mount ns reaches the host binary;
	// the host net ns operates on the real conntrack table.
	out, err := n.cfg.runMountCmd(ctx,
		[]string{"conntrack", "-D", "-p", "udp", "--dport", "53"})
	if err != nil {
		n.state.AppendLog(fmt.Sprintf("conntrack udp/53 flush skipped: %v (%s)",
			err, trimRunErr(out)))
		return
	}
	n.actions.WithLabelValues(check, "flush").Inc()
	n.state.AppendLog("ACTION: flushed stale udp/53 conntrack entries")
}

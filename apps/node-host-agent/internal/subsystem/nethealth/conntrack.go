package nethealth

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

const (
	// Conntrack pressure hysteresis: the latch arms above 0.90 of
	// the table used and only clears below 0.80 — a hovering
	// counter must not flap the state file every cycle.
	conntrackEnterRatio = 0.90
	conntrackExitRatio  = 0.80
	// conntrackDropSpike is the per-cycle delta of
	// insert_failed+drop+early_drop that counts as a conntrack
	// refuse spike (conntrack-port-pressure): a table refusing NEW flow insertions
	// at this rate pins NATed UDP tuples (the A+AAAA DNS race
	// class) — the remedy is evicting stale UDP entries.
	conntrackDropSpike = 50
	// conntrackInsertSpike is the per-cycle insert_failed-only
	// delta that triggers the surgical UNREPLIED udp flush — a much
	// smaller bar than the blunt all-UDP flush because refused
	// inserts are the earliest conntrack-pressure signal and the
	// unreplied-only delete leaves ASSURED flows (Nebula,
	// WireGuard, live DNS exchanges) untouched.
	conntrackInsertSpike = 5
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
		n.stateExit(latchdefs.LatchConntrackPressure)
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
	if n.state.Exists(latchdefs.LatchConntrackPressure) {
		if ratio < conntrackExitRatio {
			n.state.AppendLog(fmt.Sprintf(
				"conntrack-pressure cleared (used=%.0f max=%.0f ratio=%.2f)",
				used, max, ratio))
			n.stateExit(latchdefs.LatchConntrackPressure)
		}
	} else if ratio > conntrackEnterRatio {
		n.state.AppendLog(fmt.Sprintf(
			"suspect: conntrack-pressure used=%.0f max=%.0f ratio=%.2f > %.2f",
			used, max, ratio, conntrackEnterRatio))
		n.state.Enter(latchdefs.LatchConntrackPressure,
			fmt.Sprintf("used=%.0f max=%.0f ratio=%.2f", used, max, ratio))
	}
	// Past the enter ratio the table is refusing headroom — flush
	// the orphaned UNREPLIED udp entries immediately (surgical:
	// ASSURED tunnels and established flows survive), budgeted so
	// sustained pressure can't re-run conntrack -D every cycle.
	if ratio > conntrackEnterRatio {
		n.flushUnrepliedUDPConntrack(ctx, checkCT)
	}
	n.checkConntrackDropSpike(ctx)
	n.cycles.WithLabelValues(checkCT, "ok").Inc()
}

// --- conntrack-port-pressure: conntrack insert_failed/drop spike → stale-UDP flush ---

// checkConntrackDropSpike — conntrack-port-pressure: the fill-ratio gauge above only
// sees a nearly-FULL table; insert_failed/drop climb while the table
// still has headroom when stale UDP tuples collide with new
// insertions (the A+AAAA source-port race) or the table evicts live
// flows under churn (early_drop). A per-cycle delta over
// conntrackDropSpike flushes the whole UDP conntrack set — the same
// best-effort contract as the :53 flush (a missing binary or denied
// delete logs and moves on, the cycle verdict is unaffected). The
// first read only seeds the baseline so an agent restart can't
// mistake the cumulative counters for a fresh spike. ONE file read
// per cycle: the combined sum and the insert_failed delta come off
// the same procfs.ReadConntrackStat parse (the twin conntrackStatSum
// calls used to read the file twice).
func (n *NetHealth) checkConntrackDropSpike(ctx context.Context) {
	st, ok := procfs.ReadConntrackStat(n.cfg.ConntrackStatFile)
	if !ok || !(st.HasInsertFailed || st.HasDrop || st.HasEarlyDrop) {
		n.ctStatSeen = false
		n.ctInsertSeen = false
		return
	}
	// insert_failed alone — the surgical UNREPLIED flush triggers on
	// a much smaller per-cycle delta (>5) than the blunt all-UDP
	// flush (>50): refused inserts are the earliest pressure signal,
	// and the unreplied-only delete spares ASSURED flows.
	if st.HasInsertFailed {
		ins := st.InsertFailed
		if n.ctInsertSeen && ins > n.ctInsertPrev &&
			ins-n.ctInsertPrev > conntrackInsertSpike {
			n.state.SuspectLog(checkCT, fmt.Sprintf(
				"suspect: conntrack insert_failed +%d in one cycle (> %d) — flushing unreplied udp conntrack entries",
				ins-n.ctInsertPrev, conntrackInsertSpike), suspectLogCadence)
			n.flushUnrepliedUDPConntrack(ctx, checkCT)
		}
		n.ctInsertPrev, n.ctInsertSeen = ins, true
	} else {
		n.ctInsertSeen = false
	}
	// The pressure columns the header carried sum into the combined
	// delta (missing columns contribute nothing — same as the
	// per-key sum it replaced).
	sum := st.InsertFailed + st.Drop + st.EarlyDrop
	prev, seen := n.ctStatPrev, n.ctStatSeen
	n.ctStatPrev, n.ctStatSeen = sum, true
	if !seen || sum <= prev || sum-prev <= conntrackDropSpike {
		return
	}
	n.state.SuspectLog(checkCT, fmt.Sprintf(
		"suspect: conntrack insert_failed+drop spiked +%d in one cycle (> %d) — flushing stale UDP conntrack entries (budget last-conntrack-flush)",
		sum-prev, conntrackDropSpike), suspectLogCadence)
	n.flushStaleUDPConntrackAll(ctx, checkCT)
}

// conntrackFlushCooldown — one conntrack -D per window: the flush is
// a blunt instrument (every live UDP flow re-tracks on its next
// packet; WireGuard/Nebula re-handshake; CoreDNS clients see a
// one-off reply loss), so a sustained insert_failed spike or a burst
// of DNS-path transitions must not re-run it every cycle.
const conntrackFlushCooldown = 15 * time.Minute

// flushStaleUDPConntrackAll drops EVERY udp conntrack entry — the
// coarse remedy for an insert_failed/drop spike, where the wedged
// tuples aren't limited to DNS (:53). Deleting the set forces the
// kernel to re-track live UDP flows on their next packet and drops
// the stale NAT tuples the inserts were colliding with. Same
// best-effort contract as flushStaleUDPConntrack: runMountCmd seam,
// a missing conntrack binary logs and moves on.
func (n *NetHealth) flushStaleUDPConntrackAll(ctx context.Context, check string) {
	if !n.state.RateTrySpend("last-conntrack-flush", conntrackFlushCooldown) {
		logger().Debug("conntrack udp flush skipped — cooldown (last-conntrack-flush <" +
			conntrackFlushCooldown.String() + ")")
		return
	}
	// runMountCmd (nsenter -t 1 -m -n) is required — runHostCmd only
	// joins the host NET namespace, so `conntrack` would resolve
	// against the container image (which does not ship
	// conntrack-tools). The host mount ns reaches the host binary;
	// the host net ns operates on the real conntrack table.
	out, err := n.cfg.runMountCmd(ctx,
		[]string{"conntrack", "-D", "-p", "udp"})
	if err != nil {
		n.state.AppendLog(fmt.Sprintf("conntrack udp flush skipped: %v (%s)",
			err, trimRunErr(out)))
		return
	}
	n.actions.WithLabelValues(check, "flush_udp").Inc()
	n.state.AppendLog("ACTION: flushed all stale udp conntrack entries")
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

// flushStaleUDPConntrack drops stale udp/53 conntrack entries after
// a DNS-path transition (dns-fallback pins written, coredns-stub or
// nebula@ just restarted). NATed DNS replies bound to a now-dead
// endpoint's conntrack entry keep blackholing lookups until the
// entry expires — deleting them makes the fix effective immediately.
// Best-effort only: a missing conntrack binary or a denied delete
// logs and moves on, it never fails the cycle. check attributes the
// flush to the calling check.
func (n *NetHealth) flushStaleUDPConntrack(ctx context.Context, check string) {
	if !n.state.RateTrySpend("last-conntrack-flush", conntrackFlushCooldown) {
		logger().Debug("conntrack udp/53 flush skipped — cooldown (last-conntrack-flush <" +
			conntrackFlushCooldown.String() + ")")
		return
	}
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

// flushUnrepliedUDPConntrack drops only UNREPLIED udp conntrack
// entries — :53 first, then every unreplied UDP flow. UNREPLIED is
// the kernel's "no reply packet ever seen" state: exactly the orphan
// DNS/UDP tuples a filling or churning table accumulates, while
// ASSURED entries (established Nebula/WireGuard tunnels, live DNS
// exchanges) are a different conntrack state and survive untouched.
// Same best-effort runMountCmd seam and budget shape as the blunt
// flushes — a missing binary or denied delete logs and moves on,
// never fails the cycle. The budget is its own
// (last-conntrack-unreplied-flush): the surgical flush must not be
// starved by, or starve, the blunt last-conntrack-flush window.
func (n *NetHealth) flushUnrepliedUDPConntrack(ctx context.Context, check string) {
	if !n.state.RateTrySpend("last-conntrack-unreplied-flush", conntrackFlushCooldown) {
		logger().Debug("conntrack unreplied udp flush skipped — cooldown (last-conntrack-unreplied-flush <" +
			conntrackFlushCooldown.String() + ")")
		return
	}
	// runMountCmd (nsenter -t 1 -m -n) is required — runHostCmd only
	// joins the host NET namespace, so `conntrack` would resolve
	// against the container image (which does not ship
	// conntrack-tools). The host mount ns reaches the host binary;
	// the host net ns operates on the real conntrack table.
	flushed := false
	for _, args := range [][]string{
		{"conntrack", "-D", "-p", "udp", "--dport", "53", "-u", "UNREPLIED"},
		{"conntrack", "-D", "-p", "udp", "-u", "UNREPLIED"},
	} {
		out, err := n.cfg.runMountCmd(ctx, args)
		if err != nil {
			n.state.AppendLog(fmt.Sprintf("conntrack unreplied udp flush skipped: %v (%s)",
				err, trimRunErr(out)))
			continue
		}
		flushed = true
		n.actions.WithLabelValues(check, "flush_unreplied").Inc()
	}
	if flushed {
		n.state.AppendLog("ACTION: flushed unreplied udp conntrack entries")
	}
}

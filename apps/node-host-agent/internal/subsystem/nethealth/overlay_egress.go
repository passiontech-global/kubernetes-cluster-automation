package nethealth

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// --- Check: overlay-egress (12-overlay-egress.sh) ---

// ipRuleDel1500 removes a pref-1500 rule for ip across the given
// tables — the multi-table cleanup the shell runs on relay removal.
func (n *NetHealth) ipRuleDel1500(ctx context.Context, ip string, tables []int) {
	for _, t := range tables {
		_, _ = n.ip(ctx, "rule", "del", "pref", "1500", "to",
			ip+"/32", "lookup", strconv.Itoa(t))
	}
}

// overlayUp mirrors OVERLAY_UP = WD_TINC_ACTIVE || WD_NEBULA_ACTIVE.
func (n *NetHealth) overlayUp(ctx context.Context) bool {
	wd := n.cfg.Watchdog
	return n.unitEnabledActive(ctx, "nebula@"+wd.NebulaNet) ||
		n.unitEnabledActive(ctx, "tinc@"+wd.TincNet)
}

// ruleTablesFor returns every lookup table referenced by pref-1500
// rules whose dst selector is exactly ip as a host route (/32 v4,
// /128 v6) — the netlink read's `ip rule list pref 1500` + `to <ip>`
// text match. The host-route requirement mirrors the old exact-token
// match: a covering prefix like `to 8.8.8.0/24` never attributed its
// table to relay 8.8.8.8.
func ruleTablesFor(rules []netlink.Rule, ip string) []int {
	relay := net.ParseIP(ip)
	if relay == nil {
		return nil
	}
	var out []int
	for _, r := range rules {
		if r.Priority != 1500 || r.Dst == nil || r.Table == 0 {
			continue
		}
		ones, bits := r.Dst.Mask.Size()
		if ones != bits || !r.Dst.IP.Equal(relay) {
			continue
		}
		out = append(out, r.Table)
	}
	return out
}

// hasFwmark2000Rule reports whether the dump carries the pref-1390
// underlay-pin rule (`ip rule add pref 1390 fwmark 0x2000 lookup
// main`) — the netlink read of the old `ip rule list | grep
// "fwmark 0x2000"`. Mark equality is the honest check: the text
// substring also matched lookalike marks (0x20000), netlink does
// not.
func hasFwmark2000Rule(rules []netlink.Rule) bool {
	for _, r := range rules {
		if r.Mark == 0x2000 {
			return true
		}
	}
	return false
}

// prefRules filters the shared rule dump to one priority — the
// `ip rule list pref <n>` half of the read the check used to fork
// twice per cycle.
func prefRules(rules []netlink.Rule, pref int) []netlink.Rule {
	var out []netlink.Rule
	for _, r := range rules {
		if r.Priority == pref {
			out = append(out, r)
		}
	}
	return out
}

// checkOverlayEgress — sig4: conditional egress relays. Committed
// state lives in egress-state-<ip> files ("direct"|"relay"); the live
// ip rule is healed toward it each cycle. Underlay dead → relay
// immediately; underlay back → direct only after CONSEC_NEEDED fresh
// probes (anti-ping-pong hysteresis).
func (n *NetHealth) checkOverlayEgress(ctx context.Context) {
	wd := n.cfg.Watchdog
	relays := wd.OverlayEgressRelays
	table := wd.OverlayEgressTable
	if table == 0 {
		table = 100
	}
	up := n.overlayUp(ctx)
	allTables := []int{table, 100, 102, 103}

	if len(relays) == 0 || !up {
		// No overlay / empty list → remove every watchdog rule + state
		// (rules are harmless — only 0x2000-marked packets are
		// affected — but stale state files feed phantom metrics).
		for _, f := range n.egressFiles("egress-state-") {
			ip := strings.TrimPrefix(filepath.Base(f), "egress-state-")
			n.ipRuleDel1500(ctx, ip, allTables)
		}
		_, _ = n.ip(ctx, "rule", "del", "pref", "1390", "fwmark", "0x2000", "lookup", "main")
		for _, f := range n.egressFiles("egress-state-", "egress-ctr-", "egress-icmpblk-") {
			_ = os.Remove(f)
		}
		n.egressCtr.Clear()
		n.cycles.WithLabelValues(checkEgress, "ok").Inc()
		return
	}

	// One netlink dump replaces the two `ip rule list` forks the
	// shell ran per cycle: the fwmark-0x2000 presence check and
	// every relay's pref-1500 table scan derive from the same
	// []netlink.Rule (netlinkx.Rules binds a handle inside the
	// host netns — the runHostCmd nsenter wrap's Go-native
	// sibling). Writes below stay on n.ip: netlinkx is read-only.
	allRules, err := n.cfg.rulesFn(1)
	if err != nil {
		n.state.SuspectLog("egress-rulelist", fmt.Sprintf(
			"overlay-egress: rule list failed: %v — cycle aborted", err),
			suspectLogCadence)
		n.cycles.WithLabelValues(checkEgress, "abort").Inc()
		return
	}
	if !hasFwmark2000Rule(allRules) {
		_, _ = n.ip(ctx, "rule", "add", "pref", "1390", "fwmark", "0x2000", "lookup", "main")
	}
	rules1500 := prefRules(allRules, 1500)

	inSet := map[string]bool{}
	for _, r := range relays {
		inSet[r] = true
	}
	for _, r := range relays {
		stf := filepath.Join(n.cfg.WatchdogStateDir, "egress-state-"+r)
		comm := fsx.ReadTrimmed(stf)
		if comm != "relay" {
			comm = "direct"
		}
		// live reads the rule state AS THE PRUNE LEAVES IT: only a
		// rule pointing at the CURRENT table survives the stale-table
		// prune below. Deriving live from the pre-prune snapshot made
		// a stale-table-only rule read as a live relay rule — for a
		// committed=direct relay the drift heal then del'd a rule the
		// prune had just removed (suspect heal-fail, converging only
		// next cycle).
		live := "direct"
		// Prune rules pointing at tables other than the active one —
		// an overlay flip (tinc↔nebula) leaves stale-table rules that
		// would still push traffic into the dead table.
		for _, t := range ruleTablesFor(rules1500, r) {
			if t == table {
				live = "relay"
				continue
			}
			n.ipRuleDel1500(ctx, r, []int{t})
			n.state.AppendLog(fmt.Sprintf(
				"cleanup: egress %s rule lookup %d stale (current table %d)", r, t, table))
		}
		// Drift heal: live rule must match committed state (up/down
		// scripts can delete rules behind our back).
		if live != comm {
			var herr error
			if comm == "relay" {
				_, herr = n.ip(ctx, "rule", "add", "pref", "1500", "to",
					r+"/32", "lookup", strconv.Itoa(table))
			} else {
				_, herr = n.ip(ctx, "rule", "del", "pref", "1500", "to",
					r+"/32", "lookup", strconv.Itoa(table))
			}
			if herr != nil {
				// Heal failed — leave `live` as probed so the probe
				// window and the relay-dead check below see the real
				// rule state; the drift is retried next cycle.
				n.state.SuspectLog("egress-heal-"+r, fmt.Sprintf(
					"suspect: heal egress %s rule -> %s table %d failed: %v",
					r, comm, table, herr), suspectLogCadence)
			} else {
				n.state.AppendLog(fmt.Sprintf(
					latchdefs.ActionEgressHeal+" %s rule -> %s table %d (was %s)", r, comm, table, live))
				live = comm
				// B3: the rule change just switched the underlay path for
				// this peer — drop its stale nebula-udp conntrack so the
				// re-handshake happens on the new path now.
				n.flushPeerNebulaConntrack(ctx, checkEgress, r)
			}
		}
		// Probe the underlay under SO_MARK 0x2000 → pref 1390 → main
		// table, unaffected by the relay rule.
		icmpBlk := filepath.Join(n.cfg.WatchdogStateDir, "egress-icmpblk-"+r)
		probe := "relay"
		// unprobeable marks "no fresh evidence this cycle": set when
		// the TCP fallback was skipped because the probe-window rule
		// del failed — the commit log then says "committed to live"
		// rather than "(direct failed)".
		unprobeable := false
		if ok, _ := n.cfg.ping(ctx, r, 2, 4, true); ok {
			probe = "direct"
			_ = os.Remove(icmpBlk)
		} else if port := wd.OverlayEgressTCP[r]; port != "" {
			// ICMP filtered ≠ underlay dead — TCP fallback decides.
			// A live relay rule would route the connect via overlay,
			// so drop it for the probe window like the shell did.
			// hadRule is the POST-HEAL live state (the shell re-queried
			// `ip rule list pref 1500` here, not the pre-heal snapshot):
			// when the heal just re-added the relay rule, probing with
			// it in place would traverse the overlay and misreport
			// "direct" — the relay/direct flap this guards against.
			hadRule := live == "relay"
			ruleDropped := false
			if hadRule {
				if _, derr := n.ip(ctx, "rule", "del", "pref", "1500",
					"to", r+"/32", "lookup", strconv.Itoa(table)); derr != nil {
					// Probing with the relay rule still in place
					// would traverse the overlay and misreport
					// "direct" — skip the TCP fallback this cycle
					// rather than trust a rigged probe. Flag the
					// window unprobeable so the commit log below
					// says "kept live" instead of claiming
					// underlay evidence that was never collected.
					unprobeable = true
					logger().Warn("nethealth: probe-window rule del "+
						"failed — skipping TCP fallback probe this cycle",
						"relay", r,
						"table", table, "error", derr)
				} else {
					ruleDropped = true
				}
			}
			if !hadRule || ruleDropped {
				if n.cfg.tcpProbe(ctx, r, port, 5*time.Second) == nil {
					probe = "direct"
					if _, err := os.Stat(icmpBlk); err != nil {
						if werr := fsx.WriteFileAtomic(icmpBlk,
							strconv.FormatInt(n.cfg.Clock.Now().Unix(), 10)+"\n"); werr != nil {
							logger().Warn("nethealth: egress "+
								"icmp-blocked marker write failed",
								"path", icmpBlk, "error", werr)
						}
						n.state.AppendLog(fmt.Sprintf(
							"egress %s: ICMP blocked but tcp/%s alive — treat as direct (provider blocks ICMP?)", r, port))
					}
				}
			}
			if ruleDropped {
				// Restore the relay rule — a failed restore would
				// leave it removed until next cycle's drift heal,
				// so retry once inline before warning.
				_, aerr := n.ip(ctx, "rule", "add", "pref", "1500",
					"to", r+"/32", "lookup", strconv.Itoa(table))
				if aerr != nil {
					_, aerr = n.ip(ctx, "rule", "add", "pref", "1500",
						"to", r+"/32", "lookup", strconv.Itoa(table))
				}
				if aerr != nil {
					logger().Warn("nethealth: probe-window rule "+
						"restore failed — relay rule left removed "+
						"until next cycle's drift heal",
						"relay", r,
						"table", table, "error", aerr)
				}
			}
		}
		if probe == comm {
			n.egressCtr.Reset(r)
		} else {
			need := 1 // underlay dead → relay NOW (route is ready)
			if probe == "direct" {
				need = n.cfg.ConsecNeeded // recovery needs hysteresis
			}
			ctr := n.egressCtr.Hit(r)
			if ctr >= need {
				n.egressCtr.Reset(r)
				if werr := fsx.WriteFileAtomic(stf, probe+"\n"); werr != nil {
					// Committed/live drift: the rule change below
					// still runs; next cycle's heal converges.
					logger().Warn("nethealth: egress state commit "+
						"write failed — committed/live drift "+
						"heals next cycle",
						"relay", r,
						"path", stf, "error", werr)
				}
				if probe == "relay" {
					if unprobeable {
						// No probe ran — the commit only restates
						// what live already is. Logging "(direct
						// failed)" here would claim a dead-underlay
						// measurement the skipped TCP fallback
						// never produced.
						n.state.AppendLog(fmt.Sprintf(
							latchdefs.ActionEgress+"%s -> overlay relay table %d (unprobeable window — committed to live)", r, table))
					} else {
						n.state.AppendLog(fmt.Sprintf(
							latchdefs.ActionEgress+"%s -> overlay relay table %d (direct failed)", r, table))
					}
					_, _ = n.ip(ctx, "rule", "add", "pref", "1500", "to",
						r+"/32", "lookup", strconv.Itoa(table))
					n.actions.WithLabelValues(checkEgress, "rule_add").Inc()
				} else {
					n.state.AppendLog(fmt.Sprintf(
						latchdefs.ActionEgress+"%s -> direct underlay (recovered)", r))
					_, _ = n.ip(ctx, "rule", "del", "pref", "1500", "to",
						r+"/32", "lookup", strconv.Itoa(table))
					n.actions.WithLabelValues(checkEgress, "rule_del").Inc()
				}
				live = probe
				// B3: committed state just flipped — this peer's
				// udp/<nebula-port> conntrack entries still pin the
				// old path; flush only this peer's entries.
				n.flushPeerNebulaConntrack(ctx, checkEgress, r)
			} else {
				n.state.SuspectLog("egress-probe-"+r, fmt.Sprintf(
					"suspect: egress %s probe=%s cur=%s%s", r, probe, comm,
					checkkit.Progress(ctr, need)), suspectLogCadence)
			}
		}
		// Serving via relay while the tunnel itself is unreachable →
		// the relay is dead too.
		if live == "relay" {
			if ok, _ := n.cfg.ping(ctx, r, 1, 4, false); !ok {
				n.state.SuspectLog("egress-unreach-"+r, fmt.Sprintf(
					"suspect: overlay-egress unreachable %s (relay down?)", r),
					suspectLogCadence)
			}
		}
	}
	// Cleanup state/rules for relays removed from the list. One
	// relay can own 3 state files — the deletes are idempotent but
	// the log line is once per RELAY, not per file.
	pruned := map[string]bool{}
	for _, f := range append(append(n.egressFiles("egress-state-"),
		n.egressFiles("egress-ctr-")...),
		n.egressFiles("egress-icmpblk-")...) {
		base := filepath.Base(f)
		ip := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(base,
			"egress-state-"), "egress-ctr-"), "egress-icmpblk-")
		if inSet[ip] {
			continue
		}
		n.ipRuleDel1500(ctx, ip, allTables)
		_ = os.Remove(f)
		n.egressCtr.Reset(ip)
		if !pruned[ip] {
			pruned[ip] = true
			n.state.AppendLog(fmt.Sprintf(
				"cleanup: egress state/rule for %s (no longer in OVERLAY_EGRESS_RELAYS)", ip))
		}
	}
	n.cycles.WithLabelValues(checkEgress, "ok").Inc()
}

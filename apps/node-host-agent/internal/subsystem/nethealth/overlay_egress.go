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
		n.clearAllEgress(ctx, allTables)
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

	inSet := make(map[string]bool, len(relays))
	for _, r := range relays {
		inSet[r] = true
	}
	for _, r := range relays {
		n.reconcileEgressRelay(ctx, r, table, rules1500, wd.OverlayEgressTCP[r])
	}
	n.pruneRemovedEgressRelays(ctx, inSet, allTables)
	n.cycles.WithLabelValues(checkEgress, "ok").Inc()
}

func (n *NetHealth) clearAllEgress(ctx context.Context, allTables []int) {
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
}

func (n *NetHealth) reconcileEgressRelay(
	ctx context.Context,
	r string,
	table int,
	rules1500 []netlink.Rule,
	tcpPort string,
) {
	stf := filepath.Join(n.cfg.WatchdogStateDir, "egress-state-"+r)
	comm := fsx.ReadTrimmed(stf)
	if comm != "relay" {
		comm = "direct"
	}
	live := n.healEgressRelayDrift(ctx, r, comm, table, rules1500)
	probe, unprobeable := n.probeEgressUnderlay(ctx, r, live, table, tcpPort)
	live = n.applyEgressProbeResult(ctx, r, stf, comm, live, probe, unprobeable, table)

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

func (n *NetHealth) healEgressRelayDrift(
	ctx context.Context,
	r, comm string,
	table int,
	rules1500 []netlink.Rule,
) string {
	// live reads the rule state AS THE PRUNE LEAVES IT: only a
	// rule pointing at the CURRENT table survives the stale-table
	// prune below.
	live := "direct"
	for _, t := range ruleTablesFor(rules1500, r) {
		if t == table {
			live = "relay"
			continue
		}
		n.ipRuleDel1500(ctx, r, []int{t})
		n.state.AppendLog(fmt.Sprintf(
			"cleanup: egress %s rule lookup %d stale (current table %d)", r, t, table))
	}
	if live == comm {
		return live
	}
	var herr error
	if comm == "relay" {
		_, herr = n.ip(ctx, "rule", "add", "pref", "1500", "to",
			r+"/32", "lookup", strconv.Itoa(table))
	} else {
		_, herr = n.ip(ctx, "rule", "del", "pref", "1500", "to",
			r+"/32", "lookup", strconv.Itoa(table))
	}
	if herr != nil {
		n.state.SuspectLog("egress-heal-"+r, fmt.Sprintf(
			"suspect: heal egress %s rule -> %s table %d failed: %v",
			r, comm, table, herr), suspectLogCadence)
		return live
	}
	n.state.AppendLog(fmt.Sprintf(
		latchdefs.ActionEgressHeal+" %s rule -> %s table %d (was %s)", r, comm, table, live))
	n.flushPeerNebulaConntrack(ctx, checkEgress, r)
	return comm
}

func (n *NetHealth) probeEgressUnderlay(
	ctx context.Context,
	r, live string,
	table int,
	tcpPort string,
) (probe string, unprobeable bool) {
	icmpBlk := filepath.Join(n.cfg.WatchdogStateDir, "egress-icmpblk-"+r)
	if ok, _ := n.cfg.ping(ctx, r, 2, 4, true); ok {
		_ = os.Remove(icmpBlk)
		return "direct", false
	}
	if tcpPort == "" {
		return "relay", false
	}
	hadRule := live == "relay"
	ruleDropped := false
	if hadRule {
		if _, derr := n.ip(ctx, "rule", "del", "pref", "1500",
			"to", r+"/32", "lookup", strconv.Itoa(table)); derr != nil {
			logger().Warn("nethealth: probe-window rule del "+
				"failed — skipping TCP fallback probe this cycle",
				"relay", r, "table", table, "error", derr)
			return "relay", true
		}
		ruleDropped = true
	}
	probe = "relay"
	if n.cfg.tcpProbe(ctx, r, tcpPort, 5*time.Second) == nil {
		probe = "direct"
		if _, err := os.Stat(icmpBlk); err != nil {
			if werr := fsx.WriteFileAtomic(icmpBlk,
				strconv.FormatInt(n.cfg.Clock.Now().Unix(), 10)+"\n"); werr != nil {
				logger().Warn("nethealth: egress "+
					"icmp-blocked marker write failed",
					"path", icmpBlk, "error", werr)
			}
			n.state.AppendLog(fmt.Sprintf(
				"egress %s: ICMP blocked but tcp/%s alive — treat as direct (provider blocks ICMP?)", r, tcpPort))
		}
	}
	if ruleDropped {
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
				"relay", r, "table", table, "error", aerr)
		}
	}
	return probe, false
}

func (n *NetHealth) applyEgressProbeResult(
	ctx context.Context,
	r, stf, comm, live, probe string,
	unprobeable bool,
	table int,
) string {
	if probe == comm {
		n.egressCtr.Reset(r)
		return live
	}
	need := 1 // underlay dead → relay NOW (route is ready)
	if probe == "direct" {
		need = n.cfg.ConsecNeeded // recovery needs hysteresis
	}
	ctr := n.egressCtr.Hit(r)
	if ctr < need {
		n.state.SuspectLog("egress-probe-"+r, fmt.Sprintf(
			"suspect: egress %s probe=%s cur=%s%s", r, probe, comm,
			checkkit.Progress(ctr, need)), suspectLogCadence)
		return live
	}
	n.egressCtr.Reset(r)
	if werr := fsx.WriteFileAtomic(stf, probe+"\n"); werr != nil {
		logger().Warn("nethealth: egress state commit "+
			"write failed — committed/live drift heals next cycle",
			"relay", r, "path", stf, "error", werr)
	}
	if probe == "relay" {
		if unprobeable {
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
	n.flushPeerNebulaConntrack(ctx, checkEgress, r)
	return probe
}

func (n *NetHealth) pruneRemovedEgressRelays(ctx context.Context, inSet map[string]bool, allTables []int) {
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
}

// direct_tcp.go — the pref-1499 Direct-Underlay TCP bypass rule
// guard (nebula_direct_tcp_ports), moved verbatim out of the parent
// nethealth package's nebula_health.go.
package nebula

import (
	"context"
	"fmt"
	"strconv"

	"github.com/vishvananda/netlink"
)

// CheckNebulaDirectTCP enforces the pref-1499 Direct-Underlay TCP
// bypass rules (ipproto tcp dport <port> lookup main) for every
// nebula_direct_tcp_ports entry — hostconfig installs them via
// nebula-up.sh + the T5b converge; this guard re-adds a rule the
// kernel lost between converges (same failure mode the netlink route
// guard covers for the overlay tables). Only runs where the nebula
// dataplane is actually deployed.
func (n *Deps) CheckNebulaDirectTCP(ctx context.Context) {
	wd := n.WatchdogConf()
	if wd == nil || !n.NebulaUpExists(wd) {
		n.Cycles.WithLabelValues(checkNebTCP, "gated").Inc()
		return
	}
	// One netlink dump per cycle replaces the per-cycle
	// `ip rule list pref 1499` nsenter fork — the same read-only
	// netlinkx.Rules reader the overlay-egress check already drives
	// (the handle binds inside the host netns; writes below stay on
	// the IP seam). The restore folds each rule it adds into the
	// snapshot, so a duplicated port entry never attempts a second
	// add (the old per-iteration re-list saw it for free).
	rules, err := n.Rules(1)
	if err != nil {
		n.Cycles.WithLabelValues(checkNebTCP, "open_error").Inc()
		return
	}
	for _, port := range n.NebulaDirectTCPPorts() {
		if port <= 0 || port > 65535 {
			continue
		}
		if hasDirectTCPRule(rules, port) {
			continue
		}
		p := strconv.Itoa(port)
		if _, err := n.IP(ctx, "rule", "add", "pref", "1499",
			"ipproto", "tcp", "dport", p, "lookup", "main"); err != nil {
			n.State.AppendLog(fmt.Sprintf(
				"nebula-direct-tcp: ip rule add pref 1499 dport %s failed: %v",
				p, err))
			n.Cycles.WithLabelValues(checkNebTCP, "restore_error").Inc()
			continue
		}
		n.Actions.WithLabelValues(checkNebTCP, "rule_add").Inc()
		n.State.AppendLog(fmt.Sprintf(
			"ACTION: re-added pref-1499 direct-underlay tcp dport %s rule", p))
		// Fold the new rule into the snapshot.
		rules = append(rules, netlink.Rule{
			Priority: 1499,
			Dport:    &netlink.RulePortRange{Start: uint16(port), End: uint16(port)},
		})
	}
	n.Cycles.WithLabelValues(checkNebTCP, "ok").Inc()
}

// hasDirectTCPRule reports whether the pref-1499 rule set already
// carries an exact single-port dport rule for port — the structural
// reading of the old `strings.Contains(out, "dport <p>")` text
// match: the kernel prints a start==end range as the bare port
// (which the text match DID hit), while a true range prints
// "dport <lo>-<hi>" and never text-matched, so exact equality is
// the faithful translation.
func hasDirectTCPRule(rules []netlink.Rule, port int) bool {
	for _, r := range rules {
		if r.Priority == 1499 && r.Dport != nil &&
			int(r.Dport.Start) == port && int(r.Dport.End) == port {
			return true
		}
	}
	return false
}

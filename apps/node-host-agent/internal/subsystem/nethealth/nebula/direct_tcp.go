// direct_tcp.go — the pref-1499 Direct-Underlay TCP bypass rule
// guard (nebula_direct_tcp_ports), moved verbatim out of the parent
// nethealth package's nebula_health.go.
package nebula

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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
	// The pref-1499 rule table is one kernel object — listing it
	// per port ran the identical `ip rule list` (nsenter fork)
	// once per configured port every cycle.
	out, err := n.IP(ctx, "rule", "list", "pref", "1499")
	if err != nil {
		n.Cycles.WithLabelValues(checkNebTCP, "open_error").Inc()
		return
	}
	for _, port := range n.NebulaDirectTCPPorts() {
		if port <= 0 || port > 65535 {
			continue
		}
		p := strconv.Itoa(port)
		if strings.Contains(out, "dport "+p+" ") ||
			strings.Contains(out, "dport "+p+"\n") ||
			strings.HasSuffix(strings.TrimSpace(out), "dport "+p) {
			continue
		}
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
		// Fold the new rule into the snapshot — a duplicated port
		// entry in the list must not attempt a second add (the old
		// per-iteration re-list saw it for free).
		out += "dport " + p + " "
	}
	n.Cycles.WithLabelValues(checkNebTCP, "ok").Inc()
}

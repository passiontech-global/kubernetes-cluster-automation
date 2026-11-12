// group_nebula_routing.go — the nebula overlay routing pass:
// nebulaRouting renders the lighthouse/route table and the
// port()/nodeIP() helpers it needs. Split out of
// group_nebula.go — that file keeps install/config/restart.

package hostconfig

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// nebulaRouting ports the live ip rule/route/nft converge of T5b
// (tasks/interdc_nebula.yaml: mangle fwmark, populate overlay tables,
// flip ip rules to nebula, nebnat SNAT). SNAT/route source is the
// node's PUBLIC ip (interdc_nebula_node.ip); the marker table + the
// marker-daddr snat use the marker (--node-ip / registry marker).
func (c *cyc) nebulaRouting() {
	r, ctx, t := c.r, c.ctx, c.t
	dev := c.t.Vars.StrDef("interdc_nebula_dev", "neb1")
	pub, mark, mb := c.tablePub(), c.tableMark(), c.markerBase()
	pubIP := nodeIPStr(t.Node, "ip") // interdc_nebula_node.ip (public)
	mkIP := t.Markers[t.MeshName]    // registry marker
	nodeIPV := nodeIP(c)             // --node-ip or hub marker

	// Every value below lands unquoted inside `sh -c` command strings
	// — several inside sed/grep patterns where quoting would corrupt
	// the match. Charset/shape-gate them all BEFORE building commands
	// so a malformed var can never become shell metachars. pubIP/mkIP
	// use the *Req variant: they are REQUIRED route/SNAT sources, and
	// an empty pass there is not "cannot inject" — it emits
	// `src <blank>`/`snat to <blank>` that fails only inside the
	// shell at Debug level.
	safe := c.shToken("interdc_nebula_dev", dev) &&
		c.shToken("interdc_nebula_table_pub", pub) &&
		c.shToken("interdc_nebula_table_marker", mark) &&
		c.shMarkerBase("interdc_marker_base", mb) &&
		c.shIPCIDRReq("node public ip", pubIP) &&
		c.shIPCIDRReq("node marker ip", mkIP) &&
		c.shIPCIDR("node ip", nodeIPV) &&
		c.shPort("interdc_nebula_port", port(c))
	for _, tgt := range append(append([]string{}, t.Targets...), t.EgressRelays...) {
		safe = c.shIPCIDR("routing target", tgt) && safe
	}
	for _, e := range t.RelayMap[t.MeshName] {
		safe = c.shIPCIDR("relay ip", e.IP) && safe
	}
	if !safe {
		return
	}

	// Hub hairpin prune (hub_converge.yaml, incident 2026-09-16): a
	// stale static route in table main sending a target IP via ANOTHER
	// mesh node's public IP blackholes the direct edge — packets hairpin
	// through that node where rule 1500 sucks them into the tunnel.
	if t.AmLighthouse {
		meshIPs := map[string]bool{}
		for _, k := range t.Nodes.Keys() {
			nv, _ := t.Nodes.Get(k)
			if om, ok := nv.(*jinja.OMap); ok {
				if ip := nodeIPStr(om, "ip"); ip != "" {
					meshIPs[ip] = true
				}
			}
		}
		for _, tgt := range t.Targets {
			out, err := r.run(ctx, "ip", "-o", "route", "get", tgt, "mark", "0x1000")
			if err != nil {
				logger().Debug("T5b/hub: hairpin probe failed — skipping target",
					"target", tgt, "error", err)
				continue
			}
			m := hairpinViaRe.FindStringSubmatch(out)
			if m != nil && meshIPs[m[1]] {
				logger().Info("T5b/hub: pruning hairpin route via mesh IP",
					"target", tgt, "via", m[1])
				if _, err := r.run(ctx, "ip", "route", "del", tgt+"/32", "table", "main"); err != nil {
					// Best-effort prune — the live ip-rule converge
					// below still routes the target correctly.
					logger().Warn("T5b/hub: hairpin route delete failed",
						"target", tgt, "error", err)
				}
			}
		}
	}

	// fwmark + policy-routing converge — ONE generated script run
	// through a single host exec (the nebnat replay below uses the
	// same technique). The old code forked `nsenter sh -c` per rule
	// per loop: ~4 nsenter runs per mesh target plus one per
	// direct-TCP port, every 5-minute cycle. Every interpolated
	// value already passed the charset/shape gates above, and no
	// line's output is parsed back, so sequential lines inside one
	// sh -c are semantically identical to the per-command forks.
	var rs strings.Builder
	// fwmark for transport
	for _, p := range []string{"dport", "sport"} {
		for _, chain := range []string{"OUTPUT", "PREROUTING"} {
			fmt.Fprintf(&rs,
				"iptables -w 5 -t mangle -C %s -p udp --%s %s -j MARK --set-mark 0x1000 2>/dev/null || "+
					"iptables -w 5 -t mangle -A %s -p udp --%s %s -j MARK --set-mark 0x1000\n",
				chain, p, port(c), chain, p, port(c))
		}
	}
	rs.WriteString(`ip rule list | grep -q "fwmark 0x1000" || ip rule add pref 1400 fwmark 0x1000 lookup main` + "\n")

	// Proactive TCP MSS clamp: double encapsulation
	// (nebula + cilium-wg/liqo) silently blackholes TCP when a
	// SYN carries an MSS larger than the innermost path MTU. Add
	// idempotent mangle TCPMSS clamp rules for both POSTROUTING and
	// FORWARD scoped per outgoing interface — neb1, cilium_wg0
	// (gated on dev existence so dormant meshes skip), and the liqo+
	// wildcard (probed via /sys/class/net; iptables matches the name
	// pattern directly).
	for _, chain := range []string{"POSTROUTING", "FORWARD"} {
		for _, dev := range []string{"neb1", "cilium_wg0"} {
			fmt.Fprintf(&rs,
				`if ip link show dev %s >/dev/null 2>&1; then `+
					`iptables -w 5 -t mangle -C %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || `+
					`iptables -w 5 -t mangle -A %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; fi`+"\n",
				dev, chain, dev, chain, dev)
		}
		// liqo interfaces are numbered (liqo-*, liqo0, …) — probe the
		// class dir with the glob instead of a wildcard dev name, then
		// match traffic with the iptables `liqo+` pattern.
		fmt.Fprintf(&rs,
			`ls /sys/class/net | grep -q '^liqo' && { `+
				`iptables -w 5 -t mangle -C %s -o liqo+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || `+
				`iptables -w 5 -t mangle -A %s -o liqo+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; }; true`+"\n",
			chain, chain)
	}

	// Populate overlay tables ALWAYS (warm standby even when
	// overlay=tinc). pub table src = public ip; marker table src =
	// NODE_IP only when it is a marker-base IP, else flush. The
	// missing-dev early-out becomes a skipped block, not a script
	// exit — the rule converge after it must still run.
	fmt.Fprintf(&rs,
		`if ip link show dev %s >/dev/null 2>&1; then `+
			`ip route replace default dev %s src %s table %s; `+
			`case "%s" in %s.*) ip route replace default dev %s src %s table %s ;; `+
			`*) ip route flush table %s 2>/dev/null || true ;; esac; fi`+"\n",
		dev, dev, pubIP, pub, nodeIPV, mb, dev, nodeIPV, mark, mark)

	if t.Overlay == "nebula" {
		// converge ip rules: prune stale lookups for mesh dsts, ensure
		// targets + marker CIDR → $pub, marker CIDR → $mark (pref 1490).
		targets := append(append([]string{}, t.Targets...), t.EgressRelays...)
		targets = append(targets, mb+".0/24")
		for _, d := range targets {
			fmt.Fprintf(&rs,
				`for t in $(ip rule list pref 1500 | sed -n "s|.*to %s .*lookup \([0-9]*\).*|\1|p"); do [ "$t" = %s ] || ip rule del pref 1500 to %s lookup "$t" 2>/dev/null; done`+"\n",
				d, pub, d)
		}
		for _, d := range append(append([]string{}, t.Targets...), mb+".0/24") {
			fmt.Fprintf(&rs,
				`ip rule list | grep -q "to %s lookup %s" || ip rule add pref 1500 to %s lookup %s`+"\n",
				d, pub, d, pub)
		}
		for _, d := range t.EgressRelays {
			fmt.Fprintf(&rs,
				`[ "$(cat /var/lib/node-watchdog/egress-state-%s 2>/dev/null)" = relay ] && { ip rule list | grep -q "to %s lookup %s" || ip rule add pref 1500 to %s lookup %s; }; true`+"\n",
				d, d, pub, d, pub)
		}
		fmt.Fprintf(&rs,
			`for t in $(ip rule list pref 1490 | sed -n "s|.*to %s\.0/24 .*lookup \([0-9]*\).*|\1|p"); do [ "$t" = %s ] || ip rule del pref 1490 to %s.0/24 lookup "$t" 2>/dev/null; done`+"\n",
			mb, mark, mb)
		if strings.HasPrefix(nodeIPV, mb+".") {
			fmt.Fprintf(&rs,
				`ip rule list | grep -q "to %s.0/24 lookup %s" || ip rule add pref 1490 to %s.0/24 lookup %s`+"\n",
				mb, mark, mb, mark)
		} else {
			fmt.Fprintf(&rs,
				`ip rule del pref 1490 to %s.0/24 lookup %s 2>/dev/null || true`+"\n",
				mb, mark)
		}
		// pref-1499 Direct-Underlay TCP bypass: management/CP TCP
		// dports must never be sucked into the tunnel — rule them
		// into the main table (nethealth re-adds lost ones).
		for _, p := range c.nebulaDirectTCPPorts() {
			fmt.Fprintf(&rs,
				`ip rule list pref 1499 | grep -q "ipproto tcp dport %s " || ip rule add pref 1499 ipproto tcp dport %s lookup main`+"\n",
				p, p)
		}
		// flush foreign dev tables (stale nebula-era tables).
		fmt.Fprintf(&rs,
			`ip -o route show table all dev %s 2>/dev/null | sed -n "s|.* table \([0-9]*\) .*|\1|p" | sort -u | while read -r t; do [ "$t" = "%s" ] || [ "$t" = "%s" ] || ip route flush table "$t" 2>/dev/null; done`+"\n",
			dev, pub, mark)
	} else {
		// overlay=tinc: pref-1499 bypass rules go too.
		for _, p := range c.nebulaDirectTCPPorts() {
			fmt.Fprintf(&rs,
				`ip rule del pref 1499 ipproto tcp dport %s lookup main 2>/dev/null || true`+"\n", p)
		}
		// overlay=tinc rollback: drop nebula-owned rules.
		fmt.Fprintf(&rs,
			`ip rule list pref 1500 | sed -n "s/.*to \([0-9./]*\).*/\1/p" | while read -r d; do ip rule del pref 1500 to "$d" lookup %s 2>/dev/null; done; ip rule del pref 1490 to %s.0/24 lookup %s 2>/dev/null; true`+"\n",
			pub, mb, mark)
	}
	_, _ = r.run(ctx, "sh", "-c", rs.String()+"\ntrue")
	// nebnat nft — replayed via a generated script (idempotent guard
	// lines identical in effect to the ansible shell task). Marker-dst
	// SNAT goes to the MARKER (peers accept marker srcs via cert
	// subnets); everything else SNATs to the node PUBLIC ip.
	var sb strings.Builder
	fmt.Fprintf(&sb, "nft add table ip nebnat 2>/dev/null\n")
	fmt.Fprintf(&sb, "nft 'add chain ip nebnat post { type nat hook postrouting priority srcnat - 11; }' 2>/dev/null\n")
	fmt.Fprintf(&sb, `nft -a list chain ip nebnat post 2>/dev/null | sed -n "s/.*ip daddr %s\.0\/24 return.*# handle \([0-9]*\).*/\1/p" | while read -r h; do nft delete rule ip nebnat post handle $h; done`+"\n", mb)
	fmt.Fprintf(&sb, "nft list chain ip nebnat post 2>/dev/null | grep -q \"saddr %s.0/24 return\" || nft insert rule ip nebnat post oifname %s ip saddr %s.0/24 return\n", mb, dev, mb)
	fmt.Fprintf(&sb, `if ! nft list chain ip nebnat post 2>/dev/null | grep -q "daddr %s.0/24 snat"; then `+
		`h=$(nft -a list chain ip nebnat post 2>/dev/null | sed -n "s/.*oifname .%s. snat to %s.*# handle \([0-9]*\).*/\1/p" | head -1); `+
		`[ -n "$h" ] && nft delete rule ip nebnat post handle $h; `+
		`nft add rule ip nebnat post oifname %s ip daddr %s.0/24 snat to %s; fi`+"\n",
		mb, dev, pubIP, dev, mb, mkIP)
	fmt.Fprintf(&sb, "nft list chain ip nebnat post 2>/dev/null | grep -q \"oifname .%s. snat to %s\" || nft add rule ip nebnat post oifname %s snat to %s\n", dev, pubIP, dev, pubIP)
	for _, e := range t.RelayMap[t.MeshName] {
		fmt.Fprintf(&sb, "sysctl -qw net.ipv4.ip_forward=1\n")
		fmt.Fprintf(&sb, "nft list chain ip nebnat post | grep -q \"saddr %s return\" || nft insert rule ip nebnat post oifname %s ip saddr %s return\n", e.IP, dev, e.IP)
		fmt.Fprintf(&sb, "nft list chain ip nebnat post | grep -q \"daddr %s snat\" || nft add rule ip nebnat post oifname != %s ip daddr %s snat to %s\n", e.IP, dev, e.IP, pubIP)
	}
	_, _ = r.run(ctx, "sh", "-c", sb.String()+"\ntrue")
}

func port(c *cyc) string {
	return c.t.Vars.StrDef("interdc_nebula_port", "45670")
}

// nodeIP: --node-ip from k0sworker unit, else marker for hubs.
func nodeIP(c *cyc) string {
	if c.t.AmLighthouse {
		return c.t.Markers[c.t.MeshName]
	}
	b, _ := os.ReadFile(c.r.hp("/etc/systemd/system/k0sworker.service"))
	re := regexp.MustCompile(`--node-ip=([0-9.]+)`)
	if m := re.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return c.t.Markers[c.t.MeshName]
}

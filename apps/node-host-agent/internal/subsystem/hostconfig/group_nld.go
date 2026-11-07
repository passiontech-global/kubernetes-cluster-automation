// group_nld.go — T4 node-local-dns stub guard + the host-internal-ports
// nft guard that shares its allow list.
package hostconfig

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
)

// ---------- T4 nodelocaldns guard ----------

func (c *cyc) groupNLD() {
	r, ctx := c.r, c.ctx
	stubListening := false
	if out, err := r.run(ctx, "ss", "-lntu"); err == nil {
		stubListening = regexp.MustCompile(`127\.0\.0\.5[34]:53`).MatchString(out)
	} else {
		// Best-effort detection — a failed probe leaves
		// stubListening=false and the rest of T4 still converges.
		logger().Warn("T4: ss -lntu failed — cannot detect resolved stub listener; continuing",
			"error", err)
	}
	if c.resolvedRunning() {
		// ansible.builtin.fail parity: stub listening but no real
		// resolv.conf to repoint to => refuse the whole stub-disable
		// path (writing DNSStubListener=no here would black out DNS).
		refuse := false
		if stubListening {
			if !r.fileExists("/run/systemd/resolve/resolv.conf") {
				c.err("T4: resolved stub listening but no real resolv.conf — refusing to disable stub",
					"path", "/run/systemd/resolve/resolv.conf")
				refuse = true
			} else {
				// repoint symlink — atomic: create the symlink at a
				// temp name in the same dir then rename over, so a
				// failure never leaves a window with no resolv.conf.
				dst := r.hp("/etc/resolv.conf")
				fi, _ := os.Lstat(dst)
				if fi == nil || fi.Mode()&os.ModeSymlink == 0 ||
					func() bool { l, _ := os.Readlink(dst); return l != "/run/systemd/resolve/resolv.conf" }() {
					tmp := dst + ".hostconfig.tmp"
					_ = os.Remove(tmp) // stale temp from a crashed converge
					if err := os.Symlink("/run/systemd/resolve/resolv.conf", tmp); err != nil {
						c.err("T4: resolv.conf temp symlink failed — DNS not repointed",
							"path", dst, "error", err)
					} else if err := os.Rename(tmp, dst); err != nil {
						_ = os.Remove(tmp)
						c.err("T4: resolv.conf symlink repoint failed — DNS not repointed",
							"path", dst, "error", err)
					}
				}
			}
		}
		if !refuse {
			if ch, _ := r.writeManaged("/etc/systemd/resolved.conf.d/99-nodelocal-stub.conf",
				[]byte(`# Managed by node-config-agent - free :53 loopback stub for the
# node-local-dns wildcard bind (EADDRINUSE otherwise)
[Resolve]
DNSStubListener=no
`), 0o644); ch {
				r.restartService(ctx, "systemd-resolved.service")
			}
		}
	}
	// guard allow list = private + node IPs + extra, sorted —
	// shared with the host-internal-ports guard (W6.1).
	allow := c.guardAllowSources()
	nft := fmt.Sprintf(`# Managed by node-config-agent - block DNS from non-cluster sources
destroy table ip nodelocaldns_guard
table ip nodelocaldns_guard {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "lo" accept
        ip saddr { %s } accept
        tcp dport 53 drop
        udp dport 53 drop
    }
}
`, strings.Join(allow, ", "))
	c.applyNftUnit("nodelocaldns-guard", "/etc/nodelocaldns-guard.nft",
		[]byte(nft), "nodelocal-dns :53 guard (block non-cluster sources)")
	// sweep the buggy nftables.d path this port originally wrote
	_, _ = r.removeManaged("/etc/nftables.d/nodelocaldns-guard.nft")
	// W6.1: the node-internal listener ports get the same guard —
	// non-cluster sources have no business reaching kubelet/NPD/
	// exporter endpoints over the underlay.
	c.convergeHostPortsGuard()
}

// guardAllowSources returns the sorted allow CIDR/IP set shared by
// the nft guards: nodelocaldns_guard_allow_private + every node's
// registry ip + nodelocaldns_guard_allow_extra.
func (c *cyc) guardAllowSources() []string {
	allow := append(c.vs("nodelocaldns_guard_allow_private"),
		c.vs("nodelocaldns_guard_allow_extra")...)
	for _, k := range c.t.Nodes.Keys() {
		nv, _ := c.t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil {
			continue
		}
		if ip, ok := om.Get("ip"); ok {
			if s, ok := ip.(string); ok && s != "" {
				allow = append(allow, s)
			}
		}
	}
	sort.Strings(allow)
	return allow
}

// hostPortsGuardPorts are the node-internal TCP listeners (W6.1)
// that must never answer a non-cluster source over the underlay:
// kubelet healthz/ro-port/read-only, node-exporter, blackbox
// exporter, coredns metrics, node-problem-detector and the
// node-host-agent metrics port.
var hostPortsGuardPorts = []int{10248, 10250, 10256, 9100, 9115, 9253, 20256, 30020}

// convergeHostPortsGuard deploys the host-internal-ports nft guard
// + its boot oneshot (W6.1): inbound TCP to the internal listeners
// is dropped unless it arrives via loopback, a cluster datapath
// interface (neb1, cilium/lxc/cali — pod traffic paths), an
// established/related flow, or an allowlisted source. Enabled by
// default; `host_internal_ports_guard_enabled: false` tears the
// unit and the live table down.
func (c *cyc) convergeHostPortsGuard() {
	r, ctx := c.r, c.ctx
	// An UNDEFINED var means default-ON — the guard exists because
	// a missing firewall rule only ever surfaces as "how did a
	// scanner reach kubelet", so opt-out must be explicit.
	enabled := true
	if _, undef := c.t.Vars.Get("host_internal_ports_guard_enabled").(topology.Undefined); !undef {
		enabled = c.vb("host_internal_ports_guard_enabled")
	}
	if !enabled {
		_, _ = r.run(ctx, "systemctl", "disable", "--now", "host-internal-ports-guard.service")
		uch, _ := r.removeManaged("/etc/systemd/system/host-internal-ports-guard.service")
		_, _ = r.removeManaged("/etc/host-internal-ports-guard.nft")
		if uch {
			r.daemonReload(ctx)
		}
		// Drop the LIVE table too — disabling must actually reopen
		// the ports, not only stop the oneshot.
		_, _ = r.run(ctx, "sh", "-c",
			"nft delete table ip host_internal_ports_guard 2>/dev/null; true")
		return
	}
	var ports strings.Builder
	for i, p := range hostPortsGuardPorts {
		if i > 0 {
			ports.WriteString(", ")
		}
		fmt.Fprintf(&ports, "%d", p)
	}
	allow := c.guardAllowSources()
	saddr := ""
	if len(allow) > 0 {
		// An empty saddr set literal is invalid nft — skip the rule
		// when no allowlist resolved at all.
		saddr = fmt.Sprintf("        ip saddr { %s } accept\n",
			strings.Join(allow, ", "))
	}
	nft := fmt.Sprintf(`# Managed by node-config-agent - drop non-cluster traffic to node-internal ports
destroy table ip host_internal_ports_guard
table ip host_internal_ports_guard {
    chain input {
        type filter hook input priority filter - 5; policy accept;
        iifname "lo" accept
        iifname "neb1" accept
        iifname "cilium*" accept
        iifname "lxc*" accept
        iifname "cali*" accept
        ct state { established, related } accept
%s        tcp dport { %s } drop
    }
}
`, saddr, ports.String())
	c.applyNftUnit("host-internal-ports-guard", "/etc/host-internal-ports-guard.nft",
		[]byte(nft), "host internal ports guard (drop non-cluster sources to node-internal listeners)")
}

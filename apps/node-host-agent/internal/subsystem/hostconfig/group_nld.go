// group_nld.go — T4 node-local-dns stub guard + the host-internal-ports
// nft guard that shares its allow list.
package hostconfig

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
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
	// shared with the host-internal-ports guard (host-internal-ports).
	allow := c.guardAllowSources()
	allowV4, allowV6 := splitAddrFamilies(allow)
	var saddrRules strings.Builder
	// Family-scoped accepts, each gated on :53 (roadmap 1.2): a
	// blanket saddr accept here does not shield packets from the
	// LATER host-internal-ports chain (nft accept in one base chain
	// still hands the packet to the next priority), but an
	// allowlisted source must beat the dport 53 drops below — and
	// the families must be split because an inet table's ip6 packets
	// never match `ip saddr`. An empty family set is invalid nft —
	// skip its rules entirely (IPv6-less allowlist → v6 :53 falls to
	// the drop: the whole point of the inet upgrade).
	if len(allowV4) > 0 {
		fmt.Fprintf(&saddrRules, "        ip saddr { %s } tcp dport 53 accept\n",
			strings.Join(allowV4, ", "))
		fmt.Fprintf(&saddrRules, "        ip saddr { %s } udp dport 53 accept\n",
			strings.Join(allowV4, ", "))
	}
	if len(allowV6) > 0 {
		fmt.Fprintf(&saddrRules, "        ip6 saddr { %s } tcp dport 53 accept\n",
			strings.Join(allowV6, ", "))
		fmt.Fprintf(&saddrRules, "        ip6 saddr { %s } udp dport 53 accept\n",
			strings.Join(allowV6, ", "))
	}
	// inet table (roadmap 1.2): the old `table ip` guard never saw
	// IPv6 — a dual-stack listener (:53 wildcard bind) let every v6
	// source through the v4-only firewall.
	nft := fmt.Sprintf(`# Managed by node-config-agent - block DNS from non-cluster sources
destroy table inet nodelocaldns_guard
table inet nodelocaldns_guard {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "lo" accept
%s        tcp dport 53 drop
        udp dport 53 drop
    }
}
`, saddrRules.String())
	c.applyNftUnit("nodelocaldns-guard", "/etc/nodelocaldns-guard.nft",
		[]byte(nft), "nodelocal-dns :53 guard (block non-cluster sources)")
	// sweep the buggy nftables.d path this port originally wrote
	_, _ = r.removeManaged("/etc/nftables.d/nodelocaldns-guard.nft")
	// host-internal-ports: the node-internal listener ports get the same guard —
	// non-cluster sources have no business reaching kubelet/NPD/
	// exporter endpoints over the underlay.
	c.convergeHostPortsGuard()
}

// guardAllowSources returns the sorted allow CIDR/IP set the
// nodelocaldns guard uses: nodelocaldns_guard_allow_private +
// every node's registry ip + nodelocaldns_guard_allow_extra. The
// PRIVATE ranges belong to THIS guard only — pods must resolve
// node-local-dns — the ports guard deliberately does not inherit
// them (roadmap 1.2: blanket 10.0.0.0/8 on the admin ports is the
// hole, not the DNS path).
func (c *cyc) guardAllowSources() []string {
	allow := append(c.vs("nodelocaldns_guard_allow_private"),
		c.vs("nodelocaldns_guard_allow_extra")...)
	allow = append(allow, c.registryNodeIPs()...)
	slices.Sort(allow)
	return allow
}

// registryNodeIPs collects every node's registry addresses — the
// `ip` v4 entry plus the `ip6` v6 entry when the registry carries
// one. Non-mapping registry entries are skipped, not a panic (the
// TestNLDAllowSourcesScalarNode contract).
func (c *cyc) registryNodeIPs() []string {
	var ips []string
	for _, k := range c.t.Nodes.Keys() {
		nv, _ := c.t.Nodes.Get(k)
		om, _ := nv.(*jinja.OMap)
		if om == nil {
			continue
		}
		for _, key := range []string{"ip", "ip6"} {
			if ip, ok := om.Get(key); ok {
				if s, ok := ip.(string); ok && s != "" {
					ips = append(ips, s)
				}
			}
		}
	}
	return ips
}

// portsGuardAllowSources returns the sorted allow CIDR/IP set for
// the host-internal-ports guard: every node's registry IP +
// host_internal_ports_guard_allow_extra — the operator-declared
// Prometheus/monitoring sources. Deliberately NOT
// nodelocaldns_guard_allow_private (roadmap 1.2: RFC1918-wide
// access to kubelet/node-exporter/the agent's metrics+pprof ports
// is the vulnerability; pods and VLAN neighbours must not match
// these rules), and NOT the interface wildcard accepts (removed —
// see convergeHostPortsGuard).
func (c *cyc) portsGuardAllowSources() []string {
	allow := append([]string{}, c.vs("host_internal_ports_guard_allow_extra")...)
	allow = append(allow, c.registryNodeIPs()...)
	slices.Sort(allow)
	return allow
}

// splitAddrFamilies partitions an allow list into nft-usable
// literal sets — `ip saddr {…}` vs `ip6 saddr {…}` — because an
// inet table needs the explicit family match and a v6 literal in a
// v4 set is a parse error. The family test is the IPv6 literal's
// colon (covers bare addrs and prefix forms); everything else stays
// in the v4 half verbatim (config-trust parity with the old
// single-set join — whatever form the operator wrote is passed
// through, nft -c validates it).
func splitAddrFamilies(addrs []string) (v4, v6 []string) {
	for _, a := range addrs {
		if strings.Contains(a, ":") {
			v6 = append(v6, a)
			continue
		}
		v4 = append(v4, a)
	}
	return v4, v6
}

// hostPortsGuardPorts are the node-internal TCP listeners (host-internal-ports)
// that must never answer a non-cluster source over the underlay:
// kubelet healthz/ro-port/read-only, node-exporter, blackbox
// exporter, coredns metrics, node-problem-detector, the
// node-host-agent metrics port — and, per roadmap 1.2, the
// previously missing node-internal listeners: :39901 (node-host-agent
// probe/SNR), the Cilium hostNetwork agents (:4240 health,
// :4244 cilium-envoy health, :9962-9964 agent/hubble metrics) and
// the whole Kubernetes NodePort range (hostPortsGuardNodePortRange
// — the old list carried a lone 30020, which the range subsumes).
var hostPortsGuardPorts = []int{
	4240, 4244, 9100, 9115, 9253, 9962, 9963, 9964,
	10248, 10250, 10256, 20256, 39901,
}

// hostPortsGuardNodePortRange is the Kubernetes default Service
// nodePort span, dropped for non-cluster sources with the same
// reasoning as the singleton 30020 it replaces: NodePort consumers
// in this stack are in-cluster (ingress/tunnel datapath) or
// cluster sources — a WAN scanner reaching a NodePort on the
// underlay is never legitimate.
const hostPortsGuardNodePortRange = "30000-32767"

// hostPortsGuardPodExemptPorts are internal ports that must still
// answer pod-originated LOCAL-delivery traffic. :4244 is the
// cilium-agent hubble-peer listener and the hubble-peer Service
// pins internalTrafficPolicy: Local — an in-cluster consumer can
// therefore only ever reach its OWN node's endpoint, which arrives
// on a pod-veth iif (never neb1) and would hit the drop below.
// Pod→:4244 on every REMOTE node already traverses neb1 and is
// accepted, so scoping this exemption to the pod-veth wildcards
// opens nothing the overlay did not already expose — while every
// other internal port stays closed to tenant pods.
var hostPortsGuardPodExemptPorts = []int{4244}

// hostPortsGuardPodIFaces are the pod-veth interface wildcards the
// pre-roadmap-1.2 blanket accepts used, reused here ONLY in
// combination with hostPortsGuardPodExemptPorts.
var hostPortsGuardPodIFaces = []string{"cilium*", "lxc*", "cali*"}

// convergeHostPortsGuard deploys the host-internal-ports nft guard
// + its boot oneshot (host-internal-ports): inbound TCP to the internal
// listeners is dropped unless it arrives via loopback, the nebula
// cluster trunk (neb1), an established/related flow, or an
// allowlisted source (registry node IPs +
// host_internal_ports_guard_allow_extra — the operator-declared
// Prometheus/monitoring set). Roadmap 1.2 tightening: the old
// `iifname "cilium*"|"lxc*"|"cali*"` accepts and the blanket
// RFC1918 allow list are GONE — those were the pod/VLAN-neighbour
// path to /debug/pprof, kubelet and the exporters (the
// nodelocaldns guard's RFC1918 accept keeps :53 serviceable for
// pods; its accepts do not shield anything from this chain — nft
// accept in one base chain still hands the packet to the next
// priority). The table is inet (dual-stack): the old `table ip`
// never filtered a v6 wildcard bind. Enabled by default;
// `host_internal_ports_guard_enabled: false` tears the unit and
// the live table down.
func (c *cyc) convergeHostPortsGuard() {
	r, ctx := c.r, c.ctx
	// An UNDEFINED var means default-ON — the guard exists because
	// a missing firewall rule only ever surfaces as "how did a
	// scanner reach kubelet", so opt-out must be explicit.
	enabled := true
	if _, undef := c.t.Vars.Get("host_internal_ports_guard_enabled").(jinja.Undefined); !undef {
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
			"nft delete table inet host_internal_ports_guard 2>/dev/null; true")
		return
	}
	var ports strings.Builder
	for i, p := range hostPortsGuardPorts {
		if i > 0 {
			ports.WriteString(", ")
		}
		fmt.Fprintf(&ports, "%d", p)
	}
	fmt.Fprintf(&ports, ", %s", hostPortsGuardNodePortRange)
	allow := c.portsGuardAllowSources()
	allowV4, allowV6 := splitAddrFamilies(allow)
	var saddr strings.Builder
	// Family-scoped accepts — an inet table's ip6 packets never
	// match `ip saddr`, and an empty set literal is invalid nft, so
	// each family only renders when its half of the allow list
	// resolved at all (an empty allowlist drops the accept rules but
	// NOT the drops: loopback + neb1 + established + node IPs remain
	// the cluster path).
	if len(allowV4) > 0 {
		fmt.Fprintf(&saddr, "        ip saddr { %s } accept\n",
			strings.Join(allowV4, ", "))
	}
	if len(allowV6) > 0 {
		fmt.Fprintf(&saddr, "        ip6 saddr { %s } accept\n",
			strings.Join(allowV6, ", "))
	}
	var podExempt strings.Builder
	for _, p := range hostPortsGuardPodExemptPorts {
		for _, iface := range hostPortsGuardPodIFaces {
			fmt.Fprintf(&podExempt, "        iifname %q tcp dport %d accept\n", iface, p)
		}
	}
	nft := fmt.Sprintf(`# Managed by node-config-agent - drop non-cluster traffic to node-internal ports
destroy table inet host_internal_ports_guard
table inet host_internal_ports_guard {
    chain input {
        type filter hook input priority filter - 5; policy accept;
        iifname "lo" accept
        iifname "neb1" accept
        ct state { established, related } accept
%s%s        tcp dport { %s } drop
    }
}
`, saddr.String(), podExempt.String(), ports.String())
	c.applyNftUnit("host-internal-ports-guard", "/etc/host-internal-ports-guard.nft",
		[]byte(nft), "host internal ports guard (drop non-cluster sources to node-internal listeners)")
}

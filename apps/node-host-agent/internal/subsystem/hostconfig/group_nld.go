// group_nld.go — T4 node-local-dns stub guard + the host-internal-ports
// nft guard that shares its allow list.
package hostconfig

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostconfig/converge"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// ---------- T4 nodelocaldns guard ----------

func (c *cyc) groupNLD() {
	r, ctx := c.r, c.ctx
	stubListening := false
	// netlinkx sock_diag replaces the `ss -lntu` fork — pid 1 is
	// host init, so its netns is the host table systemd-resolved
	// binds. The resolved stub always binds TCP+UDP :53 together,
	// so the TCP-LISTEN + bound-UDP census sees it either way.
	if addrs, err := c.r.cfg.ListenAddrsFn(1); err == nil {
		_, stubListening = addrs["127.0.0.53:53"]
		if !stubListening {
			_, stubListening = addrs["127.0.0.54:53"]
		}
	} else {
		// Best-effort detection — a failed probe leaves
		// stubListening=false and the rest of T4 still converges.
		logger().Warn("T4: listener census failed — cannot detect resolved stub listener; continuing",
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
destroy table ip nodelocaldns_guard
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
	return c.allowSources("nodelocaldns_guard_allow",
		"nodelocaldns_guard_allow_private", "nodelocaldns_guard_allow_extra")
}

func (c *cyc) allowSources(what string, keys ...string) []string {
	var allow []string
	for _, k := range keys {
		allow = append(allow, c.vs(k)...)
	}
	allow = append(allow, c.registryNodeIPs()...)
	allow = c.nftAllowFilter(what, allow)
	slices.Sort(allow)
	allow = slices.Compact(allow)
	return allow
}

// nftAllowFilter drops allow-list entries that are not valid IP/CIDR
// literals — every survivor lands verbatim inside an nft
// `ip saddr {…}` set literal where a crafted value could splice
// arbitrary rules (the old pass-through trusted config shape). A
// refusal counts a cycle error and the entry drops out — fail
// closed: the guard's allow set narrows, it never widens. Empty
// entries refuse too: `strings.Join` would emit `a, , b` and the
// whole ruleset would fail nft -c.
func (c *cyc) nftAllowFilter(what string, addrs []string) []string {
	return slices.DeleteFunc(addrs, func(a string) bool {
		if a != "" && converge.SHIPCIDR(a) {
			return false
		}
		c.err("hostconfig: invalid IP/CIDR refused for nft allow set",
			"what", what, "value", a)
		return true
	})
}

// registryNodeIPs collects every node's registry addresses — the
// `ip` v4 entry plus the `ip6` v6 entry when the registry carries
// one — plus every mesh marker IP (interdc_markers): marker-subnet
// sources are cluster nodes too and must reach the guarded ports
// over the overlay. Non-mapping registry entries are skipped, not a
// panic (the TestNLDAllowSourcesScalarNode contract).
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
	for _, ip := range c.t.Markers {
		if ip != "" {
			ips = append(ips, ip)
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
	return c.allowSources("host_internal_ports_guard_allow", "host_internal_ports_guard_allow_extra")
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
// :10250 is the kubelet API — authenticated (anonymous gets 401 and
// kubelet authorization denies non-node subjects), but k0s clusters
// reach kubelets THROUGH konnectivity-agent pods: when the
// apiserver's dial is handled by a konnectivity-agent colocated
// with the target kubelet, the SYN hairpins
// pod→own-node-public-IP:10250 onto a pod-veth iif and hit the drop
// (incident 2026-11-14 cicd: the guard rollout broke
// apiserver→kubelet on vmi2940967 — kubectl logs/exec/stats/proxy
// and the metrics-server all died while the node stayed Ready
// because kubelet→apiserver outbound still worked). Pod→:10250 on
// every REMOTE node already traverses neb1 and is accepted, so
// scoping these exemptions to the pod-veth wildcards opens nothing
// the overlay did not already expose — while every other internal
// port stays closed to tenant pods.
// :4240 joins the exemption set: it is the Cilium agent's mesh
// health endpoint — cluster probes (and the agent's own peer probes
// arriving over a tunnel iface) must still reach it or the mesh
// reports every node dark.
var hostPortsGuardPodExemptPorts = []int{4240, 4244, 10250}

// hostPortsGuardPodIFaces are the pod-veth interface wildcards the
// pre-roadmap-1.2 blanket accepts used — pod veths (cilium*/lxc*/
// cali*, "lxc*" already covers lxc_health) — plus the CNI tunnel
// interfaces pod traffic legitimately arrives on: Calico's IPIP
// tunnel (tunl0), its VXLAN devices (vxlan.calico / vxlan-v6.calico)
// and WireGuard devices (wireguard.cali / wg-v6.cali). Reused here
// ONLY in combination with hostPortsGuardPodExemptPorts — every
// other internal port stays closed to tenant pods.
var hostPortsGuardPodIFaces = []string{
	"cilium*", "lxc*", "cali*",
	"tunl0", "vxlan.calico", "vxlan-v6.calico",
	"wireguard.cali", "wg-v6.cali",
}

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
			"nft delete table inet host_internal_ports_guard 2>/dev/null; nft delete table ip host_internal_ports_guard 2>/dev/null; true")
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
	// Fail-open: a node absent from the registry with NO allow
	// sources at all (a standalone/single-node host without vars)
	// would get a guard whose only accepts are lo / the nebula dev /
	// established — apiserver→kubelet and every local admin path
	// drops. Skip the install entirely; the warning keeps the
	// unguarded state visible instead of silently whitelisting
	// nothing.
	if !c.t.Found && len(allow) == 0 {
		logger().Warn("host-internal-ports guard skipped — node not in registry and allow set empty; ports left unguarded")
		return
	}
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
	// The nebula trunk accept follows interdc_nebula_dev — the same
	// var the routing converge and the unit templates render. It
	// lands inside an nft quoted string: the shell-token charset
	// keeps '"', '\\' and ';' out so the value cannot splice rules.
	// A refused value skips the WHOLE install — a guard missing the
	// trunk accept would sever cluster traffic anyway, which is
	// worse than leaving the ports unguarded for one cycle.
	dev := c.nebDev()
	if !c.shToken("interdc_nebula_dev", dev) {
		return
	}
	nft := fmt.Sprintf(`# Managed by node-config-agent - drop non-cluster traffic to node-internal ports
destroy table ip host_internal_ports_guard
destroy table inet host_internal_ports_guard
table inet host_internal_ports_guard {
    chain input {
        type filter hook input priority filter - 5; policy accept;
        iifname "lo" accept
        iifname %q accept
        ct state { established, related } accept
%s%s        tcp dport { %s } drop
    }
}
`, dev, saddr.String(), podExempt.String(), ports.String())
	c.applyNftUnit("host-internal-ports-guard", "/etc/host-internal-ports-guard.nft",
		[]byte(nft), "host internal ports guard (drop non-cluster sources to node-internal listeners)")
}

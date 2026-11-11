// group_sysctl.go — T1/T2/A4/T16 sysctl files, the BBR/conntrack
// module setup and the nf_conntrack hashsize sizing (split out of
// group_base.go — pure move, same package).
package hostconfig

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// ---------- T1/T2/A4/T16 + hostname hosts pin ----------

func sysctlFile(pairs [][2]string, header string) []byte {
	var b strings.Builder
	b.WriteString(header)
	for _, kv := range pairs {
		fmt.Fprintf(&b, "%s = %s\n", kv[0], kv[1])
	}
	return []byte(b.String())
}

func (c *cyc) sysctlPairs(varName string) [][2]string {
	var out [][2]string
	for _, it := range c.vl(varName) {
		m, _ := it.(*jinja.OMap) // nil-safe: Str answers "" for a nil map
		k, v := m.Str("name"), m.Str("value")
		if k == "" || v == "" {
			// Unset/degenerate var entry — render nothing rather than
			// a valueless `key = ` line sysctl --system would choke
			// on; an absent var is not an error.
			continue
		}
		// Charset gate BEFORE the render (rendered-config hardening):
		// a newline in a var value would splice further `key = value`
		// lines into the drop-in, applied verbatim by the next
		// `sysctl --system`. A refused pair is skipped — the file
		// converges with the remaining pairs, the refusal is counted
		// per dropped pair.
		if !c.cfgSysctlKey(varName, k) || !c.cfgSysctlVal(varName, v) {
			continue
		}
		out = append(out, [2]string{k, v})
	}
	return out
}

func (c *cyc) sysctlVal(varName string, idx int) string {
	p := c.sysctlPairs(varName)
	if idx < len(p) {
		return p[idx][1]
	}
	return ""
}

// T16 pairs — conntrack key only when the module is loaded.
func (c *cyc) t16Pairs() [][2]string {
	p := [][2]string{
		{"net.core.somaxconn", "8192"},
		{"net.core.netdev_max_backlog", "8192"},
		{"net.ipv4.tcp_max_syn_backlog", "8192"},
		{"net.ipv4.ip_local_port_range", "10240 65535"},
		// conntrack-port-pressure: reuse TIME_WAIT sockets for new outbound
		// connections — safe with tcp_timestamps on (default), and
		// the difference between a healthy node and EADDRNOTAVAIL on
		// the gateway/proxy churn bursts the port-range width above
		// is sized for.
		{"net.ipv4.tcp_tw_reuse", "1"},
		// ip_local_port_range: keep the kernel's ephemeral source-port allocation off
		// ports host daemons LISTEN on — an ephemeral steal of kubelet
		// 10248/10250/10256, NPD 20256, NodePort+Spegel 30000-32767,
		// Nebula UDP 45670 or Cilium WireGuard 51871 wedges the real
		// listener's next bind or blackholes its replies.
		{"net.ipv4.ip_local_reserved_ports", "10248-10260,20256,30000-32767,45670,51871"},
		{"fs.file-max", "2097152"},
		// pid-fd-pressure: pid_max headroom for the thread/FD exhaustion
		// guard (node_agent_threads_utilization_ratio latch).
		{"kernel.pid_max", "4194304"},
		// cloudflared-wedge-heal: QUIC (cloudflared) UDP buffers — the 208KB
		// default drops edge streams under load.
		{"net.core.rmem_max", "7500000"},
		{"net.core.wmem_max", "7500000"},
		{"vm.max_map_count", "524288"},
		{"net.ipv4.neigh.default.gc_thresh1", "8192"},
		{"net.ipv4.neigh.default.gc_thresh2", "32768"},
		{"net.ipv4.neigh.default.gc_thresh3", "65536"},
	}
	// aio-pressure: AIO table headroom — io_uring/native-aio DB engines
	// exhaust the stock aio-max-nr and surface EAGAIN as generic
	// "storage slow" grey failures. Only when the kernel exposes
	// aio (compiled out leaves no sysctl node; an unconditional key
	// would fail sysctl --system) — same gating as the conntrack
	// pairs above.
	if c.r.fileExists("/proc/sys/fs/aio-max-nr") ||
		fileExistsNoRoot("/proc/sys/fs/aio-max-nr") {
		// kernel-resource-table-tuning: 4M slots — the 1M convergence value still starves
		// nodes running many DB instances (ScyllaDB/MySQL/CNPG
		// workers each hold aio contexts); collect_filefd_sockstat's
		// runtime bump covers the gap before this sysctl lands.
		p = append(p, [2]string{"fs.aio-max-nr", "4194304"})
	}
	// user-namespace headroom for rootless/containerd userns-remap
	// workloads — same existence gate as aio (kernels compiled
	// without USER_NS leave no sysctl node).
	if c.r.fileExists("/proc/sys/user/max_user_namespaces") ||
		fileExistsNoRoot("/proc/sys/user/max_user_namespaces") {
		p = append(p, [2]string{"user.max_user_namespaces", "65536"})
	}
	// sysctl-hardening: keyring quota headroom — a full keyring fails
	// keyctl/add_key silently for new sessions.
	if c.r.fileExists("/proc/sys/kernel/keys/root_maxkeys") ||
		fileExistsNoRoot("/proc/sys/kernel/keys/root_maxkeys") {
		p = append(p,
			[2]string{"kernel.keys.root_maxkeys", "1000000"},
			[2]string{"kernel.keys.root_maxbytes", "25000000"},
			[2]string{"kernel.keys.maxkeys", "100000"},
			[2]string{"kernel.keys.maxbytes", "2500000"})
	}
	if c.r.fileExists("/proc/sys/net/netfilter/nf_conntrack_max") ||
		fileExistsNoRoot("/proc/sys/net/netfilter/nf_conntrack_max") {
		p = append(p, [2]string{"net.netfilter.nf_conntrack_max",
			strconv.FormatInt(c.conntrackMax(), 10)})
	}
	// sysctl-hardening: shrink dead-flow occupancy of the conntrack table —
	// TIME_WAIT/CLOSE_WAIT pileups ate the table on WAN flaps.
	if c.r.fileExists("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait") ||
		fileExistsNoRoot("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait") {
		p = append(p,
			[2]string{"net.netfilter.nf_conntrack_tcp_timeout_time_wait", "30"},
			[2]string{"net.netfilter.nf_conntrack_tcp_timeout_close_wait", "60"})
	}
	// conntrack-arp-pressure: give the IPv6 neighbour cache the same headroom as
	// IPv4 — only when the kernel exposes the ndisc table (IPv6
	// compiled out leaves no gc_thresh3 node to write to; an
	// unconditional key would fail sysctl --system). Values come
	// from the ipv6_neigh_sysctls var (defaults.yaml, same source
	// as tcp_keepalive/bbr) with a hardcoded fallback matching the
	// IPv4 tier so an older vars bundle still gets the tuning.
	if c.r.fileExists("/proc/sys/net/ipv6/neigh/default/gc_thresh3") ||
		fileExistsNoRoot("/proc/sys/net/ipv6/neigh/default/gc_thresh3") {
		var v6 [][2]string
		if c.t != nil {
			v6 = c.sysctlPairs("ipv6_neigh_sysctls")
		}
		if len(v6) == 0 {
			v6 = [][2]string{
				{"net.ipv6.neigh.default.gc_thresh1", "8192"},
				{"net.ipv6.neigh.default.gc_thresh2", "32768"},
				{"net.ipv6.neigh.default.gc_thresh3", "65536"},
			}
		}
		p = append(p, v6...)
	}
	// pty-exhaustion-guard (pty-exhaustion-guard): /dev/pts PTY table ceiling — the
	// stock kernel.pty.max=4096 starves kubectl exec/tty pods and sshd
	// under churn while the node still reports Ready. Only when the
	// kernel exposes the pty sysctl (pty compiled out leaves no node;
	// an unconditional key would fail sysctl --system). Value comes
	// from the pty_max var (defaults.yaml) with a hardcoded fallback
	// so an older vars bundle still gets the tuning.
	if c.r.fileExists("/proc/sys/kernel/pty/max") ||
		fileExistsNoRoot("/proc/sys/kernel/pty/max") {
		ptyMax := "16384"
		if c.t != nil {
			if v := strings.TrimSpace(c.t.Vars.StrDef("pty_max", "")); v != "" {
				ptyMax = v
			}
		}
		p = append(p, [2]string{"kernel.pty.max", ptyMax})
	}
	return p
}

// conntrackMax returns the conntrack table size the cluster vars
// pin — the nf_conntrack_max value conntrackHashsize sizes the hash
// table against. Empty/"None" keeps the 262144 default.
func (c *cyc) conntrackMax() int64 {
	// c.t is nil in the bare-cyc unit tests (no topology loaded) —
	// the var then counts as unset and the default applies.
	if c.t == nil {
		return 262144
	}
	if n, err := strconv.ParseInt(
		strings.TrimSpace(c.t.Vars.StrDef("conntrack_max", "")), 10, 64); err == nil && n > 0 {
		return n
	}
	return 262144
}

// conntrackHashsize sizes the nf_conntrack HASH table to the table
// max (G1 — the ksoftirqd storm post-mortem): conntrack_max=524288
// with the kernel's default 16384-bucket hash table leaves ~32-entry
// chains, and every packet lookup walks a chain under
// ksoftirqd — the CPU storm shows as softirq time, not a dropped-
// packet counter. wantBuckets = max(conntrack_max/4, 65536) keeps
// chains ≤4 entries (131072 buckets at the 524288 max). The
// modprobe.d options file persists the sizing across reboot/module
// reloads; a runtime write to the module parameter grows the live
// table immediately (shrink-on-write is refused by the kernel, so
// only a smaller live value is bumped).
func (c *cyc) conntrackHashsize() {
	r := c.r
	want := c.conntrackMax() / 4
	if want < 65536 {
		want = 65536
	}
	content := []byte(fmt.Sprintf(
		"# Managed by node-config-agent - conntrack hash bucket sizing\n"+
			"# wantBuckets = max(conntrack_max/4, 65536) — long bucket\n"+
			"# chains spin ksoftirqd on every conntrack lookup (G1).\n"+
			"options nf_conntrack hashsize=%d\n", want))
	if ch, err := r.writeManaged("/etc/modprobe.d/nf_conntrack.conf",
		content, 0o644); err == nil && ch {
		logger().Info("base: nf_conntrack hashsize persisted via modprobe.d",
			"hashsize", want)
	}
	// Live-bump the running table — the modprobe.d file only takes
	// effect on the next module load, and unloading nf_conntrack on
	// a live node is not an option. Writing hashsize grows the table
	// in place (the kernel refuses a shrink below the current value,
	// so a larger live value is left alone).
	p := "/sys/module/nf_conntrack/parameters/hashsize"
	data, err := os.ReadFile(r.hp(p))
	if err != nil {
		return // module not loaded / param absent — nothing to grow
	}
	cur, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || cur >= want {
		return
	}
	if err := os.WriteFile(r.hp(p),
		[]byte(strconv.FormatInt(want, 10)+"\n"), 0o644); err != nil {
		c.err("base: nf_conntrack live hashsize grow failed",
			"path", p, "hashsize", want, "error", err)
		return
	}
	r.actions.WithLabelValues("nf_conntrack hashsize").Inc()
	logger().Info("base: nf_conntrack live hashsize grown",
		"from", cur, "to", want)
}

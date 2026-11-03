// Task groups — one function per ansible task-file group, invoked by
// Cycle in node_tuning.yaml order.
package hostconfig

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/topology"
)

//go:embed all:templates
var templates embed.FS

// Cycle runs one full converge (all groups, playbook order).
func (r *Reconciler) Cycle(ctx context.Context) {
	start := time.Now()
	t, err := topology.Load(topology.Config{VarsDir: r.cfg.VarsDir, NodeName: r.cfg.NodeName, NowFn: r.cfg.NowFn})
	if err != nil {
		r.cycles.WithLabelValues("load", "error").Inc()
		slog.Error("hostconfig: topology load failed", "err", err)
		return
	}
	for _, e := range t.Errors {
		slog.Error("hostconfig: topology", "error", e)
	}
	c := &cyc{r: r, ctx: ctx, t: t}
	// Order mirrors node_tuning.yaml + hub_converge.yaml.
	c.group("base", c.groupBase)          // T1/T2/A4/T16 + hostname pin
	c.group("resolved", c.groupResolved)  // T3
	c.group("nodelocaldns", c.groupNLD)   // T4
	c.group("nebula", c.groupNebula)      // T5b
	c.group("watchdog", c.groupWatchdog)  // T6 (+T15/systemd watchdog)
	c.group("imagepulls", c.groupPulls)   // T7 + T17
	c.group("nodeip_cpu", c.groupNodeCPU) // T8 + T10
	c.group("coredns", c.groupCoreDNS)    // T9 (stub + hub)
	c.group("bwaudit", c.groupBwAudit)    // T11
	c.group("security", c.groupSecurity)  // fail2ban + sshd hardening
	c.group("apilb", c.groupAPILB)        // T12 (incl. fallback-map strip)
	c.group("verify", c.groupVerify)
	// Vars lazily resolve during the groups too — eval failures and
	// reference cycles land in Vars.Errors (fail-closed Undefined).
	for _, e := range t.Vars.Errors() {
		slog.Error("hostconfig: vars resolution", "error", e)
	}
	slog.Info("hostconfig: cycle done", "elapsed", time.Since(start).Round(time.Second).String())
}

type cyc struct {
	r   *Reconciler
	ctx context.Context
	t   *topology.Topology
}

func (c *cyc) group(name string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			c.r.cycles.WithLabelValues(name, "panic").Inc()
			slog.Error("hostconfig group panicked", "group", name, "panic", rec)
		}
	}()
	fn()
}

func (c *cyc) v(name string) string    { return c.t.Vars.Str(name) }
func (c *cyc) vb(name string) bool     { return c.t.Vars.Bool(name) }
func (c *cyc) vl(name string) []any    { return c.t.Vars.List(name) }
func (c *cyc) vs(name string) []string { return c.t.Vars.StrList(name) }
func (c *cyc) vi(name string) int64    { return c.t.Vars.Int(name) }
func (c *cyc) worker() bool            { return c.r.fileExists("/etc/systemd/system/k0sworker.service") }
func (c *cyc) controller() bool        { return c.r.fileExists("/etc/systemd/system/k0scontroller.service") }

// ---------- T1/T2/A4/T16 + hostname hosts pin ----------

func sysctlFile(pairs [][2]string, header string) []byte {
	var b strings.Builder
	b.WriteString(header)
	for _, kv := range pairs {
		fmt.Fprintf(&b, "%s = %s\n", kv[0], kv[1])
	}
	return []byte(b.String())
}

func (c *cyc) groupBase() {
	r := c.r
	ctx := c.ctx
	// T1 inotify + tcp keepalive (ansible.posix.sysctl per-key files).
	changed := false
	for _, f := range []struct {
		path  string
		pairs [][2]string
		hdr   string
	}{
		{"/etc/sysctl.d/99-k8s-inotify.conf",
			[][2]string{{"fs.inotify.max_user_instances", c.v("inotify_max_user_instances")},
				{"fs.inotify.max_user_watches", c.v("inotify_max_user_watches")}},
			"# Managed by node-config-agent - inotify limits\n"},
		{"/etc/sysctl.d/99-tcp-keepalive.conf", c.sysctlPairs("tcp_keepalive_sysctls"),
			"# Managed by node-config-agent - TCP keepalive (meta-conn zombie cleanup)\n"},
		{"/etc/sysctl.d/99-interdc-bbr.conf", c.sysctlPairs("bbr_sysctls"),
			"# Managed by node-config-agent - BBR+fq cho duong trunk interdc\n"},
		{"/etc/sysctl.d/99-k8s-network-tuning.conf", c.t16Pairs(),
			"# Managed by node-config-agent - T16 network/sysctl tuning\n"},
	} {
		if ch, err := r.writeManaged(f.path, sysctlFile(f.pairs, f.hdr), 0o644); err == nil && ch {
			changed = true
		}
	}
	if ch, _ := r.writeManaged("/etc/modules-load.d/interdc-bbr.conf",
		[]byte("# Managed by node-config-agent - BBR cho duong trunk interdc\ntcp_bbr\n"), 0o644); ch {
		changed = true
	}
	r.run(ctx, "modprobe", "tcp_bbr")
	r.run(ctx, "modprobe", "nf_conntrack")
	if changed {
		r.actions.WithLabelValues("sysctl --system").Inc()
		r.run(ctx, "sysctl", "--system")
	}
	// A4 assert: effective == expected (informational fail like ansible).
	out, _ := r.run(ctx, "sysctl", "-n", "net.ipv4.tcp_congestion_control", "net.core.default_qdisc")
	lines := strings.Fields(out)
	want := []string{c.sysctlVal("bbr_sysctls", 0), c.sysctlVal("bbr_sysctls", 1)}
	if len(lines) < 2 || lines[0] != want[0] || lines[1] != want[1] {
		slog.Warn("BBR/fq not effective", "got", out)
	}

	// T2 k0sworker limits drop-in.
	if c.worker() {
		c.r.ensureDir("/etc/systemd/system/k0sworker.service.d", 0o755)
		if ch, _ := r.writeManaged("/etc/systemd/system/k0sworker.service.d/10-limits.conf",
			[]byte(fmt.Sprintf(`# Managed by node-config-agent - explicit fd/task limits for k0s worker
[Service]
LimitNOFILE=%s
LimitNPROC=infinity
TasksMax=infinity
`, c.v("k0sworker_limit_nofile"))), 0o644); ch {
			r.daemonReload(ctx)
		}
	}

	// hostname -> 127.0.1.1 in /etc/hosts (lineinfile parity).
	hosts, _ := os.ReadFile(r.hp("/etc/hosts"))
	hn := c.r.cfg.NodeName
	re := regexp.MustCompile(`(?m)^\s*127\.0\.1\.1\s.*$`)
	line := "127.0.1.1 " + hn
	if re.Match(hosts) {
		if !re.MatchString(string(hosts)) || !strings.Contains(string(hosts), line) {
			nh := re.ReplaceAll(hosts, []byte(line))
			if string(nh) != string(hosts) {
				r.writeManaged("/etc/hosts", nh, 0o644)
			}
		}
	} else {
		nh := append(hosts, []byte(line+"\n")...)
		r.writeManaged("/etc/hosts", nh, 0o644)
	}
}

func (c *cyc) sysctlPairs(varName string) [][2]string {
	var out [][2]string
	for _, it := range c.vl(varName) {
		out = append(out, [2]string{strOf(it, "name"), strOf(it, "value")})
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

func strOf(m any, key string) string {
	om, _ := m.(*topology.OMap)
	if om == nil {
		return ""
	}
	v, _ := om.Get(key)
	s, _ := v.(string)
	if s == "" && v != nil {
		return fmt.Sprint(v)
	}
	return s
}

// T16 pairs — conntrack key only when the module is loaded.
func (c *cyc) t16Pairs() [][2]string {
	p := [][2]string{
		{"net.core.somaxconn", "8192"},
		{"net.core.netdev_max_backlog", "8192"},
		{"net.ipv4.tcp_max_syn_backlog", "8192"},
		{"net.ipv4.ip_local_port_range", "10240 65535"},
		{"fs.file-max", "2097152"},
		{"vm.max_map_count", "524288"},
		{"net.ipv4.neigh.default.gc_thresh1", "8192"},
		{"net.ipv4.neigh.default.gc_thresh2", "32768"},
		{"net.ipv4.neigh.default.gc_thresh3", "65536"},
	}
	if c.r.fileExists("/proc/sys/net/netfilter/nf_conntrack_max") ||
		fileExistsNoRoot("/proc/sys/net/netfilter/nf_conntrack_max") {
		p = append(p, [2]string{"net.netfilter.nf_conntrack_max", "262144"})
	}
	return p
}

func fileExistsNoRoot(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ---------- T3 resolved fallback DNS ----------

func (c *cyc) resolvedRunning() bool {
	return c.r.serviceState(c.ctx, "systemd-resolved.service") == "active"
}

func (c *cyc) groupResolved() {
	if !c.resolvedRunning() {
		return
	}
	c.r.ensureDir("/etc/systemd/resolved.conf.d", 0o755)
	if ch, _ := c.r.writeManaged("/etc/systemd/resolved.conf.d/99-fallback.conf",
		[]byte(fmt.Sprintf(`# Managed by node-config-agent - diverse public fallback upstreams
[Resolve]
FallbackDNS=%s
Cache=yes
`, c.v("fallback_dns"))), 0o644); ch {
		c.r.restartService(c.ctx, "systemd-resolved.service")
	}
}

// ---------- T4 nodelocaldns guard ----------

func (c *cyc) groupNLD() {
	r, ctx := c.r, c.ctx
	stubListening := false
	if out, err := r.run(ctx, "ss", "-lntu"); err == nil {
		stubListening = regexp.MustCompile(`127\.0\.0\.5[34]:53`).MatchString(out)
	}
	if c.resolvedRunning() {
		// ansible.builtin.fail parity: stub listening but no real
		// resolv.conf to repoint to => refuse the whole stub-disable
		// path (writing DNSStubListener=no here would black out DNS).
		refuse := false
		if stubListening {
			if !r.fileExists("/run/systemd/resolve/resolv.conf") {
				slog.Error("T4: resolved stub listening but no real resolv.conf — refusing to disable stub")
				refuse = true
			} else {
				// repoint symlink
				dst := r.hp("/etc/resolv.conf")
				fi, _ := os.Lstat(dst)
				if fi == nil || fi.Mode()&os.ModeSymlink == 0 ||
					func() bool { l, _ := os.Readlink(dst); return l != "/run/systemd/resolve/resolv.conf" }() {
					os.Remove(dst)
					os.Symlink("/run/systemd/resolve/resolv.conf", dst)
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
	// guard allow list = private + node IPs + extra, sorted.
	allow := append(c.vs("nodelocaldns_guard_allow_private"), c.vs("nodelocaldns_guard_allow_extra")...)
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
	r.removeManaged("/etc/nftables.d/nodelocaldns-guard.nft")
}

// applyNftUnit deploys an nft ruleset + its oneshot boot unit, applies
// via restart when the file changed (T4/T11 pattern).
func (c *cyc) applyNftUnit(name, path string, content []byte, desc string) {
	r, ctx := c.r, c.ctx
	ch, _ := r.writeManaged(path, content, 0o644)
	// ansible: nft -c -f <file> after deploy — an invalid ruleset fails
	// the run here and the unit keeps serving the LAST GOOD file.
	if _, err := r.run(ctx, "nft", "-c", "-f", path); err != nil {
		slog.Error("nft ruleset failed nft -c — boot unit left on last good file",
			"path", path, "err", err)
		return
	}
	unitPath := "/etc/systemd/system/" + name + ".service"
	uch, _ := r.writeManaged(unitPath, []byte(fmt.Sprintf(`[Unit]
Description=%s
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f %s
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`, desc, path)), 0o644)
	if ch || uch {
		r.daemonReload(ctx)
	}
	r.run(ctx, "systemctl", "enable", name+".service")
	if ch {
		r.run(ctx, "systemctl", "restart", name+".service")
	} else {
		r.run(ctx, "systemctl", "start", name+".service")
	}
}

// ---------- T5b nebula mesh ----------

func (c *cyc) groupNebula() {
	r, ctx, t := c.r, c.ctx, c.t
	_ = ctx
	enabled := c.vb("interdc_nebula_enabled")
	net := c.v("interdc_nebula_net")
	if net == "" || net == "None" {
		net = "interdc"
	}
	dev := c.v("interdc_nebula_dev")
	if dev == "" || net == "None" || dev == "None" {
		dev = "neb1"
	}
	unit := "nebula@" + net + ".service"

	if !enabled || !t.Found {
		// disable path — ansible: stop+disable then sweep the
		// nebula-owned ip rules and flush BOTH policy tables.
		pub, mark := c.tablePub(), c.tableMark()
		r.run(ctx, "systemctl", "disable", "--now", "nebula-route-guard.service")
		r.run(ctx, "systemctl", "disable", "--now", unit)
		r.run(ctx, "sh", "-c", fmt.Sprintf(
			`ip rule list pref 1500 | sed -n "s/.*to \([0-9./]*\).*/\1/p" | while read -r d; do ip rule del pref 1500 to "$d" lookup %s 2>/dev/null; done; `+
				`ip rule del pref 1490 to %s.0/24 lookup %s 2>/dev/null; `+
				`ip route flush table %s 2>/dev/null; ip route flush table %s 2>/dev/null; `+
				`nft delete table ip nebnat 2>/dev/null; true`,
			pub, c.markerBase(), mark, pub, mark))
		return
	}
	// T5b: kernel TUN device required (ansible assert).
	if fi, err := os.Stat("/dev/net/tun"); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		slog.Error("T5b: /dev/net/tun missing or not a char device — modprobe tun before nebula")
		return
	}
	c.nebulaInstallBinary()
	c.r.ensureDir("/etc/nebula/"+net, 0o755)

	// certs from CM mounts (NebulaCertsDir, fallback VarsDir).
	certFile := func(name string) (string, bool) {
		for _, d := range []string{r.cfg.NebulaCertsDir, r.cfg.VarsDir} {
			p := filepath2(d, name)
			if _, err := os.Stat(p); err == nil {
				b, err := os.ReadFile(p)
				return string(b), err == nil
			}
		}
		return "", false
	}
	caCert, _ := certFile("nebula-ca.crt")
	hostCert, certOK := certFile("nebula-" + t.MeshName + ".crt")

	var certChanged, cfgChanged bool
	if caCert != "" {
		ch, _ := r.writeManaged("/etc/nebula/"+net+"/ca.crt", []byte(caCert), 0o644)
		certChanged = certChanged || ch
	}
	// keypair on node when missing (key never leaves the node).
	keyPath := "/etc/nebula/" + net + "/host.key"
	if !r.fileExists(keyPath) {
		r.run(ctx, "nebula-cert", "keygen", "-out-key", keyPath, "-out-pub", "/etc/nebula/"+net+"/host.pub")
	}
	if certOK {
		ch, _ := r.writeManaged("/etc/nebula/"+net+"/host.crt", []byte(hostCert), 0o644)
		certChanged = certChanged || ch
	} else {
		slog.Warn("T5b: signed cert nebula-" + t.MeshName + ".crt not in vars CM — nebula will not start")
	}

	// render config.yaml
	rendered, err := c.nebulaConfig()
	if err != nil {
		slog.Error("T5b: render nebula config", "err", err)
		return
	}
	oldCfg, _ := os.ReadFile(r.hp("/etc/nebula/" + net + "/config.yaml"))
	ch, _ := r.writeManaged("/etc/nebula/"+net+"/config.yaml", rendered, 0o644)
	cfgChanged = ch
	needRestart := cfgChanged && c.nebulaNeedsRestart(oldCfg, rendered)

	// overlay state file + hook scripts + units
	r.writeManaged("/etc/nebula/"+net+"/overlay", []byte(t.Overlay+"\n"), 0o644)
	tctx := c.tplCtx()
	guardScriptChanged := false
	for _, name := range []string{"nebula-up.sh", "nebula-down.sh", "nebula-route-guard.sh"} {
		b, err := c.r.render(name+".j2", tctx)
		if err != nil {
			slog.Error("T5b render", "tpl", name, "err", err)
			continue
		}
		dest := "/etc/nebula/" + net + "/" + name
		if name == "nebula-route-guard.sh" {
			dest = "/usr/local/sbin/nebula-route-guard.sh"
		}
		if ch, _ := r.writeManaged(dest, b, 0o755); ch && name == "nebula-route-guard.sh" {
			guardScriptChanged = true
		}
	}
	uch, _ := r.writeManaged("/etc/systemd/system/"+unit,
		[]byte(fmt.Sprintf(`# Managed by node-config-agent
[Unit]
Description=Nebula overlay network (%%i)
Wants=network-online.target
After=network-online.target
# Marker IP (k8s --node-ip) nam tren neb1 — k0sworker cho addr qua
# drop-in cua T8. Nebula phai len TRUOC k0sworker.
Before=k0sworker.service

[Service]
Type=notify
ExecStart=/usr/local/bin/nebula -config /etc/nebula/%%i/config.yaml
# ExecReload=SIGHUP: nebula >=1.9 hot-reload duoc pki creds,
# lighthouse.*, firewall, punchy, tun.unsafe_routes, logging,
# preferred_ranges — tunnels khong dut.
ExecReload=/bin/kill -HUP $MAINPID
ExecStartPost=/etc/nebula/%%i/nebula-up.sh
ExecStopPost=/etc/nebula/%%i/nebula-down.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`)), 0o644)
	guch, _ := r.writeManaged("/etc/systemd/system/nebula-route-guard.service",
		[]byte(fmt.Sprintf(`# Managed by node-config-agent
[Unit]
Description=Nebula overlay route/rule guard (netlink monitor, <500ms restore)
After=%s
BindsTo=%s

[Service]
ExecStart=/usr/local/sbin/nebula-route-guard.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, unit, unit)), 0o644)
	if uch || guch {
		r.daemonReload(ctx)
	}

	if !certOK {
		return
	}
	wasActive := r.isActive(ctx, unit)
	// ansible: `nebula -test` validates before start — failure aborts,
	// so the broken config must not reach a (re)start.
	if _, err := r.run(ctx, "nebula", "-config", "/etc/nebula/"+net+"/config.yaml", "-test"); err != nil {
		slog.Error("T5b: nebula -test failed — not starting/reloading", "err", err)
		return
	}
	r.ensureService(ctx, unit, true, true)
	if wasActive && (certChanged || cfgChanged) {
		r.daemonReload(ctx)
		if needRestart {
			r.restartService(ctx, unit)
		} else {
			r.reloadService(ctx, unit)
		}
	}
	// Guard is a resident process: script/unit drift => restarted,
	// no drift => started (no-op). BindsTo means a nebula restart may
	// have taken it down — ensure covers that too.
	if guardScriptChanged || guch {
		r.restartService(ctx, "nebula-route-guard.service")
	} else {
		r.ensureService(ctx, "nebula-route-guard.service", true, true)
	}

	// policy routing converge (live, no daemon restart needed).
	c.nebulaRouting()
}

func filepath2(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// nebulaInstallBinary ports the version-check + tarball install path.
func (c *cyc) nebulaInstallBinary() {
	r, ctx := c.r, c.ctx
	bin := r.hp("/usr/local/bin/nebula")
	need := true
	if out, err := r.run(ctx, "/usr/local/bin/nebula", "-version"); err == nil &&
		strings.Contains(out, c.v("interdc_nebula_version")) {
		need = false
	}
	if !need {
		_ = bin
		return
	}
	tgzFile := c.v("interdc_nebula_tgz_file")
	sum := c.v("interdc_nebula_tgz_sha256")
	url := c.v("interdc_nebula_tgz_url")
	local := filepath2(r.cfg.DownloadDir, tgzFile)
	if fileExistsNoRoot(local) {
		// ansible: sha256sum -c on the STAGED file every run — a
		// corrupted/operator-swapped tarball must not install.
		if !sha256FileOK(local, sum) {
			slog.Error("T5b: staged nebula tarball sha256 mismatch — not installing",
				"file", local)
			return
		}
	} else if err := download(ctx, url, local, sum); err != nil {
		slog.Error("T5b: nebula tarball download", "err", err)
		return
	}
	if err := untarInstall(local, "nebula", r.hp("/usr/local/bin/nebula"), 0o755); err != nil {
		slog.Error("T5b: nebula install", "err", err)
		return
	}
	_ = untarInstall(local, "nebula-cert", r.hp("/usr/local/bin/nebula-cert"), 0o755)
}

// nebulaConfig renders nebula.yaml.j2 via the shared ctx.
func (c *cyc) nebulaConfig() ([]byte, error) {
	return c.r.render("nebula.yaml.j2", c.tplCtx())
}

// tplCtx builds the interdc_* var context the .j2 templates expect.
func (c *cyc) tplCtx() map[string]any {
	t := c.t
	lh := topology.NewOMap()
	for _, l := range t.Lighthouses {
		m := topology.NewOMap()
		m.Set("marker", l.Marker)
		m.Set("ip", l.IP)
		lh.Set(l.Name, m)
	}
	var routes []any
	for _, u := range t.UnsafeRoutes {
		m := topology.NewOMap()
		m.Set("route", u.Route)
		m.Set("via", u.Via)
		m.Set("metric", u.Metric)
		m.Set("install", false)
		routes = append(routes, m)
	}
	relayMap := topology.NewOMap()
	for name, es := range t.RelayMap {
		var l []any
		for _, e := range es {
			m := topology.NewOMap()
			m.Set("ip", e.IP)
			l = append(l, m)
		}
		relayMap.Set(name, &topology.List{V: l})
	}
	get := func(name string) any {
		v := c.t.Vars.Get(name)
		return v
	}
	strv := func(name, def string) any {
		s := c.v(name)
		if s == "" || s == "None" {
			return def
		}
		return s
	}
	return map[string]any{
		"interdc_node":                 t.Node,
		"interdc_nebula_node":          t.Node,
		"interdc_nodes":                t.Nodes,
		"interdc_markers":              omapOf(t.Markers),
		"interdc_nebula_net":           strv("interdc_nebula_net", "interdc"),
		"interdc_nebula_dev":           strv("interdc_nebula_dev", "neb1"),
		"interdc_nebula_port":          get("interdc_nebula_port"),
		"interdc_nebula_mtu":           get("interdc_nebula_mtu"),
		"interdc_nebula_stats_listen":  strv("interdc_nebula_stats_listen", "127.0.0.1:9800"),
		"interdc_nebula_table_pub":     get("interdc_nebula_table_pub"),
		"interdc_nebula_table_marker":  get("interdc_nebula_table_marker"),
		"interdc_marker_base":          strv("interdc_marker_base", "172.29.0"),
		"interdc_nebula_lighthouses":   lh,
		"interdc_nebula_am_lighthouse": t.AmLighthouse,
		"interdc_nebula_unsafe_routes": &topology.List{V: routes},
		"interdc_relay_map":            relayMap,
		"interdc_targets":              &topology.List{V: strSliceToAny(t.Targets)},
		"interdc_egress_relays":        &topology.List{V: strSliceToAny(t.EgressRelays)},
		"interdc_overlay":              t.Overlay,
		"interdc_dns_zone":             t.Zone,
		"interdc_dns_resolvers":        &topology.List{V: strSliceToAny(t.DNSResolvers)},
		"interdc_stub_public_upstream": strv("interdc_stub_public_upstream", "1.1.1.1 8.8.8.8"),
		"cp_endpoint":                  c.v("cp_endpoint"),
		"api_lb_backends":              c.t.Vars.Get("api_lb_backends"),
		"api_lb_vip_ip":                c.v("api_lb_vip_ip"),
		"api_lb_probe_reachable":       &topology.List{V: strSliceToAny(c.probeReachable())},
		"fail2ban_ignoreip":            c.fail2banIgnoreIP(),
		"interdc_hub_zone_serial":      c.zoneSerial(),
		"ansible_facts":                map[string]any{"hostname": c.r.cfg.NodeName},
	}
}

func omapOf(m map[string]string) *topology.OMap {
	o := topology.NewOMap()
	for k, v := range m {
		o.Set(k, v)
	}
	return o
}

func strSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// nebulaNeedsRestart ports the reloadable-vs-restart key diff:
// SIGHUP covers pki creds content, lighthouse.hosts/allow lists,
// firewall, punchy, tun.unsafe_routes, logging, preferred_ranges.
// Non-reloadable: static_host_map, routines, cipher, stats, relay,
// handshakes, listen, pki PATHS, lighthouse.am_lighthouse, tun minus
// unsafe_routes.
func (c *cyc) nebulaNeedsRestart(old, new []byte) bool {
	parse := func(b []byte) map[string]any {
		m := map[string]any{}
		if len(b) == 0 {
			return m
		}
		var y map[string]any
		if v, err := topology.DecodeYAML(b); err == nil {
			if om, ok := v.(*topology.OMap); ok {
				for _, k := range om.Keys() {
					vv, _ := om.Get(k)
					y[k] = topologyPlain(vv)
				}
			}
		}
		_ = y
		return m
	}
	_ = parse
	oldV, err1 := topology.DecodeYAML(old)
	newV, err2 := topology.DecodeYAML(new)
	if err1 != nil || err2 != nil {
		return true // unparseable → restart (safe default)
	}
	diff := func(key string) bool {
		a, _ := oldV.(*topology.OMap)
		b, _ := newV.(*topology.OMap)
		var av, bv any
		if a != nil {
			av, _ = a.Get(key)
		}
		if b != nil {
			bv, _ = b.Get(key)
		}
		return !deepEqJ(av, bv)
	}
	for _, k := range []string{"pki", "static_host_map", "static_map", "routines",
		"cipher", "stats", "relay", "handshakes", "listen"} {
		if diff(k) {
			return true
		}
	}
	sub := func(root any, keys ...string) any {
		cur := root
		for _, k := range keys {
			om, _ := cur.(*topology.OMap)
			if om == nil {
				return nil
			}
			cur, _ = om.Get(k)
		}
		return cur
	}
	if !deepEqJ(sub(oldV, "lighthouse", "am_lighthouse"), sub(newV, "lighthouse", "am_lighthouse")) {
		return true
	}
	// tun minus unsafe_routes
	strip := func(root any) map[string]any {
		out := map[string]any{}
		if om, ok := root.(*topology.OMap); ok {
			for _, k := range om.Keys() {
				if k == "unsafe_routes" {
					continue
				}
				vv, _ := om.Get(k)
				out[k] = topologyPlain(vv)
			}
		}
		return out
	}
	ot := strip(sub(oldV, "tun"))
	nt := strip(sub(newV, "tun"))
	if fmt.Sprint(ot) != fmt.Sprint(nt) {
		return true
	}
	return false
}

func topologyPlain(v any) any {
	switch t := v.(type) {
	case *topology.OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = topologyPlain(vv)
		}
		return m
	case *topology.List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = topologyPlain(x)
		}
		return out
	default:
		return v
	}
}

func deepEqJ(a, b any) bool {
	return fmt.Sprintf("%#v", topologyPlain(a)) == fmt.Sprintf("%#v", topologyPlain(b))
}

func (c *cyc) tablePub() string {
	p := c.v("interdc_nebula_table_pub")
	if p == "" || p == "None" {
		return "100"
	}
	return p
}

func (c *cyc) tableMark() string {
	p := c.v("interdc_nebula_table_marker")
	if p == "" || p == "None" {
		return "101"
	}
	return p
}

// nebulaRouting ports the live ip rule/route/nft converge of T5b
// (tasks/interdc_nebula.yaml: mangle fwmark, populate overlay tables,
// flip ip rules to nebula, nebnat SNAT). SNAT/route source is the
// node's PUBLIC ip (interdc_nebula_node.ip); the marker table + the
// marker-daddr snat use the marker (--node-ip / registry marker).
func (c *cyc) nebulaRouting() {
	r, ctx, t := c.r, c.ctx, c.t
	dev := c.v("interdc_nebula_dev")
	if dev == "" || dev == "None" {
		dev = "neb1"
	}
	pub, mark, mb := c.tablePub(), c.tableMark(), c.markerBase()
	pubIP := nodeIPStr(t.Node, "ip") // interdc_nebula_node.ip (public)
	mkIP := t.Markers[t.MeshName]    // registry marker
	nodeIPV := nodeIP(c)             // --node-ip or hub marker
	// fwmark for transport
	for _, p := range []string{"dport", "sport"} {
		for _, chain := range []string{"OUTPUT", "PREROUTING"} {
			r.run(ctx, "sh", "-c", fmt.Sprintf(
				"iptables -t mangle -C %s -p udp --%s %s -j MARK --set-mark 0x1000 2>/dev/null || "+
					"iptables -t mangle -A %s -p udp --%s %s -j MARK --set-mark 0x1000",
				chain, p, port(c), chain, p, port(c)))
		}
	}
	r.run(ctx, "sh", "-c", `ip rule list | grep -q "fwmark 0x1000" || ip rule add pref 1400 fwmark 0x1000 lookup main`)

	// Populate overlay tables ALWAYS (warm standby even when
	// overlay=tinc). pub table src = public ip; marker table src =
	// NODE_IP only when it is a marker-base IP, else flush.
	r.run(ctx, "sh", "-c", fmt.Sprintf(
		`ip link show dev %s >/dev/null 2>&1 || exit 0; `+
			`ip route replace default dev %s src %s table %s; `+
			`case "%s" in %s.*) ip route replace default dev %s src %s table %s ;; `+
			`*) ip route flush table %s 2>/dev/null || true ;; esac`,
		dev, dev, pubIP, pub, nodeIPV, mb, dev, nodeIPV, mark, mark))

	if t.Overlay == "nebula" {
		// converge ip rules: prune stale lookups for mesh dsts, ensure
		// targets + marker CIDR → $pub, marker CIDR → $mark (pref 1490).
		targets := append(append([]string{}, t.Targets...), t.EgressRelays...)
		targets = append(targets, mb+".0/24")
		for _, d := range targets {
			r.run(ctx, "sh", "-c", fmt.Sprintf(
				`for t in $(ip rule list pref 1500 | sed -n "s|.*to %s .*lookup \([0-9]*\).*|\1|p"); do [ "$t" = %s ] || ip rule del pref 1500 to %s lookup "$t" 2>/dev/null; done`,
				d, pub, d))
		}
		for _, d := range append(append([]string{}, t.Targets...), mb+".0/24") {
			r.run(ctx, "sh", "-c", fmt.Sprintf(
				`ip rule list | grep -q "to %s lookup %s" || ip rule add pref 1500 to %s lookup %s`, d, pub, d, pub))
		}
		for _, d := range t.EgressRelays {
			r.run(ctx, "sh", "-c", fmt.Sprintf(
				`[ "$(cat /var/lib/node-watchdog/egress-state-%s 2>/dev/null)" = relay ] && { ip rule list | grep -q "to %s lookup %s" || ip rule add pref 1500 to %s lookup %s; }; true`,
				d, d, pub, d, pub))
		}
		r.run(ctx, "sh", "-c", fmt.Sprintf(
			`for t in $(ip rule list pref 1490 | sed -n "s|.*to %s\.0/24 .*lookup \([0-9]*\).*|\1|p"); do [ "$t" = %s ] || ip rule del pref 1490 to %s.0/24 lookup "$t" 2>/dev/null; done`,
			mb, mark, mb))
		if strings.HasPrefix(nodeIPV, mb+".") {
			r.run(ctx, "sh", "-c", fmt.Sprintf(
				`ip rule list | grep -q "to %s.0/24 lookup %s" || ip rule add pref 1490 to %s.0/24 lookup %s`,
				mb, mark, mb, mark))
		} else {
			r.run(ctx, "sh", "-c", fmt.Sprintf(
				`ip rule del pref 1490 to %s.0/24 lookup %s 2>/dev/null || true`, mb, mark))
		}
		// flush foreign dev tables (stale nebula-era tables).
		r.run(ctx, "sh", "-c", fmt.Sprintf(
			`ip -o route show table all dev %s 2>/dev/null | sed -n "s|.* table \([0-9]*\) .*|\1|p" | sort -u | while read -r t; do [ "$t" = "%s" ] || [ "$t" = "%s" ] || ip route flush table "$t" 2>/dev/null; done`,
			dev, pub, mark))
	} else {
		// overlay=tinc rollback: drop nebula-owned rules.
		r.run(ctx, "sh", "-c", fmt.Sprintf(
			`ip rule list pref 1500 | sed -n "s/.*to \([0-9./]*\).*/\1/p" | while read -r d; do ip rule del pref 1500 to "$d" lookup %s 2>/dev/null; done; ip rule del pref 1490 to %s.0/24 lookup %s 2>/dev/null; true`,
			pub, mb, mark))
	}
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
	r.run(ctx, "sh", "-c", sb.String()+"\ntrue")
}

// sha256FileOK verifies a staged/downloaded archive against its pin.
func sha256FileOK(path, wantHex string) bool {
	if wantHex == "" {
		return true
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(b)
	return strings.EqualFold(hex.EncodeToString(sum[:]), wantHex)
}

func (c *cyc) markerBase() string {
	b := c.v("interdc_marker_base")
	if b == "" || b == "None" {
		return "172.29.0"
	}
	return b
}

func port(c *cyc) string {
	p := c.v("interdc_nebula_port")
	if p == "" || p == "None" {
		return "45670"
	}
	return p
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

// ---------- T6 watchdog (+ T15 systemd watchdog) ----------

func (c *cyc) groupWatchdog() {
	r, ctx, t := c.r, c.ctx, c.t
	_ = ctx
	if !c.worker() && !t.Found {
		return
	}
	// conf — worker variant (hub adds SIG13 block when hub:true).
	var b strings.Builder
	b.WriteString(`# Managed by node-config-agent - node-watchdog sig5 probe
# targets: public IP remote (table 100) + tunnel marker IP
# remote (table 101 = duong pod-traffic that qua mesh);
# OVERLAY_EGRESS_RELAYS: fallback relay IPs (relay_mode=fallback)
# ma node nay consume — watchdog toggle ip rule theo probe
# underlay truc tiep.
`)
	fmt.Fprintf(&b, "OVERLAY_PROBE_TARGETS=\"%s\"\n", strings.Join(t.ProbeTargets, " "))
	fmt.Fprintf(&b, "OVERLAY_PROBE_MARKERS=\"%s\"\n", strings.Join(t.ProbeMarkers, " "))
	fmt.Fprintf(&b, "OVERLAY_SLOWPATH_MARKERS=\"%s\"\n", strings.Join(t.SlowpathMkrs, " "))
	fmt.Fprintf(&b, "OVERLAY_SLOWPATH_RTT_MS=\"%s\"\n", defStr(c.v("interdc_slowpath_rtt_ms"), "100"))
	fmt.Fprintf(&b, "OVERLAY_SITE_MARKERS=\"%s\"\n", strings.Join(t.SiteMarkers, " "))
	fmt.Fprintf(&b, "OVERLAY_SITEEDGE_RTT_MS=\"%s\"\n", defStr(c.v("interdc_siteedge_rtt_ms"), "50"))
	fmt.Fprintf(&b, "OVERLAY_EGRESS_TCP=\"%s\"\n", strings.Join(t.EgressProbes, " "))
	fmt.Fprintf(&b, "OVERLAY_EGRESS_RELAYS=\"%s\"\n", strings.Join(t.EgressRelays, " "))
	fmt.Fprintf(&b, "NEBULA_NET=\"%s\"\n", defStr(c.v("interdc_nebula_net"), "interdc"))
	fmt.Fprintf(&b, "NEBULA_PORT=\"%s\"\n", defStr(c.v("interdc_nebula_port"), "45670"))
	fmt.Fprintf(&b, "NEBULA_DEV=\"%s\"\n", defStr(c.v("interdc_nebula_dev"), "neb1"))
	fmt.Fprintf(&b, "NEBULA_STATS_URL=\"http://%s/metrics\"\n", defStr(c.v("interdc_nebula_stats_listen"), "127.0.0.1:9800"))
	fmt.Fprintf(&b, "OVERLAY_ACTIVE=\"%s\"\n", t.Overlay)
	fmt.Fprintf(&b, "OVERLAY_EGRESS_TABLE=\"%s\"\n", defStr(c.v("interdc_nebula_table_pub"), "100"))
	fb := t.DNSFallbackMap
	// T12-part1: strip cp_endpoint entry when api-local-lb is enabled.
	if c.vb("api_lb_enabled") && c.worker() {
		cp := c.v("cp_endpoint")
		var keep []string
		for _, e := range strings.Fields(fb) {
			if !strings.HasPrefix(e, cp+":6443=") {
				keep = append(keep, e)
			}
		}
		fb = strings.Join(keep, " ")
	}
	fmt.Fprintf(&b, "DNS_FALLBACK_MAP=\"%s\"\n", fb)
	// defaults.yaml defines these as jinja over api_lb_backends —
	// resolve the same semantics in Go so an eval failure can never
	// leak Undefined/raw text into the conf.
	pb, lbSrv, lbVip := c.apilbWatchdogVars()
	fmt.Fprintf(&b, "API_BACKENDS=\"%s\"\n", strings.Join(pb, " "))
	fmt.Fprintf(&b, "APISERVER_GAP_MIN=\"%s\"\n", defStr(c.v("apiserver_wedge_gap_min"), "10000"))
	fmt.Fprintf(&b, "APISERVER_GAP_CYCLES=\"%s\"\n", defStr(c.v("apiserver_wedge_gap_cycles"), "2"))
	fmt.Fprintf(&b, "APISERVER_FROZEN_CYCLES=\"%s\"\n", defStr(c.v("apiserver_wedge_frozen_cycles"), "2"))
	fmt.Fprintf(&b, "API_LB_SERVERS=\"%s\"\n", lbSrv)
	fmt.Fprintf(&b, "API_LB_VIP=\"%s\"\n", lbVip)
	b.WriteString("API_LB_SOCKET=\"/run/api-local-lb-admin.sock\"\n")
	b.WriteString("API_LB_BACKEND=\"api_local_back\"\n")
	fmt.Fprintf(&b, "SIG14_LB_MODE=\"%s\"\n", defStr(c.v("apiserver_lb_guard_mode"), "off"))
	fmt.Fprintf(&b, "APISERVER_RECOVER_CYCLES=\"%s\"\n", defStr(c.v("apiserver_lb_recover_cycles"), "3"))
	if t.AmLighthouse {
		var peers []string
		for _, l := range t.Lighthouses {
			if l.Name != t.MeshName {
				peers = append(peers, l.IP)
			}
		}
		peer := ""
		if len(peers) > 0 {
			peer = peers[0] + ":6443"
		}
		fmt.Fprintf(&b, "SIG13_AUTOFIX=\"%s\"\n", defStr(c.v("sig13_autofix"), "off"))
		fmt.Fprintf(&b, "SIG13_MIN_RESTART_S=\"%s\"\n", defStr(c.v("sig13_min_restart_s"), "7200"))
		fmt.Fprintf(&b, "APISERVER_SOLO_CYCLES=\"%s\"\n", defStr(c.v("apiserver_wedge_solo_cycles"), "8"))
		fmt.Fprintf(&b, "APISERVER_FAST_PROBE_CYCLES=\"%s\"\n", defStr(c.v("apiserver_fast_probe_cycles"), "3"))
		fmt.Fprintf(&b, "APISERVER_FAST_SOLO_CYCLES=\"%s\"\n", defStr(c.v("apiserver_fast_solo_cycles"), "5"))
		fmt.Fprintf(&b, "APISERVER_STALE_MIN_ERRS=\"%s\"\n", defStr(c.v("apiserver_stale_min_errs"), "15"))
		fmt.Fprintf(&b, "API_SELF=\"%s:6443\"\n", nodeIPStr(t.Node, "ip"))
		fmt.Fprintf(&b, "API_PEER=\"%s\"\n", peer)
		fmt.Fprintf(&b, "KINE_DB_PROBE=\"%s\"\n", c.v("kine_db_probe"))
		fmt.Fprintf(&b, "KINE_POOL_AUTOFIX=\"%s\"\n", defStr(c.v("kine_pool_autofix"), "off"))
		fmt.Fprintf(&b, "KINE_POOL_MAX_CONNS=\"%s\"\n", defStr(c.v("kine_pool_max_conns"), "72"))
		fmt.Fprintf(&b, "KINE_POOL_CYCLES=\"%s\"\n", defStr(c.v("kine_pool_cycles"), "3"))
		fmt.Fprintf(&b, "KINE_POOL_MIN_RESTART_S=\"%s\"\n", defStr(c.v("kine_pool_min_restart_s"), "1200"))
		fmt.Fprintf(&b, "KINE_TTL_AUTOFIX=\"%s\"\n", defStr(c.v("kine_ttl_autofix"), "off"))
		fmt.Fprintf(&b, "KINE_TTL_MIN_RESTART_S=\"%s\"\n", defStr(c.v("kine_ttl_min_restart_s"), "1800"))
		fmt.Fprintf(&b, "KINE_TTL_REWEDGE_CYCLES=\"%s\"\n", defStr(c.v("kine_ttl_rewedge_cycles"), "2"))
		fmt.Fprintf(&b, "KINE_TTL_CTL_RESTART_S=\"%s\"\n", defStr(c.v("kine_ttl_ctl_restart_s"), "7200"))
		fmt.Fprintf(&b, "K0S_OOMLOOP_AUTOFIX=\"%s\"\n", defStr(c.v("k0s_oomloop_autofix"), "off"))
		fmt.Fprintf(&b, "K0S_OOMLOOP_MIN_KILLS=\"%s\"\n", defStr(c.v("k0s_oomloop_min_kills"), "3"))
		fmt.Fprintf(&b, "K0S_OOMLOOP_WINDOW_S=\"%s\"\n", defStr(c.v("k0s_oomloop_window_s"), "3600"))
	}
	r.writeManaged("/etc/node-watchdog.conf", []byte(b.String()), 0o644)

	// watchdog scripts mirror from CM mount (optional).
	if st, err := os.Stat(r.cfg.WatchdogScriptsDir); err == nil && st.IsDir() {
		c.installWatchdogScripts()
	}
	// The shell watchdog timer is retired on EVERY converged node —
	// independent of whether the scripts CM is mounted.
	c.retireShellWatchdog()
	// log file + textfile dir + units + installed marker + timer.
	if _, err := os.OpenFile(r.hp("/var/log/node-watchdog.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
	}
	r.ensureDir("/var/lib/node-exporter/textfile", 0o755)
	r.ensureDir("/var/lib/node-watchdog", 0o755)
	if !r.fileExists("/var/lib/node-watchdog/installed") {
		r.writeManaged("/var/lib/node-watchdog/installed",
			[]byte(fmt.Sprint(c.r.cfg.NowFn().Unix())), 0o644)
	}
	c.systemdWatchdog()
}

// apilbWatchdogVars resolves the watchdog's api-lb knobs the way
// defaults.yaml's jinja does — apiserver_probe_backends = addrs of
// backends whose name ends _ctrl, apiserver_lb_servers = "name=addr"
// for every backend, apiserver_lb_vip = name of the first *_lb
// backend. Explicit non-empty var resolutions win over derivation.
func (c *cyc) apilbWatchdogVars() (probeBackends []string, lbServers, lbVIP string) {
	probeBackends = c.vs("apiserver_probe_backends")
	lbServers = c.v("apiserver_lb_servers")
	lbVIP = c.v("apiserver_lb_vip")
	needPB := len(probeBackends) == 0
	needSrv := lbServers == "" || lbServers == "None"
	needVip := lbVIP == "" || lbVIP == "None"
	if !needPB && !needSrv && !needVip {
		return probeBackends, lbServers, lbVIP
	}
	var ctrl, srv []string
	vip := lbVIP
	for _, it := range c.vl("api_lb_backends") {
		m, _ := it.(*topology.OMap)
		if m == nil {
			continue
		}
		name, addr := strOf(m, "name"), strOf(m, "addr")
		if name == "" || addr == "" {
			continue
		}
		if needSrv {
			srv = append(srv, name+"="+addr)
		}
		if needPB && strings.HasSuffix(name, "_ctrl") {
			ctrl = append(ctrl, addr)
		}
		if needVip && vip == "" && strings.HasSuffix(name, "_lb") {
			vip = name
		}
	}
	if needPB {
		probeBackends = ctrl
	}
	if needSrv {
		lbServers = strings.Join(srv, " ")
	}
	lbVIP = vip
	return probeBackends, lbServers, lbVIP
}

func nodeIPStr(m *topology.OMap, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m.Get(key)
	s, _ := v.(string)
	return s
}

func defStr(v, d string) string {
	if v == "" || v == "None" {
		return d
	}
	return v
}

// installWatchdogScripts mirrors scripts/watchdog/{lib.sh,modules/*.sh}
// + scripts/*.sh from the CM dir onto the host, pruning stale modules.
func (c *cyc) installWatchdogScripts() {
	src := c.r.cfg.WatchdogScriptsDir
	dstLib := "/usr/local/lib/node-watchdog"
	c.r.ensureDir(dstLib+"/modules", 0o755)
	keep := map[string]bool{}
	copy := func(srcRel, dst string, mode os.FileMode) {
		b, err := os.ReadFile(src + "/" + srcRel)
		if err != nil {
			return
		}
		c.r.writeManaged(dst, b, mode)
	}
	copy("scripts/watchdog/lib.sh", dstLib+"/lib.sh", 0o644)
	entries, _ := os.ReadDir(src + "/scripts/watchdog/modules")
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sh") {
			continue
		}
		keep[e.Name()] = true
		copy("scripts/watchdog/modules/"+e.Name(), dstLib+"/modules/"+e.Name(), 0o755)
	}
	// prune host modules not in CM
	if he, err := os.ReadDir(c.r.hp(dstLib + "/modules")); err == nil {
		for _, e := range he {
			if !keep[e.Name()] {
				os.Remove(c.r.hp(dstLib + "/modules/" + e.Name()))
			}
		}
	}
	copy("scripts/node-watchdog.sh", "/usr/local/sbin/node-watchdog.sh", 0o755)
}

// retireShellWatchdog stops+disables the periodic shell watchdog and
// removes its units. Every module is a Go subsystem now — letting the
// timer run would double consecutive-* counters and race on
// /etc/hosts and ip rule with the agent's own converge.
func (c *cyc) retireShellWatchdog() {
	r, ctx := c.r, c.ctx
	r.run(ctx, "systemctl", "disable", "--now", "node-watchdog.timer")
	for _, p := range []string{
		"/etc/systemd/system/node-watchdog.timer",
		"/etc/systemd/system/node-watchdog.service",
		"/etc/systemd/system/node-watchdog-failed.service",
	} {
		if ch, _ := r.removeManaged(p); ch {
			r.daemonReload(ctx)
		}
	}
}

// systemdWatchdog ports T15 (worker feeder Option D) + the controller
// variant (memory guard, go memlimit, sshd CPUWeight, probes).
func (c *cyc) systemdWatchdog() {
	r, ctx := c.r, c.ctx
	inWorkerList := containsSS(c.vs("systemd_watchdog_hosts"), c.r.cfg.NodeName)
	inCtrlList := containsSS(c.vs("controller_systemd_watchdog_hosts"), c.r.cfg.NodeName)

	// always purge the dangerous legacy drop-in.
	if c.worker() {
		if ch, _ := r.removeManaged("/etc/systemd/system/k0sworker.service.d/40-watchdog.conf"); ch {
			r.daemonReload(ctx)
		}
	}
	if c.controller() {
		r.removeManaged("/etc/systemd/system/k0scontroller.service.d/40-watchdog.conf")
		// memory guard + go memlimit drop-ins (per-host maps).
		c.ctrlDropIn("k0scontroller_memory_max_by_host", "50-memory-guard.conf", func(v string) []byte {
			return []byte(`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
# cgroup OOM boundary cho k0scontroller (OOMPolicy=continue).
# MemorySwapMax=0: cam unit swap.
[Service]
MemoryMax=` + v + `
MemorySwapMax=0
OOMPolicy=continue
`)
		})
		c.ctrlDropIn("k0scontroller_go_memlimit_by_host", "51-go-memlimit.conf", func(v string) []byte {
			return []byte(`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
# GOMEMLIMIT soft-cap heap cua MOI Go child trong unit. GOGC=50.
[Service]
Environment=GOMEMLIMIT=` + v + `
Environment=GOGC=50
`)
		})
		// sshd CPUWeight=10000 (controller responsiveness under churn).
		for _, d := range []string{"ssh.service.d", "ssh@.service.d", "sshd.service.d"} {
			r.ensureDir("/etc/systemd/system/"+d, 0o755)
			if ch, _ := r.writeManaged("/etc/systemd/system/"+d+"/10-cpuweight.conf",
				[]byte(`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
# Giu sshd responsive khi control plane saturates CPU.
[Service]
CPUWeight=10000
`), 0o644); ch {
				r.daemonReload(ctx)
			}
		}
	}

	type wdUnit struct {
		svcName    string
		scriptDest string
		scriptSrc  string
		svc        string
		restartSvc string
		restartScr string
	}
	var units []wdUnit
	if c.worker() && inWorkerList {
		units = append(units, wdUnit{"k0sworker-watchdog", "/usr/local/sbin/k0s-kubelet-watchdog.sh",
			"scripts/k0s-kubelet-watchdog.sh",
			`# Managed by node-config-agent - T15 kubelet watchdog (Option D)
[Unit]
Description=kubelet watchdog feeder - restarts k0sworker when kubelet wedges
After=k0sworker.service
PartOf=k0sworker.service
OnFailure=k0sworker-watchdog-restart.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/k0s-kubelet-watchdog.sh
WatchdogSec=60s
NotifyAccess=main
Restart=always
RestartSec=10s
CPUWeight=500
TimeoutStartSec=2min

[Install]
WantedBy=multi-user.target
`, "/usr/local/sbin/k0sworker-remediate.sh",
			`# Managed by node-config-agent - T15 kubelet watchdog (Option D)
[Unit]
Description=remediate k0sworker after kubelet watchdog trigger

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/k0sworker-remediate.sh
TimeoutStartSec=2min
`})
	}
	if c.controller() && inCtrlList {
		units = append(units, wdUnit{"k0scontroller-watchdog", "/usr/local/sbin/k0s-systemd-watchdog-feeder.sh",
			"scripts/k0s-systemd-watchdog-feeder.sh",
			`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
[Unit]
Description=k0s controller watchdog feeder - restarts k0scontroller when apiserver wedges
After=k0scontroller.service
PartOf=k0scontroller.service
OnFailure=k0scontroller-watchdog-restart.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/k0s-systemd-watchdog-feeder.sh
WatchdogSec=60s
NotifyAccess=main
Restart=always
RestartSec=10s
CPUWeight=500
TimeoutStartSec=2min

[Install]
WantedBy=multi-user.target
`, "/usr/local/sbin/k0scontroller-remediate.sh",
			`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
[Unit]
Description=remediate k0scontroller after apiserver watchdog trigger

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/k0scontroller-remediate.sh
TimeoutStartSec=2min
`})
	}

	// reverse-converge: units on nodes NOT in list get removed.
	cleanup := func(name, script string) {
		r.run(ctx, "systemctl", "disable", "--now", name+".service")
		for _, p := range []string{"/etc/systemd/system/" + name + ".service",
			"/etc/systemd/system/" + name + "-restart.service", script} {
			r.removeManaged(p)
		}
	}
	if c.worker() && !inWorkerList {
		cleanup("k0sworker-watchdog", "/usr/local/sbin/k0s-kubelet-watchdog.sh")
		r.removeManaged("/usr/local/sbin/k0sworker-remediate.sh")
	}
	if c.controller() && !inCtrlList {
		cleanup("k0scontroller-watchdog", "/usr/local/sbin/k0s-systemd-watchdog-feeder.sh")
		r.removeManaged("/usr/local/sbin/k0scontroller-remediate.sh")
		// probe timers too
		for _, u := range []string{"k0s-apiserver-wedge-probe", "k0s-kine-pool-probe", "k0s-oomloop-probe"} {
			r.run(ctx, "systemctl", "disable", "--now", u+".timer", u+".service")
			r.removeManaged("/etc/systemd/system/" + u + ".service")
			r.removeManaged("/etc/systemd/system/" + u + ".timer")
			r.removeManaged("/usr/local/sbin/" + u + ".sh")
		}
	}

	changed := false
	for _, u := range units {
		b, err := os.ReadFile(r.cfg.WatchdogScriptsDir + "/" + u.scriptSrc)
		if err != nil {
			continue
		}
		if ch, _ := r.writeManaged(u.scriptDest, b, 0o755); ch {
			changed = true
		}
		remSrc := strings.Replace(u.scriptSrc, "k0s-kubelet-watchdog.sh", "k0sworker-remediate.sh", 1)
		remSrc = strings.Replace(remSrc, "k0s-systemd-watchdog-feeder.sh", "k0scontroller-remediate.sh", 1)
		if rb, err := os.ReadFile(r.cfg.WatchdogScriptsDir + "/" + remSrc); err == nil {
			if ch, _ := r.writeManaged(u.restartScr, rb, 0o755); ch {
				changed = true
			}
		}
		if ch, _ := r.writeManaged("/etc/systemd/system/"+u.svcName+".service", []byte(u.svc), 0o644); ch {
			changed = true
		}
		if ch, _ := r.writeManaged("/etc/systemd/system/"+u.svcName+"-restart.service", []byte(u.restartSvc), 0o644); ch {
			changed = true
		}
		r.daemonReload(ctx)
		r.run(ctx, "systemctl", "enable", "--now", u.svcName+".service")
		if changed {
			r.run(ctx, "systemctl", "restart", u.svcName+".service")
		}
	}

	// controller probe timers (fast wedge/kine pool/oomloop).
	if c.controller() && inCtrlList {
		for _, u := range []string{"k0s-apiserver-wedge-probe", "k0s-kine-pool-probe", "k0s-oomloop-probe"} {
			b, err := os.ReadFile(r.cfg.WatchdogScriptsDir + "/scripts/" + u + ".sh")
			if err != nil {
				continue
			}
			r.writeManaged("/usr/local/sbin/"+u+".sh", b, 0o755)
			timeout := "50s"
			if u == "k0s-oomloop-probe" {
				timeout = "30s"
			}
			r.writeManaged("/etc/systemd/system/"+u+".service", []byte(fmt.Sprintf(`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
[Unit]
Description=%s (60s cycle)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/%s.sh
TimeoutStartSec=%s
`, u, u, timeout)), 0o644)
			r.writeManaged("/etc/systemd/system/"+u+".timer", []byte(fmt.Sprintf(`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
[Unit]
Description=%s timer (60s)

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
RandomizedDelaySec=5

[Install]
WantedBy=timers.target
`, u)), 0o644)
			r.run(ctx, "systemctl", "enable", "--now", u+".timer")
		}
		r.daemonReload(ctx)
	}
}

func (c *cyc) ctrlDropIn(varName, file string, render func(string) []byte) {
	r := c.r
	path := "/etc/systemd/system/k0scontroller.service.d/" + file
	var val any
	if om, ok := c.t.Vars.Get(varName).(*topology.OMap); ok {
		val, _ = om.Get(c.r.cfg.NodeName)
	}
	if val == nil {
		if ch, _ := r.removeManaged(path); ch {
			r.daemonReload(c.ctx)
		}
		return
	}
	r.ensureDir("/etc/systemd/system/k0scontroller.service.d", 0o755)
	if ch, _ := r.writeManaged(path, render(fmt.Sprint(val)), 0o644); ch {
		r.daemonReload(c.ctx)
	}
}

func containsSS(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

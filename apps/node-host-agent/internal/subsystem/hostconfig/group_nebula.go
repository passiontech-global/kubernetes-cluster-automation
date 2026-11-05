// group_nebula.go — T5b nebula mesh: binary, certs, config, unit and
// the live ip rule/route/nft policy-routing converge.
package hostconfig

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/topology"
)

// ---------- T5b nebula mesh ----------

func (c *cyc) groupNebula() {
	r, ctx, t := c.r, c.ctx, c.t
	_ = ctx
	enabled := c.vb("interdc_nebula_enabled")
	net := c.v("interdc_nebula_net")
	if net == "" || net == "None" {
		net = "interdc"
	}
	// interdc_nebula_dev is resolved where it's consumed (tplCtx,
	// nebulaRouting) — no local resolution needed here.
	unit := "nebula@" + net + ".service"

	if !enabled || !t.Found {
		// disable path — ansible: stop+disable then sweep the
		// nebula-owned ip rules and flush BOTH policy tables. The
		// systemctl cleanup interpolates nothing, so it runs even
		// when a vars value would fail the charset gate below.
		_, _ = r.run(ctx, "systemctl", "disable", "--now", "nebula-route-guard.service")
		_, _ = r.run(ctx, "systemctl", "disable", "--now", unit)
		pub, mark := c.tablePub(), c.tableMark()
		// Vars land unquoted inside the sh -c below — charset-gate
		// before building the command (nebulaRouting does the same);
		// a refused value skips ONLY the interpolated sweep.
		if !(c.shToken("interdc_nebula_table_pub", pub) &&
			c.shToken("interdc_nebula_table_marker", mark) &&
			c.shMarkerBase("interdc_marker_base", c.markerBase())) {
			return
		}
		_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
			`ip rule list pref 1500 | sed -n "s/.*to \([0-9./]*\).*/\1/p" | while read -r d; do ip rule del pref 1500 to "$d" lookup %s 2>/dev/null; done; `+
				`ip rule del pref 1490 to %s.0/24 lookup %s 2>/dev/null; `+
				`ip route flush table %s 2>/dev/null; ip route flush table %s 2>/dev/null; `+
				`nft delete table ip nebnat 2>/dev/null; true`,
			pub, c.markerBase(), mark, pub, mark))
		return
	}
	// T5b: kernel TUN device required (ansible assert).
	if fi, err := os.Stat("/dev/net/tun"); err != nil {
		c.err("T5b: /dev/net/tun stat failed — modprobe tun before nebula",
			"error", err)
		return
	} else if fi.Mode()&os.ModeCharDevice == 0 {
		c.err("T5b: /dev/net/tun is not a char device — modprobe tun before nebula")
		return
	}
	c.nebulaInstallBinary()
	_ = c.r.ensureDir("/etc/nebula/"+net, 0o755)

	// certs from CM mounts (NebulaCertsDir, fallback VarsDir).
	certFile := func(name string) (string, bool) {
		for _, d := range []string{r.cfg.NebulaCertsDir, r.cfg.VarsDir} {
			p := filepath2(d, name)
			if _, err := os.Stat(p); err != nil {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				// An unreadable hit must NOT shadow the VarsDir
				// fallback — keep looking; if nothing reads, the
				// missing-cert error below counts the group.
				logger().Warn("T5b: cert file unreadable — trying fallback dir",
					"path", p, "error", err)
				continue
			}
			return string(b), true
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
		if _, err := r.run(ctx, "nebula-cert", "keygen", "-out-key", keyPath,
			"-out-pub", "/etc/nebula/"+net+"/host.pub"); err != nil {
			c.err("T5b: nebula-cert keygen failed — nebula will not start without a key",
				"key", keyPath, "error", err)
		}
	}
	if certOK {
		ch, _ := r.writeManaged("/etc/nebula/"+net+"/host.crt", []byte(hostCert), 0o644)
		certChanged = certChanged || ch
	} else {
		c.err("T5b: signed cert not in vars CM — nebula will not start",
			"cert", "nebula-"+t.MeshName+".crt")
	}

	// render config.yaml
	rendered, err := c.nebulaConfig()
	if err != nil {
		c.err("T5b: render nebula config", "error", err)
		return
	}
	oldCfg, _ := os.ReadFile(r.hp("/etc/nebula/" + net + "/config.yaml"))
	ch, _ := r.writeManaged("/etc/nebula/"+net+"/config.yaml", rendered, 0o644)
	cfgChanged = ch
	needRestart := cfgChanged && c.nebulaNeedsRestart(oldCfg, rendered)

	// overlay state file + hook scripts + units. The route-guard
	// script+unit are NOT rendered here anymore — the whole resident
	// watchdog stack is retired (pruneLegacyWatchdog sweeps it; the
	// agent's own converge heals rules/routes every cycle).
	_, _ = r.writeManaged("/etc/nebula/"+net+"/overlay", []byte(t.Overlay+"\n"), 0o644)
	tctx := c.tplCtx()
	for _, name := range []string{"nebula-up.sh", "nebula-down.sh"} {
		b, err := c.r.render(name+".j2", tctx)
		if err != nil {
			c.err("T5b render", "tpl", name, "error", err)
			continue
		}
		_, _ = r.writeManaged("/etc/nebula/"+net+"/"+name, b, 0o755)
	}
	uch, _ := r.writeManaged("/etc/systemd/system/"+unit,
		[]byte(`# Managed by node-config-agent
[Unit]
Description=Nebula overlay network (%i)
Wants=network-online.target
After=network-online.target
# Marker IP (k8s --node-ip) lives on neb1 — k0sworker waits for the
# addr via the T8 drop-in. Nebula must come up BEFORE k0sworker.
Before=k0sworker.service

[Service]
Type=notify
ExecStart=/usr/local/bin/nebula -config /etc/nebula/%i/config.yaml
# ExecReload=SIGHUP: nebula >=1.9 hot-reloads pki creds,
# lighthouse.*, firewall, punchy, tun.unsafe_routes, logging,
# preferred_ranges — tunnels do not drop.
ExecReload=/bin/kill -HUP $MAINPID
ExecStartPost=/etc/nebula/%i/nebula-up.sh
ExecStopPost=/etc/nebula/%i/nebula-down.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`), 0o644)
	if uch {
		r.daemonReload(ctx)
	}

	if !certOK {
		return
	}
	wasActive := r.isActive(ctx, unit)
	// ansible: `nebula -test` validates before start — failure aborts,
	// so the broken config must not reach a (re)start.
	if out, err := r.run(ctx, "nebula", "-config", "/etc/nebula/"+net+"/config.yaml", "-test"); err != nil {
		c.err("T5b: nebula -test failed — not starting/reloading",
			"config", "/etc/nebula/"+net+"/config.yaml", "unit", unit,
			"out", out, "error", err)
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

	// policy routing converge (live, no daemon restart needed).
	c.nebulaRouting()
}

// nebulaInstallBinary ports the version-check + tarball install path.
func (c *cyc) nebulaInstallBinary() {
	r, ctx := c.r, c.ctx
	ver := c.v("interdc_nebula_version")
	if ver == "" || ver == "None" {
		// An empty pin is NOT a match — strings.Contains(out, "") is
		// vacuously true (would pin any installed version forever)
		// and download("") is a counted bogus fetch. Not pinned =
		// not installed.
		c.err("T5b: interdc_nebula_version not pinned — nebula not installed")
		return
	}
	if out, err := r.run(ctx, "/usr/local/bin/nebula", "-version"); err == nil &&
		strings.Contains(out, ver) {
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
			c.err("T5b: staged nebula tarball sha256 mismatch — not installing",
				"file", local, "sha256", sum)
			return
		}
	} else if err := r.download(ctx, url, local, sum); err != nil {
		c.err("T5b: nebula tarball download", "url", url, "file", local, "error", err)
		return
	}
	if err := untarInstall(local, "nebula", r.hp("/usr/local/bin/nebula"), 0o755); err != nil {
		c.err("T5b: nebula install", "file", local, "error", err)
		return
	}
	if err := untarInstall(local, "nebula-cert", r.hp("/usr/local/bin/nebula-cert"), 0o755); err != nil {
		// Best-effort companion binary — the nebula binary itself is
		// installed above; a missing key only errors when keygen is
		// actually needed (counted at the keygen call site).
		logger().Warn("T5b: nebula-cert install failed — keygen unavailable",
			"file", local, "error", err)
	}
}

// nebulaConfig renders nebula.yaml.j2 via the shared ctx.
func (c *cyc) nebulaConfig() ([]byte, error) {
	return c.r.render("nebula.yaml.j2", c.tplCtx())
}

// nebulaNeedsRestart ports the reloadable-vs-restart key diff:
// SIGHUP covers pki creds content, lighthouse.hosts/allow lists,
// firewall, punchy, tun.unsafe_routes, logging, preferred_ranges.
// Non-reloadable: static_host_map, routines, cipher, stats, relay,
// handshakes, listen, pki PATHS, lighthouse.am_lighthouse, tun minus
// unsafe_routes.
func (c *cyc) nebulaNeedsRestart(old, new []byte) bool {
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
	return fmt.Sprint(ot) != fmt.Sprint(nt)
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

// hairpinViaRe extracts the first `via <ipv4>` next-hop from
// `ip -o route get` output.
var hairpinViaRe = regexp.MustCompile(`\bvia\s+([0-9.]+)`)

// nebulaDirectTCPPorts is the pref-1499 Direct-Underlay TCP bypass
// list (nebula_direct_tcp_ports var; default the management/CP
// ports). Only numeric 1-65535 entries survive — they land inside
// `ip rule` shell strings below.
func (c *cyc) nebulaDirectTCPPorts() []string {
	ports := c.vs("nebula_direct_tcp_ports")
	if len(ports) == 0 {
		ports = []string{"22", "6443", "8132", "9443", "39901"}
	}
	var out []string
	for _, p := range ports {
		if c.shPort("nebula_direct_tcp_ports", p) {
			out = append(out, p)
		}
	}
	return out
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
			if om, ok := nv.(*topology.OMap); ok {
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

	// fwmark for transport
	for _, p := range []string{"dport", "sport"} {
		for _, chain := range []string{"OUTPUT", "PREROUTING"} {
			_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
				"iptables -t mangle -C %s -p udp --%s %s -j MARK --set-mark 0x1000 2>/dev/null || "+
					"iptables -t mangle -A %s -p udp --%s %s -j MARK --set-mark 0x1000",
				chain, p, port(c), chain, p, port(c)))
		}
	}
	_, _ = r.run(ctx, "sh", "-c", `ip rule list | grep -q "fwmark 0x1000" || ip rule add pref 1400 fwmark 0x1000 lookup main`)

	// Populate overlay tables ALWAYS (warm standby even when
	// overlay=tinc). pub table src = public ip; marker table src =
	// NODE_IP only when it is a marker-base IP, else flush.
	_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
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
			_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
				`for t in $(ip rule list pref 1500 | sed -n "s|.*to %s .*lookup \([0-9]*\).*|\1|p"); do [ "$t" = %s ] || ip rule del pref 1500 to %s lookup "$t" 2>/dev/null; done`,
				d, pub, d))
		}
		for _, d := range append(append([]string{}, t.Targets...), mb+".0/24") {
			_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
				`ip rule list | grep -q "to %s lookup %s" || ip rule add pref 1500 to %s lookup %s`, d, pub, d, pub))
		}
		for _, d := range t.EgressRelays {
			_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
				`[ "$(cat /var/lib/node-watchdog/egress-state-%s 2>/dev/null)" = relay ] && { ip rule list | grep -q "to %s lookup %s" || ip rule add pref 1500 to %s lookup %s; }; true`,
				d, d, pub, d, pub))
		}
		_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
			`for t in $(ip rule list pref 1490 | sed -n "s|.*to %s\.0/24 .*lookup \([0-9]*\).*|\1|p"); do [ "$t" = %s ] || ip rule del pref 1490 to %s.0/24 lookup "$t" 2>/dev/null; done`,
			mb, mark, mb))
		if strings.HasPrefix(nodeIPV, mb+".") {
			_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
				`ip rule list | grep -q "to %s.0/24 lookup %s" || ip rule add pref 1490 to %s.0/24 lookup %s`,
				mb, mark, mb, mark))
		} else {
			_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
				`ip rule del pref 1490 to %s.0/24 lookup %s 2>/dev/null || true`, mb, mark))
		}
		// pref-1499 Direct-Underlay TCP bypass: management/CP TCP
		// dports must never be sucked into the tunnel — rule them
		// into the main table (nethealth re-adds lost ones).
		for _, p := range c.nebulaDirectTCPPorts() {
			_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
				`ip rule list pref 1499 | grep -q "ipproto tcp dport %s " || ip rule add pref 1499 ipproto tcp dport %s lookup main`,
				p, p))
		}
		// flush foreign dev tables (stale nebula-era tables).
		_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
			`ip -o route show table all dev %s 2>/dev/null | sed -n "s|.* table \([0-9]*\) .*|\1|p" | sort -u | while read -r t; do [ "$t" = "%s" ] || [ "$t" = "%s" ] || ip route flush table "$t" 2>/dev/null; done`,
			dev, pub, mark))
	} else {
		// overlay=tinc: pref-1499 bypass rules go too.
		for _, p := range c.nebulaDirectTCPPorts() {
			_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
				`ip rule del pref 1499 ipproto tcp dport %s lookup main 2>/dev/null || true`, p))
		}
		// overlay=tinc rollback: drop nebula-owned rules.
		_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(
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
	_, _ = r.run(ctx, "sh", "-c", sb.String()+"\ntrue")
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

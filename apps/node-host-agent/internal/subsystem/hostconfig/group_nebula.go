// group_nebula.go — T5b nebula mesh: binary, certs, config, unit and
// the live ip rule/route/nft policy-routing converge.
package hostconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
)

// ---------- T5b nebula mesh ----------

func (c *cyc) groupNebula() {
	r, ctx, t := c.r, c.ctx, c.t
	_ = ctx
	enabled := c.vb("interdc_nebula_enabled")
	net := c.t.Vars.StrDef("interdc_nebula_net", "interdc")
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
	binChanged := c.nebulaInstallBinary()
	_ = c.r.ensureDir("/etc/nebula/"+net, 0o755)

	// certs from CM mounts (NebulaCertsDir, fallback VarsDir).
	certFile := func(name string) (string, bool) {
		for _, d := range []string{r.cfg.NebulaCertsDir, r.cfg.VarsDir} {
			p := filepath.Join(d, name)
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
	if wasActive && (certChanged || cfgChanged || binChanged) {
		r.daemonReload(ctx)
		if needRestart || binChanged {
			// A swapped binary only takes effect on exec — SIGHUP
			// reloads config inside the OLD image, so a version-pin
			// install must force a real restart even when the
			// rendered config diff says reload suffices.
			r.restartService(ctx, unit)
		} else {
			r.reloadService(ctx, unit)
		}
	}

	// policy routing converge (live, no daemon restart needed).
	c.nebulaRouting()
}

// nebulaInstallBinary ports the version-check + tarball install path
// through installManagedBinary: <bin> -version probe → sha256-pinned
// tarball (staged or downloaded) → untarInstall of nebula plus the
// best-effort nebula-cert companion (tmp+rename). Returns true when
// the nebula binary file was actually replaced this cycle — the
// caller folds it into the service restart decision (a running
// daemon keeps the OLD image until exec; cert/config diffs alone
// never noticed a pure version bump).
func (c *cyc) nebulaInstallBinary() bool {
	ver := c.t.Vars.StrDef("interdc_nebula_version", "")
	if ver == "" {
		// An empty pin is NOT a match — strings.Contains(out, "") is
		// vacuously true (would pin any installed version forever)
		// and download("") is a counted bogus fetch. Not pinned =
		// not installed.
		c.err("T5b: interdc_nebula_version not pinned — nebula not installed")
		return false
	}
	tgzFile := c.v("interdc_nebula_tgz_file")
	sum := c.v("interdc_nebula_tgz_sha256")
	url := c.v("interdc_nebula_tgz_url")
	installed := false
	c.installManagedBinary(managedBinarySpec{
		name:     "T5b",
		artifact: "nebula tarball",
		probe: func(c *cyc) bool {
			out, err := c.r.run(c.ctx, "/usr/local/bin/nebula", "-version")
			return err == nil && strings.Contains(out, ver)
		},
		url:    url,
		sum:    sum,
		staged: filepath.Join(c.r.cfg.DownloadDir, tgzFile),
		// ansible: sha256sum -c on the STAGED file every run — a
		// corrupted/operator-swapped tarball must not install.
		refuseBadStaged: true,
		downloadLine:    "T5b: nebula tarball download",
		member:          "nebula",
		dest:            "/usr/local/bin/nebula",
		mode:            0o755,
		installErr: func(c *cyc, local string, err error) {
			c.err("T5b: nebula install", "file", local, "error", err)
		},
		companionMember:   "nebula-cert",
		companionDest:     "/usr/local/bin/nebula-cert",
		companionFailLine: "T5b: nebula-cert install failed — keygen unavailable",
		onInstalled: func(c *cyc, _ string) {
			installed = true
		},
	})
	return installed
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
	oldV, err1 := jinja.DecodeYAML(old)
	newV, err2 := jinja.DecodeYAML(new)
	if err1 != nil || err2 != nil {
		return true // unparseable → restart (safe default)
	}
	diff := func(key string) bool {
		a, _ := oldV.(*jinja.OMap)
		b, _ := newV.(*jinja.OMap)
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
			om, _ := cur.(*jinja.OMap)
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
		if om, ok := root.(*jinja.OMap); ok {
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
	return c.t.Vars.StrDef("interdc_nebula_table_pub", "100")
}

func (c *cyc) tableMark() string {
	return c.t.Vars.StrDef("interdc_nebula_table_marker", "101")
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
				"iptables -t mangle -C %s -p udp --%s %s -j MARK --set-mark 0x1000 2>/dev/null || "+
					"iptables -t mangle -A %s -p udp --%s %s -j MARK --set-mark 0x1000\n",
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
					`iptables -t mangle -C %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || `+
					`iptables -t mangle -A %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; fi`+"\n",
				dev, chain, dev, chain, dev)
		}
		// liqo interfaces are numbered (liqo-*, liqo0, …) — probe the
		// class dir with the glob instead of a wildcard dev name, then
		// match traffic with the iptables `liqo+` pattern.
		fmt.Fprintf(&rs,
			`ls /sys/class/net | grep -q '^liqo' && { `+
				`iptables -t mangle -C %s -o liqo+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || `+
				`iptables -t mangle -A %s -o liqo+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; }; true`+"\n",
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

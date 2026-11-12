// group_nebula.go — T5b nebula mesh: binary, certs, config, unit and
// the live ip rule/route/nft policy-routing converge.
package hostconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
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
	// T5b: kernel TUN device required (ansible assert) — stat through
	// HostRoot: the pod's own /dev/net/tun says nothing about the
	// host kernel module the nebula daemon actually needs.
	if fi, err := os.Stat(r.hp("/dev/net/tun")); err != nil {
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
	// binStale catches skew onInstalled cannot see: a binary written
	// by an earlier converge that never restarted the unit
	// (pre-onInstalled builds installed nebula 1.12.0 while the
	// daemon kept running 1.11.2). Only probed while the unit was
	// already active — a fresh start execs the on-disk binary anyway.
	binStale := wasActive && c.binaryNewerThanService("/usr/local/bin/nebula", unit)
	if wasActive && (certChanged || cfgChanged || binChanged || binStale) {
		r.daemonReload(ctx)
		if needRestart || binChanged || binStale {
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

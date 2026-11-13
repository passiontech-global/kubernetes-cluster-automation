// group_apilb.go — T12 api-local-lb: pinned haproxy deb install,
// candidate-staged cfg + root-netns DNAT ruleset, dedicated unit and
// the gated /etc/hosts cp_endpoint pin.
package hostconfig

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// ---------- T12 api-local-lb ----------

func (c *cyc) groupAPILB() {
	r, ctx := c.r, c.ctx
	if !c.worker() {
		return // T12 block is gated on k0sworker_unit existing
	}
	if !c.vb("api_lb_enabled") {
		// rollback: unpin (BOTH marker styles) + stop/disable; cfg/unit
		// files stay on disk for re-enable (ansible parity).
		_, _ = r.run(ctx, "systemctl", "disable", "--now", "api-local-lb.service")
		c.unpinHosts()
		return
	}
	// preflight: kubelet.conf server host should be cp_endpoint,
	// else the hosts pin does not affect this node's kubelet (warn
	// only — node may legitimately use a static IP).
	if kb, err := os.ReadFile(r.hp("/var/lib/k0s/kubelet.conf")); err == nil {
		re := regexp.MustCompile(`server:\s*https://([^:/\s]+)`)
		if m := re.FindSubmatch(kb); m != nil && string(m[1]) != c.v("cp_endpoint") {
			logger().Warn("T12: kubelet.conf server host != cp_endpoint — pin has no effect on kubelet",
				"host", string(m[1]), "cp_endpoint", c.v("cp_endpoint"))
		}
	} else {
		// Best-effort preflight — a static-IP kubelet is legitimate;
		// the pin checks below are the group's real signal.
		logger().Warn("T12: kubelet.conf unreadable — skipping server-URL check",
			"path", "/var/lib/k0s/kubelet.conf", "error", err)
	}
	tctx := c.tplCtx() // includes api_lb_probe_reachable (names)
	cfg, err := r.render("api-local-lb.haproxy.cfg.j2", tctx)
	if err != nil {
		c.err("T12 render", "error", err)
		return
	}
	// haproxy install only when missing or OLDER than the pinned
	// version — a NEWER host haproxy (unattended-upgrades/security
	// pocket) already satisfies the pin, and apt refuses the
	// downgrade anyway (exit-100 ERROR loop, incident
	// 2026-11-05 lanit-cloud-worker-nonprod-05: installed
	// 2.8.30-0ubuntu0.24.04.2 vs pin 2.8.16-0ubuntu0.24.04.3).
	// dpkg --compare-versions does the Debian-version compare on
	// the host; a missing/malformed compare falls back to
	// installing (same as the old mismatch path).
	out, _ := r.run(ctx, "dpkg-query", "-W", "-f=${Status} ${Version}", "haproxy")
	ver := c.v("api_lb_haproxy_version")
	needDeb := !strings.Contains(out, "install ok installed")
	if !needDeb && ver != "" {
		f := strings.Fields(out)
		if len(f) < 4 {
			needDeb = true
		} else if _, err := r.run(ctx, "dpkg", "--compare-versions",
			f[len(f)-1], "ge", ver); err != nil {
			needDeb = true
		}
	}
	if needDeb {
		// The deb must live on a host-visible path: download() writes
		// in the container mount ns while apt-get runs via nsenter in
		// the host's — /tmp/hostconfig doesn't exist there. The
		// watchdog state dir is mounted rw in the DS and already
		// ensured by groupWatchdog; on standalone hp() is identity.
		debFile := c.v("api_lb_haproxy_deb_file")
		hostDeb := "/var/lib/node-watchdog/" + debFile
		local := r.hp(hostDeb)
		_ = r.ensureDir("/var/lib/node-watchdog", 0o755)
		sum := c.v("api_lb_haproxy_deb_sha256")
		url := c.v("api_lb_haproxy_deb_url")
		// dpkg probe already decided needDeb above — the spec's flow
		// only owns stage/download/install here. A failed download
		// aborts the whole group (no haproxy config converge against
		// a missing binary).
		if _, ok := c.installManagedBinary(managedBinarySpec{
			name:   "T12",
			url:    url,
			sum:    sum,
			staged: local,
			downloadErr: func(c *cyc, err error) {
				c.err("T12: haproxy deb download",
					"url", url, "deb", hostDeb, "error", err)
			},
			install: func(c *cyc, _ string) error {
				// runLong: dep resolution on slow egress outlives the
				// interactive budget.
				_, err := c.r.runLong(c.ctx, "env", "DEBIAN_FRONTEND=noninteractive",
					"apt-get", "install", "-y", hostDeb)
				return err
			},
			installErr: func(c *cyc, _ string, err error) {
				c.err("T12: haproxy deb install failed — api-local-lb setup skipped",
					"deb", hostDeb, "error", err)
			},
		}); !ok {
			return
		}
	}
	// distro haproxy.service ships /etc/haproxy/haproxy.cfg (:80
	// frontend) — A1 runs a dedicated unit; keep the distro one off.
	_, _ = r.run(ctx, "systemctl", "disable", "--now", "haproxy.service")
	_ = r.ensureDir("/etc/haproxy", 0o755)
	// Candidate-staged validate-then-promote (applyNftUnit parity):
	// haproxy -c runs on the CANDIDATE — a bad render never sits at
	// the live path where ExecStart loads it on next start.
	cfgChanged, ok := c.checkedDeploy("/etc/haproxy/api-local-lb.cfg", cfg, 0o644,
		"T12: haproxy -c failed — not starting/restarting api-local-lb",
		"/usr/sbin/haproxy", "-c", "-f")
	if !ok {
		return
	}
	// Root-netns DNAT (pod host-netns consumers). FAIL-OPEN via
	// api-local-lb.service ExecStartPost/ExecStopPost hooks in the
	// unit template — the table dies with the LB.
	nftChanged := false
	if vip := c.t.Vars.StrDef("api_lb_vip_ip", ""); vip != "" {
		// The ruleset interpolates vip + ports verbatim — a control
		// byte or non-numeric port would splice arbitrary nft syntax
		// (and the DNAT ships with the LB unit, so a poisoned render
		// would load at every ExecStartPost). Refuse → the group
		// stops this cycle, nothing deploys.
		if !c.shIPCIDR("api_lb_vip_ip", vip) {
			return
		}
		ports := c.apiLBDnatPorts()
		for _, p := range ports {
			if !c.shPort("api_lb_extra_lanes dnat port", p) {
				return
			}
		}
		// runLong: same slow-egress budget as the haproxy deb —
		// and only when nftables isn't already installed (the
		// dpkg-query gate keeps converge from forking apt every
		// cycle).
		if !c.dpkgInstalled(ctx, "nftables") {
			if _, err := r.runLong(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
				"apt-get", "install", "-y", "nftables"); err != nil {
				c.err("T12: nftables install failed — nft -c may fail below",
					"error", err)
			}
		}
		var rules strings.Builder
		for _, p := range ports {
			fmt.Fprintf(&rules, "        ip daddr %s tcp dport %s dnat to 127.0.0.1:%s\n", vip, p, p)
		}
		nft := fmt.Sprintf(`# Managed by node-config-agent - root-netns DNAT %s -> 127.0.0.1
# (T12: :6443 + every port in api_lb_extra_lanes, Phase 1.3/2).
# Loaded/removed by api-local-lb.service.
# skuid exempt: "haproxy" = the LB's own outbound backend conns (anti-
# loop); 65534 = nobody — konnectivity-agent/pod host-netns run as
# this uid and must go straight through the VIP to the real backend,
# not dnat to loopback.
destroy table ip api_local_dnat
table ip api_local_dnat {
    chain output {
        type nat hook output priority dstnat; policy accept;
        meta skuid "haproxy" accept
        meta skuid 65534 accept
%s    }
}
`, vip, rules.String())
		// Same candidate-staged deploy as the cfg — nft -c runs on
		// the candidate; a bad ruleset never reaches the path
		// ExecStartPost loads.
		nch, ok := c.checkedDeploy("/etc/api-local-dnat.nft", []byte(nft), 0o644,
			"T12: nft ruleset failed nft -c — DNAT not applied",
			"nft", "-c", "-f")
		if !ok {
			return
		}
		nftChanged = nch
	}
	// sweep the invented separate-unit deployment of the first port.
	_, _ = r.run(ctx, "systemctl", "disable", "--now", "api-lb-dnat.service")
	_, _ = r.removeManaged("/etc/systemd/system/api-lb-dnat.service")
	_, _ = r.removeManaged("/etc/nftables.d/api-lb-dnat.nft")
	unit, err := r.render("api-local-lb.service.j2", tctx)
	if err != nil {
		c.err("T12 unit render", "error", err)
		return
	}
	uch, _ := r.writeManaged("/etc/systemd/system/api-local-lb.service", unit, 0o644)
	if uch {
		r.daemonReload(ctx)
	}
	r.ensureService(ctx, "api-local-lb.service", true, true)
	// Unit drift restarts too — daemon-reload alone leaves haproxy
	// running the OLD unit definition (kine.service parity).
	if cfgChanged || nftChanged || uch {
		r.restartService(ctx, "api-local-lb.service")
	}
	// Gate: LB must accept on 127.0.0.1:6443 before /etc/hosts pin —
	// pinning against a dead LB kills the node's API path entirely.
	probe := `timeout 15 bash -c 'until timeout 1 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/6443" 2>/dev/null; do sleep 0.3; done'`
	if _, err := r.run(ctx, "sh", "-c", probe); err != nil {
		c.err("T12: 127.0.0.1:6443 not serving in 15s — /etc/hosts NOT pinned", "error", err)
		return
	}
	c.pinHosts()
}

// apiLBExtraLanes — the {name, port} entries of api_lb_extra_lanes
// (Phase 2: extra local proxy lanes, e.g. konnectivity :8132 and
// k0sjoin :9443). Entries missing name or port are skipped.
func (c *cyc) apiLBExtraLanes() [][2]string {
	var out [][2]string
	for _, it := range c.vl("api_lb_extra_lanes") {
		m, _ := it.(*jinja.OMap)
		if m == nil {
			continue
		}
		n, p := m.Str("name"), m.Str("port")
		if n == "" || p == "" {
			continue
		}
		out = append(out, [2]string{n, p})
	}
	return out
}

// apiLBDnatPorts — the VIP dports redirected to 127.0.0.1: the main
// :6443 lane plus every api_lb_extra_lanes port (deduped).
func (c *cyc) apiLBDnatPorts() []string {
	ports := []string{"6443"}
	for _, lane := range c.apiLBExtraLanes() {
		if !slices.Contains(ports, lane[1]) {
			ports = append(ports, lane[1])
		}
	}
	return ports
}

// probeReachable — TCP-connect preflight for `probe: true` backends;
// collects backend NAMES (template filters on item.name).
func (c *cyc) probeReachable() []string {
	var out []string
	for _, it := range c.vl("api_lb_backends") {
		m, _ := it.(*jinja.OMap)
		if m == nil {
			continue
		}
		pb, _ := m.Get("probe")
		if bv, ok := pb.(bool); !ok || !bv {
			continue
		}
		addr, _ := m.Get("addr")
		name, _ := m.Get("name")
		as, _ := addr.(string)
		ns, _ := name.(string)
		if as == "" || ns == "" {
			continue
		}
		// net.SplitHostPort handles bracketed IPv6 ([::1]:6443) —
		// a first-colon Cut would mangle it. When SplitHostPort
		// errors (bare host, missing port) keep the first-colon cut
		// the probe always used.
		host, port, err := net.SplitHostPort(as)
		if err != nil {
			host, port, _ = strings.Cut(as, ":")
		}
		if port == "" {
			port = "6443"
		}
		// host/port land inside the single-quoted bash -c argument —
		// gate them so a vars typo can never inject shell (a quote in
		// host would close the '...' wrapper).
		if !c.shToken("api_lb_backends addr host", host) ||
			!c.shPort("api_lb_backends addr port", port) {
			continue
		}
		// ansible: timeout 5 bash -c 'cat < /dev/null > /dev/tcp/h/p'
		// — /dev/tcp is a bashism; sh/dash has no such device.
		cmd := fmt.Sprintf("timeout 5 bash -c 'cat < /dev/null > /dev/tcp/%s/%s'", host, port)
		if _, err := c.r.run(c.ctx, "sh", "-c", cmd); err == nil {
			out = append(out, ns)
		}
	}
	return out
}

// group_watchdog.go — T6 node-watchdog.conf converge (+ T15 systemd
// watchdog), the retired shell-stack prune and controller tuning drop-ins.
package hostconfig

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
)

// ---------- T6 watchdog (+ T15 systemd watchdog) ----------

func (c *cyc) groupWatchdog() {
	r, ctx, t := c.r, c.ctx, c.t
	_ = ctx
	// The retired shell watchdog stack is pruned on EVERY node class —
	// infra VMs off-registry carried kine-db-*/api-backend-guard units
	// too, so gating on worker()/Found would never sweep them.
	c.pruneLegacyWatchdog()
	if !c.worker() && !t.Found {
		return
	}
	// conf — worker variant (hub adds SIG13 block when hub:true).
	var b strings.Builder
	b.WriteString(`# Managed by node-config-agent - node-watchdog sig5 probe
# targets: public IP remote (table 100) + tunnel marker IP
# remote (table 101 = pod-traffic path through the mesh);
# OVERLAY_EGRESS_RELAYS: fallback relay IPs (relay_mode=fallback)
# this node consumes — watchdog toggles ip rule based on the
# direct-underlay probe.
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
	_, _ = r.writeManaged("/etc/node-watchdog.conf", []byte(b.String()), 0o644)

	// log file + textfile dir + state dir + installed marker — still
	// converged: nethealth latches state-*/egress-state-* files in the
	// state dir and hostmetrics/node-exporter read them (the conf +
	// routes/state files stay; only the shell stack dies).
	if f, err := os.OpenFile(r.hp("/var/log/node-watchdog.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		_ = f.Close()
	} else {
		// Best-effort compat file — the Go subsystems write state
		// latches, not this log; a create failure is not counted.
		logger().Warn("watchdog: cannot create log file — state consumers may miss it",
			"path", "/var/log/node-watchdog.log", "error", err)
	}
	_ = r.ensureDir("/var/lib/node-exporter/textfile", 0o755)
	_ = r.ensureDir("/var/lib/node-watchdog", 0o755)
	if !r.fileExists("/var/lib/node-watchdog/installed") {
		_, _ = r.writeManaged("/var/lib/node-watchdog/installed",
			[]byte(strconv.FormatInt(c.r.cfg.Clock.Now().Unix(), 10)), 0o644)
	}
	c.controllerTuning()
}

// apilbWatchdogVars resolves the watchdog's api-lb knobs the way
// defaults.yaml's jinja does — apiserver_probe_backends = addrs of
// backends whose name ends _ctrl, apiserver_lb_servers = "name=addr"
// for every backend, apiserver_lb_vip = name of the first *_lb
// backend. Explicit non-empty var resolutions win over derivation.
func (c *cyc) apilbWatchdogVars() (probeBackends []string, lbServers, lbVIP string) {
	probeBackends = strListVar(c, "apiserver_probe_backends")
	lbServers = c.v("apiserver_lb_servers")
	lbVIP = c.v("apiserver_lb_vip")
	needPB := len(probeBackends) == 0
	needSrv := c.t.Vars.StrDef("apiserver_lb_servers", "") == ""
	needVip := c.t.Vars.StrDef("apiserver_lb_vip", "") == ""
	if !needPB && !needSrv && !needVip {
		return probeBackends, lbServers, lbVIP
	}
	var ctrl, srv []string
	vip := lbVIP
	for _, it := range c.vl("api_lb_backends") {
		m, _ := it.(*jinja.OMap)
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

// strListVar reads a list-ish var safely: a real YAML list returns
// its elements, but a jinja scalar that rendered to a STRING must not
// go through Vars.List — toIter iterates strings rune-by-rune,
// spraying "a b c" into single chars (the API_BACKENDS char bug).
// String scalars split on whitespace (also strips []'"" repr chars).
func strListVar(c *cyc, name string) []string {
	if l := c.vl(name); len(l) > 0 {
		var out []string
		garbage := false
		for _, it := range l {
			s, _ := it.(string)
			out = append(out, s)
			if len(s) <= 1 {
				garbage = true
			}
		}
		if !garbage {
			return out
		}
		logger().Debug("watchdog: var list looked char-split — reparsing as scalar",
			"var", name)
	}
	raw := c.t.Vars.StrDef(name, "")
	if raw == "" {
		return nil
	}
	return strings.FieldsFunc(strings.Trim(raw, `[]'"`),
		func(r rune) bool { return r == ' ' || r == ',' || r == '\'' || r == '"' || r == '[' || r == ']' })
}

// legacyWatchdogUnits — retired shell-watchdog units, stopped+disabled
// before their unit FILES are removed. Includes the first Go port's
// *-restart OnFailure units and both node-watchdog-failed spellings
// (ansible-installed plain name, spec's @-template name).
var legacyWatchdogUnits = []string{
	"node-watchdog.timer",
	"node-watchdog.service",
	"node-watchdog-failed.service",
	"node-watchdog-failed@.service",
	"k0sworker-watchdog.service",
	"k0sworker-watchdog-restart.service",
	"k0scontroller-watchdog.service",
	"k0scontroller-watchdog-restart.service",
	"k0s-apiserver-wedge-probe.timer",
	"k0s-apiserver-wedge-probe.service",
	"k0s-kine-pool-probe.timer",
	"k0s-kine-pool-probe.service",
	"k0s-oomloop-probe.timer",
	"k0s-oomloop-probe.service",
	"nebula-route-guard.service",
	"api-backend-guard.timer",
	"api-backend-guard.service",
	"kine-db-probe.timer",
	"kine-db-probe.service",
	"kine-compact-guard.timer",
	"kine-compact-guard.service",
	"kine-db-maint.timer",
	"kine-db-maint.service",
}

// legacyWatchdogDropins — k0s drop-ins of the dead WatchdogSec design
// (10-watchdog.conf is the ansible-era name, 40-watchdog.conf the
// restart-loop variant this port already purged).
var legacyWatchdogDropins = []string{
	"/etc/systemd/system/k0sworker.service.d/10-watchdog.conf",
	"/etc/systemd/system/k0sworker.service.d/40-watchdog.conf",
	"/etc/systemd/system/k0scontroller.service.d/10-watchdog.conf",
	"/etc/systemd/system/k0scontroller.service.d/40-watchdog.conf",
}

// legacyWatchdogScripts — every shell script the stack dropped in
// /usr/local/sbin (worker feeder/remediate, controller feeder/
// remediate/probes, infra-VM kine guards, api-backend-guard, and the
// route guard this port used to render).
var legacyWatchdogScripts = []string{
	"/usr/local/sbin/node-watchdog.sh",
	"/usr/local/sbin/k0s-kubelet-watchdog.sh",
	"/usr/local/sbin/k0sworker-remediate.sh",
	"/usr/local/sbin/k0s-systemd-watchdog-feeder.sh",
	"/usr/local/sbin/k0scontroller-remediate.sh",
	"/usr/local/sbin/k0s-apiserver-wedge-probe.sh",
	"/usr/local/sbin/k0s-kine-pool-probe.sh",
	"/usr/local/sbin/k0s-oomloop-probe.sh",
	"/usr/local/sbin/kine-db-probe.sh",
	"/usr/local/sbin/kine-compact-guard.sh",
	"/usr/local/sbin/kine-db-maint.sh",
	"/usr/local/sbin/api-backend-guard.sh",
	"/usr/local/sbin/nebula-route-guard.sh",
}

// pruneLegacyWatchdog stops, disables and deletes the whole retired
// shell watchdog stack — timers/services, drop-ins, scripts and the
// /usr/local/lib/node-watchdog module dir. Every module is a Go
// subsystem now (apiprober/nethealth/workerhygiene/controllerhygiene),
// so leftover units would double consecutive-* counters and race the
// agent's own converge on /etc/hosts and ip rule. Idempotent:
// systemctl disable + removeManaged are no-ops when already gone.
// /etc/node-watchdog.conf and /etc/nebula/<net>/* are NOT touched —
// still rendered and consumed by the Go subsystems.
func (c *cyc) pruneLegacyWatchdog() {
	r, ctx := c.r, c.ctx
	// Gate the systemctl fan-out on unit files actually present:
	// `systemctl disable` on a long-deleted unit is still a full
	// host exec (nsenter + D-Bus) per name — ~23 forks of pure
	// waste every cycle once the sweep has done its job. The stat
	// pass costs only filesystem reads, and the survivors share
	// ONE disable call (systemctl accepts a unit list).
	var live []string
	for _, u := range legacyWatchdogUnits {
		if r.fileExists("/etc/systemd/system/" + u) {
			live = append(live, u)
		}
	}
	if len(live) > 0 {
		_, _ = r.run(ctx, "systemctl",
			append([]string{"disable", "--now"}, live...)...)
	}
	removed := false
	for _, u := range legacyWatchdogUnits {
		if ch, _ := r.removeManaged("/etc/systemd/system/" + u); ch {
			removed = true
		}
	}
	for _, p := range legacyWatchdogDropins {
		if ch, _ := r.removeManaged(p); ch {
			removed = true
		}
	}
	for _, s := range legacyWatchdogScripts {
		_, _ = r.removeManaged(s)
	}
	// module lib dir (lib.sh + modules/*.sh) — removeManaged refuses
	// dirs on purpose, this one is pruned wholesale.
	if err := os.RemoveAll(r.hp("/usr/local/lib/node-watchdog")); err != nil {
		// Best-effort sweep of retired files — leftover shell libs
		// are inert, so a failed prune only warns.
		logger().Warn("prune watchdog lib dir failed",
			"path", "/usr/local/lib/node-watchdog", "error", err)
	}
	if removed {
		r.daemonReload(ctx)
	}
	// stale prom of the shell emitter — standalone hosts keep theirs
	// (hostmetrics still reads state latches from the same dir).
	if !r.cfg.Standalone {
		_, _ = r.removeManaged("/var/lib/node-exporter/textfile/node-watchdog.prom")
	}
}

// controllerTuning keeps the k0scontroller cgroup drop-ins that used
// to ride along in systemd-watchdog-controller.yaml — they are node
// tuning, not watchdog units: the MemoryMax/OOMPolicy boundary is
// what the oomloop guard's design assumes (boot peak swap-out instead
// of OOM-kill), and the sshd CPUWeight keeps SSH responsive under
// control-plane churn. Per-host maps converge both ways (absent host
// => drop-in removed).
func (c *cyc) controllerTuning() {
	r := c.r
	if !c.controller() {
		return
	}
	c.ctrlDropIn("k0scontroller_memory_max_by_host", "50-memory-guard.conf", func(v string) []byte {
		return []byte(`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
# cgroup OOM boundary for k0scontroller (OOMPolicy=continue).
# BUG-H2: no MemorySwapMax — the 12GiB /swapfile-kine must stay usable.
[Service]
MemoryMax=` + v + `
OOMPolicy=continue
`)
	})
	c.ctrlDropIn("k0scontroller_go_memlimit_by_host", "51-go-memlimit.conf", func(v string) []byte {
		return []byte(`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
# GOMEMLIMIT soft-caps the heap of EVERY Go child in the unit. GOGC=50.
[Service]
Environment=GOMEMLIMIT=` + v + `
Environment=GOGC=50
`)
	})
	// sshd CPUWeight=10000 (controller responsiveness under churn).
	for _, d := range []string{"ssh.service.d", "ssh@.service.d", "sshd.service.d"} {
		_ = r.ensureDir("/etc/systemd/system/"+d, 0o755)
		if ch, _ := r.writeManaged("/etc/systemd/system/"+d+"/10-cpuweight.conf",
			[]byte(`# Managed by passiontech base/node-watchdog - systemd-watchdog-controller.yaml
# Keep sshd responsive when the control plane saturates CPU.
[Service]
CPUWeight=10000
`), 0o644); ch {
			r.daemonReload(c.ctx)
		}
	}
}

func (c *cyc) ctrlDropIn(varName, file string, render func(string) []byte) {
	r := c.r
	path := "/etc/systemd/system/k0scontroller.service.d/" + file
	var val any
	if om, ok := c.t.Vars.Get(varName).(*jinja.OMap); ok {
		val, _ = om.Get(c.r.cfg.NodeName)
	}
	if val == nil {
		if ch, _ := r.removeManaged(path); ch {
			r.daemonReload(c.ctx)
		}
		return
	}
	_ = r.ensureDir("/etc/systemd/system/k0scontroller.service.d", 0o755)
	if ch, _ := r.writeManaged(path, render(fmt.Sprint(val)), 0o644); ch {
		r.daemonReload(c.ctx)
	}
}

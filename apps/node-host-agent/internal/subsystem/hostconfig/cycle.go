// cycle.go — Cycle orchestration (Cycle/CycleWithErrors), the per-cycle
// cyc context, and the helpers shared across converge groups. The
// generic mechanisms live in the sibling converge package (this
// subsystem's subtree) — the helpers here are
// thin delegates keeping the group_*.go call sites (and their tests)
// on their original names.
package hostconfig

import (
	"context"
	"embed"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostconfig/converge"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

//go:embed all:templates
var templates embed.FS

// Cycle runs one full converge (all groups, playbook order).
func (r *Reconciler) Cycle(ctx context.Context) {
	_ = r.CycleWithErrors(ctx)
}

// CycleWithErrors runs one full converge and returns the number of
// errors observed: topology load/derivation errors, lazy vars
// resolution failures, per-group write/command/render errors and
// panics. A clean cycle (errs == 0) stamps lastOK
// (node_host_agent_hostconfig_last_success_seconds); converge-once
// maps a non-zero count onto exit 1 while the daemon path keeps the
// old fire-and-forget Cycle behaviour.
func (r *Reconciler) CycleWithErrors(ctx context.Context) int {
	start := time.Now()
	t, err := topology.Load(topology.Config{VarsDir: r.cfg.VarsDir, NodeName: r.cfg.NodeName, Clock: r.cfg.Clock})
	if err != nil {
		r.cycles.WithLabelValues("load", "error").Inc()
		logger().Error("hostconfig: topology load failed",
			"varsDir", r.cfg.VarsDir, "node", r.cfg.NodeName, "error", err)
		return 1
	}
	c := &cyc{r: r, ctx: ctx, t: t}
	// Managed-op helpers (writeManaged/removeManaged/ensureDir/
	// systemctl actions) attribute their failures to the active cycle
	// via r.cur — cycles run on a single goroutine.
	prev := r.cur
	r.cur = c
	defer func() { r.cur = prev }()
	// t.Errors already carries the load-time vars eval failures
	// (topology.Load appends Vars.Errors) — remember the prefix length
	// so the lazy group-time resolutions below don't double count.
	varsSeen := len(t.Vars.Errors())
	for _, e := range t.Errors {
		c.err("hostconfig: topology", "node", r.cfg.NodeName, "error", e)
	}
	// Order mirrors node_tuning.yaml + hub_converge.yaml.
	for _, g := range c.groups() {
		c.group(g.name, g.run)
	}
	// Vars lazily resolve during the groups too — eval failures and
	// reference cycles land in Vars.Errors (fail-closed Undefined).
	for _, e := range t.Vars.Errors()[varsSeen:] {
		c.err("hostconfig: vars resolution", "error", e)
	}
	if c.errs == 0 {
		r.lastOK.Set(float64(r.cfg.Clock.Now().Unix()))
	}
	logger().Info("hostconfig: cycle done",
		"node", r.cfg.NodeName, "errors", c.errs,
		"elapsed", time.Since(start).Round(time.Second).String())
	return c.errs
}

type cyc struct {
	r    *Reconciler
	ctx  context.Context
	t    *topology.Topology
	errs int // errors observed so far this cycle (all groups + vars)
	// journaldRestarted is set by journaldStorage when it bounced
	// systemd-journald this cycle (drop-in or journal-dir change) —
	// journaldIntegrity's silent-journald remedy reads it so one
	// converge never spends the restart budget on a second bounce.
	journaldRestarted bool
}

// err logs at Error level AND marks the current cycle (and the group
// it is running inside) failed — the channel every failure a group
// surfaces reports through so the cycles metric and converge-once's
// exit code see it.
func (c *cyc) err(msg string, args ...any) {
	c.errs++
	logger().Error(msg, args...)
}

// cycGroup is one entry in the ordered converge registry: the
// prometheus `cycles` group label plus the group body CycleWithErrors
// runs under c.group's error/panic accounting.
type cycGroup struct {
	name string
	run  func()
}

// groups builds the ordered group list CycleWithErrors iterates. The
// ORDER is load-bearing — it mirrors node_tuning.yaml +
// hub_converge.yaml playbook order and must not be resequenced.
func (c *cyc) groups() []cycGroup {
	return []cycGroup{
		{"base", c.groupBase},                   // T1/T2/A4/T16 + hostname pin
		{"resolved", c.groupResolved},           // T3
		{"nodelocaldns", c.groupNLD},            // T4
		{"nebula", c.groupNebula},               // T5b
		{"watchdog", c.groupWatchdog},           // T6 (+T15/systemd watchdog)
		{"imagepulls", c.groupPulls},            // T7 + T17
		{"nodeip_cpu", c.groupNodeCPU},          // T8 + T10
		{"coredns", c.groupCoreDNS},             // T9 (stub + hub)
		{"bwaudit", c.groupBwAudit},             // T11
		{"security", c.groupSecurity},           // fail2ban + sshd hardening
		{"apilb", c.groupAPILB},                 // T12 (incl. fallback-map strip)
		{"swap", c.groupSwap},                   // node_tuning_swap.yaml
		{"hub-metrics-fw", c.groupHubMetricsFW}, // node_exporter_hub.yaml (standalone)
		{"api-lb-vm", c.groupAPILBVM},           // api_lb_guard.yaml converge
		{"kine", c.groupKineService},            // Phase 3: kine.service split into its own unit
		{"etcdctl", c.groupEtcdctl},             // embedded-etcd controllers: /var/lib/k0s/bin/etcdctl
		{"verify", c.groupVerify},
	}
}

// group runs one converge group and records the outcome:
// cycles{name,"ok"} when the group observed no error, {"error"} when
// it did, {"panic"} when it panicked (a panic also counts toward the
// cycle's error total).
func (c *cyc) group(name string, fn func()) {
	before := c.errs
	defer func() {
		if rec := recover(); rec != nil {
			c.err("hostconfig group panicked", "group", name, "panic", rec)
			c.r.cycles.WithLabelValues(name, "panic").Inc()
			return
		}
		if c.errs > before {
			c.r.cycles.WithLabelValues(name, "error").Inc()
		} else {
			c.r.cycles.WithLabelValues(name, "ok").Inc()
		}
	}()
	fn()
}

func (c *cyc) v(name string) string { return c.t.Vars.Str(name) }

// dpkgInstalled reports whether pkg is fully installed
// ("install ok installed") — the apt-get skip gate so a converge
// doesn't fork apt (and take the dpkg lock) for packages the host
// already satisfies.
func (c *cyc) dpkgInstalled(ctx context.Context, pkg string) bool {
	out, _ := c.r.run(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
	return strings.Contains(out, "install ok installed")
}

func (c *cyc) vb(name string) bool { return c.t.Vars.Bool(name) }

func (c *cyc) vl(name string) []any { return c.t.Vars.List(name) }

func (c *cyc) vs(name string) []string { return c.t.Vars.StrList(name) }

func (c *cyc) vi(name string) int64 { return c.t.Vars.Int(name) }

func (c *cyc) worker() bool { return c.r.fileExists("/etc/systemd/system/k0sworker.service") }

func (c *cyc) controller() bool { return c.r.fileExists("/etc/systemd/system/k0scontroller.service") }

func fileExistsNoRoot(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// hostOps adapts the Reconciler to converge.Ops — the seam
// converge.Deploy/NftUnit drive. Every method routes through the
// metric + noteErr-carrying wrappers so a deploy's writes, removes,
// checks, and systemctl calls attribute exactly like the
// pre-extraction code.
type hostOps struct{ r *Reconciler }

func (o hostOps) Join(p string) string { return o.r.hp(p) }

func (o hostOps) WriteManaged(p string, b []byte, m os.FileMode) (bool, error) {
	return o.r.writeManaged(p, b, m)
}

func (o hostOps) RemoveManaged(p string) (bool, error) { return o.r.removeManaged(p) }

func (o hostOps) Run(ctx context.Context, name string, args ...string) (string, error) {
	return o.r.run(ctx, name, args...)
}

func (o hostOps) DaemonReload(ctx context.Context)            { o.r.daemonReload(ctx) }
func (o hostOps) EnableService(ctx context.Context, u string) { o.r.enableService(ctx, u) }
func (o hostOps) StartService(ctx context.Context, u string)  { o.r.startService(ctx, u) }
func (o hostOps) RestartService(ctx context.Context, u string) {
	o.r.restartService(ctx, u)
}

func (r *Reconciler) ops() converge.Ops { return hostOps{r} }

// checkedDeploy is the candidate-staging validate-then-promote half
// of applyNftUnit, shared by the haproxy/nft deploys in groupAPILB —
// the mechanism is converge.Deploy; this wrapper preserves the old
// (changed, ok) contract and the errMsg-attributed check failure.
//
// Returns (changed, ok): ok=false means the stage write or check
// failed — already counted (writeManaged's noteErr via
// ErrManagedWrite, or the counted c.err here carrying errMsg) and
// the caller must abort the deploy.
func (c *cyc) checkedDeploy(path string, content []byte, mode os.FileMode, errMsg string, check ...string) (changed, ok bool) {
	changed, err := converge.Deploy(c.ctx, c.r.ops(), path, content, mode, check...)
	if err != nil {
		// A managed-write failure was already attributed inside
		// writeManaged's noteErr — counting it again here would
		// double the cycle's error total.
		if !errors.Is(err, converge.ErrManagedWrite) {
			c.err(errMsg, "path", path, "error", err)
		}
		return false, false
	}
	return changed, true
}

// applyNftUnit deploys an nft ruleset + its oneshot boot unit, applies
// via restart when the file changed (T4/T11 pattern). converge.NftUnit
// owns the stage→validate→promote→unit choreography; failures that
// were not already attributed inside a managed write count here.
func (c *cyc) applyNftUnit(name, path string, content []byte, desc string) {
	if err := converge.NftUnit(c.ctx, c.r.ops(), name, path, content, desc); err != nil &&
		!errors.Is(err, converge.ErrManagedWrite) {
		c.err("hostconfig: nft ruleset failed nft -c — deploy path keeps the last good file",
			"unit", name, "path", path, "error", err)
	}
}

// tplCtx builds the interdc_* var context the .j2 templates expect.
func (c *cyc) tplCtx() map[string]any {
	t := c.t
	lh := jinja.NewOMap()
	for _, l := range t.Lighthouses {
		m := jinja.NewOMap()
		m.Set("marker", l.Marker)
		m.Set("ip", l.IP)
		lh.Set(l.Name, m)
	}
	var routes []any
	for _, u := range t.UnsafeRoutes {
		m := jinja.NewOMap()
		m.Set("route", u.Route)
		m.Set("via", u.Via)
		m.Set("metric", u.Metric)
		m.Set("install", false)
		routes = append(routes, m)
	}
	relayMap := jinja.NewOMap()
	for name, es := range t.RelayMap {
		var l []any
		for _, e := range es {
			m := jinja.NewOMap()
			m.Set("ip", e.IP)
			l = append(l, m)
		}
		relayMap.Set(name, &jinja.List{V: l})
	}
	get := func(name string) any {
		v := c.t.Vars.Get(name)
		return v
	}
	strv := func(name, def string) any {
		return c.t.Vars.StrDef(name, def)
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
		"interdc_nebula_unsafe_routes": &jinja.List{V: routes},
		"interdc_relay_map":            relayMap,
		"interdc_targets":              &jinja.List{V: strSliceToAny(t.Targets)},
		"interdc_egress_relays":        &jinja.List{V: strSliceToAny(t.EgressRelays)},
		"nebula_direct_tcp_ports":      &jinja.List{V: strSliceToAny(c.nebulaDirectTCPPorts())},
		"interdc_overlay":              t.Overlay,
		"interdc_dns_zone":             t.Zone,
		"interdc_dns_resolvers":        &jinja.List{V: strSliceToAny(t.DNSResolvers)},
		"interdc_stub_public_upstream": strv("interdc_stub_public_upstream", "1.1.1.1 8.8.8.8"),
		"cp_endpoint":                  c.v("cp_endpoint"),
		"api_lb_backends":              c.t.Vars.Get("api_lb_backends"),
		"api_lb_extra_lanes":           c.t.Vars.Get("api_lb_extra_lanes"),
		"api_lb_vip_ip":                c.v("api_lb_vip_ip"),
		"api_lb_probe_reachable":       &jinja.List{V: strSliceToAny(c.probeReachable())},
		"fail2ban_ignoreip":            c.fail2banIgnoreIP(),
		"interdc_hub_zone_serial":      c.zoneSerial(),
		"ansible_facts":                map[string]any{"hostname": c.r.cfg.NodeName},
	}
}

func omapOf(m map[string]string) *jinja.OMap {
	o := jinja.NewOMap()
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

func topologyPlain(v any) any {
	switch t := v.(type) {
	case *jinja.OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = topologyPlain(vv)
		}
		return m
	case *jinja.List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = topologyPlain(x)
		}
		return out
	default:
		return v
	}
}

// sha256FileOK verifies a staged/downloaded archive against its pin.
func sha256FileOK(path, wantHex string) bool {
	return converge.Sha256FileOK(path, wantHex)
}

func (c *cyc) markerBase() string {
	return c.t.Vars.StrDef("interdc_marker_base", "172.29.0")
}

func nodeIPStr(m *jinja.OMap, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m.Get(key)
	s, _ := v.(string)
	return s
}

func defStr(v, d string) string { return converge.DefStr(v, d) }

// lineInFile is ansible lineinfile parity: replace the LAST line
// matching re with line; when absent insert after the last line
// matching insAfter (or append at EOF).
func lineInFile(s, re, line, insAfter string) string {
	return converge.LineInFile(s, re, line, insAfter)
}

// ---------- download helpers ----------

// download fetches url to dst under the Config.HTTPTimeout client
// deadline (nebula/coredns/etcdctl tarballs, haproxy + kine deb/bin).
func (r *Reconciler) download(ctx context.Context, url, dst, wantSHA256 string) error {
	return converge.DownloadFile(ctx, url, dst, wantSHA256, r.cfg.HTTPTimeout)
}

// downloadFile streams url to dst atomically under an explicit client
// deadline (nexpDownload floors the timeout above HTTPTimeout).
func downloadFile(ctx context.Context, url, dst, wantSHA256 string, timeout time.Duration) error {
	return converge.DownloadFile(ctx, url, dst, wantSHA256, timeout)
}

// untarInstall extracts member name from a .tar.gz and atomically
// installs to dst.
func untarInstall(tgz, member, dst string, mode os.FileMode) error {
	return converge.UntarInstall(tgz, member, dst, mode)
}

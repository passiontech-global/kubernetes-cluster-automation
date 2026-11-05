// cycle.go — Cycle orchestration (Cycle/CycleWithErrors), the per-cycle
// cyc context, and the helpers shared across converge groups.
package hostconfig

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/pagecache"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
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
	t, err := topology.Load(topology.Config{VarsDir: r.cfg.VarsDir, NodeName: r.cfg.NodeName, NowFn: r.cfg.NowFn})
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
		r.lastOK.Set(float64(r.cfg.NowFn().Unix()))
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

func (c *cyc) vb(name string) bool { return c.t.Vars.Bool(name) }

func (c *cyc) vl(name string) []any { return c.t.Vars.List(name) }

func (c *cyc) vs(name string) []string { return c.t.Vars.StrList(name) }

func (c *cyc) vi(name string) int64 { return c.t.Vars.Int(name) }

func (c *cyc) worker() bool { return c.r.fileExists("/etc/systemd/system/k0sworker.service") }

func (c *cyc) controller() bool { return c.r.fileExists("/etc/systemd/system/k0scontroller.service") }

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

func fileExistsNoRoot(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// checkedDeploy is the candidate-staging validate-then-promote half
// of applyNftUnit, shared by the haproxy/nft deploys in groupAPILB:
// content is written to path+".candidate", the check command runs
// against the CANDIDATE (its name appended to check argv), and only a
// passing candidate is promoted to path via writeManaged — a bad
// render therefore never sits at the live path where the unit loads
// it on next start. The candidate is swept on every outcome.
//
// An unchanged file skips staging entirely (it was validated the
// cycle it was promoted) but still sweeps a stale candidate a crashed
// converge left behind.
//
// Returns (changed, ok): ok=false means the stage write or check
// failed — already counted (writeManaged's noteErr or the counted
// c.err here carrying errMsg) and the caller must abort the deploy.
func (c *cyc) checkedDeploy(path string, content []byte, mode os.FileMode, errMsg string, check ...string) (changed, ok bool) {
	r, ctx := c.r, c.ctx
	changed = true
	if old, err := os.ReadFile(r.hp(path)); err == nil &&
		sha256.Sum256(old) == sha256.Sum256(content) {
		changed = false
	}
	if !changed {
		// Cheap sweep, ENOENT ignored — a candidate orphaned between
		// stage and promote must not linger next to the live file.
		if err := os.Remove(r.hp(path + ".candidate")); err != nil && !os.IsNotExist(err) {
			logger().Warn("hostconfig: stale candidate sweep failed",
				"path", path+".candidate", "error", err)
		}
		return false, true
	}
	cand := path + ".candidate"
	if _, err := r.writeManaged(cand, content, mode); err != nil {
		return false, false // writeManaged counted the failure via noteErr
	}
	if out, err := r.run(ctx, check[0], append(check[1:], cand)...); err != nil {
		c.err(errMsg,
			"path", path, "candidate", cand,
			"check", strings.Join(check, " "), "out", out, "error", err)
		r.removeManaged(cand)
		return false, false
	}
	changed, _ = r.writeManaged(path, content, mode)
	r.removeManaged(cand)
	return changed, true
}

// applyNftUnit deploys an nft ruleset + its oneshot boot unit, applies
// via restart when the file changed (T4/T11 pattern).
func (c *cyc) applyNftUnit(name, path string, content []byte, desc string) {
	r, ctx := c.r, c.ctx
	// `nft -c` runs on the CANDIDATE — writeManaged must only ever
	// land a validated ruleset at the deploy path, or a broken render
	// would persist where the oneshot unit loads it at boot.
	ch, ok := c.checkedDeploy(path, content, 0o644,
		"nft ruleset failed nft -c — deploy path keeps the last good file",
		"nft", "-c", "-f")
	if !ok {
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
	r.enableService(ctx, name+".service")
	if ch {
		r.restartService(ctx, name+".service")
	} else {
		r.startService(ctx, name+".service")
	}
}

func filepath2(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
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
		"nebula_direct_tcp_ports":      &topology.List{V: strSliceToAny(c.nebulaDirectTCPPorts())},
		"interdc_overlay":              t.Overlay,
		"interdc_dns_zone":             t.Zone,
		"interdc_dns_resolvers":        &topology.List{V: strSliceToAny(t.DNSResolvers)},
		"interdc_stub_public_upstream": strv("interdc_stub_public_upstream", "1.1.1.1 8.8.8.8"),
		"cp_endpoint":                  c.v("cp_endpoint"),
		"api_lb_backends":              c.t.Vars.Get("api_lb_backends"),
		"api_lb_extra_lanes":           c.t.Vars.Get("api_lb_extra_lanes"),
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

// sha256FileOK verifies a staged/downloaded archive against its pin.
func sha256FileOK(path, wantHex string) bool {
	if wantHex == "" {
		return true
	}
	sum, err := pagecache.Sha256File(path)
	if err != nil {
		return false
	}
	return strings.EqualFold(sum, wantHex)
}

func (c *cyc) markerBase() string {
	b := c.v("interdc_marker_base")
	if b == "" || b == "None" {
		return "172.29.0"
	}
	return b
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

func containsSS(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// lineInFile is ansible lineinfile parity: replace the LAST line
// matching re with line; when absent insert after the last line
// matching insAfter (or append at EOF).
func lineInFile(s, re, line, insAfter string) string {
	rex := regexp.MustCompile(re)
	if loc := findLastMatch(rex, s); loc != nil {
		nl := strings.IndexByte(s[loc[0]:], '\n')
		end := len(s)
		if nl >= 0 {
			end = loc[0] + nl + 1
		}
		if !strings.HasSuffix(line, "\n") {
			line += "\n"
		}
		return s[:loc[0]] + line + s[end:]
	}
	if insAfter != "" {
		ia := regexp.MustCompile(insAfter)
		if loc := findLastMatch(ia, s); loc != nil {
			nl := strings.IndexByte(s[loc[0]:], '\n')
			end := loc[0] + nl + 1
			if nl < 0 {
				end = len(s)
				return s[:end] + "\n" + line + "\n"
			}
			return s[:end] + line + "\n" + s[end:]
		}
	}
	return s + line + "\n"
}

func findLastMatch(re *regexp.Regexp, s string) []int {
	var last []int
	for _, loc := range re.FindAllStringIndex(s, -1) {
		last = loc
	}
	return last
}

// ---------- download helpers ----------

// download fetches url to dst under the Config.HTTPTimeout client
// deadline (nebula/coredns/etcdctl tarballs, haproxy + kine deb/bin).
func (r *Reconciler) download(ctx context.Context, url, dst, wantSHA256 string) error {
	return downloadFile(ctx, url, dst, wantSHA256, r.cfg.HTTPTimeout)
}

// downloadFile streams url to dst atomically: tmp file + sha256
// verify + fsync + rename, partial tmp swept on every failure path.
func downloadFile(ctx context.Context, url, dst, wantSHA256 string, timeout time.Duration) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".dl"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err == nil {
		// fsync before rename — the staged artifact must be durable;
		// Close's error counts too (NFS/delayed-write failures only
		// surface there). Drop the just-written pages after Sync —
		// archives are staged for untarInstall/sha256FileOK, not for
		// serving, and their cache would pin the pod's cgroup charge.
		if err = f.Sync(); err == nil {
			pagecache.Drop(f)
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if wantSHA256 != "" && !strings.EqualFold(wantSHA256, fmt.Sprintf("%x", h.Sum(nil))) {
		os.Remove(tmp)
		return fmt.Errorf("download %s: sha256 mismatch", url)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// untarInstall extracts member name from a .tar.gz and atomically
// installs to dst.
func untarInstall(tgz, member, dst string, mode os.FileMode) error {
	f, err := os.Open(tgz)
	if err != nil {
		return err
	}
	// Drop the archive's read-behind pages on the way out — the tgz
	// is only scanned once per install.
	defer func() { pagecache.Drop(f); _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hd, err := tr.Next()
		if err != nil {
			return fmt.Errorf("%s not found in %s", member, tgz)
		}
		if filepath.Base(hd.Name) == member {
			tmp := dst + ".tmp"
			out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			if err == nil {
				// fsync before rename (writeManaged parity) — a
				// crash after rename must never expose a zeroed
				// binary at the install path. Then drop the staged
				// pages: a freshly installed binary's cache charge
				// belongs to whoever execs it, not to this pod's
				// working set.
				if err = out.Sync(); err == nil {
					pagecache.Drop(out)
				}
			}
			// Close's error counts too — delayed-write failures only
			// surface there.
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				// sweep the partial tmp — a truncated member must not
				// linger next to the live binary.
				os.Remove(tmp)
				return err
			}
			if err := os.Rename(tmp, dst); err != nil {
				os.Remove(tmp)
				return err
			}
			return nil
		}
	}
}

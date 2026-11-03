// groups_tuning.go — the remaining node_tuning.yaml task groups:
// T7/T17 image-pulls+kubelet, T8/T10 nodeip+cpu, T9 coredns stub/hub,
// T11 bw audit, security, T12 api-local-lb, verify + download helpers.
package hostconfig

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
)

// ---------- T7 + T17 ----------
// Port of tasks/node_tuning_image_pulls.yaml + node_tuning_kubelet.yaml.
// Header contract: the agent NEVER restarts k0s/containerd — changes
// take effect on the next natural restart.

// k0s unit paths ansible discovers (worker + controller).
var t7UnitPaths = []string{
	"/etc/systemd/system/k0sworker.service",
	"/etc/systemd/system/k0scontroller.service",
}

// kubelet config candidate paths when the daemon isn't running to
// discover --config from (ansible stat loop, same order).
var t7KubeletCfgCandidates = []string{
	"/run/k0s/kubelet/config.yaml",
	"/var/lib/k0s/kubelet/config.yaml",
	"/run/k0s/kubelet-config.yaml",
	"/var/lib/k0s/kubelet-config.yaml",
}

var (
	t7ExtraArgsRe = regexp.MustCompile(`--kubelet-extra-args=\S+`)
	t7DataDirRe   = regexp.MustCompile(`ExecStart=.*k0s (worker|controller) --data-dir=\S+`)
)

// kubeletCfgPath ports the T7 discovery: --config of the running
// kubelet (via /proc cmdline), else the first existing candidate.
func (c *cyc) kubeletCfgPath() string {
	if out, err := c.r.run(c.ctx, "sh", "-c",
		`pid=$(pgrep -x kubelet | head -1); `+
			`if [ -n "$pid" ]; then tr '\0' '\n' < "/proc/$pid/cmdline" `+
			`| awk '/^--config=/{sub(/^--config=/,"");print;exit} /^--config$/{getline;print;exit}'; fi`); err == nil {
		if p := strings.TrimSpace(out); p != "" {
			return p
		}
	}
	for _, p := range t7KubeletCfgCandidates {
		if c.r.fileExists(p) {
			return p
		}
	}
	return ""
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

// evictionMinReclaimMap returns the expected evictionMinimumReclaim
// nested map (var kubelet_eviction_min_reclaim as mapping, else the
// ansible hardcoded block order).
func (c *cyc) evictionMinReclaimMap() *topology.OMap {
	if om, ok := c.t.Vars.Get("kubelet_eviction_min_reclaim").(*topology.OMap); ok && om.Len() > 0 {
		return om
	}
	m := topology.NewOMap()
	m.Set("memory.available", "200Mi")
	m.Set("nodefs.available", "1Gi")
	m.Set("imagefs.available", "2Gi")
	return m
}

// evictionBlock renders the evictionMinimumReclaim block (ansible
// t17_emr_block shape — sub-keys quoted when string).
func evictionBlock(m *topology.OMap) string {
	var b strings.Builder
	b.WriteString("evictionMinimumReclaim:\n")
	for _, k := range m.Keys() {
		v, _ := m.Get(k)
		if s, ok := v.(string); ok {
			fmt.Fprintf(&b, "  %s: %q\n", k, s)
		} else {
			fmt.Fprintf(&b, "  %s: %v\n", k, v)
		}
	}
	return b.String()
}

// emrMapEqual compares the on-disk sub-key block semantically (parse
// via YAML, same as ansible from_yaml compare).
func emrMapEqual(cur string, want *topology.OMap) bool {
	v, err := topology.DecodeYAML([]byte(cur))
	if err != nil {
		return false
	}
	got, ok := v.(*topology.OMap)
	if !ok || got == nil || got.Len() != want.Len() {
		return false
	}
	for _, k := range want.Keys() {
		gv, ok := got.Get(k)
		if !ok {
			return false
		}
		wv, _ := want.Get(k)
		if fmt.Sprint(topologyPlain(gv)) != fmt.Sprint(topologyPlain(wv)) {
			return false
		}
	}
	return true
}

var t17EmrBlockRe = regexp.MustCompile(`(?m)^evictionMinimumReclaim:[^\n]*\n( +[^\n]*\n?)*`)

// emrDump extracts the indented sub-key lines under a top-level
// `evictionMinimumReclaim:` (ansible awk parity).
func emrDump(s string) string {
	var b strings.Builder
	in := false
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(ln, "evictionMinimumReclaim:") {
			in = true
			continue
		}
		if in {
			if len(ln) > 0 && (ln[0] == ' ' || ln[0] == '\t') {
				b.WriteString(ln + "\n")
			} else {
				in = false
			}
		}
	}
	return b.String()
}

func (c *cyc) groupPulls() {
	r, ctx := c.r, c.ctx
	// T7 - resolve k0s unit paths (worker AND controller).
	var units []string
	for _, p := range t7UnitPaths {
		if r.fileExists(p) {
			units = append(units, p)
		}
	}
	if len(units) == 0 {
		return
	}
	qps := defStr(c.v("kubelet_registry_qps"), "2")
	burst := defStr(c.v("kubelet_registry_burst"), "4")
	maxPar := defStr(c.v("kubelet_max_parallel_image_pulls"), "4")
	apiQPS := defStr(c.v("kubelet_api_qps"), "100")
	apiBurst := defStr(c.v("kubelet_api_burst"), "50")
	pids := defStr(c.v("kubelet_pod_pids_limit"), "4096")
	dl := defStr(c.v("containerd_max_concurrent_downloads"), "5")

	// Flags go INSIDE --kubelet-extra-args with literal \x20
	// separators — a real space would turn them into bare k0s argv.
	changed := false
	for _, p := range units {
		b, err := os.ReadFile(r.hp(p))
		if err != nil {
			c.err("T7: cannot read unit — skipping pull-flag converge",
				"path", p, "error", err)
			continue
		}
		u := string(b)
		u2 := u
		if strings.Contains(u2, "--kubelet-extra-args") {
			if !strings.Contains(u2, "--serialize-image-pulls") {
				u2 = t7ExtraArgsRe.ReplaceAllString(u2,
					"${0}\\x20--serialize-image-pulls=false")
			}
			if !strings.Contains(u2, "--registry-qps") {
				u2 = t7ExtraArgsRe.ReplaceAllString(u2,
					"${0}\\x20--registry-qps="+qps+"\\x20--registry-burst="+burst)
			}
		} else {
			// Unit without extra-args: inject full token after
			// `k0s (worker|controller) --data-dir=\S+` (bootstrap
			// installFlags parity).
			u2 = t7DataDirRe.ReplaceAllString(u2,
				"${0} --kubelet-extra-args=--serialize-image-pulls=false\\x20--registry-qps="+
					qps+"\\x20--registry-burst="+burst)
		}
		if u2 != u {
			if ch, _ := r.writeManaged(p, []byte(u2), 0o644); ch {
				changed = true
			}
		}
	}
	if changed {
		r.daemonReload(ctx)
	}

	// Kubelet config live patch (T7 maxParallelImagePulls + T17
	// kubeAPIQPS/Burst, podPidsLimit, evictionMinimumReclaim).
	cfgPath := c.kubeletCfgPath()
	if cfgPath != "" && r.fileExists(cfgPath) {
		kf, err := os.ReadFile(r.hp(cfgPath))
		if err != nil {
			c.err("T7: kubelet config unreadable — skipping live patch",
				"path", cfgPath, "error", err)
		} else {
			s := string(kf)
			// Scalar keys: lineinfile regexp '^key:' replace /
			// insertafter '^kind: KubeletConfiguration'.
			for _, kv := range [][2]string{
				{"maxParallelImagePulls", maxPar},
				{"kubeAPIQPS", apiQPS},
				{"kubeAPIBurst", apiBurst},
				{"podPidsLimit", pids},
			} {
				s = lineInFile(s, "(?m)^"+kv[0]+":", kv[0]+": "+kv[1],
					`(?m)^kind: KubeletConfiguration`)
			}
			// evictionMinimumReclaim is a nested MAP — normalize the
			// block when it semantically drifts (key-order/quote
			// differences on k0s-rendered files don't rewrite).
			want := c.evictionMinReclaimMap()
			if !emrMapEqual(emrDump(s), want) {
				s = t17EmrBlockRe.ReplaceAllString(s, "")
				s = lineInFile(s, `\A\z`, // never matches → insert
					strings.TrimSuffix(evictionBlock(want), "\n"),
					`(?m)^kind: KubeletConfiguration`)
			}
			r.writeManaged(cfgPath, []byte(s), 0o644)
		}
	}

	// containerd drop-ins — containerd-2.x plugin paths
	// ([plugins.'io.containerd.cri.v1.images']). NO restart.
	r.ensureDir("/etc/k0s/containerd.d", 0o755)
	r.writeManaged("/etc/k0s/containerd.d/90-parallel-pulls.toml", []byte(fmt.Sprintf(
		`# Managed by node-config-agent - T7 parallel image pulls.
# Cap concurrent layer downloads now that kubelet has
# serializeImagePulls off — bounds pull-storm bandwidth;
# pairs with maxParallelImagePulls=%s at the kubelet.
[plugins.'io.containerd.cri.v1.images']
  max_concurrent_downloads = %s
`, maxPar, dl)), 0o644)
	r.writeManaged("/etc/k0s/containerd.d/91-registry-mirror.toml", []byte(
		`# Managed by node-config-agent - T7 spegel P2P mirror prep.
# The spegel init container writes /etc/containerd/certs.d/*/hosts.toml
# (mirror http://<node-ip>:30020); containerd only reads certs.d when
# config_path is declared — this drop-in is the prerequisite. Mirror
# failure -> containerd falls back upstream itself (no SPOF).
[plugins.'io.containerd.cri.v1.images']
  # Must stay false for the node to serve unpacked layers to peers
  # via spegel (upstream default is already false; declared
  # explicitly to guard against a distro/config that flips it on).
  discard_unpacked_layers = false
[plugins.'io.containerd.cri.v1.images'.registry]
  config_path = '/etc/containerd/certs.d'
`), 0o644)
	r.ensureDir("/etc/containerd/certs.d", 0o755)
	// sweep the buggy drop-in + restart behaviour of the first port
	r.removeManaged("/etc/k0s/containerd.d/parallel-pulls.toml")
}

// ---------- T8 + T10 ----------

func (c *cyc) groupNodeCPU() {
	r, ctx := c.r, c.ctx
	if c.worker() && !c.t.AmLighthouse {
		r.ensureDir("/etc/systemd/system/k0sworker.service.d", 0o755)
		if ch, _ := r.writeManaged("/etc/systemd/system/k0sworker.service.d/20-wait-nodeip.conf",
			[]byte(`# Managed by node-config-agent - T8: wait for the marker IP
# on neb1 before k0sworker binds --node-ip (nebula Before=k0sworker).
[Unit]
After=nebula@interdc.service
Wants=nebula@interdc.service

[Service]
ExecStartPre=/bin/sh -c 'for i in $(seq 1 60); do ip addr show dev neb1 | grep -q "inet .* scope global" && exit 0; sleep 1; done; exit 0'
`), 0o644); ch {
			r.daemonReload(ctx)
		}
	}
	// T10 cpu protection.
	w := c.v("critical_cpu_weight")
	if w == "" || w == "None" {
		w = "500"
	}
	if c.worker() {
		if ch, _ := r.writeManaged("/etc/systemd/system/k0sworker.service.d/30-cpu-weight.conf",
			[]byte("# Managed by node-config-agent - T10 CPU starvation protection\n[Service]\nCPUWeight="+w+"\n"), 0o644); ch {
			r.daemonReload(ctx)
			if _, err := r.run(ctx, "systemctl", "set-property", "k0sworker.service", "CPUWeight="+w); err != nil {
				// Best-effort live apply — the declared state is on
				// disk; the agent never restarts k0s so the drop-in
				// lands at the next natural restart.
				slog.Warn("T10: set-property failed — drop-in applies at next restart",
					"unit", "k0sworker.service", "value", w, "error", err)
			}
		}
	}
	if c.t.Found {
		r.ensureDir("/etc/systemd/system/nebula@interdc.service.d", 0o755)
		quota := c.v("interdc_nebula_cpu_quota")
		if quota == "" || quota == "None" {
			quota = "150%"
		}
		if ch, _ := r.writeManaged("/etc/systemd/system/nebula@interdc.service.d/10-cpu-quota.conf",
			[]byte("# Managed by node-config-agent - T10 nebula CPU bound\n[Service]\nCPUQuota="+quota+"\n"), 0o644); ch {
			r.daemonReload(ctx)
			if _, err := r.run(ctx, "systemctl", "set-property", "nebula@interdc.service", "CPUQuota="+quota); err != nil {
				// Best-effort live apply — same drop-in contract.
				slog.Warn("T10: set-property failed — drop-in applies at next restart",
					"unit", "nebula@interdc.service", "value", quota, "error", err)
			}
		}
	}
}

// ---------- T9 coredns stub + hub ----------
// Port of tasks/node_tuning_coredns_stub.yaml (worker local stub) +
// the hub_converge.yaml mesh-resolver section (hub zone authority).

func (c *cyc) zoneName() string {
	if z := nodeIPStr(c.t.Zone, "zone"); z != "" {
		return z
	}
	return "passiontech.internal"
}

func (c *cyc) groupCoreDNS() {
	r, ctx, t := c.r, c.ctx, c.t
	zone := c.zoneName()
	upstream := defStr(c.v("interdc_stub_public_upstream"), "1.1.1.1 8.8.8.8")
	firstUpstream := strings.Fields(upstream)
	pub1 := "1.1.1.1"
	if len(firstUpstream) > 0 {
		pub1 = firstUpstream[0]
	}
	net := defStr(c.v("interdc_nebula_net"), "interdc")
	// Stub unit After= follows the ACTIVE overlay (ansible template).
	afterUnit := "nebula@" + net + ".service"
	if t.Overlay != "nebula" {
		afterUnit = "tinc@" + defStr(c.v("interdc_tinc_net"), "interdc") + ".service"
	}
	marker := t.Markers[t.MeshName]

	isHub := t.AmLighthouse
	if !isHub && len(t.DNSResolvers) == 0 {
		return // T9 gates entirely on interdc_dns_resolvers | length > 0
	}

	c.corednsInstallBinary()
	r.ensureDir("/etc/coredns", 0o755)

	var corefile, desc string
	if isHub {
		desc = "CoreDNS mesh resolver (" + zone + ")"
		corefile = fmt.Sprintf(`# Managed by hub_converge.yaml - mesh resolver
%s {
    bind %s 127.0.0.1
    file /etc/coredns/db.%s {
        reload 1m
    }
    errors
}
. {
    bind %s 127.0.0.1
    forward . %s {
        policy sequential
        health_check 10s
    }
    cache 300 {
        serve_stale 1h
    }
    errors
}
`, zone, marker, zone, marker, upstream)
	} else {
		desc = "CoreDNS local stub (" + zone + " + cache)"
		resolvers := strings.Join(t.DNSResolvers, " ")
		corefile = fmt.Sprintf(`# Managed by node-config-agent (T9) - local stub, domain-aware
# routing: %s -> mesh resolvers; "." -> public
# upstreams, then the mesh (rescue via tinc).
%s {
    bind 127.0.0.1
    forward . %s {
        policy sequential
        health_check 10s
    }
    errors
}
. {
    bind 127.0.0.1
    forward . %s %s {
        policy sequential
        health_check 10s
    }
    cache 300 {
        serve_stale 1h
    }
    errors
}
`, zone, zone, resolvers, upstream, resolvers)
	}

	cfgChanged := false
	if isHub {
		if zb, err := c.renderZoneFile(); err == nil {
			if ch, _ := r.writeManaged("/etc/coredns/db."+zone, zb, 0o644); ch {
				cfgChanged = true
			}
		} else {
			c.err("T9: zone file render", "zone", zone, "error", err)
		}
	}
	if ch, _ := r.writeManaged("/etc/coredns/Corefile", []byte(corefile), 0o644); ch {
		cfgChanged = true
	}
	r.writeManaged("/etc/systemd/system/coredns.service", []byte(fmt.Sprintf(`# Managed by %s
[Unit]
Description=%s
After=network-online.target %s
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/coredns -conf /etc/coredns/Corefile
Restart=always
RestartSec=5
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, map[bool]string{true: "hub_converge.yaml", false: "node-config-agent (T9)"}[isHub],
		desc, afterUnit)), 0o644)
	r.daemonReload(ctx)
	r.ensureService(ctx, "coredns.service", true, true)
	if cfgChanged {
		r.restartService(ctx, "coredns.service")
	}

	// Hub: zone record pins make the hub independent of its own
	// resolver (blockinfile interdc-zone-pins).
	if isHub {
		c.pinZoneRecords(zone)
		// dig verify BEFORE repointing resolv.conf — a dead resolver
		// must not leave the hub DNS-less (retries, like ansible until).
		ok := false
		var lastErr error
		for i := 0; i < 15; i++ {
			out, err := r.run(ctx, "dig", "@127.0.0.1", "ns1."+zone, "+short", "+time=3", "+tries=1")
			lastErr = err
			if err == nil && strings.TrimSpace(out) != "" {
				ok = true
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
		if !ok {
			c.err("T9/hub: coredns did not answer — resolv.conf NOT repointed",
				"query", "ns1."+zone, "error", lastErr)
			return
		}
	} else {
		// Worker: stub must answer the internal zone before resolv.conf
		// repoints at it (single-shot, ansible failed_when parity).
		if out, err := r.run(ctx, "dig", "@127.0.0.1", c.v("cp_endpoint"), "+short", "+time=3", "+tries=1"); err != nil || strings.TrimSpace(out) == "" {
			c.err("T9: stub does not answer cp_endpoint — resolv.conf NOT repointed",
				"cp_endpoint", c.v("cp_endpoint"), "out", strings.TrimSpace(out), "error", err)
			return
		}
		if fb := c.vs("cp_endpoint_fallback_names"); len(fb) > 0 {
			if out, err := r.run(ctx, "dig", "@127.0.0.1", fb[0], "+short", "+time=3", "+tries=1"); err != nil || strings.TrimSpace(out) == "" {
				c.err("T9: stub fails external recursion — resolv.conf NOT repointed",
					"name", fb[0], "out", strings.TrimSpace(out), "error", err)
				return
			}
		}
	}
	c.writeResolvConf(isHub, pub1)
}

// writeResolvConf captures search/domain/options extras, drops the
// resolved-managed symlink, and writes the static stub resolv.conf
// (worker + hub variants).
func (c *cyc) writeResolvConf(isHub bool, pub1 string) {
	r, ctx, t := c.r, c.ctx, c.t
	extra, _ := r.run(ctx, "sh", "-c",
		`grep -E '^(search|domain|options)' /etc/resolv.conf | grep -vFx 'options timeout:2 attempts:2' || true`)
	dst := r.hp("/etc/resolv.conf")
	if fi, err := os.Lstat(dst); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		os.Remove(dst)
	}
	var rc strings.Builder
	if isHub {
		fmt.Fprintf(&rc, `# Managed by hub_converge.yaml - local coredns first,
# %s + another hub resolver as fallback when the stub dies.
nameserver 127.0.0.1
nameserver %s


`, pub1, pub1)
		own := t.Markers[t.MeshName]
		for _, rz := range t.DNSResolvers {
			if rz != own {
				fmt.Fprintf(&rc, "nameserver %s\n", rz)
				break
			}
		}
	} else {
		fmt.Fprintf(&rc, `# Managed by node-config-agent (T9) - coredns stub first,
# %s + mesh resolver as fallback when the stub dies.
nameserver 127.0.0.1
nameserver %s
nameserver %s
`, pub1, pub1, t.DNSResolvers[0])
	}
	fmt.Fprintf(&rc, "options timeout:2 attempts:2\n%s\n", extra)
	r.writeManaged("/etc/resolv.conf", []byte(rc.String()), 0o644)
}

// pinZoneRecords — hub_converge blockinfile parity: full zone records
// + node.<zone> records pinned into /etc/hosts so the hub's own
// services (kine etc.) resolve even when coredns is down.
func (c *cyc) pinZoneRecords(zone string) {
	var blk strings.Builder
	c.eachZoneRecord(func(name, ip string) {
		fmt.Fprintf(&blk, "\n%s %s.%s", ip, name, zone)
	})
	blk.WriteString("\n")
	if c.zoneNodeRecords() {
		blk.WriteString("\n")
		for _, k := range c.t.Nodes.Keys() {
			nv, _ := c.t.Nodes.Get(k)
			om, _ := nv.(*topology.OMap)
			if om == nil {
				continue
			}
			nm := nodeIPStr(om, "name")
			if nm == "" || c.t.Markers[nm] == "" {
				continue
			}
			fmt.Fprintf(&blk, "\n%s %s.node.%s", c.t.Markers[nm], nm, zone)
		}
	}
	block := "# BEGIN interdc-zone-pins managed block\n" +
		strings.TrimPrefix(blk.String(), "\n") + "\n# END interdc-zone-pins managed block\n"
	c.blockInHosts("interdc-zone-pins", block)
}

// eachZoneRecord iterates interdc_dns_zone.records (flat map
// name → {ip|<static> | node|<registry key>}), resolving node refs
// to that node's marker IP.
func (c *cyc) eachZoneRecord(fn func(name, ip string)) {
	recs, _ := c.t.Zone.Get("records")
	rom, _ := recs.(*topology.OMap)
	if rom == nil {
		return
	}
	for _, rn := range rom.Keys() {
		rv, _ := rom.Get(rn)
		rm, _ := rv.(*topology.OMap)
		if rm == nil {
			continue
		}
		if nv, ok := rm.Get("node"); ok {
			// node: <registry key> -> marker of that node's name
			if nvv, ok2 := c.t.Nodes.Get(fmt.Sprint(nv)); ok2 {
				if om, ok3 := nvv.(*topology.OMap); ok3 {
					if mk := c.t.Markers[nodeIPStr(om, "name")]; mk != "" {
						fn(rn, mk)
					}
				}
			}
		} else if iv, ok := rm.Get("ip"); ok {
			fn(rn, fmt.Sprint(iv))
		}
	}
}

func (c *cyc) zoneNodeRecords() bool {
	v, ok := c.t.Zone.Get("node_records")
	if !ok {
		return true // ansible default(true)
	}
	b, _ := v.(bool)
	return b
}

// renderZoneFile builds db.<zone> for hub nodes — hub_converge.yaml
// inline template parity (SOA/NS/A, service + node records, flat
// schema {zone, ttl, records:{name:{ip|node}}, node_records}).
func (c *cyc) renderZoneFile() ([]byte, error) {
	t, zone := c.t, c.zoneName()
	ttl := "60"
	if tv, ok := t.Zone.Get("ttl"); ok && tv != nil {
		ttl = fmt.Sprint(tv)
	}
	var hubs []string
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil {
			continue
		}
		if hv, ok := om.Get("hub"); ok {
			if b, _ := hv.(bool); b {
				hubs = append(hubs, nodeIPStr(om, "name"))
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$TTL %s\n", ttl)
	fmt.Fprintf(&b, "@   IN SOA ns1.%s. admin.%s. (\n        %d ; serial=hash(records), changes only when content changes\n        60 15 604800 30 )\n",
		zone, zone, c.zoneSerial())
	b.WriteString("\n") // {% set _hubs %} line
	for i := range hubs {
		fmt.Fprintf(&b, "\n    IN NS ns%d.%s.\n", i+1, zone)
	}
	b.WriteString("\n") // {% endfor %}
	for i, h := range hubs {
		fmt.Fprintf(&b, "\n%-30s IN A %s\n", fmt.Sprintf("ns%d", i+1), t.Markers[h])
	}
	b.WriteString("\n") // {% endfor %}
	b.WriteString("; service records: interdc_dns_zone.yaml\n")
	b.WriteString("; (do NOT use '#' — the coredns/miekg zone parser does not accept\n")
	b.WriteString("; '#' as a comment, only ';' — \"not a TTL\" crashloop 2026-09-16)\n")
	c.eachZoneRecord(func(name, ip string) {
		b.WriteString("\n\n")
		fmt.Fprintf(&b, "%-30s IN A %s\n", name, ip)
		b.WriteString("\n")
	})
	b.WriteString("\n") // {% endfor %}
	b.WriteString("; node records: <tinc_name>.node.<zone> -> marker\n")
	if c.zoneNodeRecords() {
		b.WriteString("\n") // {% if node_records %}
		for _, k := range t.Nodes.Keys() {
			nv, _ := t.Nodes.Get(k)
			om, _ := nv.(*topology.OMap)
			if om == nil {
				continue
			}
			nm := nodeIPStr(om, "name")
			if nm == "" || t.Markers[nm] == "" {
				continue
			}
			fmt.Fprintf(&b, "\n%-30s IN A %s\n", nm+".node", t.Markers[nm])
		}
		b.WriteString("\n") // {% endfor %}
	}
	return []byte(b.String()), nil
}

// zoneSerial — ansible: (interdc_nodes|to_json ~ interdc_dns_zone|to_json)
// | hash('sha256') | int(0,16) % 4294967295. Changes only when the
// inputs change (no DNS blip on every converge).
func (c *cyc) zoneSerial() int64 {
	nj, _ := json.Marshal(jsonPlain(c.t.Nodes))
	zj, _ := json.Marshal(jsonPlain(c.t.Zone))
	h := sha256.Sum256(append(nj, zj...))
	i := new(big.Int).SetBytes(h[:])
	i.Mod(i, big.NewInt(4294967295))
	return i.Int64()
}

// jsonPlain renders OMap/List as sorted-key JSON-compatible values.
func jsonPlain(v any) any {
	switch t := v.(type) {
	case *topology.OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = jsonPlain(vv)
		}
		return m
	case *topology.List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = jsonPlain(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsonPlain(x)
		}
		return out
	default:
		return v
	}
}

func (c *cyc) corednsInstallBinary() {
	ver := c.v("interdc_coredns_version")
	if out, err := c.r.run(c.ctx, "/usr/local/bin/coredns", "-version"); err == nil &&
		strings.Contains(out, "CoreDNS-"+ver) {
		return
	}
	tgz := c.v("interdc_coredns_tgz")
	sum := c.v("interdc_coredns_sha256")
	url := c.v("interdc_coredns_url")
	local := filepath.Join(c.r.cfg.DownloadDir, tgz)
	if fileExistsNoRoot(local) {
		// ansible: sha256sum -c every run when outdated.
		if !sha256FileOK(local, sum) {
			c.err("T9: staged coredns tgz sha256 mismatch — not installing",
				"file", local, "sha256", sum)
			return
		}
	} else if err := download(c.ctx, url, local, sum); err != nil {
		c.err("T9: coredns download", "url", url, "file", local, "error", err)
		return
	}
	if err := untarInstall(local, "coredns", c.r.hp("/usr/local/bin/coredns"), 0o755); err != nil {
		c.err("T9: coredns install failed — stub will not run",
			"file", local, "error", err)
	}
}

// ---------- T11 bw audit ----------

func (c *cyc) groupBwAudit() {
	if !c.vb("interdc_nebula_enabled") || !c.t.Found {
		return
	}
	dev := defStr(c.v("interdc_nebula_dev"), "neb1")
	var in, out strings.Builder
	for _, a := range c.t.BwAuditTargets {
		fmt.Fprintf(&in, "        iifname \"%s\" ip saddr %s counter comment \"%s in-neb\"\n", dev, a.Addr, a.Label)
		fmt.Fprintf(&out, "        oifname \"%s\" ip daddr %s counter comment \"%s out-neb\"\n", dev, a.Addr, a.Label)
	}
	nft := fmt.Sprintf(`# Managed by node-config-agent - per-peer bandwidth accounting on
# %s.
# Counter-only + policy accept: cannot break traffic.
# Inspect: nft list table inet interdc_acct
destroy table inet interdc_acct
table inet interdc_acct {
    chain input {
        type filter hook input priority filter; policy accept;
%s    }
    chain output {
        type filter hook output priority filter; policy accept;
%s    }
}
`, dev, in.String(), out.String())
	c.applyNftUnit("interdc-acct", "/etc/interdc-acct.nft",
		[]byte(nft), "interdc per-peer bandwidth accounting (nft counters)")
	// sweep the invented first-port deployment (wrong table + paths)
	c.r.run(c.ctx, "systemctl", "disable", "--now", "interdc-bw-audit.service")
	c.r.removeManaged("/etc/systemd/system/interdc-bw-audit.service")
	c.r.removeManaged("/etc/nftables.d/interdc-bw-audit.nft")
}

// ---------- security (fail2ban + sshd hardening) ----------

func (c *cyc) groupSecurity() {
	r, ctx := c.r, c.ctx
	if c.vb("fail2ban_enabled") {
		if out, _ := r.run(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}", "fail2ban"); out != "installed" {
			if _, err := r.run(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
				"apt-get", "install", "-y", "fail2ban"); err != nil {
				c.err("security: fail2ban install failed — jail will not apply",
					"error", err)
			}
		}
		b, err := r.render("fail2ban-cluster.conf.j2", c.tplCtx())
		if err != nil {
			c.err("fail2ban render", "error", err)
			return
		}
		r.ensureDir("/etc/fail2ban/jail.d", 0o755)
		// bootstrap-era jail whitelists only localhost and would
		// shadow the mesh whitelist (.local reads after .conf).
		legacyRm, _ := r.removeManaged("/etc/fail2ban/jail.d/sshd.local")
		ch, _ := r.writeManaged("/etc/fail2ban/jail.d/90-cluster-sshd.conf", b, 0o644)
		// stale filename of the first port
		r.removeManaged("/etc/fail2ban/jail.d/cluster.conf")
		r.ensureService(ctx, "fail2ban.service", true, true)
		if ch || legacyRm {
			r.restartService(ctx, "fail2ban.service")
		}
		r.run(ctx, "fail2ban-client", "status", "sshd") // informational
	} else if _, u := c.t.Vars.Get("fail2ban_enabled").(topology.Undefined); !u {
		// ansible: only when fail2ban_enabled is defined and false —
		// remove the jail AND purge the package.
		r.removeManaged("/etc/fail2ban/jail.d/90-cluster-sshd.conf")
		r.removeManaged("/etc/fail2ban/jail.d/cluster.conf")
		if _, err := r.run(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "purge", "-y", "fail2ban"); err != nil {
			c.err("security: fail2ban purge failed — package remains",
				"error", err)
		}
	}
	if c.vb("ssh_hardening_enabled") {
		// 60- file was renamed to 00- (first-match-wins vs
		// 50-cloud-init.conf) — always purge the old name.
		rm60, _ := r.removeManaged("/etc/ssh/sshd_config.d/60-passiontech-hardening.conf")
		r.ensureDir("/etc/ssh/sshd_config.d", 0o755)
		ch, _ := r.writeManaged("/etc/ssh/sshd_config.d/00-passiontech-hardening.conf",
			[]byte(`# Managed by Ansible - node-config-agent (port tu bootstrap/ansible/ssh_hardening.yaml)
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
`), 0o644)
		if ch || rm60 {
			// ansible: sshd -t gate BEFORE restart — a broken drop-in
			// must never take sshd down on a public node.
			if out, err := r.run(ctx, "sshd", "-t"); err == nil {
				r.restartService(ctx, "ssh.service")
			} else {
				c.err("sshd -t failed — not restarting ssh.service",
					"path", "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf",
					"out", out, "error", err)
			}
		}
		if out, err := r.run(ctx, "sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"); err != nil {
			// Best-effort verify only — a failed probe proves nothing
			// about the applied config.
			slog.Warn("ssh-hardening: sshd -T failed — cannot verify effective config",
				"error", err)
		} else if !strings.Contains(out, "passwordauthentication no") {
			c.err("ssh-hardening: passwordauthentication still enabled — drop-in not effective",
				"path", "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf")
		}
	} else if _, u := c.t.Vars.Get("ssh_hardening_enabled").(topology.Undefined); !u {
		rm1, _ := r.removeManaged("/etc/ssh/sshd_config.d/00-passiontech-hardening.conf")
		rm2, _ := r.removeManaged("/etc/ssh/sshd_config.d/60-passiontech-hardening.conf")
		if rm1 || rm2 {
			if _, err := r.run(ctx, "sshd", "-t"); err == nil {
				r.restartService(ctx, "ssh.service")
			} else {
				c.err("ssh-hardening: sshd -t failed — drop-in removal not active until restart",
					"error", err)
			}
		}
	}
}

// fail2banIgnoreIP — set_fact parity: localhost + sorted mesh node
// IPs (automation SSHes public->public) + optional extras.
func (c *cyc) fail2banIgnoreIP() string {
	var mesh []string
	for _, k := range c.t.Nodes.Keys() {
		nv, _ := c.t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil {
			continue
		}
		if ip := nodeIPStr(om, "ip"); ip != "" {
			mesh = append(mesh, ip)
		}
	}
	sort.Strings(mesh)
	parts := []string{"127.0.0.1/8", "::1"}
	parts = append(parts, mesh...)
	if ex := strings.TrimSpace(c.v("fail2ban_ignoreip_extra")); ex != "" && ex != "None" {
		parts = append(parts, ex)
	}
	return strings.Join(parts, " ")
}

// ---------- T12 api-local-lb ----------

func (c *cyc) groupAPILB() {
	r, ctx := c.r, c.ctx
	if !c.worker() {
		return // T12 block is gated on k0sworker_unit existing
	}
	if !c.vb("api_lb_enabled") {
		// rollback: unpin (BOTH marker styles) + stop/disable; cfg/unit
		// files stay on disk for re-enable (ansible parity).
		r.run(ctx, "systemctl", "disable", "--now", "api-local-lb.service")
		c.unpinHosts()
		return
	}
	// preflight: kubelet.conf server host should be cp_endpoint,
	// else the hosts pin does not affect this node's kubelet (warn
	// only — node may legitimately use a static IP).
	if kb, err := os.ReadFile(r.hp("/var/lib/k0s/kubelet.conf")); err == nil {
		re := regexp.MustCompile(`server:\s*https://([^:/\s]+)`)
		if m := re.FindSubmatch(kb); m != nil && string(m[1]) != c.v("cp_endpoint") {
			slog.Warn("T12: kubelet.conf server host != cp_endpoint — pin has no effect on kubelet",
				"host", string(m[1]), "cp_endpoint", c.v("cp_endpoint"))
		}
	} else {
		// Best-effort preflight — a static-IP kubelet is legitimate;
		// the pin checks below are the group's real signal.
		slog.Warn("T12: kubelet.conf unreadable — skipping server-URL check",
			"path", "/var/lib/k0s/kubelet.conf", "error", err)
	}
	tctx := c.tplCtx() // includes api_lb_probe_reachable (names)
	cfg, err := r.render("api-local-lb.haproxy.cfg.j2", tctx)
	if err != nil {
		c.err("T12 render", "error", err)
		return
	}
	// haproxy install only when missing or wrong pinned version.
	out, _ := r.run(ctx, "dpkg-query", "-W", "-f=${Status} ${Version}", "haproxy")
	ver := c.v("api_lb_haproxy_version")
	if !strings.Contains(out, "install ok installed") ||
		(ver != "" && !strings.Contains(out, ver)) {
		// The deb must live on a host-visible path: download() writes
		// in the container mount ns while apt-get runs via nsenter in
		// the host's — /tmp/hostconfig doesn't exist there. The
		// watchdog state dir is mounted rw in the DS and already
		// ensured by groupWatchdog; on standalone hp() is identity.
		debFile := c.v("api_lb_haproxy_deb_file")
		hostDeb := "/var/lib/node-watchdog/" + debFile
		local := r.hp(hostDeb)
		r.ensureDir("/var/lib/node-watchdog", 0o755)
		if !(fileExistsNoRoot(local) && sha256FileOK(local, c.v("api_lb_haproxy_deb_sha256"))) {
			if err := download(ctx, c.v("api_lb_haproxy_deb_url"), local, c.v("api_lb_haproxy_deb_sha256")); err != nil {
				c.err("T12: haproxy deb download",
					"url", c.v("api_lb_haproxy_deb_url"), "deb", hostDeb, "error", err)
				return
			}
		}
		if _, err := r.run(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "install", "-y", hostDeb); err != nil {
			c.err("T12: haproxy deb install failed — continuing with installed version",
				"deb", hostDeb, "error", err)
		}
	}
	// distro haproxy.service ships /etc/haproxy/haproxy.cfg (:80
	// frontend) — A1 runs a dedicated unit; keep the distro one off.
	r.run(ctx, "systemctl", "disable", "--now", "haproxy.service")
	r.ensureDir("/etc/haproxy", 0o755)
	cfgChanged, _ := r.writeManaged("/etc/haproxy/api-local-lb.cfg", cfg, 0o644)
	// validate cfg before touching the unit (ansible fails the run).
	if out, err := r.run(ctx, "/usr/sbin/haproxy", "-c", "-f", "/etc/haproxy/api-local-lb.cfg"); err != nil {
		c.err("T12: haproxy -c failed — not starting/restarting api-local-lb",
			"conf", "/etc/haproxy/api-local-lb.cfg", "out", out, "error", err)
		return
	}
	// Root-netns DNAT (pod host-netns consumers). FAIL-OPEN via
	// api-local-lb.service ExecStartPost/ExecStopPost hooks in the
	// unit template — the table dies with the LB.
	nftChanged := false
	if vip := c.v("api_lb_vip_ip"); vip != "" && vip != "None" {
		if _, err := r.run(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "install", "-y", "nftables"); err != nil {
			c.err("T12: nftables install failed — nft -c may fail below",
				"error", err)
		}
		var rules strings.Builder
		for _, p := range c.apiLBDnatPorts() {
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
		nftChanged, _ = r.writeManaged("/etc/api-local-dnat.nft", []byte(nft), 0o644)
		if out, err := r.run(ctx, "nft", "-c", "-f", "/etc/api-local-dnat.nft"); err != nil {
			c.err("T12: nft ruleset failed nft -c — DNAT not applied",
				"path", "/etc/api-local-dnat.nft", "vip", vip,
				"out", out, "error", err)
			return
		}
	}
	// sweep the invented separate-unit deployment of the first port.
	r.run(ctx, "systemctl", "disable", "--now", "api-lb-dnat.service")
	r.removeManaged("/etc/systemd/system/api-lb-dnat.service")
	r.removeManaged("/etc/nftables.d/api-lb-dnat.nft")
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
	if cfgChanged || nftChanged {
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
		m, _ := it.(*topology.OMap)
		if m == nil {
			continue
		}
		n, p := strOf(m, "name"), strOf(m, "port")
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
		if !containsSS(ports, lane[1]) {
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
		m, _ := it.(*topology.OMap)
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
		host, port, _ := strings.Cut(as, ":")
		if port == "" {
			port = "6443"
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

// hostsBlockRe matches a managed block in BOTH marker styles: the
// ansible blockinfile `{mark} <name> managed block` and the first
// port's `ANSIBLE MANAGED BLOCK - <name>` — stale blocks of either
// style must be replaced/removed (dead pin otherwise).
func hostsBlockRe(mark string) *regexp.Regexp {
	q := regexp.QuoteMeta(mark)
	return regexp.MustCompile(
		`(?ms)# BEGIN ` + q + ` managed block\n.*?# END ` + q + ` managed block\n?|` +
			`(?ms)# BEGIN ANSIBLE MANAGED BLOCK - ` + q + `\n.*?# END ANSIBLE MANAGED BLOCK - ` + q + `\n?`)
}

// blockInHosts upserts an ansible-style managed block in /etc/hosts.
func (c *cyc) blockInHosts(mark, block string) {
	hosts, _ := os.ReadFile(c.r.hp("/etc/hosts"))
	re := hostsBlockRe(mark)
	var nh []byte
	if re.Match(hosts) {
		nh = re.ReplaceAll(hosts, []byte(block))
	} else {
		nh = append(append([]byte{}, hosts...), []byte(block)...)
	}
	c.r.writeManaged("/etc/hosts", nh, 0o644)
}

func (c *cyc) removeFromHosts(mark string) {
	hosts, err := os.ReadFile(c.r.hp("/etc/hosts"))
	if err != nil {
		c.err("T12: cannot read /etc/hosts — managed block not removed",
			"mark", mark, "error", err)
		return
	}
	nh := hostsBlockRe(mark).ReplaceAll(hosts, nil)
	if string(nh) != string(hosts) {
		c.r.writeManaged("/etc/hosts", nh, 0o644)
	}
}

// pinHosts — blockinfile `# {mark} api-local-lb managed block`.
func (c *cyc) pinHosts() {
	block := "# BEGIN api-local-lb managed block\n127.0.0.1 " + c.v("cp_endpoint") +
		"\n# END api-local-lb managed block\n"
	hosts, _ := os.ReadFile(c.r.hp("/etc/hosts"))
	if len(hosts) > 0 && hosts[len(hosts)-1] != '\n' {
		block = "\n" + block
	}
	c.blockInHosts("api-local-lb", block)
}

func (c *cyc) unpinHosts() {
	c.removeFromHosts("api-local-lb")
}

// ---------- verify (informational) ----------

// groupVerify is the informational tail group (ansible debug/assert
// parity) — its probes only log; they never count a group error.
func (c *cyc) groupVerify() {
	if out, err := c.r.run(c.ctx, "getent", "ahosts", c.v("cp_endpoint")); err == nil {
		slog.Info("hostconfig verify: cp_endpoint resolves", "getent", out)
	} else {
		slog.Warn("hostconfig verify: cp_endpoint does not resolve",
			"cp_endpoint", c.v("cp_endpoint"), "error", err)
	}
	if out, err := c.r.run(c.ctx, "sysctl", "-n",
		"net.ipv4.tcp_congestion_control", "net.core.default_qdisc"); err == nil {
		slog.Info("hostconfig verify: cc/qdisc", "sysctl", out)
	} else {
		slog.Warn("hostconfig verify: cc/qdisc unreadable", "error", err)
	}
}

// ---------- download helpers ----------

func download(ctx context.Context, url, dst, wantSHA256 string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
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
	f.Close()
	if err != nil {
		return err
	}
	if wantSHA256 != "" && !strings.EqualFold(wantSHA256, fmt.Sprintf("%x", h.Sum(nil))) {
		os.Remove(tmp)
		return fmt.Errorf("download %s: sha256 mismatch", url)
	}
	return os.Rename(tmp, dst)
}

// untarInstall extracts member name from a .tar.gz and atomically
// installs to dst.
func untarInstall(tgz, member, dst string, mode os.FileMode) error {
	f, err := os.Open(tgz)
	if err != nil {
		return err
	}
	defer f.Close()
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
			out.Close()
			if err != nil {
				// sweep the partial tmp — a truncated member must not
				// linger next to the live binary.
				os.Remove(tmp)
				return err
			}
			return os.Rename(tmp, dst)
		}
	}
}

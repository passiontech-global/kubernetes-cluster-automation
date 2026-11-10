// group_kubelet.go — T7+T17 image-pulls + kubelet config tuning:
// k0s unit --kubelet-extra-args converge, the kubelet config live
// patch (maxParallelImagePulls/kubeAPIQPS/podPidsLimit/
// evictionMinimumReclaim) and the containerd pull drop-ins.
package hostconfig

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
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
	// --kubelet-extra-args= may be bare or single/double-quoted. The
	// quoted arms MUST come first: a bare \S+ match would swallow a
	// closing quote and appended \x20-flags would land OUTSIDE the
	// value — bare k0s argv with literal backslash-x-2-0 garbage.
	t7ExtraArgsRe = regexp.MustCompile(`--kubelet-extra-args=("[^"\n]*"|'[^'\n]*'|\S+)`)
	t7DataDirRe   = regexp.MustCompile(`ExecStart=.*k0s (worker|controller) --data-dir=\S+`)
)

// t7AppendExtraArgs appends extra inside the --kubelet-extra-args
// VALUE — before the closing quote when the value is quoted — so the
// literal \x20 separators stay within the kubelet arg string.
// ok=false means the value has an UNTERMINATED quote ("abc with no
// closing ") — appending would merge flags into a string systemd
// tokenizes differently than intended, so the caller drops the whole
// rewrite rather than emit a mangled ExecStart.
func t7AppendExtraArgs(u, extra string) (string, bool) {
	ok := true
	out := t7ExtraArgsRe.ReplaceAllStringFunc(u, func(m string) string {
		v := strings.TrimPrefix(m, "--kubelet-extra-args=")
		if v != "" && (v[0] == '"' || v[0] == '\'') {
			if len(v) < 2 || v[len(v)-1] != v[0] {
				// Quote opened but never closed — leave m untouched
				// and refuse the rewrite.
				ok = false
				return m
			}
			return m[:len(m)-1] + extra + m[len(m)-1:]
		}
		return m + extra
	})
	return out, ok
}

// kubeletCfgPath ports the T7 discovery: --config of the RUNNING
// kubelet first (via /proc cmdline — the only source that follows a
// non-listed --config), the on-disk candidates only as fallback when
// the daemon isn't running or exposes no --config. Candidate-first
// would silently patch a stale unit file (e.g. a /run/k0s leftover
// beside the live /var/lib/k0s path) that the running kubelet never
// reads — the write would succeed and the heal silently not happen.
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

// evictionMinReclaimMap returns the expected evictionMinimumReclaim
// nested map (var kubelet_eviction_min_reclaim as mapping, else the
// ansible hardcoded block order).
func (c *cyc) evictionMinReclaimMap() *jinja.OMap {
	if om, ok := c.t.Vars.Get("kubelet_eviction_min_reclaim").(*jinja.OMap); ok && om.Len() > 0 {
		return om
	}
	m := jinja.NewOMap()
	m.Set("memory.available", "200Mi")
	m.Set("nodefs.available", "1Gi")
	m.Set("imagefs.available", "2Gi")
	return m
}

// evictionBlock renders the evictionMinimumReclaim block (ansible
// t17_emr_block shape — sub-keys quoted when string).
func evictionBlock(m *jinja.OMap) string {
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
func emrMapEqual(cur string, want *jinja.OMap) bool {
	v, err := jinja.DecodeYAML([]byte(cur))
	if err != nil {
		return false
	}
	got, ok := v.(*jinja.OMap)
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
	shutdownGrace := defStr(c.v("kubelet_shutdown_grace_period"), "60s")
	shutdownGraceCritical := defStr(c.v("kubelet_shutdown_grace_period_critical_pods"), "20s")

	// Rendered-config charset gates (the non-shell sibling of
	// flagsOK below): these scalars land verbatim in the kubelet
	// KubeletConfiguration YAML and the containerd toml, where a
	// newline/colon in a var would inject an arbitrary key the
	// consuming daemon parses wholesale. maxPar renders into BOTH
	// files, dl into the toml — gate each once at derivation so a
	// refusal skips both renders with one counted error per scalar.
	maxParOK := c.cfgScalar("kubelet_max_parallel_image_pulls", maxPar)
	dlOK := c.cfgScalar("containerd_max_concurrent_downloads", dl)

	// Flags go INSIDE --kubelet-extra-args with literal \x20
	// separators — a real space would turn them into bare k0s argv.
	// qps/burst land raw inside ExecStart — a vars value carrying
	// whitespace/metachars would corrupt the unit (a newline splits
	// ExecStart into a bogus second line). Same charset gate the
	// sh -c interpolations use; a refused value skips ONLY the unit
	// rewrite — the kubelet-cfg/containerd converge below does not
	// interpolate them.
	flagsOK := c.shToken("kubelet_registry_qps", qps) &&
		c.shToken("kubelet_registry_burst", burst)
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
		if flagsOK {
			if strings.Contains(u2, "--kubelet-extra-args") {
				ok := true
				if !strings.Contains(u2, "--serialize-image-pulls") {
					u2, ok = t7AppendExtraArgs(u2, `\x20--serialize-image-pulls=false`)
				}
				if ok && !strings.Contains(u2, "--registry-qps") {
					u2, ok = t7AppendExtraArgs(u2,
						`\x20--registry-qps=`+qps+`\x20--registry-burst=`+burst)
				}
				if !ok {
					// Unterminated quote — leave the unit file
					// untouched rather than write a mangled ExecStart.
					c.err("T7: unterminated --kubelet-extra-args quote — unit left untouched",
						"path", p)
					continue
				}
			} else {
				// Unit without extra-args: inject full token after
				// `k0s (worker|controller) --data-dir=\S+` (bootstrap
				// installFlags parity).
				u2 = t7DataDirRe.ReplaceAllString(u2,
					"${0} --kubelet-extra-args=--serialize-image-pulls=false\\x20--registry-qps="+
						qps+"\\x20--registry-burst="+burst)
			}
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
			// insertafter '^kind: KubeletConfiguration'. Each value is
			// charset-gated (see maxParOK above) — kubelet parses the
			// file wholesale, so a newline in a var would inject an
			// arbitrary key into KubeletConfiguration. A refused
			// value skips ONLY its own line; the remaining keys
			// converge untouched.
			for _, kv := range []struct {
				key string
				val string
				ok  bool
			}{
				{"maxParallelImagePulls", maxPar, maxParOK},
				{"kubeAPIQPS", apiQPS, c.cfgScalar("kubelet_api_qps", apiQPS)},
				{"kubeAPIBurst", apiBurst, c.cfgScalar("kubelet_api_burst", apiBurst)},
				{"podPidsLimit", pids, c.cfgScalar("kubelet_pod_pids_limit", pids)},
				// host-protection-drop-ins: k0sworker-profile parity — graceful node
				// shutdown must have a kubelet window to drain in;
				// group_base.go derives logind's InhibitDelayMaxSec
				// from the same kubelet_shutdown_grace_period var.
				// Values come from the node-config-agent defaults
				// (kubelet_shutdown_grace_period*) and match the
				// k0sctl worker profiles.
				{"shutdownGracePeriod", shutdownGrace,
					c.cfgScalar("kubelet_shutdown_grace_period", shutdownGrace)},
				{"shutdownGracePeriodCriticalPods", shutdownGraceCritical,
					c.cfgScalar("kubelet_shutdown_grace_period_critical_pods", shutdownGraceCritical)},
			} {
				if !kv.ok {
					continue
				}
				s = lineInFile(s, "(?m)^"+kv.key+":", kv.key+": "+kv.val,
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
			// The write result matters: a failed write must not fall
			// through silently to the containerd drop-ins with the
			// summary unable to tell patched from skipped.
			if ch, err := r.writeManaged(cfgPath, []byte(s), 0o644); err != nil {
				c.err("T7: kubelet config write failed", "path", cfgPath, "error", err)
			} else if ch {
				logger().Info("T7: kubelet config live-patched", "path", cfgPath)
			}
		}
	}

	// containerd drop-ins — containerd-2.x plugin paths
	// ([plugins.'io.containerd.cri.v1.images']). NO restart. The two
	// rendered scalars are the gates computed at derivation above; a
	// refusal skips the whole file (both values are assignments in
	// it) with the error already counted.
	_ = r.ensureDir("/etc/k0s/containerd.d", 0o755)
	if maxParOK && dlOK {
		_, _ = r.writeManaged("/etc/k0s/containerd.d/90-parallel-pulls.toml", []byte(fmt.Sprintf(
			`# Managed by node-config-agent - T7 parallel image pulls.
# Cap concurrent layer downloads now that kubelet has
# serializeImagePulls off — bounds pull-storm bandwidth;
# pairs with maxParallelImagePulls=%s at the kubelet.
[plugins.'io.containerd.cri.v1.images']
  max_concurrent_downloads = %s
`, maxPar, dl)), 0o644)
	}
	_, _ = r.writeManaged("/etc/k0s/containerd.d/91-registry-mirror.toml", []byte(
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
	_ = r.ensureDir("/etc/containerd/certs.d", 0o755)
	// sweep the buggy drop-in + restart behaviour of the first port
	_, _ = r.removeManaged("/etc/k0s/containerd.d/parallel-pulls.toml")
}

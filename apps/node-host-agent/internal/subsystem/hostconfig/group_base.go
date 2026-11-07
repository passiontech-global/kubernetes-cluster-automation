// group_base.go — T1/T2/A4/T16 sysctls, k0s limits drop-ins, hostname
// pin, journald integrity/persistence probe and the agent self-stage.
package hostconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
)

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
			"# Managed by node-config-agent - BBR+fq for the interdc trunk path\n"},
		{"/etc/sysctl.d/99-k8s-network-tuning.conf", c.t16Pairs(),
			"# Managed by node-config-agent - T16 network/sysctl tuning\n"},
	} {
		if ch, err := r.writeManaged(f.path, sysctlFile(f.pairs, f.hdr), 0o644); err == nil && ch {
			changed = true
		}
	}
	if ch, _ := r.writeManaged("/etc/modules-load.d/interdc-bbr.conf",
		[]byte("# Managed by node-config-agent - BBR for the interdc trunk path\ntcp_bbr\n"), 0o644); ch {
		changed = true
	}
	if _, err := r.run(ctx, "modprobe", "tcp_bbr"); err != nil {
		c.err("base: modprobe failed — BBR unavailable until the module loads",
			"module", "tcp_bbr", "error", err)
	}
	if _, err := r.run(ctx, "modprobe", "nf_conntrack"); err != nil {
		c.err("base: modprobe failed — conntrack sysctls may not apply",
			"module", "nf_conntrack", "error", err)
	}
	if changed {
		r.actions.WithLabelValues("sysctl --system").Inc()
		if _, err := r.run(ctx, "sysctl", "--system"); err != nil {
			c.err("base: sysctl --system failed — new sysctl files written but not applied",
				"error", err)
		}
	}
	// A4 assert: effective == expected (informational fail like
	// ansible) — best-effort verify; the apply failures above are
	// what count the group error.
	out, _ := r.run(ctx, "sysctl", "-n", "net.ipv4.tcp_congestion_control", "net.core.default_qdisc")
	lines := strings.Fields(out)
	want := []string{c.sysctlVal("bbr_sysctls", 0), c.sysctlVal("bbr_sysctls", 1)}
	if len(lines) < 2 || lines[0] != want[0] || lines[1] != want[1] {
		logger().Warn("BBR/fq not effective — kernel values differ from rendered sysctls",
			"got", out, "want", strings.Join(want, " "))
	}

	// T2 k0sworker limits drop-in.
	if c.worker() {
		_ = c.r.ensureDir("/etc/systemd/system/k0sworker.service.d", 0o755)
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

	// W10-KR4 k0scontroller limits drop-in — same fd/task headroom as
	// the worker unit so systemd never caps the controller's thread
	// count below kernel pid_max during reconcile bursts.
	if c.controller() {
		_ = c.r.ensureDir("/etc/systemd/system/k0scontroller.service.d", 0o755)
		if ch, _ := r.writeManaged("/etc/systemd/system/k0scontroller.service.d/10-limits.conf",
			[]byte(fmt.Sprintf(`# Managed by node-config-agent - explicit fd/task limits for k0s controller
[Service]
LimitNOFILE=%s
LimitNPROC=infinity
TasksMax=infinity
`, c.v("k0scontroller_limit_nofile"))), 0o644); ch {
			r.daemonReload(ctx)
		}
		// W13-CP2: clamp GOMEMLIMIT so the per-child soft cap can
		// never leave the unit's sibling processes without room under
		// MemoryMax (the multi-child cgroup OOMKill shape).
		c.k0scontrollerGoMemlimitSumGuard()
	}

	// hostname -> 127.0.1.1 in /etc/hosts (lineinfile parity).
	hosts, hostsErr := os.ReadFile(r.hp("/etc/hosts"))
	if hostsErr != nil && !os.IsNotExist(hostsErr) {
		// Best-effort pre-warning only — the writeManaged failure
		// below is what counts the group error.
		logger().Warn("base: cannot read /etc/hosts — hostname pin update will fail",
			"error", hostsErr)
	}
	hn := c.r.cfg.NodeName
	// The separator must be a non-newline whitespace — bare `\s`
	// could eat the newline after a value-less `127.0.1.1` line and
	// let the match swallow the NEXT line on replace.
	re := regexp.MustCompile(`(?m)^\s*127\.0\.1\.1[ \t].*$`)
	line := "127.0.1.1 " + hn
	if m := re.Find(hosts); m != nil {
		// The pin must carry THIS hostname as a whole field — a
		// substring Contains matched "127.0.1.1 worker-10" when hn
		// was "worker-1" and left the wrong pin live.
		pinned := false
		for _, f := range strings.Fields(string(m))[1:] {
			if f == hn {
				pinned = true
				break
			}
		}
		if !pinned {
			if nh := re.ReplaceAll(hosts, []byte(line)); string(nh) != string(hosts) {
				_, _ = r.writeManaged("/etc/hosts", nh, 0o644)
			}
		}
	} else {
		// Glue guard: a hosts file without a trailing newline must
		// not fuse the pin onto the last existing line.
		if len(hosts) > 0 && hosts[len(hosts)-1] != '\n' {
			hosts = append(hosts, '\n')
		}
		nh := append(hosts, []byte(line+"\n")...)
		_, _ = r.writeManaged("/etc/hosts", nh, 0o644)
	}

	// Journald persistence BEFORE the integrity probe: on standalone
	// hosts the drop-in converge below is what guarantees the probe's
	// silent-journald restart lands on Storage=persistent, and a
	// drop-in/dir change already bounced journald this cycle
	// (c.journaldRestarted) so the probe must not spend the restart
	// budget a second time.
	c.journaldPersistence()

	// A5 (lightweight hostconfig half — workerhygiene owns the
	// unit-scoped probe): journald integrity. A corrupt journal or an
	// abnormally empty read while journal files exist on disk (post
	// hard-reboot truncation) means logging is silently dead; rotate
	// + vacuum so journald recovers. A journald producing NO files at
	// all while a storage root exists (started before the dir
	// appeared, or lost them under it) is restarted instead — the
	// rotate remedy cannot create files.
	c.journaldIntegrity()

	// Self-stage the agent binary on the host for hostPath-mounted
	// consumers (concourse-worker-init Cach A mounts
	// /usr/local/bin/node-host-agent hostPath:File read-only). The
	// standalone systemd deployment ships the binary by other means.
	if !r.cfg.Standalone {
		c.selfStageBinary()
	}
}

// journaldRotateCooldown caps how often journaldIntegrity may run
// rotate+vacuum (last-journald-rotate latch in the watchdog state
// dir — last-* names are janitor-safe); journaldRestartCooldown is
// the same budget for the silent-journald restart remedy
// (last-journald-restart).
const (
	journaldRotateCooldown  = time.Hour
	journaldRestartCooldown = time.Hour
)

// journaldIntegrity is the cheap journald probe groupBase runs every
// cycle. Three verdicts:
//
//   - CORRUPT — `journalctl` prints corruption markers, or returns
//     nothing at all while journal files are on disk (post
//     hard-reboot truncation). Remedy: `journalctl --rotate
//     --vacuum-time=3d` so journald recovers (last-journald-rotate
//     cooldown).
//   - SILENT — journalctl reports "No journal files" or produces
//     literally nothing while a journal storage root exists: journald
//     is running but writing nowhere (started before /var/log/journal
//     appeared, or lost its files under it — the cicd controller
//     incident, an empty /var/log/journal/<machine-id> + "No journal
//     files were found."). Rotate cannot create files; the remedy is
//     `systemctl restart systemd-journald`, which journaldStorage
//     has already pointed at persistent storage this cycle
//     (last-journald-restart cooldown). The storage-root gate keeps
//     journald-less minimal hosts out — there silence is
//     configuration, not a fault.
//
// A missing journalctl or a failed read without corruption markers is
// NEITHER — the tool may simply be absent (minimal image) and either
// remedy would fail anyway.
func (c *cyc) journaldIntegrity() {
	r, ctx := c.r, c.ctx
	// No -q: --quiet suppresses "No journal files were found." — the
	// incident signature the SILENT verdict needs (the notice is a
	// journald diagnostic on stderr, folded into out by the Runner).
	out, err := r.run(ctx, "journalctl", "-n", "5", "--no-pager")
	low := strings.ToLower(out)
	corrupt := strings.Contains(low, "corrupt") ||
		strings.Contains(low, "invalid object") ||
		strings.Contains(low, "failed to open journal")
	empty := err == nil && strings.TrimSpace(out) == ""
	files := false
	for _, pat := range []string{
		"/var/log/journal/*/*.journal*",
		"/run/log/journal/*/*.journal*",
	} {
		if m, gerr := filepath.Glob(r.hp(pat)); gerr == nil && len(m) > 0 {
			files = true
			break
		}
	}
	if empty && files {
		// Abnormally empty read: journal files exist on disk but the
		// journal returns no entries at all.
		corrupt = true
	}
	// FilesGone counts even on a non-zero exit — the "No journal
	// files" notice is positive evidence journald has no storage,
	// unlike a bare exec failure. The empty-and-no-files half keeps
	// the err==nil gate: a failed exec with empty output is the
	// missing-binary case, not blindness.
	silent := !corrupt && c.journalStoragePresent() &&
		(journalwatch.FilesGone(out) || (empty && !files))
	switch {
	case corrupt:
		// Cooldown latch like nethealth's last-* budgets: a persistently
		// corrupt (or false-positive) probe would otherwise re-run
		// rotate+vacuum — and re-fail — every cycle, pinning errs and
		// hammering the journal on every converge. The last-* name is
		// janitor-safe (only state-* latches are swept).
		if !r.state.RateOK("last-journald-rotate", journaldRotateCooldown) {
			logger().Warn("base: journald journal still corrupt — rotate+vacuum in cooldown, skipping",
				"cooldown", journaldRotateCooldown.String())
			return
		}
		logger().Warn("base: journald journal corrupt/abnormally empty — rotating + vacuuming",
			"action", "journalctl --rotate --vacuum-time=3d",
			"probe_out", out)
		r.actions.WithLabelValues("journalctl --rotate --vacuum-time=3d").Inc()
		// Spend on the attempt: a failing rotate retries next cycle no
		// more than once per cooldown window.
		_ = r.ensureDir(watchdogStateDir, 0o755)
		r.state.RateSpend("last-journald-rotate")
		// runLong: vacuum of a multi-GB journal on a slow disk blows past
		// the interactive command budget.
		if vout, verr := r.runLong(ctx, "journalctl", "--rotate", "--vacuum-time=3d"); verr != nil {
			c.err("base: journalctl rotate/vacuum failed",
				"out", vout, "error", verr)
		}
	case silent:
		if c.journaldRestarted {
			// journaldStorage already bounced journald this cycle —
			// give it the rest of the converge to open files; if the
			// probe is still silent next cycle the remedy fires then
			// (still inside the restart cooldown budget).
			logger().Info("base: journald silent — already restarted by the persistence converge this cycle")
			return
		}
		if !r.state.RateOK("last-journald-restart", journaldRestartCooldown) {
			logger().Warn("base: journald still writing no journal files — restart in cooldown, skipping",
				"cooldown", journaldRestartCooldown.String())
			return
		}
		logger().Warn("base: journald writing no journal files though storage exists — restarting",
			"action", "systemctl restart systemd-journald.service",
			"probe_out", out)
		// Spend on the attempt: a failing restart retries no more
		// than once per cooldown window.
		_ = r.ensureDir(watchdogStateDir, 0o755)
		r.state.RateSpend("last-journald-restart")
		r.restartService(ctx, "systemd-journald.service")
	}
}

// journalStoragePresent mirrors journalwatch.Tracker.Present for the
// HostRoot view: true while /var/log/journal or /run/log/journal
// exists — the "journald should be writing" witness that gates the
// SILENT verdict.
func (c *cyc) journalStoragePresent() bool {
	for _, d := range []string{"/var/log/journal", "/run/log/journal"} {
		if fi, err := os.Stat(c.r.hp(d)); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

// selfStageBinary mirrors the RUNNING agent binary out to the host's
// /usr/local/bin/node-host-agent. The DS mounts /host/usr/local rw —
// the host copy lets concourse-worker-init run the exact same build
// inside the worker container without baking it into the concourse
// image. SHA256-compared every cycle; writeManaged does the atomic
// tmp + chmod 0755 + rename so a truncated binary can never be
// bind-mounted by the init container.
func (c *cyc) selfStageBinary() {
	r := c.r
	src, err := os.Executable()
	if err != nil || src == "" {
		src = "/node-host-agent" // container image path (fallback)
	}
	// os.Executable reports "<path> (deleted)" when the binary was
	// replaced in-place — strip the suffix and fall back to the path
	// the DS ships when src is unreadable (same rule
	// resolveLocalBinary uses for the hubsync mirror).
	src = strings.TrimSuffix(src, " (deleted)")
	// Streamed sha + pagecache drop for BOTH sides of the compare:
	// hashing ~30 MB through os.ReadFile every cycle pinned ~60 MB
	// of page cache inside the pod cgroup permanently.
	srcSum, err := pagecache.Sha256File(src)
	if err != nil && src != "/node-host-agent" {
		src = "/node-host-agent"
		srcSum, err = pagecache.Sha256File(src)
	}
	if err != nil {
		c.err("self-stage: cannot read running binary", "path", src, "error", err)
		return
	}
	dst := "/usr/local/bin/node-host-agent"
	if oldSum, err := pagecache.Sha256File(r.hp(dst)); err == nil &&
		oldSum == srcSum {
		// host already carries this exact build — still re-tighten a
		// drifted mode: the hostPath consumer needs the exec bit.
		if fi, serr := os.Stat(r.hp(dst)); serr == nil && fi.Mode().Perm() != 0o755 {
			if cerr := os.Chmod(r.hp(dst), 0o755); cerr != nil {
				c.err("self-stage: chmod 0755 failed", "path", dst, "error", cerr)
			}
		}
		return
	}
	srcb, err := pagecache.ReadFile(src)
	if err != nil {
		c.err("self-stage: cannot read running binary", "path", src, "error", err)
		return
	}
	if _, err := r.writeManaged(dst, srcb, 0o755); err != nil {
		// writeManaged already counted the failure via noteErr —
		// log context only, do not count the same fault twice.
		logger().Error("self-stage: install agent binary on host failed",
			"path", dst, "error", err)
		return
	}
	// writeManaged preserves a pre-existing file's mode — force 0755.
	if err := os.Chmod(r.hp(dst), 0o755); err != nil {
		c.err("self-stage: chmod 0755 failed", "path", dst, "error", err)
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

// T16 pairs — conntrack key only when the module is loaded.
func (c *cyc) t16Pairs() [][2]string {
	p := [][2]string{
		{"net.core.somaxconn", "8192"},
		{"net.core.netdev_max_backlog", "8192"},
		{"net.ipv4.tcp_max_syn_backlog", "8192"},
		{"net.ipv4.ip_local_port_range", "10240 65535"},
		// W12-KR3: reuse TIME_WAIT sockets for new outbound
		// connections — safe with tcp_timestamps on (default), and
		// the difference between a healthy node and EADDRNOTAVAIL on
		// the gateway/proxy churn bursts the port-range width above
		// is sized for.
		{"net.ipv4.tcp_tw_reuse", "1"},
		// W5.1: keep the kernel's ephemeral source-port allocation off
		// ports host daemons LISTEN on — an ephemeral steal of kubelet
		// 10248/10250/10256, NPD 20256, NodePort+Spegel 30000-32767,
		// Nebula UDP 45670 or Cilium WireGuard 51871 wedges the real
		// listener's next bind or blackholes its replies.
		{"net.ipv4.ip_local_reserved_ports", "10248-10260,20256,30000-32767,45670,51871"},
		{"fs.file-max", "2097152"},
		// W10-KR2: pid_max headroom for the thread/FD exhaustion
		// guard (node_agent_threads_utilization_ratio latch).
		{"kernel.pid_max", "4194304"},
		// W10-NM2: QUIC (cloudflared) UDP buffers — the 208KB
		// default drops edge streams under load.
		{"net.core.rmem_max", "7500000"},
		{"net.core.wmem_max", "7500000"},
		{"vm.max_map_count", "524288"},
		{"net.ipv4.neigh.default.gc_thresh1", "8192"},
		{"net.ipv4.neigh.default.gc_thresh2", "32768"},
		{"net.ipv4.neigh.default.gc_thresh3", "65536"},
	}
	// W8-KR2: keyring quota headroom — a full keyring fails
	// keyctl/add_key silently for new sessions.
	if c.r.fileExists("/proc/sys/kernel/keys/root_maxkeys") ||
		fileExistsNoRoot("/proc/sys/kernel/keys/root_maxkeys") {
		p = append(p,
			[2]string{"kernel.keys.root_maxkeys", "1000000"},
			[2]string{"kernel.keys.root_maxbytes", "25000000"},
			[2]string{"kernel.keys.maxkeys", "100000"},
			[2]string{"kernel.keys.maxbytes", "2500000"})
	}
	if c.r.fileExists("/proc/sys/net/netfilter/nf_conntrack_max") ||
		fileExistsNoRoot("/proc/sys/net/netfilter/nf_conntrack_max") {
		p = append(p, [2]string{"net.netfilter.nf_conntrack_max", "262144"})
	}
	// W8-KR2: shrink dead-flow occupancy of the conntrack table —
	// TIME_WAIT/CLOSE_WAIT pileups ate the table on WAN flaps.
	if c.r.fileExists("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait") ||
		fileExistsNoRoot("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait") {
		p = append(p,
			[2]string{"net.netfilter.nf_conntrack_tcp_timeout_time_wait", "30"},
			[2]string{"net.netfilter.nf_conntrack_tcp_timeout_close_wait", "60"})
	}
	// W7-H5: give the IPv6 neighbour cache the same headroom as
	// IPv4 — only when the kernel exposes the ndisc table (IPv6
	// compiled out leaves no gc_thresh3 node to write to; an
	// unconditional key would fail sysctl --system). Values come
	// from the ipv6_neigh_sysctls var (defaults.yaml, same source
	// as tcp_keepalive/bbr) with a hardcoded fallback matching the
	// IPv4 tier so an older vars bundle still gets the tuning.
	if c.r.fileExists("/proc/sys/net/ipv6/neigh/default/gc_thresh3") ||
		fileExistsNoRoot("/proc/sys/net/ipv6/neigh/default/gc_thresh3") {
		var v6 [][2]string
		if c.t != nil {
			v6 = c.sysctlPairs("ipv6_neigh_sysctls")
		}
		if len(v6) == 0 {
			v6 = [][2]string{
				{"net.ipv6.neigh.default.gc_thresh1", "8192"},
				{"net.ipv6.neigh.default.gc_thresh2", "32768"},
				{"net.ipv6.neigh.default.gc_thresh3", "65536"},
			}
		}
		p = append(p, v6...)
	}
	return p
}

// ---------- W13-CP2: k0scontroller GOMEMLIMIT sum guard ----------

// goMemlimitSiblingReserve is the budget the OTHER k0scontroller
// children need inside MemoryMax while the capped child sits at
// GOMEMLIMIT: etcd/kine ~0.9-1.5G + kcm/scheduler ~0.6G +
// konnectivity + non-heap/cgroup overhead (the cicd 2026-10-22..25
// incident shape: 2.4G apiserver + ~2.3G siblings on a 5G unit).
// It bounds the guard at MemoryMax-2GiB, which keeps BOTH documented
// sizing anchors feasible: 2900MiB <= 5G-2G on cicd and ~4500MiB <=
// 7G-2G on the kine-split clusters.
const goMemlimitSiblingReserve = 2 << 30 // 2 GiB

// goMemlimitGuardDropIn is the override file — it sorts AFTER
// 51-go-memlimit.conf lexically, so an Environment=GOMEMLIMIT it
// carries wins over the per-host value only while the guard needs
// to clamp; when the configured value is safe the file is removed
// and 51- stands alone.
const goMemlimitGuardDropIn = "/etc/systemd/system/k0scontroller.service.d/52-go-memlimit-sumguard.conf"

// k0scontrollerGoMemlimitSumGuard is the cgroup-OOMKill side of
// W13-CP2. GOMEMLIMIT is a PER-PROCESS soft cap systemd plants on
// every Go child of k0scontroller.service (kube-apiserver, kine or
// etcd, kube-controller-manager, kube-scheduler,
// konnectivity-server) — no single child's GC ever sees the
// aggregate. If a configured cap leaves less than
// goMemlimitSiblingReserve for the siblings, the SUM of children
// RSS can overrun MemoryMax and the cgroup OOM-kills the whole unit
// (API down 20-45s — fatal on single-controller clusters). The
// guard renders/removes 52-go-memlimit-sumguard.conf:
//
//   - gomemlimit <= MemoryMax - reserve → drop-in removed, the
//     51-go-memlimit.conf value stands;
//   - gomemlimit > cap → drop-in written with the clamped value
//     (its lexical position overrides 51-'s Environment=);
//   - either var missing/unparseable → drop-in removed, nothing to
//     clamp against (fail-open: the per-host maps are the intent).
func (c *cyc) k0scontrollerGoMemlimitSumGuard() {
	r := c.r
	memMax, maxOK := parseByteSize(strOf(
		c.t.Vars.Get("k0scontroller_memory_max_by_host"), r.cfg.NodeName))
	limit, limOK := parseByteSize(strOf(
		c.t.Vars.Get("k0scontroller_go_memlimit_by_host"), r.cfg.NodeName))
	capBytes := memMax - goMemlimitSiblingReserve
	if !maxOK || !limOK || capBytes <= 0 || limit <= capBytes {
		if ch, _ := r.removeManaged(goMemlimitGuardDropIn); ch {
			r.daemonReload(c.ctx)
		}
		return
	}
	clamped := capBytes / (1 << 20) // floor to whole MiB
	logger().Warn("base: k0scontroller GOMEMLIMIT exceeds MemoryMax-"+
		"2GiB sibling reserve — clamping (a single child's soft cap "+
		"must leave room for the other unit children)",
		"configured", strOf(c.t.Vars.Get(
			"k0scontroller_go_memlimit_by_host"), r.cfg.NodeName),
		"memory_max", strOf(c.t.Vars.Get(
			"k0scontroller_memory_max_by_host"), r.cfg.NodeName),
		"clamped_mib", clamped)
	if ch, _ := r.writeManaged(goMemlimitGuardDropIn,
		[]byte(fmt.Sprintf(`# Managed by node-config-agent - W13-CP2 GOMEMLIMIT sum guard
# The configured cap leaves < 2GiB for the unit's other children
# (etcd/kine + kcm + scheduler + konnectivity + non-heap). Sum of
# children RSS must stay under MemoryMax or the cgroup OOM-kills
# the whole control-plane unit. Overrides 51-go-memlimit.conf.
[Service]
Environment=GOMEMLIMIT=%dMiB
`, clamped)), 0o644); ch {
		r.daemonReload(c.ctx)
	}
}

// byteSizeRe parses systemd/Go memory quantities — "7G", "512M",
// "2900MiB", "5GB", "1500MiB", bare bytes.
var byteSizeRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([KMGT](?:i?B)?|B)?$`)

// parseByteSize parses a size string into bytes. K/M/G/T (and their
// *iB/*B forms) are powers of 1024 — the systemd convention both
// MemoryMax and GOMEMLIMIT follow.
func parseByteSize(s string) (int64, bool) {
	m := byteSizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	num, err := strconv.ParseFloat(m[1], 64)
	if err != nil || num < 0 {
		return 0, false
	}
	suffix := strings.ToUpper(m[2])
	suffix = strings.TrimSuffix(suffix, "IB") // "GiB"→"G", "KiB"→"K", "MiB"→"M"
	suffix = strings.TrimSuffix(suffix, "B")  // "GB"→"G", "B"→""
	var mult float64
	switch suffix {
	case "":
		mult = 1
	case "K":
		mult = 1 << 10
	case "M":
		mult = 1 << 20
	case "G":
		mult = 1 << 30
	case "T":
		mult = 1 << 40
	default:
		return 0, false
	}
	return int64(num * mult), true
}

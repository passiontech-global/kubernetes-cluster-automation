// group_base.go — groupBase orchestration: the T1/T2/A4/T16 sysctl
// converge (helpers in group_sysctl.go), k0s limits drop-ins, the
// coredump storm guard, the journald persistence + integrity probes
// (group_journald.go), the gomemlimit-sum guard (group_gomemlimit.go),
// the hostname /etc/hosts pin (group_hosts.go) and the agent
// self-stage.
package hostconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
)

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
	// G1: size the nf_conntrack hash table to the table itself — a
	// small default hashsize leaves long bucket chains that spin
	// ksoftirqd on every lookup under conntrack pressure.
	c.conntrackHashsize()
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

	// Coredump guard: disable host coredump storage — a crashing daemon
	// (or k0s child) dropping multi-hundred-MB cores into
	// /var/lib/systemd/coredump is the classic slow disk-filler;
	// Storage=none + ProcessSizeMax=0 keeps cores unprocessed and
	// unstored. A drop-in change needs the systemd daemon reload to
	// be visible to journald/coredumpctl.
	_ = r.ensureDir("/etc/systemd/coredump.conf.d", 0o755)
	if ch, _ := r.writeManaged("/etc/systemd/coredump.conf.d/99-node-ops.conf",
		[]byte(`# Managed by node-config-agent - coredump storm guard.
# Core dumps are neither stored nor processed; the disk-bloat
# guard no longer has to sweep /var/lib/systemd/coredump.
[Coredump]
Storage=none
ProcessSizeMax=0
`), 0o644); ch {
		// Best-effort reload — coredump.conf.d is read by
		// systemd-coredump on demand, so a failed reload must not
		// fail the whole base group (T10 set-property parity: warn
		// only, the declared state is already on disk).
		r.actions.WithLabelValues("daemon-reload").Inc()
		if err := r.sysd().DaemonReload(ctx); err != nil {
			logger().Warn("base: coredump.conf.d daemon-reload failed",
				"error", err)
		}
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
		// gomemlimit-sum: clamp GOMEMLIMIT so the per-child soft cap can
		// never leave the unit's sibling processes without room under
		// MemoryMax (the multi-child cgroup OOMKill shape).
		c.k0scontrollerGoMemlimitSumGuard()
	}

	// hostname -> 127.0.1.1 in /etc/hosts (lineinfile parity).
	c.hostnamePin()

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

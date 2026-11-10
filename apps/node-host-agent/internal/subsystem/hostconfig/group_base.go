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
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
)

func (c *cyc) groupBase() {
	r := c.r
	ctx := c.ctx
	// T1 inotify + tcp keepalive (ansible.posix.sysctl per-key files).
	// Vars-derived values are charset-gated BEFORE the render — a
	// newline or metachar in a var would render as extra `key = value`
	// lines the next `sysctl --system` applies verbatim. A refused (or
	// unset) value drops its PAIR: the file converges with the
	// remaining pairs, the refusal is counted per dropped pair.
	var inotifyPairs [][2]string
	for _, kv := range []struct{ key, varName string }{
		{"fs.inotify.max_user_instances", "inotify_max_user_instances"},
		{"fs.inotify.max_user_watches", "inotify_max_user_watches"},
	} {
		v := c.v(kv.varName)
		if v == "" {
			continue // var absent — converge nothing rather than a valueless line
		}
		if !c.cfgSysctlVal(kv.varName, v) {
			continue // refused + already counted
		}
		inotifyPairs = append(inotifyPairs, [2]string{kv.key, v})
	}
	changed := false
	for _, f := range []struct {
		path  string
		pairs [][2]string
		hdr   string
	}{
		{"/etc/sysctl.d/99-k8s-inotify.conf", inotifyPairs,
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
	// what count the group error. Skipped entirely when
	// bbr_sysctls converges nothing — an absent var is not an
	// error above, and asserting "" against the live values would
	// warn forever on nodes that simply don't set it.
	if pairs := c.sysctlPairs("bbr_sysctls"); len(pairs) > 0 {
		out, _ := r.run(ctx, "sysctl", "-n", "net.ipv4.tcp_congestion_control", "net.core.default_qdisc")
		lines := strings.Fields(out)
		want := []string{c.sysctlVal("bbr_sysctls", 0), c.sysctlVal("bbr_sysctls", 1)}
		if len(lines) < 2 || lines[0] != want[0] || lines[1] != want[1] {
			logger().Warn("BBR/fq not effective — kernel values differ from rendered sysctls",
				"got", out, "want", strings.Join(want, " "))
		}
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
		// The value is a systemd assignment rendered verbatim — a
		// newline/metachar var would inject a SECOND directive
		// systemd applies; an unparsable one is dropped at
		// daemon-reload and the unit silently keeps stock fd limits.
		// Refuse both: skip the write, count the error. An empty
		// var is absent, not refused — gating it here (like the
		// sysctl pairs above) keeps it from erroring every cycle.
		if nofile := c.v("k0sworker_limit_nofile"); nofile != "" && c.cfgLimitNOFILE("k0sworker_limit_nofile", nofile) {
			if ch, _ := r.writeManaged("/etc/systemd/system/k0sworker.service.d/10-limits.conf",
				[]byte(fmt.Sprintf(`# Managed by node-config-agent - explicit fd/task limits for k0s worker
[Service]
LimitNOFILE=%s
LimitNPROC=infinity
TasksMax=infinity
`, nofile)), 0o644); ch {
				r.daemonReload(ctx)
			}
		}
	}

	// k0scontroller-limits k0scontroller limits drop-in — same fd/task headroom as
	// the worker unit so systemd never caps the controller's thread
	// count below kernel pid_max during reconcile bursts.
	if c.controller() {
		_ = c.r.ensureDir("/etc/systemd/system/k0scontroller.service.d", 0o755)
		// Same verbatim-assignment gate as the worker drop-in above.
		if nofile := c.v("k0scontroller_limit_nofile"); nofile != "" && c.cfgLimitNOFILE("k0scontroller_limit_nofile", nofile) {
			if ch, _ := r.writeManaged("/etc/systemd/system/k0scontroller.service.d/10-limits.conf",
				[]byte(fmt.Sprintf(`# Managed by node-config-agent - explicit fd/task limits for k0s controller
[Service]
LimitNOFILE=%s
LimitNPROC=infinity
TasksMax=infinity
`, nofile)), 0o644); ch {
				r.daemonReload(ctx)
			}
		}
		// gomemlimit-sum: clamp GOMEMLIMIT so the per-child soft cap can
		// never leave the unit's sibling processes without room under
		// MemoryMax (the multi-child cgroup OOMKill shape).
		c.k0scontrollerGoMemlimitSumGuard()
	}

	// host-protection-drop-ins host-level protection drop-ins, written idempotently
	// (writeManaged is a sha256-gated atomic write; a no-diff cycle
	// rewrites nothing):
	//   - networkd: never manage the CNI's foreign routes/rules — a
	//     networkd restart wiping cilium/calico routes is the classic
	//     "node loses its pod network after an upgrade" outage.
	//   - logind: InhibitDelayMaxSec derives from the SAME
	//     kubelet_shutdown_grace_period var groupPulls renders into
	//     the kubelet's shutdownGracePeriod (+5s scheduling buffer,
	//     floor 65) — the kubelet's graceful-shutdown window must fit
	//     inside logind's inhibit delay or systemd kills the node
	//     mid-drain. logind only parses logind.conf at start/reload,
	//     so a changed drop-in triggers a unit RELOAD below (reload
	//     only — a restart tears down sessions).
	//   - apt: keep unattended-upgrades off the packages a k0s node
	//     depends on, and off automatic reboots.
	_ = r.ensureDir("/etc/systemd/networkd.conf.d", 0o755)
	_, _ = r.writeManaged("/etc/systemd/networkd.conf.d/99-preserve-cni-routes.conf",
		[]byte(`# Managed by node-config-agent - host-protection-drop-ins CNI route preservation.
# networkd must not flush routes/rules the CNI installed.
[Network]
ManageForeignRoutes=no
ManageForeignRoutingPolicyRules=no
`), 0o644)
	_ = r.ensureDir("/etc/systemd/logind.conf.d", 0o755)
	// The rendered value is the numeric seconds — the raw var never
	// enters the file, so nothing can inject comment/section lines.
	grace := defStr(c.v("kubelet_shutdown_grace_period"), "60s")
	if ch, _ := r.writeManaged("/etc/systemd/logind.conf.d/99-k8s-shutdown.conf",
		[]byte(`# Managed by node-config-agent - host-protection-drop-ins graceful kubelet shutdown.
# InhibitDelayMaxSec tracks kubelet_shutdown_grace_period (the kubelet's
# shutdownGracePeriod) plus a 5s scheduling buffer.
[Login]
InhibitDelayMaxSec=`+strconv.FormatInt(logindInhibitDelaySecs(grace), 10)+`
`), 0o644); ch {
		// The drop-in is INERT until logind re-parses its config
		// (kubelet-graceful-shutdown: a written delay sat unloaded until the next
		// reboot). `systemctl reload systemd-logind.service` is the
		// safe apply — the unit is Type=notify-reload with
		// ReloadSignal=SIGHUP, no session teardown (a restart WOULD
		// drop sessions/inhibits mid-shutdown). Warn-only on failure,
		// coredump daemon-reload parity: the declared state is on
		// disk and lands at the next reload/reboot.
		r.actions.WithLabelValues("reload:systemd-logind.service").Inc()
		if err := r.sysd().ReloadService(ctx, "systemd-logind.service"); err != nil {
			logger().Warn("base: systemd-logind reload failed — drop-in inert until the next reload/reboot",
				"error", err)
		}
	}
	_ = r.ensureDir("/etc/apt/apt.conf.d", 0o755)
	_, _ = r.writeManaged("/etc/apt/apt.conf.d/99-k8s-unattended-safety",
		[]byte(`// Managed by node-config-agent - host-protection-drop-ins unattended-upgrade safety.
Unattended-Upgrade::Package-Blacklist {
    "containerd*";
    "runc";
    "k0s*";
    "iptables*";
    "nftables";
    "kmod";
    "systemd";
    "systemd-sysv";
    "udev";
};
Unattended-Upgrade::Automatic-Reboot "false";
`), 0o644)

	// multipathd-mount-isolation multipathd isolation: on hosts where multipath-tools is
	// installed, multipathd claims every new block device it can see —
	// including /dev/longhorn/*, RBD images and plain sd*/vd*/nvme*
	// disks the kubelet/CSI layer owns — and wedges MountVolume.SetUp
	// with "device is already mounted or busy". Blacklist them all so
	// multipathd stays out of the CSI path. Only converged when
	// multipath is actually present on the host: an unconditional
	// drop-in would create /etc/multipath/conf.d on hosts that never
	// installed the daemon.
	if r.fileExists("/etc/multipath") || r.fileExists("/etc/multipath.conf") {
		_ = r.ensureDir("/etc/multipath/conf.d", 0o755)
		_, _ = r.writeManaged("/etc/multipath/conf.d/99-k8s-node-ops.conf",
			[]byte(`# Managed by node-config-agent - host-protection-drop-ins multipathd isolation.
# multipathd must not claim local disks or CSI/RBD/Longhorn block
# devices — a claimed device wedges kubelet MountVolume.SetUp with
# "device is already mounted or busy" (multipathd-mount-isolation).
blacklist {
    devnode "^(sd[a-z0-9]+|vd[a-z0-9]+|nvme[0-9]+n[0-9]+|longhorn/.*|rbd[0-9]+)$"
}
`), 0o644)
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

// logindInhibitDelaySecs derives logind's InhibitDelayMaxSec from the
// SAME kubelet_shutdown_grace_period var groupPulls renders into the
// kubelet's shutdownGracePeriod (group_kubelet.go) — the two must move
// together: if the kubelet's graceful-shutdown window outgrows
// logind's inhibit delay, systemd kills the node mid-drain. The kubelet
// window carries a 5s scheduling buffer, floored at 65s (the 60s
// default + buffer); an unparsable/zero var falls back to that 60s
// default rather than shrinking the protection below the floor.
func logindInhibitDelaySecs(grace string) int64 {
	d, err := time.ParseDuration(grace)
	if err != nil || d <= 0 {
		d = time.Minute
	}
	s := int64((d + 5*time.Second) / time.Second)
	if s < 65 {
		s = 65
	}
	return s
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

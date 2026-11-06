// runtime_resource_guards.go — the host runtime-resource hygiene
// guards: the things a node can be silently dying of while every
// healthz is still green. All series land in the node_agent_*
// textfile family via the shared deps counters/gauges
// (writeNodeAgentPromTextfile); all remedies are cooldown-budgeted.
//
//   - cgroup-dying-reclaim    — cgroup v2 nr_dying_descendants
//     piling up pins page cache/dentries inside cgroups the kernel
//     already deleted (the dying-cgroup leak behind phantom memory
//     pressure + slow cgroup walks): drop_caches + memory.reclaim
//     on a 30m budget, state-cgroup-dying-leak latch.
//   - systemd-session-hygiene — abandoned logind sessions (ssh
//     drops, cron remnants) pile up and every loginctl/D-Bus call
//     walks the whole list (D-Bus stalls → systemctl/kubelet calls
//     time out): terminate stale sessions + reset-failed on a 30m
//     budget, state-systemd-session-bloat latch.
//   - overlayfs-stale-mount   — pods stuck Waiting/Failed on
//     ESTALE/missing-lowerdir overlay errors never heal by
//     retrying: the corrupt layer is removed via ctrRmImage so the
//     next pull re-fetches (15m shared last-ctr-image-rm budget).
//   - io-pressure-throttler   — disk io_ticks util, write await
//     and PSI io full avgs exported every cycle; above the
//     pressure bar the known background IO hogs (backup/scan
//     agents) get renice +19 + ionice idle so latency-critical
//     work wins the disk.
//   - conntrack-tcp-liberal-guard — on neb1 nodes (asymmetric
//     overlay routing marks in-window ACK/RST INVALID → silent
//     drops) nf_conntrack_tcp_be_liberal must be 1.
//   - clock-jump-session-healer — a wall-clock step (NTP slew,
//     RTC catch-up) strands every cached-token client: when a
//     fresh clock-stepped-at marker exists and konnectivity-agent
//     logs 401/x509, recreate its pod on a 30m budget.
package runtime

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/pods"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// defaultCgroupRoot is the host cgroup-v2 unified hierarchy as a
	// host-absolute path — ConfigFromEnv resolves it through
	// hostPath ("/host"-prefixed in the DaemonSet, verbatim on a
	// standalone host) behind NODE_HOST_AGENT_CGROUP_ROOT;
	// applyDefaults uses the constant verbatim so a direct-New
	// caller gets the standalone path.
	// cgroupDyingThreshold is the nr_dying_descendants count above
	// which dying cgroups are considered leaked — the level where
	// cgroup-file walks and memory accounting visibly degrade
	// (kernel 5.4+ reclaim path is known to lag hard past ~10^3).
	cgroupDyingThreshold = 5000
	// cgroupReclaimInterval is the last-cgroup-drop-caches budget —
	// drop_caches is node-wide and costs real IO while it runs.
	cgroupReclaimInterval = 30 * time.Minute
	// cgroupReclaimBytes is the memory.reclaim write — a bounded
	// proactive reclaim nudge, not a limit change (the file takes
	// "amount to reclaim" values; an undersized pool just returns
	// fewer pages).
	cgroupReclaimBytes = "256M\n"

	// defaultSystemdSessionsDir is the logind session state dir as
	// a host-absolute path — one file per session plus .ref
	// companions (skipped). Same hostPath contract as
	// defaultCgroupRoot: ConfigFromEnv resolves it through hostPath
	// behind NODE_HOST_AGENT_SYSTEMD_SESSIONS_DIR; applyDefaults
	// uses it verbatim for direct-New callers.
	// systemdSessionStaleAge is the "abandoned" evidence bar — a
	// closing/abandoned session file untouched this long is stuck,
	// not tearing down (logind rewrites the file on state change,
	// so mtime approximates when the state was entered).
	systemdSessionStaleAge = 2 * time.Hour
	// systemdSessionAbandonedMin is the stale-session count that
	// trips the bloat latch — a couple of stuck sessions are
	// normal; dozens walk every D-Bus session call.
	systemdSessionAbandonedMin = 20
	// systemdDbusSlowSeconds is the is-system-running round trip
	// above which D-Bus itself is counted degraded.
	systemdDbusSlowSeconds = 3.0
	// systemdSessionMaxTerminate bounds loginctl calls per cycle —
	// each terminate is a D-Bus round trip on the bus that is
	// already slow.
	systemdSessionMaxTerminate = 20
	// systemdResetFailedInterval is the last-systemd-reset-failed
	// budget — dead-unit bookkeeping also feeds the unit-table
	// bloat the session janitor fights.
	systemdResetFailedInterval = 30 * time.Minute

	// ioPSIFullHigh is the /proc/pressure/io `full` average
	// (percent) above which the node is IO-starved — same percent
	// scale as the memory PSI thresholds.
	ioPSIFullHigh = 25.0
	// diskWriteAwaitHighMs is the per-cycle mean write await above
	// which latency-critical IO is queued behind bulk writers.
	diskWriteAwaitHighMs = 200.0

	// konnLogTailLines bounds the konnectivity log tail the
	// clock-jump healer greps.
	konnLogTailLines = 200
	// clockJumpMarkerFresh is how recent the clock-stepped-at
	// marker must be for pod-session healing — a step older than
	// this either healed already or isn't the cause of a NEW 401
	// (clients recover by token refresh eventually).
	clockJumpMarkerFresh = 10 * time.Minute
	// clockJumpMarkerFile is the marker a clock-step remedy leaves
	// in the watchdog state dir (epoch content, mtime fallback).
	clockJumpMarkerFile = "clock-stepped-at"
)

var (
	// overlayStaleRe matches the overlayfs mount-failure signatures
	// a stuck container surfaces in its Waiting message (ESTALE
	// from a stale NFS-backed lowerdir, a lowerdir path containerd
	// lost, or the rwlayer create error the CRI reports).
	overlayStaleRe = regexp.MustCompile(
		`ESTALE|stale file handle|failed to mount overlay: no such file or directory|failed to create ?rwlayer`)

	// konnClockErrorRe matches the auth-expiry signatures a
	// konnectivity-agent emits after a wall-clock step threw its
	// cached SA token / TLS cert validity window off.
	konnClockErrorRe = regexp.MustCompile(`401 Unauthorized|x509`)

	// diskPartRe names block devices that are partitions, not
	// whole disks — nvme/mmc style pN suffixes and the classic
	// sdX#/vdX# letter-digit forms. A partition's io_ticks is
	// double-counted against its parent's, so only whole devices
	// feed the utilization/await gauges.
	diskPartRe = regexp.MustCompile(`p[0-9]+$|^(sd|vd|xvd|hd)[a-z]+[0-9]+$`)

	// ioThrottleTargets are the background IO-hog comms the
	// io-pressure throttler deprioritizes — backup, scanner and
	// maintenance agents whose bulk reads/writes starve
	// latency-critical work but tolerate idle-class scheduling.
	ioThrottleTargets = map[string]bool{
		"kopia": true, "velero": true, "trivy": true,
		"maltrail": true, "fstrim": true, "falco": true,
		"ig": true, "obi": true,
	}
)

// --- Check: cgroup-dying-reclaim ---
// On cgroup v2 a deleted cgroup lingers as "dying" while any page
// it accounted is still referenced — nr_dying_descendants counts
// them. Thousands of dying cgroups pin slab/page-cache the kernel
// cannot hand back, inflate every cgroupfs walk (runc list, cadvisor)
// and fake memory pressure on the node. Reclaim is the kernel's own
// escape hatch: drop_caches releases dentries/inodes/pagecache and
// memory.reclaim proactively reclaims without OOM pressure.

type CgroupDyingCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *CgroupDyingCheck) Name() string { return wdeps.CheckCgroupDying }

// cgroupStatDying parses one cgroup.stat file for the
// nr_dying_descendants field — ok=false when the file or the field
// is unreadable (cgroup v1 host, missing mount: the check is
// dormant there).
func cgroupStatDying(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "nr_dying_descendants" {
			if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// Run executes one cgroup-dying round.
func (c *CgroupDyingCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCgroupDying, "gated").Inc()
		return
	}
	root := c.d.Cfg.Runtime.CgroupRoot
	var dying int64
	found := false
	for _, p := range []string{
		filepath.Join(root, "cgroup.stat"),
		filepath.Join(root, "kubepods.slice", "cgroup.stat"),
	} {
		if v, ok := cgroupStatDying(p); ok {
			found = true
			if v > dying {
				dying = v
			}
		}
	}
	if !found {
		// cgroup v1 host or the hierarchy isn't mounted — the whole
		// check is dormant (same "unreadable → abort" rule as the
		// other procfs probes).
		c.d.Cycles.WithLabelValues(wdeps.CheckCgroupDying, "abort").Inc()
		return
	}
	c.d.CgroupDyingDescendants = dying
	if dying <= cgroupDyingThreshold {
		c.fails = 0
		c.d.State.Exit(hoststate.LatchCgroupDyingLeak, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckCgroupDying, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cgroup-dying-leak nr_dying_descendants=%d (check %d/%d)",
			dying, c.fails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckCgroupDying, "ok").Inc()
		return
	}
	c.d.State.Enter(hoststate.LatchCgroupDyingLeak,
		fmt.Sprintf("nr_dying_descendants=%d", dying))
	if !c.d.State.RateTrySpend("last-cgroup-drop-caches", cgroupReclaimInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cgroup-dying-leak nr_dying_descendants=%d - reclaim cooldown (<30m), skip",
			dying))
		c.d.Cycles.WithLabelValues(wdeps.CheckCgroupDying, "ok").Inc()
		return
	}
	c.reclaim(root, dying)
	c.d.Cycles.WithLabelValues(wdeps.CheckCgroupDying, "ok").Inc()
}

// reclaim runs the budgeted reclaim pass: drop_caches frees the
// dentry/inode/page cache pinning dying cgroups ("2" first — slab
// objects are the common pin; "1" as the pagecache-only fallback
// for kernels/configs that reject the level), then memory.reclaim
// asks the cgroup-v2 core to proactively reclaim on the root and
// the kubepods subtree. Writes are best-effort: memory.reclaim is
// absent on older kernels and drop_caches can EBUSY — neither
// turns the cycle into a failure, and the budget was already
// spent (rate_spend parity).
func (c *CgroupDyingCheck) reclaim(root string, dying int64) {
	p := filepath.Join(c.d.Cfg.ProcRoot, "sys", "vm", "drop_caches")
	if err := os.WriteFile(p, []byte("2\n"), 0o644); err != nil {
		if err2 := os.WriteFile(p, []byte("1\n"), 0o644); err2 != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cgroup-dying-leak drop_caches writes failed: %v / %v",
				err, err2))
		}
	}
	for _, rec := range []string{
		filepath.Join(root, "memory.reclaim"),
		filepath.Join(root, "kubepods.slice", "memory.reclaim"),
	} {
		if err := os.WriteFile(rec, []byte(cgroupReclaimBytes), 0o644); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cgroup-dying-leak memory.reclaim write %s failed: %v",
				rec, err))
		}
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: cgroup-dying-leak reclaim - nr_dying_descendants=%d, wrote drop_caches + memory.reclaim",
		dying))
	c.d.CgroupReclaimRuns++
	c.d.Actions.WithLabelValues(wdeps.CheckCgroupDying, "reclaim").Inc()
}

// --- Check: systemd-session-hygiene ---
// Every login/cron session PID 1 tracks costs a logind record;
// abandoned ones (dead ssh, wedged scopes) are never reaped and the
// whole list is walked by every D-Bus session call — past a few
// dozen, systemctl/loginctl/kubelet's D-Bus traffic visibly stalls.
// The check counts sessions, times the is-system-running round trip
// as the D-Bus health signal, and reaps stale sessions plus the
// failed-unit bookkeeping when either trips.

type SystemdSessionCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *SystemdSessionCheck) Name() string { return wdeps.CheckSystemdSessions }

// sessionState returns the STATE= value of a logind session file —
// "" when unreadable or absent.
func sessionState(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "STATE="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// scanSessions counts session state files and collects the ids of
// sessions stuck closing/abandoned longer than the stale-age bar.
// .ref companions and non-regular entries are skipped — they are
// bookkeeping, not sessions. An unreadable dir yields zeroes (a
// host without logind is a dormant check, not an error).
func (c *SystemdSessionCheck) scanSessions() (total int, stale []string) {
	dir := c.d.Cfg.Runtime.SessionsDir
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, nil
	}
	now := c.d.Cfg.Seams.NowFn()
	for _, en := range ents {
		if en.IsDir() || strings.HasSuffix(en.Name(), ".ref") {
			continue
		}
		total++
		st := ""
		if data, err := os.ReadFile(filepath.Join(dir, en.Name())); err == nil {
			st = sessionState(data)
		}
		if st != "closing" && st != "abandoned" {
			continue
		}
		info, err := en.Info()
		if err != nil || now.Sub(info.ModTime()) < systemdSessionStaleAge {
			continue
		}
		stale = append(stale, en.Name())
	}
	return total, stale
}

// Run executes one systemd-session round.
func (c *SystemdSessionCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "gated").Inc()
		return
	}
	total, stale := c.scanSessions()
	c.d.SystemdSessionsTotal = int64(total)
	c.d.SystemdSessionsStale = int64(len(stale))
	sd := c.d.Cfg.Systemd
	latency := -1.0
	if sd != nil {
		// The is-system-running call is itself the D-Bus probe —
		// ANY answer (running/degraded/offline) means D-Bus replied
		// and only the round-trip TIME is the signal. The
		// measurement uses the seam clock, not time.Now: the test
		// seam keeps latency deterministic.
		t0 := c.d.Cfg.Seams.NowFn()
		if _, err := sd.Exec(ctx, "systemctl", "is-system-running"); err != nil {
			// A non-zero exit is still a D-Bus round trip (degraded
			// reports exit 1); only log at debug level via suspect
			// — the latency number already carries the verdict.
			logger().Debug("workerhygiene: is-system-running probe non-ok",
				"error", err)
		}
		latency = c.d.Cfg.Seams.NowFn().Sub(t0).Seconds()
		c.d.SystemdDbusLatencySec = latency
	}
	triggered := len(stale) >= systemdSessionAbandonedMin ||
		latency > systemdDbusSlowSeconds
	if !triggered {
		c.d.State.Exit(hoststate.LatchSystemdSessionBloat, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "ok").Inc()
		return
	}
	c.d.State.Enter(hoststate.LatchSystemdSessionBloat, fmt.Sprintf(
		"abandoned=%d dbus_latency=%.2fs", len(stale), latency))
	if sd == nil {
		// No host exec wired — evidence + latch only.
		c.d.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "ok").Inc()
		return
	}
	reaped := 0
	for _, id := range stale {
		if reaped >= systemdSessionMaxTerminate {
			break
		}
		if _, err := sd.Exec(ctx, "loginctl", "terminate-session", id); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-session-hygiene terminate-session %s failed: %v",
				id, err))
			continue
		}
		reaped++
	}
	if reaped > 0 {
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: systemd-session-hygiene terminated %d stale session(s)", reaped))
		c.d.SystemdSessionsReaped += int64(reaped)
		c.d.Actions.WithLabelValues(wdeps.CheckSystemdSessions, "terminate_session").
			Add(float64(reaped))
	}
	if c.d.State.RateTrySpend("last-systemd-reset-failed", systemdResetFailedInterval) {
		if _, err := sd.Exec(ctx, "systemctl", "reset-failed"); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-session-hygiene reset-failed failed: %v", err))
		} else {
			c.d.Actions.WithLabelValues(wdeps.CheckSystemdSessions, "reset_failed").Inc()
		}
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "ok").Inc()
}

// --- Check: overlayfs-stale-mount ---
// An ESTALE / missing-lowerdir overlay mount failure does not heal
// by kubelet retrying the same corrupt snapshot — the layer on
// disk IS the problem. After the evidence persists for
// ConsecNeeded cycles the check removes the image through the same
// ctrRmImage seam + shared 15m last-ctr-image-rm budget the
// corrupted-image healer uses, so kubelet's next pull re-fetches
// the layer.

type OverlayFSStaleCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *OverlayFSStaleCheck) Name() string { return wdeps.CheckOverlayFSStale }

// Run executes one overlayfs-stale round.
func (c *OverlayFSStaleCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "gated").Inc()
		return
	}
	if !e.APIOK {
		// Inconclusive — same "keep state, never act" rule as the
		// other pod-list checks.
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "abort").Inc()
		return
	}
	stale := 0
	seen := map[string]bool{}
	for i := range e.Pods {
		p := &e.Pods[i]
		statuses := slices.Concat(p.Status.InitContainerStatuses,
			p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses)
		match := false
		for _, cs := range statuses {
			if w := cs.State.Waiting; w != nil &&
				overlayStaleRe.MatchString(w.Message) {
				match = true
				break
			}
		}
		// A pod that exhausted retries reports the same mount
		// failure at pod level — cover that too (the container
		// Waiting state is already gone).
		if !match && p.Status.Phase == corev1.PodFailed &&
			overlayStaleRe.MatchString(p.Status.Message) {
			match = true
		}
		if !match {
			continue
		}
		stale++
		// The image refs to rm come from the pod's OWN statuses —
		// a stale lowerdir is a layer of the image the pod asked
		// for. Normalized like the corrupted-image healer (ctr rm
		// matches store names verbatim).
		for _, cs := range statuses {
			if cs.Image != "" {
				seen[ctr.NormalizeCRIImageName(cs.Image)] = true
			}
			if cs.ImageID != "" {
				seen[ctr.NormalizeCRIImageName(cs.ImageID)] = true
			}
		}
	}
	if stale == 0 {
		c.fails = 0
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
		return
	}
	c.fails++
	c.d.OverlayFSStaleMounts += int64(stale)
	if c.fails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: overlayfs-stale-mount stale_pods=%d (check %d/%d)",
			stale, c.fails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
		return
	}
	if len(seen) == 0 {
		// Stale evidence but no image ref to act on — counted and
		// logged, nothing removable.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: overlayfs-stale-mount stale_pods=%d but no image refs", stale))
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
		return
	}
	images := make([]string, 0, len(seen))
	for img := range seen {
		images = append(images, img)
	}
	sort.Strings(images)
	if !c.d.State.RateTrySpend("last-ctr-image-rm", wdeps.CtrImageRmInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: overlayfs-stale-mount image(s) %s - in rm cooldown (<15m), skip",
			strings.Join(images, " ")))
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE acting (lib.sh rate_spend
	// parity): a failed rm still consumed it.
	for _, img := range images {
		if err := c.d.Cfg.Seams.CtrRmImage(ctx, img); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: overlayfs-stale-mount image rm %s failed: %v", img, err))
			continue
		}
		c.d.State.AppendLog("ACTION: overlayfs-stale-mount removed image " + img)
		c.d.Actions.WithLabelValues(wdeps.CheckOverlayFSStale, "image_rm").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
}

// --- Check: io-pressure-throttler ---
// Bulk background IO (backups, vulnerability scans, fstrim, eBPF
// agents) starves latency-critical writes: the node shows healthy
// while every fsync queues behind a kopia stream. The check keeps a
// per-whole-disk io_ticks/util and write-await delta plus the PSI
// io `full` averages as gauges, and above the pressure bar puts the
// known background hogs into idle IO class + lowest CPU priority.
// Throttling is sticky per pid — a pid is deprioritized once, and a
// pid-slot reuse (same pid, different comm) re-qualifies.

// diskIOStat is one whole-disk row of /proc/diskstats, reduced to
// the counters the deltas need (all in kernel units: ios, ms).
type diskIOStat struct {
	wrIOS   uint64 // field 7  — writes completed
	wrTicks uint64 // field 10 — ms spent writing
	ioTicks uint64 // field 12 — ms doing IO (utilization source)
}

// isWholeDisk reports whether a diskstats device name is a whole
// disk rather than a partition or virtual device — partition IO is
// double-counted in its parent and loop/dm/zram/ram devices are
// stacked layers, not the spindle that stalls.
func isWholeDisk(name string) bool {
	for _, p := range []string{
		"loop", "ram", "zram", "dm-", "md", "nbd", "sr", "fd", "pmem",
	} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return !diskPartRe.MatchString(name)
}

// parseDiskstats reduces /proc/diskstats to whole-disk rows.
// Malformed rows are skipped — the format is stable across kernels
// but extra trailing fields (discards, flush) must not matter.
func parseDiskstats(data []byte) map[string]diskIOStat {
	out := map[string]diskIOStat{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 || !isWholeDisk(f[2]) {
			continue
		}
		var s diskIOStat
		if v, err := strconv.ParseUint(f[7], 10, 64); err == nil {
			s.wrIOS = v
		}
		if v, err := strconv.ParseUint(f[10], 10, 64); err == nil {
			s.wrTicks = v
		}
		if v, err := strconv.ParseUint(f[12], 10, 64); err == nil {
			s.ioTicks = v
		}
		out[f[2]] = s
	}
	return out
}

// psiIOFullAvgs parses <ProcRoot>/pressure/io — the `full` avg60
// and avg300 values (percent of wall time ALL tasks stalled on IO).
// ok=false when PSI io is unavailable (old kernel / psi disabled)
// — the check then runs on the diskstats half alone.
func psiIOFullAvgs(d *wdeps.Deps) (avg60, avg300 float64, ok bool) {
	data, err := os.ReadFile(filepath.Join(d.Cfg.ProcRoot, "pressure", "io"))
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "full" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, cut := strings.Cut(kv, "=")
			if !cut {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			switch k {
			case "avg60":
				avg60, ok = x, true
			case "avg300":
				avg300 = x
			}
		}
	}
	return avg60, avg300, ok
}

// IOPressureCheck is the disk-IO starvation guard as a Check. It
// keeps the previous diskstats snapshot for the delta math and the
// pid→comm throttle ledger (pid reuse protection).
type IOPressureCheck struct {
	d         *wdeps.Deps
	lastDisk  map[string]diskIOStat
	lastTime  time.Time
	throttled map[int]string
}

// Name returns the check label / WD_SIG key.
func (c *IOPressureCheck) Name() string { return wdeps.CheckIOPressure }

// Run executes one io-pressure round.
func (c *IOPressureCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckIOPressure, "gated").Inc()
		return
	}
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, "diskstats"))
	if err != nil {
		c.d.Cycles.WithLabelValues(wdeps.CheckIOPressure, "abort").Inc()
		return
	}
	now := c.d.Cfg.Seams.NowFn()
	cur := parseDiskstats(data)
	util, await := 0.0, 0.0
	if c.lastDisk != nil {
		dtMs := float64(now.Sub(c.lastTime).Milliseconds())
		if dtMs > 0 {
			var dWr, dWrMs uint64
			for name, s := range cur {
				prev, ok := c.lastDisk[name]
				// A wrapped/reset counter or a new device yields no
				// delta — skip rather than invent huge numbers.
				if !ok || s.ioTicks < prev.ioTicks {
					continue
				}
				if u := float64(s.ioTicks-prev.ioTicks) / dtMs; u > util {
					util = u
				}
				if s.wrIOS >= prev.wrIOS {
					dWr += s.wrIOS - prev.wrIOS
				}
				if s.wrTicks >= prev.wrTicks {
					dWrMs += s.wrTicks - prev.wrTicks
				}
			}
			if dWr > 0 {
				await = float64(dWrMs) / float64(dWr)
			}
		}
	}
	c.lastDisk, c.lastTime = cur, now
	c.d.DiskIOUtilRatio = util
	c.d.DiskWriteAwaitMs = await
	avg60, avg300, psiOK := psiIOFullAvgs(c.d)
	c.d.IOPSIFullAvg60 = avg60
	c.d.IOPSIFullAvg300 = avg300
	pressure := await > diskWriteAwaitHighMs ||
		(psiOK && (avg300 > ioPSIFullHigh || avg60 > ioPSIFullHigh))
	if !pressure {
		c.d.Cycles.WithLabelValues(wdeps.CheckIOPressure, "ok").Inc()
		return
	}
	if c.throttled == nil {
		c.throttled = map[int]string{}
	}
	pids := e.PidsOnce()
	// Prune dead pids from the ledger — and a recycled pid whose
	// comm changed re-qualifies below (the entry still matches only
	// the same comm).
	alive := map[int]bool{}
	for _, pid := range pids {
		alive[pid] = true
	}
	for pid := range c.throttled {
		if !alive[pid] {
			delete(c.throttled, pid)
		}
	}
	for _, pid := range pids {
		if _, done := c.throttled[pid]; done {
			continue
		}
		raw, err := os.ReadFile(c.d.Proc.File(pid, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(raw))
		if !ioThrottleTargets[comm] {
			continue
		}
		// Deprioritize BOTH dimensions: renice +19 (CPU) and ionice
		// idle (the process only gets the disk when nothing else
		// wants it). Either failing is logged, never fatal — a pid
		// can exit mid-sweep.
		if err := c.d.Cfg.Seams.ReniceFn(pid); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: io-pressure-throttler renice +19 pid=%d (%s) failed: %v",
				pid, comm, err))
		}
		if err := c.d.Cfg.Seams.IoniceIdleFn(pid); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: io-pressure-throttler ionice -c3 pid=%d (%s) failed: %v",
				pid, comm, err))
		}
		c.throttled[pid] = comm
		c.d.IOThrottledProcs++
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: io-pressure-throttler deprioritized pid=%d comm=%s (await=%.1fms psi60=%.1f psi300=%.1f)",
			pid, comm, await, avg60, avg300))
		c.d.Actions.WithLabelValues(wdeps.CheckIOPressure, "throttle").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckIOPressure, "ok").Inc()
}

// --- Check: conntrack-tcp-liberal-guard ---
// On neb1 (nebula overlay) nodes the underlay policy route returns
// replies over a different path than the outbound flow, so
// conntrack sees ACK/RST that look "out of window" and — with
// nf_conntrack_tcp_be_liberal=0 — marks them INVALID and drops
// them. The guard pins the sysctl to 1 on neb1 nodes; non-neb1
// nodes keep the kernel default (the fix exists because of the
// overlay's asymmetry).

type ConntrackLiberalCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *ConntrackLiberalCheck) Name() string { return wdeps.CheckConntrackLiberal }

// Run executes one conntrack-liberal round.
func (c *ConntrackLiberalCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckConntrackLiberal, "gated").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(
		c.d.Cfg.Net.SysClassNet, c.d.Cfg.Net.NebulaIface)); err != nil {
		// No nebula iface — the asymmetric-path problem this guard
		// exists for can't occur; leave the kernel default alone.
		c.d.Cycles.WithLabelValues(wdeps.CheckConntrackLiberal, "ok").Inc()
		return
	}
	p := filepath.Join(c.d.Cfg.ProcRoot, "sys", "net", "netfilter",
		"nf_conntrack_tcp_be_liberal")
	data, err := os.ReadFile(p)
	if err != nil {
		// Module not loaded / sysctl absent — dormant, not an error.
		c.d.Cycles.WithLabelValues(wdeps.CheckConntrackLiberal, "abort").Inc()
		return
	}
	if strings.TrimSpace(string(data)) != "0" {
		c.d.Cycles.WithLabelValues(wdeps.CheckConntrackLiberal, "ok").Inc()
		return
	}
	if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: conntrack-tcp-liberal-guard write %s failed: %v", p, err))
		c.d.Cycles.WithLabelValues(wdeps.CheckConntrackLiberal, "ok").Inc()
		return
	}
	c.d.State.AppendLog(
		"ACTION: conntrack-tcp-liberal-guard set nf_conntrack_tcp_be_liberal=1 (neb1 present)")
	c.d.ConntrackLiberalFixes++
	c.d.Actions.WithLabelValues(wdeps.CheckConntrackLiberal, "sysctl_write").Inc()
	c.d.Cycles.WithLabelValues(wdeps.CheckConntrackLiberal, "ok").Inc()
}

// --- Check: clock-jump-session-healer ---
// A wall-clock step (NTP makestep, RTC catch-up, suspend/resume)
// invalidates every cached-token session at once: konnectivity-agent
// keeps its token and starts failing with 401/x509 while the pod
// looks Running. When the clock-stepped-at marker (written by the
// clock-step remedy) is fresh AND the konnectivity log shows the
// auth-failure signature, recreate the pod so it re-bakes fresh
// credentials — the same remedy the konnectivity IP-drift check
// uses, on its own 30m budget.

type ClockJumpCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *ClockJumpCheck) Name() string { return wdeps.CheckClockJump }

// clockSteppedAt reads the clock-stepped-at marker in the state
// dir — epoch content first, file mtime as the fallback shape.
func clockSteppedAt(d *wdeps.Deps) (time.Time, bool) {
	p := filepath.Join(d.Cfg.WatchdogStateDir, clockJumpMarkerFile)
	data, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}, false
	}
	if ep, err := strconv.ParseInt(
		strings.TrimSpace(string(data)), 10, 64); err == nil && ep > 0 {
		return time.Unix(ep, 0), true
	}
	if fi, err := os.Stat(p); err == nil {
		return fi.ModTime(), true
	}
	return time.Time{}, false
}

// konnPodLog returns a log tail for this node's konnectivity-agent
// pod — the pod log file under PodLogsDir first (kubelet keeps the
// tail even while the apiserver is unreachable), the podLogFn API
// seam as fallback when the file path yields nothing.
func konnPodLog(d *wdeps.Deps, ctx context.Context, p *corev1.Pod) string {
	dir := filepath.Join(d.Cfg.Disk.PodLogsDir,
		p.Namespace+"_"+p.Name+"_"+string(p.UID))
	if logs, err := filepath.Glob(filepath.Join(dir, "*", "*.log")); err == nil {
		var best string
		var bestMod time.Time
		for _, lf := range logs {
			fi, err := os.Stat(lf)
			if err != nil || !fi.ModTime().After(bestMod) {
				continue
			}
			best, bestMod = lf, fi.ModTime()
		}
		if best != "" {
			if data, err := tailFile(best, 64<<10); err == nil && len(data) > 0 {
				return string(data)
			}
		}
	}
	if d.Cfg.Seams.PodLogFn != nil {
		if out, err := d.Cfg.Seams.PodLogFn(ctx, p.Namespace, p.Name,
			konnLogTailLines); err == nil {
			return out
		}
	}
	return ""
}

// tailFile reads the last n bytes of path — log tails must not
// slurp a multi-GB 0.log.
func tailFile(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > n {
		if _, err := f.Seek(-n, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(f)
}

// Run executes one clock-jump round.
func (c *ClockJumpCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "gated").Inc()
		return
	}
	stepped, ok := clockSteppedAt(c.d)
	if !ok || c.d.Cfg.Seams.NowFn().Sub(stepped) > clockJumpMarkerFresh {
		// No recent step — the signature this check heals can't be
		// attributed to a clock jump.
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
		return
	}
	if !e.APIOK {
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "abort").Inc()
		return
	}
	var konn *corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		if p.Namespace == "kube-system" && pods.KonnPodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil {
			konn = p
			break
		}
	}
	if konn == nil {
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
		return
	}
	logs := konnPodLog(c.d, ctx, konn)
	if !konnClockErrorRe.MatchString(logs) {
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
		return
	}
	if !c.d.State.RateTrySpend("last-clock-jump-konn", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(
			"suspect: clock-jump-session-healer konn auth-fail evidence but recreate cooldown (<30m), skip")
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: clock-jump-session-healer recreating konnectivity-agent %s/%s - fresh clock-step marker + 401/x509 in log",
		konn.Namespace, konn.Name))
	if pods.DeleteKonnectivityPod(c.d, ctx, e.Pods) {
		c.d.Actions.WithLabelValues(wdeps.CheckClockJump, "pod_delete").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
}

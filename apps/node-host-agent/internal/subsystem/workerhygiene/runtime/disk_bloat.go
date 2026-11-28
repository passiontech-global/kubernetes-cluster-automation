// disk_bloat.go — the disk-bloat runaway-dir detector
// (wdeps.CheckDiskBloat): the watermark-gated stale-dir walk +
// critical-band pod eviction. The disk side-guards that used to
// ride this check's cycle slot are now their own wdeps.Check
// entries — run_tmpfs.go, dev_shm.go, coredump_gc.go,
// writable_layer.go and localpv_quota.go.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kubeutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// disk-bloat disk-bloat thresholds: above the warn watermark the
// bounded walk runs (at most once per DiskBloatScanInterval —
// the walk itself costs IO on the disk that is already full);
// above the critical watermark a non-system offender may be
// evicted outright. Any single dir past the pod threshold is a
// runaway target.
const (
	diskBloatEvictInterval = 15 * time.Minute // last-disk-bloat-evict budget
	// diskBloatRunawayDeltaBytes and diskBloatRunawayMinShare* gate the
	// Wave 6 Pre-DiskPressure runaway emptyDir/pod-log pre-eviction in
	// the warn band (used > BloatWatermark, before kubelet DiskPressure
	// mass-evicts innocent pods).
	diskBloatRunawayDeltaBytes  int64 = 256 << 20 // >=256 MiB growth since previous scan
	diskBloatRunawayMinShareNum int64 = 2         // >=40% (2/5) of total pod bytes
	diskBloatRunawayMinShareDen int64 = 5
	// coredumpMinAge keeps an in-progress core write from being
	// swept the same cycle the watermark trip fires.
	coredumpMinAge = 15 * time.Minute
	// coredumpSweepMax bounds one cycle's stale-core removal blast
	// radius (runTmpfsSweepMax parity — a storm drains at a fixed
	// rate across cycles).
	coredumpSweepMax = 64
	// defaultPodLogsDir is the /var/log/pods host mount — the
	// BUG-H8 pod-log attribution walk scans it.
)

// bloatHit is one over-threshold directory found by the walk.
type bloatHit struct {
	label string
	bytes int64
}

// readDirNamesChecked lists immediate subdirectories of dir and reports
// readErr=true when ReadDir fails for a non-ENOENT reason (e.g. EACCES/ENOTDIR).
func readDirNamesChecked(dir string) ([]string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, !os.IsNotExist(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, false
}

// podLogDirUID extracts the pod uid from a /var/log/pods dir name
// (<ns>_<pod>_<uid>): neither namespaces nor pod names can contain
// '_', so the LAST '_' delimits the uid. "" when there is no
// trailing segment.
func podLogDirUID(base string) string {
	if i := strings.LastIndexByte(base, '_'); i >= 0 && i+1 < len(base) {
		return base[i+1:]
	}
	return ""
}

// scanBloat runs the bounded walks the check is defined over:
// kubelet emptyDir volumes (tmpfs-backed ones can't fill the disk —
// skipped via statfs type), containerd overlayfs snapshots, and the
// /var/log/pods stdout log dirs (BUG-H8 — a runaway log writer
// fills the disk while its emptyDir stays small, and a leaked
// snapshot pins space no volume path accounts for). Over-threshold
// dirs return as hits; podTotals/podByUID feed the
// critical-watermark eviction decision.
// All dir sizings go through Deps.WalkBudgeted: the per-cycle
// WalkOnce cache (memoize each path once per cycle) plus the
// MaxBloatScanEntries entry budget live there now.

func (c *DiskBloatCheck) scanBloat(e *wdeps.CycleEnv, pods []corev1.Pod) (hits []bloatHit,
	podTotals map[string]int64, podByUID map[string]*corev1.Pod) {
	hits, podTotals, podByUID, _ = c.scanBloatChecked(e, pods)
	return hits, podTotals, podByUID
}

func (c *DiskBloatCheck) scanBloatChecked(e *wdeps.CycleEnv, pods []corev1.Pod) (hits []bloatHit,
	podTotals map[string]int64, podByUID map[string]*corev1.Pod, scanErr bool) {
	podByUID = map[string]*corev1.Pod{}
	podTotals = map[string]int64{}
	podHitRecorded := map[string]bool{}
	for i := range pods {
		podByUID[string(pods[i].UID)] = &pods[i]
	}
	threshold := c.d.Cfg.Disk.BloatPodThresholdBytes
	// (1) emptyDir volumes: pods/<uid>/volumes/kubernetes.io~empty-dir/<vol>.
	uidDirs, uErr := readDirNamesChecked(c.d.Cfg.PodsDir)
	if uErr {
		scanErr = true
	}
	for _, uidDir := range uidDirs {
		uid := filepath.Base(uidDir)
		vols, vErr := readDirNamesChecked(filepath.Join(
			uidDir, "volumes", "kubernetes.io~empty-dir"))
		if vErr {
			scanErr = true
		}
		for _, vol := range vols {
			var vst unix.Statfs_t
			if err := c.d.Cfg.Seams.Host.StatfsFn(vol, &vst); err == nil &&
				vst.Type == int64(unix.TMPFS_MAGIC) {
				continue // medium=Memory emptyDir — can't fill the disk
			}
			size, _ := c.d.WalkBudgeted(e, vol)
			podTotals[uid] += size
			if size > threshold {
				podHitRecorded[uid] = true
				label := "pod-uid " + uid
				if p, ok := podByUID[uid]; ok && p != nil {
					label = "pod " + p.Namespace + "/" + p.Name
				}
				hits = append(hits, bloatHit{
					label: label + " volume " + filepath.Base(vol),
					bytes: size})
			}
		}
	}
	// (2) containerd overlayfs snapshots — <id>/fs is the unpacked
	// layer content; a leaked snapshot pins real disk. The CRI
	// plugin uses the container ID (== the task dir name) as the
	// snapshot key, so a live task dir maps the snapshot back to
	// its pod's uid for the eviction decision; unresolvable
	// snapshots stay hits-only. The root is the configured ACTIVE
	// snapshotter (WLayerSnapshotsDir) — the same knob the
	// writable-layer scan walks, not a second hardcoded derivation.
	snapRoot := c.d.Cfg.Disk.WLayerSnapshotsDir
	mountIDs := snapshotMountIDs(c.d, e)
	snaps, sErr := readDirNamesChecked(snapRoot)
	if sErr {
		scanErr = true
	}
	for _, snap := range snaps {
		id := filepath.Base(snap)
		size, _ := c.d.WalkBudgeted(e, filepath.Join(snap, "fs"))
		if size <= 0 {
			continue
		}
		uid := snapshotPodUID(c.d, id, mountIDs)
		if uid != "" {
			podTotals[uid] += size
		}
		if size > threshold {
			if uid != "" {
				podHitRecorded[uid] = true
			}
			hits = append(hits, bloatHit{
				label: "snapshot " + id, bytes: size})
		}
	}
	// (3) pod stdout log dirs — <PodLogsDir>/<ns>_<pod>_<uid>/: the
	// containerd CRI writes container logs here (rotated at 10MiB ×
	// 5 by kubelet, but a chatty container under a stuck rotation —
	// or a pod with hundreds of short-lived restarts — outruns it).
	logDirs, lErr := readDirNamesChecked(c.d.Cfg.Disk.PodLogsDir)
	if lErr {
		scanErr = true
	}
	for _, logDir := range logDirs {
		base := filepath.Base(logDir)
		uid := podLogDirUID(base)
		size, _ := c.d.WalkBudgeted(e, logDir)
		if uid != "" {
			podTotals[uid] += size
		}
		if size > threshold {
			if uid != "" {
				podHitRecorded[uid] = true
			}
			label := "pod-logs " + base
			if p, ok := podByUID[uid]; ok && p != nil {
				label = "pod " + p.Namespace + "/" + p.Name + " logs"
			}
			hits = append(hits, bloatHit{label: label, bytes: size})
		}
	}
	// (4) aggregated per-pod total: a pod splitting bloat across multiple
	// emptyDir volumes, snapshots, and logs can cross BloatPodThresholdBytes
	// without any single directory crossing it.
	var aggUIDs []string
	for uid, total := range podTotals {
		if total > threshold && !podHitRecorded[uid] {
			aggUIDs = append(aggUIDs, uid)
		}
	}
	slices.Sort(aggUIDs)
	for _, uid := range aggUIDs {
		label := "pod-uid " + uid
		if p, ok := podByUID[uid]; ok && p != nil {
			label = "pod " + p.Namespace + "/" + p.Name
		}
		hits = append(hits, bloatHit{label: label + " total", bytes: podTotals[uid]})
	}
	return hits, podTotals, podByUID, scanErr
}

// snapshotMountIDs parses the host /proc/1/mountinfo once and maps
// each overlayfs snapshot ("<snapRoot>/<id>/fs" used as a mount's
// upperdir=) to the containerd task id whose rootfs mount consumes
// it — the mount point is <taskRoot>/<id>/rootfs. containerd names
// snapshot dirs numerically, so the dir name alone can never key a
// task dir; the live mount is the only snapshot→container binding.
// "" map on an unreadable mountinfo (callers fall back to the
// name-keyed lookup).
func snapshotMountIDs(d *wdeps.Deps, e *wdeps.CycleEnv) map[string]string {
	entries, _, err := d.MountinfoEntries(e)
	if err != nil {
		return nil
	}
	hostTaskRoot := fsx.HostSidePath(d.Cfg.CtrTaskRoot)
	hostSandboxRoot := fsx.HostSidePath(d.Cfg.SandboxCtlRoot)
	hostSnapRoot := fsx.HostSidePath(d.Cfg.Disk.WLayerSnapshotsDir) + "/"
	out := map[string]string{}
	for _, ent := range entries {
		if !ent.HasMount || !ent.HasSep {
			continue
		}
		mount := ent.Mountpoint
		var taskID string
		for _, root := range []string{hostTaskRoot, hostSandboxRoot} {
			if strings.HasPrefix(mount, root+"/") &&
				strings.HasSuffix(mount, "/rootfs") {
				taskID = filepath.Base(strings.TrimSuffix(mount, "/rootfs"))
				break
			}
		}
		if taskID == "" {
			continue
		}
		for opt := range strings.SplitSeq(ent.SuperOpts, ",") {
			if !strings.HasPrefix(opt, "upperdir=") {
				continue
			}
			up := procfs.UnescapeMountPath(strings.TrimPrefix(opt, "upperdir="))
			if rel, ok := strings.CutPrefix(up, hostSnapRoot); ok {
				// rel = "<id>/fs" — the snapshot dir name.
				if fsDir, ok := strings.CutSuffix(rel, "/fs"); ok &&
					!strings.Contains(fsDir, "/") {
					out[fsDir] = taskID
				}
			}
		}
	}
	return out
}

// taskDirPodUID resolves a containerd task/sandbox dir id back to
// the pod uid via its config.json io.kubernetes.pod.uid annotation —
// either task root may hold it. "" when no dir resolves.
func taskDirPodUID(d *wdeps.Deps, id string) string {
	for _, root := range []string{d.Cfg.CtrTaskRoot, d.Cfg.SandboxCtlRoot} {
		cfgData, err := os.ReadFile(filepath.Join(root, id, "config.json"))
		if err != nil {
			continue
		}
		if m := wdeps.PodUIDRe.FindSubmatch(cfgData); m != nil {
			return string(m[1])
		}
	}
	return ""
}

// snapshotPodUID resolves a containerd snapshot id back to the pod
// uid owning it. mountIDs (snapshotMountIDs) wins: snapshot dir
// names are numeric, so the mountinfo upperdir→rootfs binding maps
// them to the 64-hex task id first; the direct name-as-task-dir
// lookup stays as the fallback for name-keyed snapshotters and
// tests. "" when nothing resolves (leaked/orphan snapshot — no pod
// to bill it to).
func snapshotPodUID(d *wdeps.Deps, id string, mountIDs map[string]string) string {
	if cid := mountIDs[id]; cid != "" {
		if uid := taskDirPodUID(d, cid); uid != "" {
			return uid
		}
	}
	return taskDirPodUID(d, id)
}

// DiskBloatCheck is the disk-bloat runaway-dir detector as a Check. It
// owns the scan stamp (ex-Hygiene.lastBloatScan) — the bounded
// walk costs IO on the very disk that is full, so above the warn
// watermark it runs at most once per DiskBloatScanInterval.
type DiskBloatCheck struct {
	d            *wdeps.Deps
	lastScan     time.Time
	prevPodBytes map[string]int64
}

// Name returns the check label / WD_SIG key.
func (c *DiskBloatCheck) Name() string { return wdeps.CheckDiskBloat }

// Run executes one disk-bloat round.
func (c *DiskBloatCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckDiskBloat) {
		return
	}
	used, ok := c.d.DiskUsageRatio(c.d.Cfg.K0sDataDir)
	if !ok {
		// statfs failed or returned garbage — inconclusive; keep
		// the latch like a failed probe.
		c.d.CycleResult(wdeps.CheckDiskBloat, "abort")
		return
	}
	if used <= c.d.Cfg.Disk.BloatWatermark {
		c.prevPodBytes = nil
		c.d.State.Exit(latchdefs.LatchDiskBloat, nil)
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}
	// The walk is IO on the disk that is full — at most once per
	// DiskBloatScanInterval; an existing latch persists meanwhile.
	if c.d.Cfg.Seams.Host.Clock.Now().Sub(c.lastScan) < c.d.Cfg.Disk.BloatScanInterval {
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}
	hits, podTotals, podByUID, scanErr := c.scanBloatChecked(e, e.Pods)
	if len(hits) == 0 {
		if scanErr {
			c.d.CycleResult(wdeps.CheckDiskBloat, "abort")
			return
		}
		c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
		c.prevPodBytes = podTotals
		c.d.State.Exit(latchdefs.LatchDiskBloat, nil)
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}
	prevPodBytes := c.prevPodBytes
	if scanErr {
		// Incomplete scan: discard the partial baseline so the next
		// clean scan cannot fabricate a delta spike.
		c.prevPodBytes = nil
		prevPodBytes = nil
	} else {
		c.prevPodBytes = podTotals
	}
	c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
	c.d.State.Enter(latchdefs.LatchDiskBloat, fmt.Sprintf("targets=%d", len(hits)))
	for _, hit := range hits {
		// NPD contract: the ACTION entry line feeds DiskBloatRunaway
		// (events.go) — ActionEntryRe(LatchDiskBloat) parses it.
		c.d.State.AppendLog(fmt.Sprintf(
			latchdefs.ActionEntryPrefix(latchdefs.LatchDiskBloat)+
				"target=%s bytes=%d used_pct=%.1f",
			hit.label, hit.bytes, used*100))
	}
	c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "detect").Inc()
	if !e.APIOK {
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}

	victim, victimBytes, victimDelta, preEvict := c.pickEvictVictim(used, podTotals, prevPodBytes, podByUID)
	if victim == nil {
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}
	if c.d.Cfg.Client == nil {
		c.d.State.AppendLog("suspect: disk-bloat pod evict skipped — kubernetes client nil")
		c.d.CycleResult(wdeps.CheckDiskBloat, "abort")
		return
	}
	// L1↔L3 hold: check maintenance BEFORE spending the cooldown
	// budget so a drain does not burn last-disk-bloat-evict.
	if c.d.HoldLocalAction(ctx) {
		c.d.State.AppendLog("cleanup: disk-bloat evict held — " +
			"cluster maintenance in progress")
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}
	if !c.d.State.RateTrySpend("last-disk-bloat-evict", diskBloatEvictInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: disk-bloat victim %s/%s bytes=%d - in evict cooldown (<15m), skip",
			victim.Namespace, victim.Name, victimBytes))
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}
	// Budget spent atomically BEFORE the eviction (rate_spend parity
	// — a failed evict still consumed it). policy/v1 Eviction — NOT
	// a raw pod delete: the apiserver enforces the victim's
	// PodDisruptionBudget atomically, so a PDB-protected pod is
	// refused instead of silently disrupted (psi-memory-thrash
	// evict parity). The UID precondition closes the listing→evict
	// race: a same-name pod is a different object and the apiserver
	// refuses (kubeutil.EvictPodV1).
	ev := kubeutil.EvictPodV1(victim)
	if err := c.d.Cfg.Client.PolicyV1().Evictions(victim.Namespace).
		Evict(ctx, ev); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: disk-bloat evict %s/%s failed: %v",
			victim.Namespace, victim.Name, err))
	} else {
		if preEvict {
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: disk-bloat evicted pod %s/%s - runaway +%d bytes (total %d bytes), /var/lib/k0s at %.1f%% (pre-DiskPressure)",
				victim.Namespace, victim.Name, victimDelta, victimBytes, used*100))
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: disk-bloat evicted pod %s/%s - emptyDir holds %d bytes, /var/lib/k0s at %.1f%%",
				victim.Namespace, victim.Name, victimBytes, used*100))
		}
		c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "pod_evict").Inc()
	}
	c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
}

// podAllContainersEphemeralLimited reports whether every active runtime
// container of pod (all Spec.Containers, all native-sidecar InitContainers,
// and regular InitContainers while Pending) declares a positive
// limits.ephemeral-storage bound. A pod with an initContainer or sidecar
// declaring a limit while another running container omits it still lacks
// full kubelet ephemeral-storage protection and remains pre-evictable.
func podAllContainersEphemeralLimited(pod *corev1.Pod) bool {
	if pod == nil || len(pod.Spec.Containers) == 0 {
		return false
	}
	hasLimit := func(c *corev1.Container) bool {
		q, ok := c.Resources.Limits[corev1.ResourceEphemeralStorage]
		return ok && q.Sign() > 0
	}
	for i := range pod.Spec.Containers {
		if !hasLimit(&pod.Spec.Containers[i]) {
			return false
		}
	}
	for i := range pod.Spec.InitContainers {
		ic := &pod.Spec.InitContainers[i]
		isSidecar := ic.RestartPolicy != nil && *ic.RestartPolicy == corev1.ContainerRestartPolicyAlways
		if (isSidecar || pod.Status.Phase == corev1.PodPending) && !hasLimit(ic) {
			return false
		}
	}
	return true
}

// pickEvictVictim selects at most one eviction target:
//   - Critical band (used > BloatCriticalWatermark): largest unprotected
//     pod exceeding BloatPodThresholdBytes.
//   - Warn band (used > BloatWatermark): Wave 6 pre-DiskPressure runaway
//     pre-eviction — a single unprotected pod WITHOUT full ephemeral-storage
//     limits that grew >=256 MiB since the previous scan, holds >=40% of
//     total bloated pod bytes, and exceeds BloatPodThresholdBytes.
func (c *DiskBloatCheck) pickEvictVictim(
	used float64,
	podTotals, prevPodBytes map[string]int64,
	podByUID map[string]*corev1.Pod,
) (victim *corev1.Pod, victimBytes, victimDelta int64, preEvict bool) {
	eligible := func(p *corev1.Pod, total int64) bool {
		return total > c.d.Cfg.Disk.BloatPodThresholdBytes &&
			p != nil &&
			p.DeletionTimestamp == nil &&
			!wdeps.EvictProtectedNamespaces[p.Namespace] &&
			!wdeps.IsEvictProtectedPod(p)
	}
	if used > c.d.Cfg.Disk.BloatCriticalWatermark {
		for uid, total := range podTotals {
			p := podByUID[uid]
			if !eligible(p, total) {
				continue
			}
			if victim == nil || total > victimBytes || (total == victimBytes && uid < string(victim.UID)) {
				victim, victimBytes = p, total
			}
		}
		return victim, victimBytes, 0, false
	}
	if prevPodBytes == nil {
		return nil, 0, 0, false
	}
	var totalPodBytes int64
	for _, total := range podTotals {
		if total > 0 {
			totalPodBytes += total
		}
	}
	if totalPodBytes <= 0 {
		return nil, 0, 0, false
	}
	for uid, total := range podTotals {
		p := podByUID[uid]
		if !eligible(p, total) || podAllContainersEphemeralLimited(p) {
			continue
		}
		delta := total - prevPodBytes[uid]
		if delta < diskBloatRunawayDeltaBytes {
			continue
		}
		if total*diskBloatRunawayMinShareDen < totalPodBytes*diskBloatRunawayMinShareNum {
			continue
		}
		if victim == nil || delta > victimDelta || (delta == victimDelta && (total > victimBytes || (total == victimBytes && uid < string(victim.UID)))) {
			victim, victimBytes, victimDelta = p, total, delta
		}
	}
	return victim, victimBytes, victimDelta, victim != nil
}

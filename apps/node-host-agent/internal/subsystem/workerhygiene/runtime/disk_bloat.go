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

// readDirNames lists the immediate subdirectories of dir (an
// unreadable/absent root yields nil — the scan just sees no dirs).
func readDirNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
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
// walkBytes sizes one dir through the per-cycle WalkOnce cache when
// the cycle provides it (scanBloat and writableLayerScan walk the
// same snapshot/pod-volume dirs in one cycle — the walk runs once),
// falling back to a direct bounded walk otherwise.
func walkBytes(d *wdeps.Deps, e *wdeps.CycleEnv, root string) (int64, bool) {
	if e != nil && e.WalkOnce != nil {
		return e.WalkOnce(root)
	}
	return d.WalkBytes(root)
}

func (c *DiskBloatCheck) scanBloat(e *wdeps.CycleEnv, pods []corev1.Pod) (hits []bloatHit,
	podTotals map[string]int64, podByUID map[string]*corev1.Pod) {
	podByUID = map[string]*corev1.Pod{}
	podTotals = map[string]int64{}
	for i := range pods {
		podByUID[string(pods[i].UID)] = &pods[i]
	}
	threshold := c.d.Cfg.Disk.BloatPodThresholdBytes
	// (1) emptyDir volumes: pods/<uid>/volumes/kubernetes.io~empty-dir/<vol>.
	for _, uidDir := range readDirNames(c.d.Cfg.PodsDir) {
		uid := filepath.Base(uidDir)
		for _, vol := range readDirNames(filepath.Join(
			uidDir, "volumes", "kubernetes.io~empty-dir")) {
			var vst unix.Statfs_t
			if err := c.d.Cfg.Seams.Host.StatfsFn(vol, &vst); err == nil &&
				vst.Type == int64(unix.TMPFS_MAGIC) {
				continue // medium=Memory emptyDir — can't fill the disk
			}
			size, _ := walkBytes(c.d, e, vol)
			podTotals[uid] += size
			if size > threshold {
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
	mountIDs := snapshotMountIDs(c.d)
	for _, snap := range readDirNames(snapRoot) {
		id := filepath.Base(snap)
		size, _ := walkBytes(c.d, e, filepath.Join(snap, "fs"))
		if size <= 0 {
			continue
		}
		if uid := snapshotPodUID(c.d, id, mountIDs); uid != "" {
			podTotals[uid] += size
		}
		if size > threshold {
			hits = append(hits, bloatHit{
				label: "snapshot " + id, bytes: size})
		}
	}
	// (3) pod stdout log dirs — <PodLogsDir>/<ns>_<pod>_<uid>/: the
	// containerd CRI writes container logs here (rotated at 10MiB ×
	// 5 by kubelet, but a chatty container under a stuck rotation —
	// or a pod with hundreds of short-lived restarts — outruns it).
	for _, logDir := range readDirNames(c.d.Cfg.Disk.PodLogsDir) {
		base := filepath.Base(logDir)
		uid := podLogDirUID(base)
		size, _ := walkBytes(c.d, e, logDir)
		if uid != "" {
			podTotals[uid] += size
		}
		if size > threshold {
			label := "pod-logs " + base
			if p, ok := podByUID[uid]; ok && p != nil {
				label = "pod " + p.Namespace + "/" + p.Name + " logs"
			}
			hits = append(hits, bloatHit{label: label, bytes: size})
		}
	}
	return hits, podTotals, podByUID
}

// snapshotMountIDs parses the host /proc/1/mountinfo once and maps
// each overlayfs snapshot ("<snapRoot>/<id>/fs" used as a mount's
// upperdir=) to the containerd task id whose rootfs mount consumes
// it — the mount point is <taskRoot>/<id>/rootfs. containerd names
// snapshot dirs numerically, so the dir name alone can never key a
// task dir; the live mount is the only snapshot→container binding.
// "" map on an unreadable mountinfo (callers fall back to the
// name-keyed lookup).
func snapshotMountIDs(d *wdeps.Deps) map[string]string {
	data, err := os.ReadFile(d.Cfg.MountinfoFile)
	if err != nil {
		return nil
	}
	hostTaskRoot := fsx.HostSidePath(d.Cfg.CtrTaskRoot)
	hostSandboxRoot := fsx.HostSidePath(d.Cfg.SandboxCtlRoot)
	hostSnapRoot := fsx.HostSidePath(d.Cfg.Disk.WLayerSnapshotsDir) + "/"
	out := map[string]string{}
	for ln := range strings.SplitSeq(string(data), "\n") {
		sep := strings.LastIndex(ln, " - ")
		if sep < 0 {
			continue
		}
		f := strings.Fields(ln[:sep])
		if len(f) < 5 {
			continue
		}
		mount := procfs.UnescapeMountPath(f[4])
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
		for opt := range strings.SplitSeq(ln[sep+3:], ",") {
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
	d        *wdeps.Deps
	lastScan time.Time
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
	c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
	hits, podTotals, podByUID := c.scanBloat(e, e.Pods)
	if len(hits) == 0 {
		c.d.State.Exit(latchdefs.LatchDiskBloat, nil)
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}
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
	// Critical band: emergency-evict the largest non-system pod
	// holding more than the threshold — kube-system/node-ops are
	// never deleted by this check.
	if used <= c.d.Cfg.Disk.BloatCriticalWatermark || !e.APIOK {
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
		return
	}
	var victim *corev1.Pod
	var victimBytes int64
	for uid, total := range podTotals {
		p := podByUID[uid]
		if total <= c.d.Cfg.Disk.BloatPodThresholdBytes || p == nil ||
			p.DeletionTimestamp != nil ||
			wdeps.EvictProtectedNamespaces[p.Namespace] ||
			wdeps.IsEvictProtectedPod(p) {
			continue
		}
		if victim == nil || total > victimBytes {
			victim, victimBytes = p, total
		}
	}
	if victim == nil {
		c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
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
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: disk-bloat evicted pod %s/%s - emptyDir holds %d bytes, /var/lib/k0s at %.1f%%",
		victim.Namespace, victim.Name, victimBytes, used*100))
	if err := c.d.Cfg.Client.PolicyV1().Evictions(victim.Namespace).
		Evict(ctx, ev); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: disk-bloat evict %s/%s failed: %v",
			victim.Namespace, victim.Name, err))
	} else {
		c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "pod_evict").Inc()
	}
	c.d.CycleResult(wdeps.CheckDiskBloat, "ok")
}

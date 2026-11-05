package workerhygiene

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// walkBytes sums regular-file sizes under root. The walk is bounded:
// after maxBloatWalkEntries entries it stops and reports
// truncated=true — the total is then a lower bound (a tree that
// huge is bloat by definition, but the walk must never become its
// own IO problem on the disk that is already full).
func (h *Hygiene) walkBytes(root string) (total int64, truncated bool) {
	entries := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, never fatal
		}
		entries++
		if entries > maxBloatWalkEntries {
			truncated = true
			return fs.SkipAll
		}
		if d.Type().IsRegular() {
			if fi, ierr := d.Info(); ierr == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total, truncated
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
func (h *Hygiene) scanBloat(pods []corev1.Pod) (hits []bloatHit,
	podTotals map[string]int64, podByUID map[string]*corev1.Pod) {
	podByUID = map[string]*corev1.Pod{}
	podTotals = map[string]int64{}
	for i := range pods {
		podByUID[string(pods[i].UID)] = &pods[i]
	}
	threshold := h.cfg.DiskBloatPodThresholdBytes
	// (1) emptyDir volumes: pods/<uid>/volumes/kubernetes.io~empty-dir/<vol>.
	for _, uidDir := range readDirNames(h.cfg.KubeletPodsDir) {
		uid := filepath.Base(uidDir)
		for _, vol := range readDirNames(filepath.Join(
			uidDir, "volumes", "kubernetes.io~empty-dir")) {
			var vst unix.Statfs_t
			if err := h.cfg.statfsFn(vol, &vst); err == nil &&
				int64(vst.Type) == int64(unix.TMPFS_MAGIC) {
				continue // medium=Memory emptyDir — can't fill the disk
			}
			size, _ := h.walkBytes(vol)
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
	// snapshots stay hits-only.
	snapRoot := filepath.Join(h.cfg.K0sDataDir, "containerd",
		"io.containerd.snapshotter.v1.overlayfs", "snapshots")
	for _, snap := range readDirNames(snapRoot) {
		id := filepath.Base(snap)
		size, _ := h.walkBytes(filepath.Join(snap, "fs"))
		if size <= 0 {
			continue
		}
		if uid := h.snapshotPodUID(id); uid != "" {
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
	for _, logDir := range readDirNames(h.cfg.PodLogsDir) {
		base := filepath.Base(logDir)
		uid := podLogDirUID(base)
		size, _ := h.walkBytes(logDir)
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

// snapshotPodUID resolves a containerd snapshot id back to the pod
// uid owning it — the CRI plugin uses the container ID as the
// snapshot key, and the runtime-v2 task dir of that ID carries the
// io.kubernetes.pod.uid annotation in config.json (either task root
// may hold it). "" when no task dir resolves (leaked/orphan
// snapshot — no pod to bill it to).
func (h *Hygiene) snapshotPodUID(id string) string {
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		cfgData, err := os.ReadFile(filepath.Join(root, id, "config.json"))
		if err != nil {
			continue
		}
		if m := podUIDRe.FindSubmatch(cfgData); m != nil {
			return string(m[1])
		}
	}
	return ""
}

func (h *Hygiene) checkDiskBloat(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkDiskBloat, "gated").Inc()
		return
	}
	var st unix.Statfs_t
	used := -1.0
	if err := h.cfg.statfsFn(h.cfg.K0sDataDir, &st); err == nil &&
		st.Blocks > 0 && st.Bavail <= st.Blocks {
		used = float64(st.Blocks-st.Bavail) / float64(st.Blocks)
	}
	if used < 0 {
		// statfs failed or returned garbage — inconclusive; keep
		// the latch like a failed probe.
		h.cycles.WithLabelValues(checkDiskBloat, "abort").Inc()
		return
	}
	if used <= h.cfg.K0sDiskBloatWatermark {
		h.state.Exit("disk-bloat", nil)
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	// The walk is IO on the disk that is full — at most once per
	// DiskBloatScanInterval; an existing latch persists meanwhile.
	if h.cfg.nowFn().Sub(h.lastBloatScan) < h.cfg.DiskBloatScanInterval {
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	h.lastBloatScan = h.cfg.nowFn()
	hits, podTotals, podByUID := h.scanBloat(pods)
	if len(hits) == 0 {
		h.state.Exit("disk-bloat", nil)
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	h.state.Enter("disk-bloat", fmt.Sprintf("targets=%d", len(hits)))
	for _, hit := range hits {
		// NPD contract: "ACTION disk-bloat: target=... bytes=...
		// used_pct=..." feeds DiskBloatRunaway (events.go).
		h.state.AppendLog(fmt.Sprintf(
			"ACTION disk-bloat: target=%s bytes=%d used_pct=%.1f",
			hit.label, hit.bytes, used*100))
	}
	h.actions.WithLabelValues(checkDiskBloat, "detect").Inc()
	// Critical band: emergency-evict the largest non-system pod
	// holding more than the threshold — kube-system/node-ops are
	// never deleted by this check.
	if used <= h.cfg.K0sDiskBloatCriticalWatermark || !apiOK {
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	var victim *corev1.Pod
	var victimBytes int64
	for uid, total := range podTotals {
		p := podByUID[uid]
		if total <= h.cfg.DiskBloatPodThresholdBytes || p == nil ||
			p.DeletionTimestamp != nil ||
			p.Namespace == "kube-system" || p.Namespace == "node-ops" {
			continue
		}
		if victim == nil || total > victimBytes {
			victim, victimBytes = p, total
		}
	}
	if victim == nil {
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	if !h.state.RateTrySpend("last-disk-bloat-evict", diskBloatEvictInterval) {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: disk-bloat victim %s/%s bytes=%d - in evict cooldown (<15m), skip",
			victim.Namespace, victim.Name, victimBytes))
		h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity —
	// a failed delete still consumed it).
	if err := h.cfg.Client.CoreV1().Pods(victim.Namespace).Delete(
		ctx, victim.Name, metav1.DeleteOptions{}); err != nil {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: disk-bloat evict %s/%s failed: %v",
			victim.Namespace, victim.Name, err))
	} else {
		h.state.AppendLog(fmt.Sprintf(
			"ACTION: disk-bloat evicted pod %s/%s - emptyDir holds %d bytes, /var/lib/k0s at %.1f%%",
			victim.Namespace, victim.Name, victimBytes, used*100))
		h.actions.WithLabelValues(checkDiskBloat, "pod_evict").Inc()
	}
	h.cycles.WithLabelValues(checkDiskBloat, "ok").Inc()
}

// --- Check: d-state-storm (W7-H1) ---
// A wedged block device (btrfs/jbd2 journal), loop device
// (baggageclaim/LocalPV) or kernel mutex drops the calling process
// into D (uninterruptible sleep) — un-killable, invisible to the
// zombie storm (state Z) and the statfs stall probes (the mount
// still answers while a runc/shim sits frozen in fsync/umount).
// The check reuses the per-cycle pid sweep: every state-D process
// is counted, and the runtime-critical subset (runc, containerd*,
// k0s*, kubelet, btrfs-*, jbd2/* kernel threads) is tallied
// separately — a storm in THOSE wedges the pod lifecycle, not just
// one workload. /proc/<pid>/wchan names the kernel function holding
// the task, reported in the latch-entry ACTION line. No remedy is
// attempted (a D-state process survives SIGKILL and every service
// restart): the latch drives nodereporter's KernelHungTasks
// condition for the NHC→SNR reboot escalation path.

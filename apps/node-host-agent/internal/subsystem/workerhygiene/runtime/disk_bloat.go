// disk_bloat.go — the W6.3 runaway-dir detector
// (wdeps.CheckDiskBloat) plus the disk side-guards that ride
// the same cycle slot: the localpv-quota LocalPV hard-quota enforcer
// (pvc-* over 1.5x capacity under disk pressure → deprioritize the
// owning pod's tasks) and the run-tmpfs host /run tmpfs guard
// (80% fill → journald vacuum + orphan .tmp sweep, 15m budget).
package runtime

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// W6.3 disk-bloat thresholds: above the warn watermark the
// bounded walk runs (at most once per DiskBloatScanInterval —
// the walk itself costs IO on the disk that is already full);
// above the critical watermark a non-system offender may be
// evicted outright. Any single dir past the pod threshold is a
// runaway target.
const (
	diskBloatEvictInterval = 15 * time.Minute // last-disk-bloat-evict budget
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
func (c *DiskBloatCheck) scanBloat(pods []corev1.Pod) (hits []bloatHit,
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
			size, _ := c.d.WalkBytes(vol)
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
	snapRoot := filepath.Join(c.d.Cfg.K0sDataDir, "containerd",
		"io.containerd.snapshotter.v1.overlayfs", "snapshots")
	for _, snap := range readDirNames(snapRoot) {
		id := filepath.Base(snap)
		size, _ := c.d.WalkBytes(filepath.Join(snap, "fs"))
		if size <= 0 {
			continue
		}
		if uid := c.snapshotPodUID(id); uid != "" {
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
		size, _ := c.d.WalkBytes(logDir)
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
func (c *DiskBloatCheck) snapshotPodUID(id string) string {
	for _, root := range []string{c.d.Cfg.CtrTaskRoot, c.d.Cfg.SandboxCtlRoot} {
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

// DiskBloatCheck is the W6.3 runaway-dir detector as a Check. It
// owns the scan stamp (ex-Hygiene.lastBloatScan) — the bounded
// walk costs IO on the very disk that is full, so above the warn
// watermark it runs at most once per DiskBloatScanInterval.
type DiskBloatCheck struct {
	d        *wdeps.Deps
	lastScan time.Time
	// localPVThrottled is the localpv-quota per-PVC throttle ledger —
	// a pod is deprioritized once per process lifetime (the
	// throttle is sticky until the pod restarts anyway).
	localPVThrottled map[string]bool
}

// Name returns the check label / WD_SIG key.
func (c *DiskBloatCheck) Name() string { return wdeps.CheckDiskBloat }

// Run executes one disk-bloat round.
func (c *DiskBloatCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "gated").Inc()
		return
	}
	// Disk side-guards run every cycle — their own watermarks
	// decide, independent of the /var/lib/k0s bloat watermark.
	c.runTmpfsGuard(ctx)
	c.localPVQuota(ctx, e)
	var st unix.Statfs_t
	used := -1.0
	if err := c.d.Cfg.Seams.Host.StatfsFn(c.d.Cfg.K0sDataDir, &st); err == nil &&
		st.Blocks > 0 && st.Bavail <= st.Blocks {
		used = float64(st.Blocks-st.Bavail) / float64(st.Blocks)
	}
	if used < 0 {
		// statfs failed or returned garbage — inconclusive; keep
		// the latch like a failed probe.
		c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "abort").Inc()
		return
	}
	if used <= c.d.Cfg.Disk.BloatWatermark {
		c.d.State.Exit(hoststate.LatchDiskBloat, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "ok").Inc()
		return
	}
	// The walk is IO on the disk that is full — at most once per
	// DiskBloatScanInterval; an existing latch persists meanwhile.
	if c.d.Cfg.Seams.Host.Clock.Now().Sub(c.lastScan) < c.d.Cfg.Disk.BloatScanInterval {
		c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "ok").Inc()
		return
	}
	c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
	hits, podTotals, podByUID := c.scanBloat(e.Pods)
	if len(hits) == 0 {
		c.d.State.Exit(hoststate.LatchDiskBloat, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "ok").Inc()
		return
	}
	c.d.State.Enter(hoststate.LatchDiskBloat, fmt.Sprintf("targets=%d", len(hits)))
	for _, hit := range hits {
		// NPD contract: "ACTION disk-bloat: target=... bytes=...
		// used_pct=..." feeds DiskBloatRunaway (events.go).
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION disk-bloat: target=%s bytes=%d used_pct=%.1f",
			hit.label, hit.bytes, used*100))
	}
	c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "detect").Inc()
	// Critical band: emergency-evict the largest non-system pod
	// holding more than the threshold — kube-system/node-ops are
	// never deleted by this check.
	if used <= c.d.Cfg.Disk.BloatCriticalWatermark || !e.APIOK {
		c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "ok").Inc()
		return
	}
	var victim *corev1.Pod
	var victimBytes int64
	for uid, total := range podTotals {
		p := podByUID[uid]
		if total <= c.d.Cfg.Disk.BloatPodThresholdBytes || p == nil ||
			p.DeletionTimestamp != nil ||
			p.Namespace == "kube-system" || p.Namespace == "node-ops" {
			continue
		}
		if victim == nil || total > victimBytes {
			victim, victimBytes = p, total
		}
	}
	if victim == nil {
		c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "ok").Inc()
		return
	}
	if !c.d.State.RateTrySpend("last-disk-bloat-evict", diskBloatEvictInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: disk-bloat victim %s/%s bytes=%d - in evict cooldown (<15m), skip",
			victim.Namespace, victim.Name, victimBytes))
		c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity —
	// a failed delete still consumed it).
	if err := c.d.Cfg.Client.CoreV1().Pods(victim.Namespace).Delete(
		ctx, victim.Name, metav1.DeleteOptions{}); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: disk-bloat evict %s/%s failed: %v",
			victim.Namespace, victim.Name, err))
	} else {
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: disk-bloat evicted pod %s/%s - emptyDir holds %d bytes, /var/lib/k0s at %.1f%%",
			victim.Namespace, victim.Name, victimBytes, used*100))
		c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "pod_evict").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "ok").Inc()
}

// --- localpv-quota: LocalPV hard-quota enforcer ---
//
// A pod writing past 1.5x its PV's capacity on an OpenEBS localpv
// hostpath under disk pressure (>80% used) starves every other
// volume on the node — the provisioner has no quota of its own.
// The enforcer measures each pvc-* dir under the provisioner
// roots, resolves the owning pod through the pod LIST's
// volume->PVC->PV chain, and deprioritizes that pod's processes
// (renice +19 + ionice idle + cgroup io.weight=1 when the v2
// interface exists). Throttled pods land in the
// localPVThrottled ledger — one throttle per agent lifetime; the
// deprioritization is sticky until the pod restarts anyway.

// localPVScanRoots returns the roots the quota scan walks —
// LocalPVQuotaDir when configured, else the ST2 provisioner roots.
func (c *DiskBloatCheck) localPVScanRoots() []string {
	if c.d.Cfg.Disk.LocalPVQuotaDir != "" {
		return []string{c.d.Cfg.Disk.LocalPVQuotaDir}
	}
	return c.d.Cfg.Disk.OrphanHostPathDirs
}

// localPVQuota runs one localpv-quota round: over-quota pvc-* dirs under
// disk pressure get their owning pod's tasks deprioritized and a
// LocalPVQuotaExceeded event emitted.
func (c *DiskBloatCheck) localPVQuota(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.APIOK || c.d.Cfg.Client == nil {
		return // PV/PVC resolution needs the apiserver
	}
	if c.localPVThrottled == nil {
		c.localPVThrottled = map[string]bool{}
	}
	pvs, err := c.d.Cfg.Client.CoreV1().PersistentVolumes().
		List(ctx, metav1.ListOptions{})
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: localpv-quota PV list failed: %v — quota scan inconclusive", err))
		return
	}
	pvCap := map[string]int64{}
	for _, pv := range pvs.Items {
		if q, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
			pvCap[pv.Name] = q.Value()
		}
	}
	// claim->pod map: pod.Spec.Volumes[].PersistentVolumeClaim —
	// resolve each claim to its PV name via a cluster-wide PVC list.
	pvcs, err := c.d.Cfg.Client.CoreV1().PersistentVolumeClaims("").
		List(ctx, metav1.ListOptions{})
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: localpv-quota PVC list failed: %v — quota scan inconclusive", err))
		return
	}
	claimPV := map[string]string{} // "<ns>/<claim>" -> volumeName
	for _, pvc := range pvcs.Items {
		claimPV[pvc.Namespace+"/"+pvc.Name] = pvc.Spec.VolumeName
	}
	podByPV := map[string]*corev1.Pod{}
	for i := range e.Pods {
		for _, v := range e.Pods[i].Spec.Volumes {
			if v.PersistentVolumeClaim == nil {
				continue
			}
			if pv := claimPV[e.Pods[i].Namespace+"/"+
				v.PersistentVolumeClaim.ClaimName]; pv != "" {
				podByPV[pv] = &e.Pods[i]
			}
		}
	}
	for _, root := range c.localPVScanRoots() {
		ents, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			if !ent.IsDir() || !strings.HasPrefix(ent.Name(), "pvc-") {
				continue
			}
			dir := filepath.Join(root, ent.Name())
			cap, ok := pvCap[ent.Name()]
			if !ok || cap <= 0 || c.localPVThrottled[dir] {
				continue
			}
			size, _ := c.d.WalkBytes(dir)
			if size <= int64(float64(cap)*c.d.Cfg.Disk.LocalPVQuotaRatio) {
				continue
			}
			// The quota only bites under real disk pressure —
			// over-request-but-plenty-free is a sizing problem,
			// not a node emergency.
			if !c.d.DiskUsageAboveWatermark(root) {
				continue
			}
			pod := podByPV[ent.Name()]
			if pod == nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: localpv-quota %s %dB > %.0fx PV cap (%dB) but no owning pod on this node",
					dir, size, c.d.Cfg.Disk.LocalPVQuotaRatio, cap))
				continue
			}
			c.throttlePVTasks(ctx, e, pod, dir, size, cap)
		}
	}
}

// throttlePVTasks deprioritizes every live task pid of the pod:
// renice +19 + ionice idle via the shared seams, plus cgroup v2
// io.weight=1 on the pod slice when the interface exists. The
// io.max variant is deliberately NOT written — an absolute byte
// rate has no safe value without device knowledge; io.weight
// achieves the same relative starvation (documented deviation).
func (c *DiskBloatCheck) throttlePVTasks(ctx context.Context,
	e *wdeps.CycleEnv, pod *corev1.Pod, dir string, size, cap int64) {

	uid := string(pod.UID)
	tasks, _ := e.TasksOnce()
	throttled := 0
	for _, t := range tasks[uid] {
		if !t.Live || t.PID <= 0 {
			continue
		}
		if err := c.d.Cfg.Seams.Host.ReniceFn(t.PID); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: localpv-quota renice +19 pid=%d failed: %v", t.PID, err))
		}
		if err := c.d.Cfg.Seams.Host.IoniceIdleFn(t.PID); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: localpv-quota ionice -c3 pid=%d failed: %v", t.PID, err))
		}
		throttled++
	}
	// cgroup v2 io.weight drop — best-effort: write `1` (lowest
	// weight) on the pod slice's io.weight if the file exists.
	kubepods := filepath.Join(c.d.Cfg.Runtime.CgroupRoot, "kubepods.slice")
	for _, podDir := range podSliceDirs(kubepods) {
		if podUIDFromSlice(podDir) != uid {
			continue
		}
		wf := filepath.Join(podDir, "io.weight")
		if _, err := os.Stat(wf); err == nil {
			if werr := os.WriteFile(wf, []byte("1"), 0o644); werr != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: localpv-quota io.weight write %s failed: %v", wf, werr))
			}
		}
		for _, scope := range containerScopeDirs(podDir) {
			wf := filepath.Join(scope, "io.weight")
			if _, err := os.Stat(wf); err == nil {
				_ = os.WriteFile(wf, []byte("1"), 0o644)
			}
		}
	}
	c.localPVThrottled[dir] = true
	c.d.LocalPVQuotaThrottled++
	c.emitPVQuotaEvent(ctx, pod, dir, size, cap, throttled)
	c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "localpv_throttle").Inc()
}

// emitPVQuotaEvent creates the LocalPVQuotaExceeded Warning event
// on the throttled pod.
func (c *DiskBloatCheck) emitPVQuotaEvent(ctx context.Context,
	pod *corev1.Pod, dir string, size, cap int64, throttled int) {

	now := c.d.Cfg.Seams.Host.Clock.Now()
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.%x", pod.Name, now.UnixNano()),
			Namespace: pod.Namespace,
		},
		EventTime: metav1.NewMicroTime(now),
		Reason:    "LocalPVQuotaExceeded",
		Note: fmt.Sprintf(
			"localpv dir %s holds %d bytes > %.0fx PV capacity %d bytes under disk pressure — %d tasks deprioritized (ionice idle + renice +19 + io.weight)",
			dir, size, c.d.Cfg.Disk.LocalPVQuotaRatio, cap, throttled),
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-host-agent",
		ReportingInstance:   c.d.Cfg.NodeName,
		Action:              "LocalPVQuotaExceeded",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
			UID:        pod.UID,
		},
	}
	if _, err := c.d.Cfg.Client.EventsV1().Events(pod.Namespace).
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: LocalPVQuotaExceeded event create failed for %s/%s: %v",
			pod.Namespace, pod.Name, err))
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: LocalPVQuotaExceeded — pod %s/%s dir=%s %dB > %.0fx cap %dB, %d tasks deprioritized",
		pod.Namespace, pod.Name, dir, size,
		c.d.Cfg.Disk.LocalPVQuotaRatio, cap, throttled))
}

// --- run-tmpfs: host /run tmpfs guard ---
//
// A full /run tmpfs kills containerd.sock, dbus and every lockfile
// on the host while every probe still answers — the classic
// "node looks healthy, nothing works" outage. The guard statfs's
// the /run mount for both bytes AND inode usage; past 80% on
// either it spends the last-run-tmpfs-clean 15m budget on a
// journal vacuum (--vacuum-size=16M on the host journal dir —
// /run/log/journal is the usual filler) plus a bounded orphan
// .tmp sweep (files older than 2h). The fill ratio itself lands
// on node_agent_run_tmpfs_used_ratio every cycle.

const (
	runTmpfsHighRatio  = 0.80
	runTmpfsCleanEvery = 15 * time.Minute
	runTmpfsMinAge     = 2 * time.Hour
	runTmpfsSweepMax   = 64 // bound one cycle's tmp sweep
)

// runTmpfsGuard executes one run-tmpfs round.
func (c *DiskBloatCheck) runTmpfsGuard(ctx context.Context) {
	var st unix.Statfs_t
	if err := c.d.Cfg.Seams.Host.StatfsFn(c.d.Cfg.Disk.HostRunDir, &st); err != nil ||
		st.Blocks == 0 {
		return // unmeasurable — keep the last ratio, never act blind
	}
	used := 1.0 - float64(st.Bavail)/float64(st.Blocks)
	if st.Files > 0 && st.Ffree <= st.Files {
		if iu := 1.0 - float64(st.Ffree)/float64(st.Files); iu > used {
			used = iu
		}
	}
	c.d.RunTmpfsUsedRatio = used
	if used <= runTmpfsHighRatio {
		return
	}
	if !c.d.State.RateTrySpend("last-run-tmpfs-clean", runTmpfsCleanEvery) {
		return
	}
	cleaned := false
	// (1) journald vacuum — the usual filler. Exec runs
	// nsenter-wrapped to the host namespaces, so JournalVacuumDir
	// is the HOST view (/run/log/journal), not the container's
	// /host/ path.
	if sd := c.d.Cfg.Systemd; sd != nil {
		if _, err := sd.Exec(ctx, "journalctl",
			"--directory="+c.d.Cfg.Disk.JournalVacuumDir,
			"--vacuum-size=16M"); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: run-tmpfs journal vacuum %s failed: %v",
				c.d.Cfg.Disk.JournalVacuumDir, err))
		} else {
			cleaned = true
		}
	}
	// (2) orphan .tmp sweep — files older than 2h under /run.
	// Bounded: at most runTmpfsSweepMax removals per cycle.
	now := c.d.Cfg.Seams.Host.Clock.Now()
	removed := 0
	_ = filepath.WalkDir(c.d.Cfg.Disk.HostRunDir,
		func(path string, de fs.DirEntry, err error) error {
			if err != nil || removed >= runTmpfsSweepMax {
				return nil //nolint:nilerr // unreadable entries are skipped, never fatal
			}
			if !de.Type().IsRegular() ||
				!strings.HasSuffix(de.Name(), ".tmp") {
				return nil
			}
			fi, ierr := de.Info()
			if ierr != nil || now.Sub(fi.ModTime()) < runTmpfsMinAge {
				return nil //nolint:nilerr // stat failures skip the entry, never fatal
			}
			if rerr := os.Remove(path); rerr == nil {
				removed++
				cleaned = true
			}
			return nil
		})
	if cleaned {
		c.d.RunTmpfsCleanups++
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: run-tmpfs-clean — /run at %.0f%%, journal vacuumed to 16M, %d orphan .tmp removed",
			used*100, removed))
		c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "run_tmpfs_clean").Inc()
	}
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

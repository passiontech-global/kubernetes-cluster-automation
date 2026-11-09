// disk_bloat.go — the disk-bloat runaway-dir detector
// (wdeps.CheckDiskBloat) plus the disk side-guards that ride
// the same cycle slot: the run-tmpfs host /run tmpfs guard
// (80% fill → journald vacuum + orphan .tmp sweep, 15m budget)
// and the coredump sweep + overlayfs writable-layer scan.
// The localpv-quota hard-quota enforcer lives in
// localpv_quota.go.
package runtime

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
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
func (c *DiskBloatCheck) walkBytes(e *wdeps.CycleEnv, root string) (int64, bool) {
	if e != nil && e.WalkOnce != nil {
		return e.WalkOnce(root)
	}
	return c.d.WalkBytes(root)
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
			size, _ := c.walkBytes(e, vol)
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
		size, _ := c.walkBytes(e, filepath.Join(snap, "fs"))
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
		size, _ := c.walkBytes(e, logDir)
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

// diskBloatEvictProtectedNamespaces — namespaces the critical-band
// evictor never touches (psiEvictExcludedNamespaces parity): system
// daemons, CNI/mesh control planes, storage operators, cert/secrets
// plumbing, the flux delivery layer, the remediation namespace.
// At 92% the disk is dying, but evicting the components needed to
// recover makes the outage unrecoverable.
var diskBloatEvictProtectedNamespaces = map[string]bool{
	"kube-system":      true,
	"node-ops":         true,
	"medik8s":          true,
	"cilium":           true,
	"linkerd":          true,
	"linkerd-cni":      true,
	"openebs":          true,
	"cert-manager":     true,
	"external-secrets": true,
	"operators":        true,
	"everest-system":   true,
	"scylla":           true,
	"scylla-manager":   true,
	"flux-system":      true,
}

// diskBloatEvictCriticalPriorityClasses — pods the scheduler marked
// untouchable (psiEvictCriticalPriorityClasses parity).
var diskBloatEvictCriticalPriorityClasses = map[string]bool{
	"system-node-critical":    true,
	"system-cluster-critical": true,
}

// diskBloatOwnedByStatefulSet reports whether any ownerReference is
// a StatefulSet — a stateful workload's pod holds identity-bound
// storage; the critical band must not churn it (psi parity).
func diskBloatOwnedByStatefulSet(p *corev1.Pod) bool {
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "StatefulSet" {
			return true
		}
	}
	return false
}

// DiskBloatCheck is the disk-bloat runaway-dir detector as a Check. It
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
	if c.d.Gated(e, wdeps.CheckDiskBloat) {
		return
	}
	// Disk side-guards run every cycle — their own watermarks
	// decide, independent of the /var/lib/k0s bloat watermark.
	c.runTmpfsGuard(ctx)
	c.measureDevShm()
	c.localPVQuota(ctx, e)
	// Stale coredump sweep (watermark-gated) and the
	// bounded writable-layer runaway scan (interval-budgeted).
	c.coredumpGC()
	c.writableLayerScan(ctx, e)
	var st unix.Statfs_t
	used := -1.0
	if err := c.d.Cfg.Seams.Host.StatfsFn(c.d.Cfg.K0sDataDir, &st); err == nil &&
		st.Blocks > 0 && st.Bavail <= st.Blocks {
		used = float64(st.Blocks-st.Bavail) / float64(st.Blocks)
	}
	if used < 0 {
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
			diskBloatEvictProtectedNamespaces[p.Namespace] ||
			diskBloatEvictCriticalPriorityClasses[p.Spec.PriorityClassName] ||
			diskBloatOwnedByStatefulSet(p) {
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
	// evict parity).
	ev := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      victim.Name,
			Namespace: victim.Namespace,
		},
	}
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
	// Bounded: at most runTmpfsSweepMax removals per cycle. An
	// fd-held file is skipped (runTmpfsFDOpen): unlinking it would
	// orphan the writer's inode — no space regained, data lost at
	// close (incident parity with unlinked-open-files).
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
			if c.runTmpfsFDOpen(path, fi) {
				// SKIP open-fd — removing an fd-held spool file
				// unlinks the name but not the inode: the writer
				// keeps filling an orphan inode (no space regained)
				// and its data vanishes at close, exactly during
				// the ≥80% emergency this sweep serves.
				c.d.State.AppendLog(fmt.Sprintf(
					"SKIP open-fd %s — held open, not an orphan; sweep left it alone",
					path))
				return nil
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

// runTmpfsFDOpen reports whether any process holds an open fd on
// the candidate file. The /proc fd walk runs only once a sweep
// candidate exists (never on an empty walk) and compares
// readlink targets under HostRunDir by Dev+Inode — the path check
// alone would miss hardlinks/renames. Unreadable /proc/<pid>
// entries are skipped: a process dying mid-scan is normal.
func (c *DiskBloatCheck) runTmpfsFDOpen(path string, fi os.FileInfo) bool {
	cst, ok := fi.Sys().(*syscall.Stat_t) // os stat results expose syscall.Stat_t, not unix.Stat_t
	if !ok {
		return false // uncomparable — fail open like the old sweep
	}
	pids, err := c.d.Proc.PIDs()
	if err != nil {
		return false
	}
	runPrefix := c.d.Cfg.Disk.HostRunDir + "/"
	for _, pid := range pids {
		fdDir := c.d.Proc.File(pid, "fd")
		fds, rerr := os.ReadDir(fdDir)
		if rerr != nil {
			continue // raced exit — normal, never fatal
		}
		for _, fd := range fds {
			target, lerr := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if lerr != nil || !strings.HasPrefix(target, runPrefix) {
				continue
			}
			tfi, serr := os.Stat(target)
			if serr != nil {
				continue
			}
			if tst, tok := tfi.Sys().(*syscall.Stat_t); tok &&
				tst.Dev == cst.Dev && tst.Ino == cst.Ino {
				return true
			}
		}
	}
	return false
}

// --- dev-shm: host /dev/shm tmpfs fill gauge (W19-K2) ---
//
// /dev/shm is a small tmpfs (typically half of RAM) that IPC-heavy
// workloads — postgres shared buffers, JVM heaps, chrome/chromium
// renderers — fill silently; once full every shm_open/mmap fails
// while disk watermarks stay green. The guard only MEASURES: statfs
// the shm mount for bytes+inodes, publish the worst ratio on
// node_agent_dev_shm_used_ratio every cycle. No remediation — a
// full shm is a workload bug, and deleting shm files corrupts
// running processes; the Prometheus alert owns the page.

// measureDevShm executes one dev-shm round.
func (c *DiskBloatCheck) measureDevShm() {
	var st unix.Statfs_t
	if err := c.d.Cfg.Seams.Host.StatfsFn(c.d.Cfg.Disk.HostShmDir, &st); err != nil ||
		st.Blocks == 0 {
		return // unmeasurable — keep the last ratio, never fake a 0
	}
	used := 1.0 - float64(st.Bavail)/float64(st.Blocks)
	if st.Files > 0 && st.Ffree <= st.Files {
		if iu := 1.0 - float64(st.Ffree)/float64(st.Files); iu > used {
			used = iu
		}
	}
	c.d.DevShmUsedRatio = used
}

// --- Coredump-storm guard + overlayfs writable-layer scan ---

// coredumpGC sweeps stale core dumps under CoredumpDir once the
// filesystem holding it crosses the disk-bloat warn watermark (the
// same evidence source the disk-bloat walk gates on). The coredump
// Storage=none drop-in keeps a converged host's store empty; this is
// the backstop for nodes the drop-in has not reached yet. Files
// younger than coredumpMinAge survive one cycle so an in-progress
// core write is never truncated mid-sweep.
func (c *DiskBloatCheck) coredumpGC() {
	dir := c.d.Cfg.Disk.CoredumpDir
	if dir == "" {
		return
	}
	var st unix.Statfs_t
	if err := c.d.Cfg.Seams.Host.StatfsFn(dir, &st); err != nil ||
		st.Blocks <= 0 || st.Bavail > st.Blocks {
		return // inconclusive — never sweep on garbage statfs
	}
	used := float64(st.Blocks-st.Bavail) / float64(st.Blocks)
	if used <= c.d.Cfg.Disk.BloatWatermark {
		return
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := c.d.Cfg.Seams.Host.Clock.Now()
	type coreFile struct {
		path string
		mod  time.Time
	}
	var stale []coreFile
	for _, ent := range ents {
		if !ent.Type().IsRegular() {
			continue
		}
		fi, err := ent.Info()
		if err != nil || now.Sub(fi.ModTime()) < coredumpMinAge {
			continue
		}
		stale = append(stale, coreFile{
			path: filepath.Join(dir, ent.Name()),
			mod:  fi.ModTime(),
		})
	}
	// Oldest first — a capped sweep drains the oldest evidence
	// deterministically instead of ReadDir-order.
	sort.Slice(stale, func(i, j int) bool { return stale[i].mod.Before(stale[j].mod) })
	removed := 0
	for _, f := range stale {
		if removed >= coredumpSweepMax {
			break // bound one cycle's blast radius — parity with runTmpfsSweepMax
		}
		if err := os.Remove(f.path); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: disk-bloat coredump rm %s failed: %v", f.path, err))
			continue
		}
		removed++
	}
	if removed == 0 {
		return
	}
	line := fmt.Sprintf(
		"ACTION: disk-bloat coredump sweep — removed %d stale core files from %s (used %.1f%%)",
		removed, dir, used*100)
	if drained := len(stale) - removed; drained > 0 {
		line += fmt.Sprintf(" — cap %d reached, %d remaining drain next cycle",
			coredumpSweepMax, drained)
	}
	c.d.State.AppendLog(line)
	c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "coredump_rm").Inc()
}

// podDeclaresEphemeralStorage reports whether ANY container of the
// pod (init + regular) pins a limits.ephemeral-storage value — the
// pods the writable-layer scan may legitimately leave alone (their
// writable layers are already bounded by the kubelet eviction chain).
func podDeclaresEphemeralStorage(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for i := range pod.Spec.InitContainers {
		if _, ok := pod.Spec.InitContainers[i].Resources.Limits[corev1.ResourceEphemeralStorage]; ok {
			return true
		}
	}
	for i := range pod.Spec.Containers {
		if _, ok := pod.Spec.Containers[i].Resources.Limits[corev1.ResourceEphemeralStorage]; ok {
			return true
		}
	}
	return false
}

// writableLayerScan is the runaway writable-layer detector:
// a container WITHOUT a limits.ephemeral-storage bound can grow its
// overlayfs upperdir until the node falls into DiskPressure — the
// one write surface the kubelet's eviction chain never measures.
// The scan walks (a) the active overlayfs snapshotter's <id>/fs
// upperdirs and (b) the kubelet pod volume dirs of pods lacking the
// limit; any writable layer past WLayerBloatThresholdBytes (5 GiB —
// deliberately tighter than the disk-bloat eviction threshold) raises a
// ContainerWritableLayerBloat Warning event (on the owning pod when
// the snapshot/pod dir resolves, else node-scoped). It is
// interval-budgeted (BloatScanInterval) because the size walk is IO
// on the very disk that is filling.
func (c *DiskBloatCheck) writableLayerScan(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.APIOK || c.d.Cfg.Client == nil {
		return // pod attribution needs the apiserver
	}
	if !c.d.State.RateTrySpend("last-wlayer-scan",
		c.d.Cfg.Disk.BloatScanInterval) {
		return
	}
	threshold := c.d.Cfg.Disk.WLayerBloatThresholdBytes
	podByUID := map[string]*corev1.Pod{}
	for i := range e.Pods {
		podByUID[string(e.Pods[i].UID)] = &e.Pods[i]
	}
	// (a) overlayfs snapshot upperdirs — the CRI plugin keys the
	// snapshot by container id and snapshotPodUID resolves it back
	// through the task dirs' pod-uid annotation.
	for _, snap := range readDirNames(c.d.Cfg.Disk.WLayerSnapshotsDir) {
		fsDir := filepath.Join(snap, "fs")
		size, _ := c.walkBytes(e, fsDir)
		if size <= threshold {
			continue
		}
		var pod *corev1.Pod
		if uid := c.snapshotPodUID(filepath.Base(snap)); uid != "" {
			pod = podByUID[uid]
		}
		if podDeclaresEphemeralStorage(pod) {
			continue
		}
		c.emitWLayerBloatEvent(ctx, pod, fsDir, size)
	}
	// (b) kubelet pod emptyDir volumes of pods without the limit —
	// the write surface the snapshot key can't see. Restricted to
	// volumes/kubernetes.io~empty-dir: configmap/secret/projected
	// volumes are kubelet-materialized (read-only), and a
	// medium=Memory emptyDir is tmpfs-backed — it fills RAM, never
	// the data disk (scanBloat's emptyDir walk applies the same
	// statfs gate).
	for _, uidDir := range readDirNames(c.d.Cfg.PodsDir) {
		pod := podByUID[filepath.Base(uidDir)]
		if podDeclaresEphemeralStorage(pod) {
			continue
		}
		for _, vol := range readDirNames(filepath.Join(
			uidDir, "volumes", "kubernetes.io~empty-dir")) {
			var vst unix.Statfs_t
			if err := c.d.Cfg.Seams.Host.StatfsFn(vol, &vst); err == nil &&
				vst.Type == int64(unix.TMPFS_MAGIC) {
				continue // medium=Memory emptyDir — can't fill the disk
			}
			size, _ := c.walkBytes(e, vol)
			if size <= threshold {
				continue
			}
			c.emitWLayerBloatEvent(ctx, pod, vol, size)
		}
	}
}

// emitWLayerBloatEvent raises the ContainerWritableLayerBloat
// Warning event — pod-scoped when the writable layer resolves back
// to a pod on this node, else node-scoped in the event namespace.
func (c *DiskBloatCheck) emitWLayerBloatEvent(ctx context.Context,
	pod *corev1.Pod, dir string, size int64) {
	now := c.d.Cfg.Seams.Host.Clock.Now()
	ns := c.d.Cfg.Host.EventNamespace
	regarding := corev1.ObjectReference{
		APIVersion: "v1",
		Kind:       "Node",
		Name:       c.d.Cfg.NodeName,
	}
	name := fmt.Sprintf("%s.wlayer.%x", c.d.Cfg.NodeName, now.UnixNano())
	owner := "node " + c.d.Cfg.NodeName
	if pod != nil {
		ns = pod.Namespace
		regarding = corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
			UID:        pod.UID,
		}
		name = fmt.Sprintf("%s.wlayer.%x", pod.Name, now.UnixNano())
		owner = "pod " + pod.Namespace + "/" + pod.Name
	}
	if err := c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		Name:      name,
		Namespace: ns,
		Reason:    "ContainerWritableLayerBloat",
		Note: fmt.Sprintf(
			"writable layer %s holds %d bytes > threshold %d and the container declares no limits.ephemeral-storage — DiskPressure risk",
			dir, size, c.d.Cfg.Disk.WLayerBloatThresholdBytes),
		When:      now,
		Regarding: regarding,
		Owner:     owner,
	}); err != nil {
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: ContainerWritableLayerBloat — %s dir=%s bytes=%d threshold=%d",
		owner, dir, size, c.d.Cfg.Disk.WLayerBloatThresholdBytes))
	c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "wlayer_detect").Inc()
}

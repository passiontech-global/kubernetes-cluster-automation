// orphan_pod_volumes.go — the orphan-pod-volumes check
// (wdeps.CheckOrphanPodVols): reaps <PodsDir>/<uid> trees whose pod
// is gone — the disk leak a force-deleted or evicted pod leaves
// when kubelet's teardown died between container stop and dir
// removal (the P2-#11 postmortem class: orphaned volume dirs
// accumulating GBs of unreferenced data on the node's disk).
//
// Every reap is gated fail-closed on ALL of:
//
//  1. e.APIOK — the apiserver pod LIST is conclusive and the uid is
//     absent from it (an inconclusive LIST rehomes nothing).
//  2. The per-cycle containerd task map is complete and holds no
//     task for the uid (a surviving sandbox/task still owns the
//     dir's mounts).
//  3. /proc/1/mountinfo shows no mountpoint at or below
//     <hostPodsDir>/<uid> — still-mounted dirs belong to
//     mountinfo-hygiene, which runs earlier in the dispatch order.
//  4. The dir's mtime AND the opv-seen-<uid> confirm marker are both
//     past Ctr.OrphanPodVolsMinAge (default 60m) — the
//     ConfirmMarker two-phase confirm (mi-task-seen-* parity).
//  5. volumes/, volume-subpaths/ and volumeDevices/ hold only the
//     empty CSI/emptyDir/projected dir skeleton plus vol_data.json
//     / etc-hosts metadata and kubelet device symlinks — any other
//     file, symlink or unreadable entry means user data and the
//     dir is reported, never touched.
//  6. The pod dir itself holds NOTHING but those three kubelet volume
//     trees — a foreign file/dir at the root is data we cannot account
//     for, so the whole dir is kept even when the volume trees are
//     clean. An unreadable pod dir fails closed too.
//
// At most orphanPodVolsMaxReapPerCycle pod dirs are removed per
// cycle so a mass orphan event drains at a fixed rate.
package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

const (
	// orphanPodVolsMaxReapPerCycle bounds the per-cycle RemoveAll
	// blast radius — a mass orphan event drains at a fixed rate
	// (mountinfoMaxReapPerCycle parity).
	orphanPodVolsMaxReapPerCycle = 5
	// orphanPodVolsMarkerPrefix is the ConfirmMarker prefix —
	// opv-seen-<uid> stamps first sight; the reap needs the marker
	// AND the dir mtime both past OrphanPodVolsMinAge.
	orphanPodVolsMarkerPrefix = "opv-seen-"
)

// OrphanPodVolsCheck is the orphaned kubelet pod volume dir reaper.
type OrphanPodVolsCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *OrphanPodVolsCheck) Name() string { return wdeps.CheckOrphanPodVols }

// Run executes one orphan-pod-volumes round.
func (c *OrphanPodVolsCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckOrphanPodVols) {
		return
	}
	ents, err := os.ReadDir(c.d.Cfg.PodsDir)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: orphan-pod-volumes read %s failed: %v — scan skipped",
			c.d.Cfg.PodsDir, err))
		c.d.CycleResult(wdeps.CheckOrphanPodVols, "abort")
		return
	}
	if !e.APIOK {
		// Gate 1's verdict is unverifiable without the pod LIST —
		// fail closed for the whole pass.
		c.d.State.AppendLog(
			"suspect: orphan-pod-volumes pod LIST inconclusive — reap stands down")
		c.d.CycleResult(wdeps.CheckOrphanPodVols, "abort")
		return
	}
	podLive := map[string]bool{}
	for i := range e.Pods {
		podLive[string(e.Pods[i].UID)] = true
	}
	// Normalize the host-side root once: a trailing slash or a ".."
	// in the configured PodsDir would otherwise desync the mount
	// prefix check from the paths mountinfo reports.
	hostPodsDir := filepath.Clean(fsx.HostSidePath(c.d.Cfg.PodsDir))
	minAge := c.d.Cfg.Ctr.OrphanPodVolsMinAge
	now := c.d.Cfg.Seams.Host.Clock.Now()

	// Gates 2+3 evidence is shared across candidates — lazily
	// resolved on the first orphan-shaped uid so an idle cycle
	// (every dir live) never builds the task map or parses
	// mountinfo. Both fail closed: an incomplete verdict stops the
	// whole pass, not just one dir.
	var tasks map[string][]wdeps.CtrTask
	var tasksComplete, tasksFetched bool
	tasksOnce := func() (map[string][]wdeps.CtrTask, bool) {
		if !tasksFetched {
			tasksFetched = true
			if e.TasksOnce != nil {
				tasks, tasksComplete = e.TasksOnce()
			}
		}
		return tasks, tasksComplete
	}
	var mounts []string
	var mountsOK, mountsFetched bool
	mountsOnce := func() ([]string, bool) {
		if !mountsFetched {
			mountsFetched = true
			mountsOK = c.loadHostMounts(&mounts)
		}
		return mounts, mountsOK
	}

	reaped := 0
	capLogged := false
	seen := map[string]bool{} // uids still orphan-shaped — marker keep-set
	for _, en := range ents {
		if !en.IsDir() || !isPodUIDDirName(en.Name()) {
			continue
		}
		uid := en.Name()
		if podLive[uid] {
			continue // gate 1 — pod still exists
		}
		taskMap, complete := tasksOnce()
		if !complete {
			// Gate 2 unverifiable — fail closed for the WHOLE pass:
			// pruning markers now would wipe every opv-seen-<uid>
			// stamp on a transient ctr timeout and reset the 60m
			// confirm windows, so abort like the APIOK gate does.
			c.d.State.AppendLog(
				"suspect: orphan-pod-volumes containerd task map inconclusive — reap stands down")
			c.d.CycleResult(wdeps.CheckOrphanPodVols, "abort")
			return
		}
		if _, ok := taskMap[uid]; ok {
			continue // a containerd task still references the pod
		}
		ms, mok := mountsOnce()
		if !mok {
			// Gate 3 unverifiable — same fail-closed abort as gate 2.
			c.d.CycleResult(wdeps.CheckOrphanPodVols, "abort")
			return
		}
		if mountUnderPodDir(ms, hostPodsDir, uid) {
			continue // still mounted — mountinfo-hygiene owns it
		}
		seen[uid] = true
		podDir := filepath.Clean(filepath.Join(c.d.Cfg.PodsDir, uid))
		// Gate 4 — BOTH the dir mtime and the confirm marker must
		// be past minAge: mtime alone can be refreshed by a late
		// kubelet write, the marker alone can't see a recycled dir.
		fi, err := os.Stat(podDir)
		if err != nil || now.Sub(fi.ModTime()) < minAge {
			continue
		}
		first, confirmed := c.d.State.ConfirmMarker(
			orphanPodVolsMarkerPrefix+uid, minAge)
		if first {
			c.d.State.AppendLog(fmt.Sprintf(
				"orphan-pod-volumes: orphan pod dir %.8s candidate - confirm in %dm",
				uid, int(minAge.Minutes())))
			continue
		}
		if !confirmed {
			continue // inside the confirm window
		}
		// Gate 5 — every kubelet volume tree must hold only plugin
		// skeleton + kubelet metadata; anything else is user data.
		// volumes/ and volume-subpaths/ share the residue rule;
		// volumeDevices/ holds kubelet device symlinks only.
		if !orphanPodVolsResidueOnly(filepath.Clean(filepath.Join(podDir, "volumes"))) ||
			!orphanPodVolsResidueOnly(filepath.Clean(filepath.Join(podDir, "volume-subpaths"))) ||
			!orphanVolDevicesResidueOnly(filepath.Clean(filepath.Join(podDir, "volumeDevices"))) {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: orphan pod dir %.8s holds volume data - left in place",
				uid))
			continue
		}
		// Gate 6 — the volume trees are clean, but a foreign entry at
		// the pod-dir root is not ours to judge: keep the whole dir
		// rather than RemoveAll something we did not inspect.
		if !orphanPodDirOnlyVolumeTrees(podDir) {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: orphan pod dir %.8s holds unexpected entries - left in place",
				uid))
			continue
		}
		if reaped >= orphanPodVolsMaxReapPerCycle {
			if !capLogged {
				capLogged = true
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: orphan-pod-volumes reap cap %d reached — remaining orphans drain next cycle",
					orphanPodVolsMaxReapPerCycle))
			}
			continue
		}
		if c.d.HoldLocalAction(ctx) {
			c.d.State.AppendLog("suspect: orphan-pod-volumes reap held — cluster maintenance in progress")
			continue
		}
		if err := os.RemoveAll(podDir); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: orphan-pod-volumes remove %s failed: %v", podDir, err))
			continue
		}
		reaped++
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: orphan-pod-volumes removed orphan pod dir %s - pod gone >%dm, no mounts/tasks",
			podDir, int(minAge.Minutes())))
		c.d.Actions.WithLabelValues(wdeps.CheckOrphanPodVols, "rm_dir").Inc()
		c.d.State.ClearBudget(orphanPodVolsMarkerPrefix + uid)
	}
	// Drop confirm markers for uids no longer orphan-shaped (pod
	// reappeared, tasks/mounts returned) so a recycled uid restarts
	// its confirm window instead of inheriting a stale stamp.
	c.d.State.PruneMarkers(orphanPodVolsMarkerPrefix,
		func(id string) bool { return seen[id] })
	c.d.CycleResult(wdeps.CheckOrphanPodVols, "ok")
}

// isPodUIDDirName reports whether a PodsDir entry name has the
// kubelet pod-dir shape — a 36-char UUID. Anything else (lost+found,
// stray files, non-UUID dirs) is not ours to judge.
func isPodUIDDirName(name string) bool {
	if len(name) != 36 {
		return false
	}
	for i, r := range name {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') ||
				(r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

// loadHostMounts parses <MountinfoFile> into the mountpoint list —
// the same field-5 + unescape the mountinfo-hygiene check uses.
// ok=false on a read failure OR an empty parse: "no mounts found"
// is not positive evidence that the pod dir is unmounted, so the
// caller must fail closed rather than detach on it.
func (c *OrphanPodVolsCheck) loadHostMounts(out *[]string) bool {
	data, err := os.ReadFile(c.d.Cfg.MountinfoFile)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: orphan-pod-volumes read %s failed: %v — mount gate unverifiable",
			c.d.Cfg.MountinfoFile, err))
		return false
	}
	for ln := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		// Clean every path: mountinfo may carry a trailing slash or
		// a ".." segment, and an unnormalized path would evade the
		// subtree prefix match below.
		p := filepath.Clean(procfs.UnescapeMountPath(f[4]))
		if p != "." && p != "" {
			*out = append(*out, p)
		}
	}
	if len(*out) == 0 {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: orphan-pod-volumes read %s yielded no mountpoints — mount gate unverifiable",
			c.d.Cfg.MountinfoFile))
		return false
	}
	return true
}

// mountUnderPodDir reports whether any mountpoint sits ANYWHERE in
// the subtree AT or BELOW <hostPodsDir>/<uid> — deep volume paths
// as well as direct children. Both sides are cleaned so a trailing
// slash or ".." segment cannot slip a still-mounted volume past
// the check and let the reaper detach it.
func mountUnderPodDir(mounts []string, hostPodsDir, uid string) bool {
	base := filepath.Clean(filepath.Join(hostPodsDir, uid))
	prefix := base + string(filepath.Separator)
	for _, m := range mounts {
		m = filepath.Clean(m)
		if m == base || strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

// orphanPodDirOnlyVolumeTrees reports whether podDir holds only the
// entries kubelet's makePodDataDirs always creates: the three volume
// trees plus etc-hosts, the empty plugins/ skeleton and containers/
// (subdirs + kubelet log symlinks). Any other entry — a user file, a
// stray directory, a symlink — means we cannot account for what
// RemoveAll would destroy, so the dir is kept. A read error (including
// a dir that vanished mid-sweep) is fail-closed too.
func orphanPodDirOnlyVolumeTrees(podDir string) bool {
	ents, err := os.ReadDir(podDir)
	if err != nil {
		return false
	}
	for _, en := range ents {
		switch en.Name() {
		case "volumes", "volume-subpaths", "volumeDevices":
			continue
		case "etc-hosts":
			// Regular file only — a symlink named etc-hosts is not
			// the kubelet metadata file.
			if en.Type().IsRegular() {
				continue
			}
			return false
		case "plugins":
			if orphanDirTreeEmpty(filepath.Join(podDir, "plugins")) {
				continue
			}
			return false
		case "containers":
			if orphanVolDevicesResidueOnly(filepath.Join(podDir, "containers")) {
				continue
			}
			return false
		default:
			return false
		}
	}
	return true
}

// orphanDirTreeEmpty reports whether dir is an empty directory tree
// (the plugin skeleton kubelet leaves behind). Missing counts as empty;
// any file or symlink anywhere inside stays fail-closed.
func orphanDirTreeEmpty(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return os.IsNotExist(err)
	}
	for _, en := range ents {
		if !en.IsDir() || !orphanDirTreeEmpty(filepath.Join(dir, en.Name())) {
			return false
		}
	}
	return true
}

// orphanPodVolsResidueOnly reports whether one pod volume tree
// (volumes/ or volume-subpaths/) holds nothing but the empty
// plugin skeleton (CSI/emptyDir/projected dir structure) and
// kubelet metadata files — any other entry (user file, symlink,
// unreadable dir) means the dir is reported, never reaped.
func orphanPodVolsResidueOnly(vols string) bool {
	return volsResidueOK(vols)
}

// orphanVolDevicesResidueOnly reports whether volumeDevices/ holds
// only kubelet's device symlinks (kubernetes.io~* → /dev/...).
// Pod workloads can never write into this tree — kubelet creates
// the links — so a symlink carries no payload and counts as
// residue; regular files, fifos and anything else stay fail-closed.
func orphanVolDevicesResidueOnly(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return os.IsNotExist(err)
	}
	for _, en := range ents {
		if en.IsDir() {
			if !orphanVolDevicesResidueOnly(filepath.Join(dir, en.Name())) {
				return false
			}
			continue
		}
		if en.Type()&os.ModeSymlink == 0 {
			return false
		}
	}
	return true
}

func volsResidueOK(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		// A missing volumes/ tree (pod had no volumes, or an earlier
		// pass already cleaned it) is EMPTY residue — safe to reap.
		// Any OTHER read failure stays fail-closed.
		return os.IsNotExist(err)
	}
	for _, en := range ents {
		if en.IsDir() {
			if !volsResidueOK(filepath.Join(dir, en.Name())) {
				return false
			}
			continue
		}
		// Regular files survive only as kubelet/CSI metadata —
		// vol_data.json (CSI volume attributes) and etc-hosts.
		// Symlinks and everything else count as user data.
		if en.Type().IsRegular() &&
			(en.Name() == "vol_data.json" || en.Name() == "etc-hosts") {
			continue
		}
		return false
	}
	return true
}

// mountinfo_hygiene.go — the mountinfo-hygiene check: the
// host /proc/1/mountinfo table bloat detector plus the orphaned
// mount reaper for the two leak groups the node actually produces:
//
//   - runtime-v2 task bundle rootfs mounts
//     /run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io/<id>/rootfs
//     whose task/container <id> is gone from the ctr listing (neither
//     the task root nor the sandbox-controller root carries the dir
//     any more) — the teardown died between umount and rm (the ctr task reaper's
//     predecessor leak), confirmed stale >30m via a first-sighting
//     marker (cni-netns-gc parity).
//   - kubelet pod volume mounts /var/lib/k0s/kubelet/pods/<uid>/volumes/*
//     whose pod <uid> is gone from the node's apiserver pod list AND
//     no containerd task still references the uid, with the pod dir
//     itself stale >30m (mtime).
//
// Every orphan is lazily unmounted (`umount -l`) through the systemd
// nsenter wrapper so the HOST mount namespace is the one modified —
// the paths parsed from mountinfo are already host-side.
package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

const (
	// mountinfoBloatLines is the table-size warn threshold — a
	// healthy worker sits at a few hundred entries; thousands of
	// lines mean leaked mounts are accumulating and every mount
	// walk on the node (kubelet, CNI, stats) slows down.
	mountinfoBloatLines = 1500
	// mountinfoOrphanAge is the 30m confirmation window both orphan
	// groups must be stale past before any umount fires.
	mountinfoOrphanAge = 30 * time.Minute
	// mountinfoMaxReapPerCycle bounds the per-cycle umount blast
	// radius (orphan-sandbox-netns parity — a mass leak drains at a fixed rate).
	mountinfoMaxReapPerCycle = 10
	// mountinfoBloatEventBudget rate-limits the MountinfoTableBloat
	// event — the table bloats slowly, one event per hour is ample.
	mountinfoBloatEventBudget = time.Hour

	// The clear thresholds are DERIVED from the configured enter thresholds
	// (enterRatio*0.80, sharedMax*3/4) — a fixed 0.65/2048 pair would never
	// be reachable when an operator lowers the enter knobs, wedging the
	// MountTablePressure latch permanently.
	mountTableClearFactor     = 0.80
	mountSharedClearDivisor   = 4
	mountSharedClearNumerator = 3
	mountMaxDefaultCeiling    = int64(100000)
	mountMaxRaiseCooldown     = 30 * time.Minute
	mountMaxRaiseBudgetFile   = "last-mount-max-raise"
	mountPressureLogCadence   = time.Hour
)

// MountinfoCheck is the mountinfo table hygiene check.
type MountinfoCheck struct {
	d               *wdeps.Deps
	fails           int
	shimWedgeStreak int
}

// NewMountinfo builds the mountinfo-hygiene check.
func NewMountinfo(d *wdeps.Deps) *MountinfoCheck { return &MountinfoCheck{d: d} }

// Name returns the check label / WD_SIG key.
func (c *MountinfoCheck) Name() string { return wdeps.CheckMountinfo }

// Run executes one mountinfo-hygiene round.
func (c *MountinfoCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckMountinfo) {
		return
	}
	entries, lines, err := c.d.MountinfoEntries(e)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: mountinfo-hygiene read %s failed: %v — scan skipped",
			c.d.Cfg.MountinfoFile, err))
		c.d.CycleResult(wdeps.CheckMountinfo, "abort")
		return
	}
	hostTaskRoot := fsx.HostSidePath(c.d.Cfg.CtrTaskRoot)
	hostPodsDir := fsx.HostSidePath(c.d.Cfg.PodsDir)

	// podByUID only counts when the apiserver answered — an
	// inconclusive LIST must never rehome a mounted volume
	// (teardown fail-closed parity).
	podLive := map[string]bool{}
	podVolEligible := e.APIOK
	if podVolEligible {
		for i := range e.Pods {
			podLive[string(e.Pods[i].UID)] = true
		}
	}
	// The containerd task map is the "no ctr container references
	// it" verdict; an incomplete map (a root unlistable) makes the
	// pod-volume group unverifiable → fail closed. Lazily resolved:
	// the map only matters when a pod-volume mount line actually
	// shows up (and only when the apiserver answered), so a cycle
	// with no pod-volume candidates never builds it.
	var tasks map[string][]wdeps.CtrTask
	tasksComplete := false
	tasksFetched := false
	tasksOnce := func() (map[string][]wdeps.CtrTask, bool) {
		if !tasksFetched {
			tasksFetched = true
			if e.TasksOnce != nil {
				tasks, tasksComplete = e.TasksOnce()
			}
		}
		return tasks, tasksComplete
	}

	seen := map[string]bool{}       // marker ids still candidates
	pendingVol := map[string]bool{} // pod-vol UIDs needing marker retention
	sawIncompleteTasks := false
	sawTaskStatErr := false
	sawVolScanErr := false
	reaped := 0        // per-cycle umount blast radius
	capLogged := false // the reap-cap suspect line logs once per cycle
	umountHoldChecked := false
	umountHeld := false
	holdUmount := func() bool {
		if !umountHoldChecked {
			umountHoldChecked = true
			umountHeld = c.d.HoldLocalAction(ctx)
		}
		return umountHeld
	}
	now := c.d.Cfg.Seams.Host.Clock.Now()

	for _, ent := range entries {
		if !ent.HasMount {
			continue
		}
		mount := ent.Mountpoint // field 5 is the mount point
		if strings.HasPrefix(mount, hostTaskRoot+"/") &&
			strings.HasSuffix(mount, "/rootfs") {
			id := filepath.Base(strings.TrimSuffix(mount, "/rootfs"))
			if id == "" || id == "." || id == "/" {
				continue
			}
			// Task/container listing parity: the id must be gone
			// from BOTH the runtime-v2 task root and the sandbox
			// controller root. A dir still present means the task
			// record exists (ctr-tasks owns the wedged-dir case).
			// A non-ENOENT stat failure is unverifiable — fail closed
			// and keep the confirmation marker intact.
			taskListed, taskOK := taskDirStatus(c.d.Cfg.CtrTaskRoot, id)
			sbListed, sbOK := taskDirStatus(c.d.Cfg.SandboxCtlRoot, id)
			if !taskOK || !sbOK {
				sawTaskStatErr = true
				seen["mi-task-seen-"+id] = true
				continue
			}
			if taskListed || sbListed {
				// Recovered → drop any pending confirmation —
				// ClearBudget removes file AND the RAM lastSpent
				// mirror so the 30m window truly resets.
				c.d.State.ClearBudget("mi-task-seen-" + id)
				continue
			}
			seen["mi-task-seen-"+id] = true
			marker := "mi-task-seen-" + id
			if !c.d.StateFileExists(marker) {
				c.d.State.RateSpend(marker)
				c.d.State.AppendLog(fmt.Sprintf(
					"mountinfo-hygiene: orphan task rootfs candidate %.12s - confirm in %dm",
					id, int(mountinfoOrphanAge.Minutes())))
				continue
			}
			if !c.d.State.RateOK(marker, mountinfoOrphanAge) {
				continue // inside the 30m confirmation window
			}
			if reaped >= mountinfoMaxReapPerCycle {
				if !capLogged {
					capLogged = true
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: mountinfo-hygiene reap cap %d reached — remaining orphans drain next cycle",
						mountinfoMaxReapPerCycle))
				}
				continue // skip the pointless stat/glob/marker work
			}
			if holdUmount() {
				c.d.State.SuspectLog("mountinfo-umount-held",
					"suspect: mountinfo-hygiene orphan umount held — cluster maintenance in progress",
					mountPressureLogCadence)
				continue
			}
			if c.umountOrphan(ctx, mount) {
				reaped++
				c.d.State.ClearBudget(marker)
			}
			continue
		}
		if !podVolEligible {
			continue // an inconclusive LIST must never rehome a volume
		}
		if !strings.HasPrefix(mount, hostPodsDir+"/") {
			continue
		}
		{
			rel := strings.TrimPrefix(mount, hostPodsDir+"/")
			// The mount point must sit under the pod's volumes tree:
			// <uid>/volumes/<plugin>/<vol>.
			parts := strings.SplitN(rel, "/", 3)
			if len(parts) < 3 || !strings.HasPrefix(parts[1], "volumes") {
				continue
			}
			uid := parts[0]
			if uid == "" || podLive[uid] {
				continue
			}
			taskMap, _ := tasksOnce()
			if _, ok := taskMap[uid]; ok {
				continue // a containerd task still references the pod
			}
			// An incomplete map makes the pod-volume group
			// unverifiable → fail closed.
			if !tasksComplete {
				sawIncompleteTasks = true
				continue
			}
			// Staleness evidence is the pod dir's own mtime — the
			// spec's "pod dir stale > 30m" gate.
			podDir := filepath.Join(c.d.Cfg.PodsDir, uid)
			fi, err := os.Stat(podDir)
			if err != nil {
				if !os.IsNotExist(err) {
					sawVolScanErr = true
					pendingVol[uid] = true
				}
				continue
			}
			if now.Sub(fi.ModTime()) < mountinfoOrphanAge {
				continue
			}
			marker := "mi-vol-seen-" + uid
			first, confirmed := c.d.State.ConfirmMarker(marker, mountinfoOrphanAge)
			if first || !confirmed {
				pendingVol[uid] = true
				if first {
					c.d.State.AppendLog(fmt.Sprintf(
						"mountinfo-hygiene: orphan pod volume candidate %.8s - confirm in %dm",
						uid, int(mountinfoOrphanAge.Minutes())))
				}
				continue
			}
			if reaped >= mountinfoMaxReapPerCycle {
				pendingVol[uid] = true
				if !capLogged {
					capLogged = true
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: mountinfo-hygiene reap cap %d reached — remaining orphans drain next cycle",
						mountinfoMaxReapPerCycle))
				}
				continue
			}
			if holdUmount() {
				pendingVol[uid] = true
				c.d.State.SuspectLog("mountinfo-umount-held",
					"suspect: mountinfo-hygiene orphan umount held — cluster maintenance in progress",
					mountPressureLogCadence)
				continue
			}
			if c.umountOrphan(ctx, mount) {
				reaped++
			} else {
				pendingVol[uid] = true
			}
		}
	}
	pruneMountinfoMarkers(c.d, seen)
	if !sawVolScanErr && c.d.Cfg.PodsDir != "" {
		if _, rerr := os.ReadDir(c.d.Cfg.PodsDir); rerr != nil && !os.IsNotExist(rerr) {
			sawVolScanErr = true
		}
	}
	if podVolEligible && !sawIncompleteTasks && !sawVolScanErr {
		c.d.State.PruneMarkers("mi-vol-seen-", func(id string) bool { return pendingVol[id] })
	}

	if lines > mountinfoBloatLines {
		c.emitBloatEvent(ctx, lines)
	}
	pressureOK := c.checkMountPressure(ctx, entries, lines)
	loopOK := c.reapOrphanLoops(ctx, e, entries, hostPodsDir, podLive, tasksOnce)
	shimWedgeOK := c.reconcileShimMountWedges(ctx, e, entries, hostPodsDir, podLive)
	if !pressureOK || !loopOK || !shimWedgeOK || sawTaskStatErr || sawVolScanErr || sawIncompleteTasks {
		c.d.CycleResult(wdeps.CheckMountinfo, "abort")
		return
	}
	c.d.CycleResult(wdeps.CheckMountinfo, "ok")
}

func (c *MountinfoCheck) checkMountPressure(ctx context.Context, entries []wdeps.MountEntry, totalMounts int) bool {
	maxShared, maxGroup, maxMount := maxSharedPeerGroup(entries)

	enterRatio := c.d.Cfg.Wave3.MountTableEnterRatio
	sharedMax := c.d.Cfg.Wave3.MountSharedStormMax
	// Clear thresholds move WITH the enter knobs so the latch can always
	// recover (no fixed 0.65/2048 that an operator cannot reach).
	clearRatio := enterRatio * mountTableClearFactor
	sharedClearMax := sharedMax * mountSharedClearNumerator / mountSharedClearDivisor

	mountMaxPath := filepath.Join(c.d.Cfg.ProcRoot, "sys", "fs", "mount-max")
	mountMax := mountMaxDefaultCeiling
	mountMaxReadable := false
	raw, err := os.ReadFile(mountMaxPath)
	switch {
	case err == nil:
		v, perr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if perr != nil || v <= 0 {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: mountinfo-hygiene parse %s failed: %q (%v) — mount pressure inconclusive, keeping state",
				mountMaxPath, strings.TrimSpace(string(raw)), perr))
			return false
		}
		mountMax = v
		mountMaxReadable = true
	case os.IsNotExist(err):
		// Older kernels lack fs.mount-max — fall back to default ceiling.
	default:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: mountinfo-hygiene read %s failed: %v — mount pressure inconclusive, keeping state",
			mountMaxPath, err))
		return false
	}
	c.d.Series.MountMaxSharedPeers = int64(maxShared)

	ratio := float64(totalMounts) / float64(mountMax)
	ceiling := c.d.Cfg.Wave3.MountMaxCeiling
	// The raise is the ONLY destructive action in this function. Ask
	// the maintenance gate only when it is actually candidates —
	// calling HoldLocalAction on a healthy sweep hits Nodes().Get
	// every 60s from every node for no reason.
	eligible := mountMaxReadable && ratio >= enterRatio && mountMax < ceiling
	held := false
	if eligible {
		// Maintenance gate: a local action hold must not be
		// overridden by a background kernel-tuning write.
		held = c.d.HoldLocalAction(ctx)
	}
	if eligible && !held &&
		c.d.State.RateTrySpend(mountMaxRaiseBudgetFile, mountMaxRaiseCooldown) {
		newMax := mountMax * 2
		if newMax > ceiling {
			newMax = ceiling
		}
		if err := os.WriteFile(mountMaxPath, []byte(fmt.Sprintf("%d\n", newMax)), 0o644); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: mountinfo-hygiene raise fs.mount-max %d->%d failed: %v",
				mountMax, newMax, err))
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: mountinfo-hygiene raised fs.mount-max %d->%d (entries=%d ratio=%.2f)",
				mountMax, newMax, totalMounts, ratio))
			c.d.Actions.WithLabelValues(wdeps.CheckMountinfo, "raise_mount_max").Inc()
			mountMax = newMax
			ratio = float64(totalMounts) / float64(mountMax)
		}
	} else if eligible && held {
		c.d.State.SuspectLog("mount-max-raise-held", fmt.Sprintf(
			"suspect: mountinfo-hygiene fs.mount-max raise held by maintenance (entries=%d ratio=%.2f)",
			totalMounts, ratio), mountPressureLogCadence)
	}
	c.d.Series.MountTableUtilRatio = ratio

	tripped := ratio >= enterRatio || maxShared >= sharedMax
	cleared := ratio <= clearRatio && maxShared < sharedClearMax
	switch {
	case tripped:
		if c.d.StreakPending(&c.fails, fmt.Sprintf(
			"suspect: mountinfo-hygiene mount pressure entries=%d/%d (%.2f) max_shared=%d",
			totalMounts, mountMax, ratio, maxShared)) {
			return true
		}
		c.d.State.Enter(latchdefs.LatchMountTablePressure, fmt.Sprintf(
			"entries=%d/%d (%.2f) max_shared=%d (group=%s mount=%s)",
			totalMounts, mountMax, ratio, maxShared, maxGroup, maxMount))
	case cleared:
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchMountTablePressure, nil)
	default:
		// Inside the hysteresis band: no verdict change, but drop any
		// stale streak so a re-trip needs a fresh confirmation window.
		c.fails = 0
	}
	return true
}

func maxSharedPeerGroup(entries []wdeps.MountEntry) (maxCount int, maxGroup, maxMount string) {
	counts := map[string]int{}
	repMount := map[string]string{}
	for _, ent := range entries {
		if !ent.HasMount || len(ent.SharedGroups) == 0 {
			continue
		}
		for _, grp := range ent.SharedGroups {
			counts[grp]++
			if _, ok := repMount[grp]; !ok {
				repMount[grp] = ent.Mountpoint
			}
			if counts[grp] > maxCount {
				maxCount = counts[grp]
				maxGroup = grp
				maxMount = repMount[grp]
			}
		}
	}
	return maxCount, maxGroup, maxMount
}

// taskDirStatus reports whether <root>/<id> still exists — the ctr
// task/container listing's filesystem port (the CRI plugin keeps a
// task dir per live container; a dir present means the record lives).
// ok=false on non-ENOENT stat errors so callers fail closed without
// clearing pending markers or unmounting mounts.
func taskDirStatus(root, id string) (listed, ok bool) {
	if root == "" {
		return false, true
	}
	_, err := os.Stat(filepath.Join(root, id))
	if err == nil {
		return true, true
	}
	if os.IsNotExist(err) {
		return false, true
	}
	return false, false
}

// taskDirListed reports whether <root>/<id> exists (used by unit tests).
func taskDirListed(root, id string) bool {
	listed, _ := taskDirStatus(root, id)
	return listed
}

// umountOrphan lazily unmounts one orphan mountpoint inside the HOST
// mount namespace. No systemd client (tests/nil) or a failed umount
// keeps the orphan (and the marker) for the next cycle.
func (c *MountinfoCheck) umountOrphan(ctx context.Context, mount string) bool {
	if c.d.Cfg.Systemd == nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: mountinfo-hygiene orphan %s confirmed but no systemd client — skip umount",
			mount))
		return false
	}
	out, err := c.d.Cfg.Systemd.Exec(ctx, "umount", "-l", mount)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: mountinfo-hygiene umount -l %s failed: %v (%s)",
			mount, err, strings.TrimSpace(out)))
		return false
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: mountinfo-hygiene umount -l orphan mount %s - stale >%dm",
		mount, int(mountinfoOrphanAge.Minutes())))
	c.d.Actions.WithLabelValues(wdeps.CheckMountinfo, "umount_rm").Inc()
	return true
}

// emitBloatEvent creates the MountinfoTableBloat Warning event on
// the node (rate-limited to one per hour — the table grows slowly).
func (c *MountinfoCheck) emitBloatEvent(ctx context.Context, lines int) {
	if c.d.Cfg.Client == nil {
		return
	}
	if !c.d.State.RateTrySpend("last-mountinfo-bloat-event",
		mountinfoBloatEventBudget) {
		return
	}
	now := c.d.Cfg.Seams.Host.Clock.Now()
	if err := c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		Name:      fmt.Sprintf("%s.mountinfo-bloat.%x", c.d.Cfg.NodeName, now.UnixNano()),
		Namespace: c.d.Cfg.Host.EventNamespace,
		Reason:    "MountinfoTableBloat",
		Note: fmt.Sprintf(
			"host mountinfo table holds %d entries (> %d) — leaked mounts are accumulating",
			lines, mountinfoBloatLines),
		When: now,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       c.d.Cfg.NodeName,
		},
	}); err != nil {
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: MountinfoTableBloat — mountinfo entries=%d threshold=%d",
		lines, mountinfoBloatLines))
}

// pruneMountinfoMarkers drops mi-task-seen-* markers whose id is no
// longer an orphan candidate (the task reappeared or the leak
// resolved) — stale-marker hygiene, cni-netns-gc parity.
func pruneMountinfoMarkers(d *wdeps.Deps, seen map[string]bool) {
	ms, err := filepath.Glob(filepath.Join(d.Cfg.WatchdogStateDir, "mi-task-seen-*"))
	if err != nil {
		return
	}
	for _, m := range ms {
		if base := filepath.Base(m); !seen[base] {
			d.State.ClearBudget(base)
		}
	}
}

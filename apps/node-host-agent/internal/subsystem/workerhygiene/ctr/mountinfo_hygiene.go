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
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
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
)

// MountinfoCheck is the mountinfo table hygiene check.
type MountinfoCheck struct{ d *wdeps.Deps }

// NewMountinfo builds the mountinfo-hygiene check.
func NewMountinfo(d *wdeps.Deps) *MountinfoCheck { return &MountinfoCheck{d: d} }

// Name returns the check label / WD_SIG key.
func (c *MountinfoCheck) Name() string { return wdeps.CheckMountinfo }

// Run executes one mountinfo-hygiene round.
func (c *MountinfoCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckMountinfo) {
		return
	}
	data, err := os.ReadFile(c.d.Cfg.MountinfoFile)
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

	seen := map[string]bool{} // marker ids still candidates
	reaped := 0               // per-cycle umount blast radius
	capLogged := false        // the reap-cap suspect line logs once per cycle
	now := c.d.Cfg.Seams.Host.Clock.Now()

	for ln := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		mount := procfs.UnescapeMountPath(f[4]) // field 5 is the mount point
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
			if taskDirListed(c.d.Cfg.CtrTaskRoot, id) ||
				taskDirListed(c.d.Cfg.SandboxCtlRoot, id) {
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
			} else if c.umountOrphan(ctx, mount) {
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
				continue
			}
			// Staleness evidence is the pod dir's own mtime — the
			// spec's "pod dir stale > 30m" gate.
			podDir := filepath.Join(c.d.Cfg.PodsDir, uid)
			fi, err := os.Stat(podDir)
			if err != nil || now.Sub(fi.ModTime()) < mountinfoOrphanAge {
				continue
			}
			if reaped >= mountinfoMaxReapPerCycle {
				if !capLogged {
					capLogged = true
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: mountinfo-hygiene reap cap %d reached — remaining orphans drain next cycle",
						mountinfoMaxReapPerCycle))
				}
				continue
			}
			if c.umountOrphan(ctx, mount) {
				reaped++
			}
		}
	}
	pruneMountinfoMarkers(c.d, seen)

	if n := countLines(data); n > mountinfoBloatLines {
		c.emitBloatEvent(ctx, n)
	}
	c.d.CycleResult(wdeps.CheckMountinfo, "ok")
}

// taskDirListed reports whether <root>/<id> still exists — the ctr
// task/container listing's filesystem port (the CRI plugin keeps a
// task dir per live container; a dir present means the record lives).
func taskDirListed(root, id string) bool {
	if root == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(root, id))
	return err == nil
}

// countLines counts non-empty mountinfo lines.
func countLines(data []byte) int {
	n := 0
	for ln := range strings.SplitSeq(string(data), "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
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

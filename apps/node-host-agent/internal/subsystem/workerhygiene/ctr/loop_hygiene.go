// loop_hygiene.go — Wave-3 #4b: orphan /dev/loop* device reaper.
//
// Detects loop devices under <SysBlockDir>/loop* whose backing_file was
// deleted (" (deleted)" suffix) or belonged to a dead pod UID when APIOK &&
// tasksComplete, with an empty holders/ dir and absent from EVERY mount
// namespace's mountinfo (a loop mounted only inside a container's mount ns
// must never be detached), confirmed over 30m (loop-seen-<dev>), then
// detached through `losetup -d` in the HOST namespace.
package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	loopMarkerPrefix = "loop-seen-"
	loopMaxReap      = 10
	// loopSuspectLogCadence throttles the "skipped detach" suspect lines
	// (held by maintenance / no host /dev) so a persistent condition does
	// not spam the watchdog log every cycle.
	loopSuspectLogCadence = time.Hour
)

func (c *MountinfoCheck) reapOrphanLoops(
	ctx context.Context,
	e *wdeps.CycleEnv,
	mountinfoData []byte,
	hostPodsDir string,
	podLive map[string]bool,
	tasksOnce func() (map[string][]wdeps.CtrTask, bool),
) bool {
	if !c.d.Cfg.Wave3.LoopGCEnabled {
		return true
	}
	// The caller derives this from PodsDir; a trailing slash would
	// otherwise turn "<dir>/" into "<dir>//" in the prefix compare.
	hostPodsDir = filepath.Clean(hostPodsDir)
	sysBlock := c.d.Cfg.Wave3.SysBlockDir
	if sysBlock == "" {
		return true
	}
	if _, rerr := os.ReadDir(sysBlock); rerr != nil {
		if os.IsNotExist(rerr) {
			c.d.State.PruneMarkers(loopMarkerPrefix, func(string) bool { return false })
			return true
		}
		return false
	}
	loopDirs, err := filepath.Glob(filepath.Join(sysBlock, "loop*"))
	if err != nil || len(loopDirs) == 0 {
		c.d.State.PruneMarkers(loopMarkerPrefix, func(string) bool { return false })
		return true
	}

	pid1Sources := parseMountSources(mountinfoData)
	// The full namespace scan is built lazily — only when a candidate is
	// actually about to be detached. Paths from every /proc/<pid>/mountinfo
	// are merged (procfs.UnescapeMountPath inside parseMountSources) so a
	// loop mounted in a container's mount ns is never mistaken for an orphan.
	allSources := map[string]bool{}
	allScanned := false
	sawScanErr := false
	seen := map[string]bool{}
	reaped := 0

	for _, dir := range loopDirs {
		devName := filepath.Base(dir)
		if !isLoopDevName(devName) {
			continue
		}
		// A loop device with partitions (loopNp*) is in use by a
		// filesystem on the partition — detaching the parent would
		// pull the mount out from under it. Fail closed. On Linux
		// the partition sysfs nodes live INSIDE the parent's dir
		// (/sys/block/loop0/loop0p1), so the glob must be relative
		// to `dir`, not to sysBlock.
		if hasLoopPartitions(dir, devName) {
			continue
		}
		// autoclear=1 means the kernel clears the device on last close;
		// it is still wired into a live teardown path, never an orphan.
		// Non-ENOENT read errors leave autoclear indeterminate -> fail closed.
		auto, aerr := os.ReadFile(filepath.Join(dir, "loop", "autoclear"))
		if aerr != nil {
			if !os.IsNotExist(aerr) {
				sawScanErr = true
				seen[devName] = true
				continue
			}
		} else if strings.TrimSpace(string(auto)) == "1" {
			continue
		}
		backingBytes, err := os.ReadFile(filepath.Join(dir, "loop", "backing_file"))
		if err != nil {
			if !os.IsNotExist(err) {
				sawScanErr = true
			}
			continue
		}
		backing := strings.TrimSpace(string(backingBytes))
		if backing == "" {
			continue
		}

		isOrphan := strings.HasSuffix(backing, " (deleted)")
		if !isOrphan && hostPodsDir != "" && strings.HasPrefix(backing, hostPodsDir+"/") {
			if e == nil || !e.APIOK {
				// Transient API outage makes pod-backed loop liveness
				// indeterminate: preserve markers rather than pruning.
				sawScanErr = true
				seen[devName] = true
				continue
			}
			rel := strings.TrimPrefix(backing, hostPodsDir+"/")
			uid, _, _ := strings.Cut(rel, "/")
			if uid != "" && !podLive[uid] {
				taskMap, tasksComplete := tasksOnce()
				if !tasksComplete {
					sawScanErr = true
				} else if _, hasTask := taskMap[uid]; !hasTask {
					isOrphan = true
				}
			}
		}
		if !isOrphan {
			continue
		}

		// holders/ MUST be readable and empty — any error (including a
		// missing/unstatable dir) is indeterminate → fail closed.
		holders, err := os.ReadDir(filepath.Join(dir, "holders"))
		if err != nil {
			if !os.IsNotExist(err) {
				sawScanErr = true
			}
			seen[devName] = true
			continue
		}
		if len(holders) > 0 {
			continue
		}

		// /dev/loopN must be absent from EVERY mount namespace, not just
		// PID 1's — a container may hold the only mount of the loop.
		mounted, ok := c.loopMountedAnywhere(pid1Sources, devName, &allSources, &allScanned)
		if !ok {
			sawScanErr = true
			seen[devName] = true
			continue
		}
		if mounted {
			continue
		}

		seen[devName] = true
		marker := loopMarkerPrefix + devName
		if _, confirmed := c.d.State.ConfirmMarker(marker, mountinfoOrphanAge); !confirmed {
			continue
		}
		if reaped >= loopMaxReap {
			continue
		}
		// Destructive heal gate: an L1/L3 maintenance hold must never be
		// overridden by this background reaper.
		if c.d.HoldLocalAction(ctx) {
			c.d.State.SuspectLog("loop-detach-held",
				"suspect: mountinfo-hygiene loop detach held by maintenance",
				loopSuspectLogCadence)
			continue
		}
		// losetup -d runs inside PID 1's mount namespace, so the
		// device is reachable either through the mounted /host/dev
		// (standalone) OR through PID 1's own root (/proc/1/root/dev
		// in the DaemonSet, which does NOT mount /host/dev). Checking
		// only /host/dev made every DaemonSet detach skip forever.
		hostDevPath := filepath.Join(c.d.Cfg.Wave3.HostDevDir, devName)
		pid1DevPath := c.d.Proc.File(1, "root", "dev", devName)
		if _, err := os.Stat(hostDevPath); err != nil {
			if _, err2 := os.Stat(pid1DevPath); err2 != nil {
				c.d.State.SuspectLog("loop-detach-no-hostdev", fmt.Sprintf(
					"suspect: mountinfo-hygiene loop %s confirmed but host /dev not mounted — skip detach",
					devName), loopSuspectLogCadence)
				continue
			}
		}
		// Run losetup in the HOST mount namespace via the systemd seam —
		// the plain /dev/<dev> path is resolved after nsenter, so it is the
		// host's device node that is detached, not a container /dev copy.
		devPath := filepath.Join("/dev", devName)
		if err := c.d.Cfg.Seams.Host.DetachLoopFn(ctx, devPath); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: mountinfo-hygiene loop detach %s (%s) failed: %v",
				devPath, backing, err))
			continue
		}
		reaped++
		c.d.State.ClearBudget(marker)
		c.d.Series.LoopDevicesReaped++
		c.d.Actions.WithLabelValues(wdeps.CheckMountinfo, "loop_detach").Inc()
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: mountinfo-hygiene detached orphan loop device %s (backing=%q)",
			devPath, backing))
	}

	if !sawScanErr {
		c.d.State.PruneMarkers(loopMarkerPrefix, func(id string) bool { return seen[id] })
	}
	return !sawScanErr
}

// loopMountedAnywhere reports whether devName is a mount source in any mount
// namespace. The first return is false when the verdict is indeterminate
// (/proc unreadable) so the caller fails closed. pid1Sources is the already
// parsed /proc/1/mountinfo handed to this check; the full scan is built lazily
// and shared across all candidates in a cycle.
func (c *MountinfoCheck) loopMountedAnywhere(pid1Sources map[string]bool,
	devName string, allSources *map[string]bool, allScanned *bool) (mounted, ok bool) {
	dev := "/dev/" + devName
	if pid1Sources[dev] {
		return true, true
	}
	if !*allScanned {
		m := map[string]bool{}
		pids, err := c.d.Proc.PIDs()
		if err != nil {
			// An unreadable /proc cannot prove the loop is unused.
			return false, false
		}
		seenNS := map[string]bool{}
		if c.d.Cfg.MountinfoFile == c.d.Proc.File(1, "mountinfo") {
			if ns, nerr := os.Readlink(c.d.Proc.File(1, "ns", "mnt")); nerr == nil && ns != "" {
				seenNS[ns] = true
			}
		}
		scanErr := false
		for _, pid := range pids {
			ns, nerr := os.Readlink(c.d.Proc.File(pid, "ns", "mnt"))
			if nerr == nil && ns != "" && seenNS[ns] {
				continue
			}
			data, err := os.ReadFile(c.d.Proc.File(pid, "mountinfo"))
			if err != nil {
				if !os.IsNotExist(err) {
					// Unreadable /proc/<pid>/mountinfo (e.g. EACCES) cannot
					// prove a container mount namespace does not mount dev.
					scanErr = true
				}
				// ENOENT: process exited mid-walk — its namespace is gone.
				// Do not record seenNS[ns] until ReadFile succeeds so sibling
				// PIDs in the same mount namespace are still scanned.
				continue
			}
			if nerr == nil && ns != "" {
				seenNS[ns] = true
			}
			for src := range parseMountSources(data) {
				m[src] = true
			}
		}
		*allSources = m
		if scanErr {
			*allScanned = false
			if m[dev] {
				return true, true
			}
			return false, false
		}
		*allScanned = true
	}
	return (*allSources)[dev], true
}

// hasLoopPartitions reports whether <dir>/<devName>p* exists, where
// dir is the loop device's OWN sysfs directory (/sys/block/loop0).
// Linux places loop partitions at /sys/block/loop0/loop0p1, never at
// /sys/block/loop0p1 — globbing beside the parent silently missed
// every partition and detached in-use loops.
func hasLoopPartitions(dir, devName string) bool {
	if !isLoopDevName(devName) {
		return false
	}
	m, err := filepath.Glob(filepath.Join(dir, devName+"p*"))
	if err != nil {
		return false
	}
	for _, p := range m {
		if strings.HasPrefix(filepath.Base(p), devName+"p") {
			return true
		}
	}
	return false
}

// isLoopDevName accepts only loop<digits> (loop0, loop12, ...).
// Everything else (loop-control, loop0p1, a nested path) is rejected
// before it can be spliced into a glob pattern.
func isLoopDevName(name string) bool {
	const prefix = "loop"
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return false
	}
	for i := len(prefix); i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

func parseMountSources(mountinfoData []byte) map[string]bool {
	sources := map[string]bool{}
	for ln := range strings.SplitSeq(string(mountinfoData), "\n") {
		f := strings.Fields(ln)
		for i, tok := range f {
			if tok == "-" && i+2 < len(f) {
				sources[procfs.UnescapeMountPath(f[i+2])] = true
				break
			}
		}
	}
	return sources
}

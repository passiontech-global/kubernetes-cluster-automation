// loop_hygiene.go — Wave-3 #4b: orphan /dev/loop* device reaper.
//
// Detects loop devices under <SysBlockDir>/loop* whose backing_file was
// deleted (" (deleted)" suffix) or belonged to a dead pod UID when APIOK &&
// tasksComplete, with an empty holders/ dir and absent from /proc/1/mountinfo,
// confirmed over 30m (loop-seen-<dev>), then detaches via LOOP_CLR_FD.
package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	loopMarkerPrefix = "loop-seen-"
	loopMaxReap      = 10
)

func (c *MountinfoCheck) reapOrphanLoops(
	_ context.Context,
	e *wdeps.CycleEnv,
	mountinfoData []byte,
	hostPodsDir string,
	podLive map[string]bool,
	tasksOnce func() (map[string][]wdeps.CtrTask, bool),
) {
	if !c.d.Cfg.Wave3.LoopGCEnabled {
		return
	}
	sysBlock := c.d.Cfg.Wave3.SysBlockDir
	if sysBlock == "" {
		return
	}
	loopDirs, err := filepath.Glob(filepath.Join(sysBlock, "loop*"))
	if err != nil || len(loopDirs) == 0 {
		c.d.State.PruneMarkers(loopMarkerPrefix, func(string) bool { return false })
		return
	}

	mountedSources := parseMountSources(mountinfoData)
	seen := map[string]bool{}
	reaped := 0

	for _, dir := range loopDirs {
		devName := filepath.Base(dir)
		if !strings.HasPrefix(devName, "loop") {
			continue
		}
		backingBytes, err := os.ReadFile(filepath.Join(dir, "loop", "backing_file"))
		if err != nil {
			continue
		}
		backing := strings.TrimSpace(string(backingBytes))
		if backing == "" {
			continue
		}

		isOrphan := strings.HasSuffix(backing, " (deleted)")
		if !isOrphan && e != nil && e.APIOK && hostPodsDir != "" && strings.HasPrefix(backing, hostPodsDir+"/") {
			rel := strings.TrimPrefix(backing, hostPodsDir+"/")
			uid, _, _ := strings.Cut(rel, "/")
			if uid != "" && !podLive[uid] {
				taskMap, tasksComplete := tasksOnce()
				if tasksComplete {
					if _, hasTask := taskMap[uid]; !hasTask {
						isOrphan = true
					}
				}
			}
		}
		if !isOrphan {
			continue
		}

		// Check holders/ is empty; fail closed on any non-NotExist read error.
		holders, err := os.ReadDir(filepath.Join(dir, "holders"))
		if err != nil && !os.IsNotExist(err) {
			continue
		}
		if err == nil && len(holders) > 0 {
			continue
		}

		// Ensure /dev/loopN is not referenced in /proc/1/mountinfo.
		if mountedSources["/dev/"+devName] {
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
		devPath := filepath.Join(c.d.Cfg.Wave3.HostDevDir, devName)
		if err := c.d.Cfg.Seams.Host.DetachLoopFn(devPath); err != nil {
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

	c.d.State.PruneMarkers(loopMarkerPrefix, func(id string) bool { return seen[id] })
}

func parseMountSources(mountinfoData []byte) map[string]bool {
	sources := map[string]bool{}
	for ln := range strings.SplitSeq(string(mountinfoData), "\n") {
		f := strings.Fields(ln)
		for i, tok := range f {
			if tok == "-" && i+2 < len(f) {
				sources[f[i+2]] = true
				break
			}
		}
	}
	return sources
}

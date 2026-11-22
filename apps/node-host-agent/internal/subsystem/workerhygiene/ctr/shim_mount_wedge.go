// shim_mount_wedge.go — K3 containerd-shim EBUSY mount-namespace wedge
// detector & healer inside MountinfoCheck.
//
// Detects dead-pod volume mounts (<hostPodsDir>/<uid>/volumes/...) present in
// host mountinfo (with procfs.UnescapeMountPath) that are still pinned by a
// process's /proc/<pid>/fd or /proc/<pid>/mountinfo. Fast-paths to a no-op
// when no dead-pod volume mounts appear in host mountinfo, avoids cmdline/
// environ reads on all processes (D-state safe), gates remediation/escalation
// on ConsecNeeded + HoldLocalAction, enforces host-root anti-spoof before any
// SIGKILL, and enters/exits the shared pod-teardown-wedged latch under
// wdeps.CheckMountinfo.
package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

type deadPodMount struct {
	mount string
	uid   string
}

type shimWedgeIncident struct {
	pid              int
	comm             string
	state            string
	isShim           bool
	hostRootVerified bool
	mount            string
	uid              string
}

func extractDeadPodMounts(mountinfoData []byte, hostPodsDir string, podLive map[string]bool) []deadPodMount {
	cleanPodsDir := filepath.Clean(hostPodsDir)
	if cleanPodsDir == "" || cleanPodsDir == "." || cleanPodsDir == "/" {
		return nil
	}
	prefix := cleanPodsDir + "/"
	seen := map[string]bool{}
	var out []deadPodMount
	for ln := range strings.SplitSeq(string(mountinfoData), "\n") {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		mount := filepath.Clean(procfs.UnescapeMountPath(f[4]))
		rel, ok := strings.CutPrefix(mount, prefix)
		if !ok {
			continue
		}
		parts := strings.SplitN(rel, "/", 3)
		if len(parts) < 3 || !strings.HasPrefix(parts[1], "volumes") {
			continue
		}
		uid := parts[0]
		if uid == "" || uid == "." || uid == ".." || podLive[uid] {
			continue
		}
		if seen[mount] {
			continue
		}
		seen[mount] = true
		out = append(out, deadPodMount{mount: mount, uid: uid})
	}
	return out
}

func matchDeadPodMount(target string, deadMounts []deadPodMount) (deadPodMount, bool) {
	for _, dm := range deadMounts {
		if target == dm.mount || strings.HasPrefix(target, dm.mount+"/") {
			return dm, true
		}
	}
	return deadPodMount{}, false
}

func (c *MountinfoCheck) reconcileShimMountWedges(
	ctx context.Context,
	e *wdeps.CycleEnv,
	mountinfoData []byte,
	hostPodsDir string,
	podLive map[string]bool,
) bool {
	if e == nil || !e.APIOK {
		// Fail closed when API is unreachable: do not scan, act, clear
		// streak, or release any held pod-teardown-wedged latch.
		return true
	}

	deadMounts := extractDeadPodMounts(mountinfoData, hostPodsDir, podLive)
	if len(deadMounts) == 0 {
		c.shimWedgeStreak = 0
		c.d.State.ExitFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckMountinfo, nil)
		return true
	}

	pids, pidsOK := c.d.CyclePIDs(e)
	if !pidsOK {
		return false
	}

	var stats map[int]procfs.Stat
	if e.StatsOnce != nil {
		stats = e.StatsOnce()
	}

	inconclusive := false
	var incidents []shimWedgeIncident
	for _, pid := range pids {
		if pid <= 1 {
			continue
		}
		var st procfs.Stat
		var sok bool
		if stats != nil {
			st, sok = stats[pid]
		} else {
			st, sok = c.d.Proc.Stat(pid)
		}
		if !sok || len(st.Fields) == 0 {
			if procFileReadNonENOENT(c.d.Proc.File(pid, "stat")) {
				inconclusive = true
			}
			continue
		}
		state := st.Fields[0]
		if state == "X" || state == "x" {
			continue
		}
		if !st.HasComm || !runtimeKillComm(st.Comm) {
			continue
		}

		var matched deadPodMount
		pinned := false
		fdDir := c.d.Proc.File(pid, "fd")
		fds, fdErr := os.ReadDir(fdDir)
		if fdErr != nil {
			if !os.IsNotExist(fdErr) {
				inconclusive = true
			}
		} else {
			for _, fd := range fds {
				target, lerr := os.Readlink(filepath.Join(fdDir, fd.Name()))
				if lerr != nil {
					if !os.IsNotExist(lerr) {
						inconclusive = true
					}
					continue
				}
				cleanTarget := filepath.Clean(strings.TrimSuffix(target, " (deleted)"))
				if dm, ok := matchDeadPodMount(cleanTarget, deadMounts); ok {
					matched = dm
					pinned = true
					break
				}
			}
		}

		if !pinned {
			miBytes, miErr := os.ReadFile(c.d.Proc.File(pid, "mountinfo"))
			if miErr != nil {
				if !os.IsNotExist(miErr) {
					inconclusive = true
				}
			} else {
				for ln := range strings.SplitSeq(string(miBytes), "\n") {
					f := strings.Fields(ln)
					if len(f) < 5 {
						continue
					}
					mp := filepath.Clean(procfs.UnescapeMountPath(f[4]))
					if dm, ok := matchDeadPodMount(mp, deadMounts); ok {
						matched = dm
						pinned = true
						break
					}
				}
			}
		}

		if !pinned {
			continue
		}

		hostRootOK, shimInc := verifyHostRootShim(c.d, pid)
		if shimInc {
			inconclusive = true
		}
		incidents = append(incidents, shimWedgeIncident{
			pid:              pid,
			comm:             st.Comm,
			state:            state,
			isShim:           strings.HasPrefix(st.Comm, "containerd-shim"),
			hostRootVerified: hostRootOK,
			mount:            matched.mount,
			uid:              matched.uid,
		})
	}

	if len(incidents) == 0 {
		if !inconclusive {
			c.shimWedgeStreak = 0
			c.d.State.ExitFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckMountinfo, nil)
		}
		return !inconclusive
	}

	c.shimWedgeStreak++
	need := c.d.Cfg.ConsecNeeded
	if need <= 0 {
		need = 1
	}
	if c.shimWedgeStreak < need {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: mountinfo-hygiene dead-pod mount %s (uid=%s) pinned by pid=%d (check %d/%d)",
			incidents[0].mount, incidents[0].uid, incidents[0].pid, c.shimWedgeStreak, need))
		return !inconclusive
	}

	c.d.State.EnterFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckMountinfo,
		fmt.Sprintf("ebusy-mount=%s pid=%d uid=%s", incidents[0].mount, incidents[0].pid, incidents[0].uid))

	held := c.d.HoldLocalAction(ctx)
	umountDone := map[string]bool{}
	for _, inc := range incidents {
		if held {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: mountinfo-hygiene EBUSY dead-pod mount %s (uid=%s) pinned by pid=%d held by maintenance",
				inc.mount, inc.uid, inc.pid))
			continue
		}
		if inc.state == "D" || inc.state == "Z" {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: mountinfo-hygiene EBUSY dead-pod mount %s (uid=%s) pinned by %s-state shim pid=%d — escalated to pod-teardown-wedged",
				inc.mount, inc.uid, inc.state, inc.pid))
			c.d.Actions.WithLabelValues(wdeps.CheckMountinfo, "ebusy_escalate").Inc()
			continue
		}
		if !inc.isShim || !inc.hostRootVerified {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: mountinfo-hygiene EBUSY dead-pod mount %s (uid=%s) pinned by non-host-root pid=%d — shim kill refused",
				inc.mount, inc.uid, inc.pid))
			if c.d.Cfg.Systemd != nil && !umountDone[inc.mount] {
				umountDone[inc.mount] = true
				c.ebusyLazyUmount(ctx, inc)
			}
			continue
		}

		unmounted := false
		if c.d.Cfg.Systemd != nil {
			if !umountDone[inc.mount] {
				umountDone[inc.mount] = true
				unmounted = c.ebusyLazyUmount(ctx, inc)
			} else {
				unmounted = true
			}
		}
		if !unmounted && runtimeKillComm(inc.comm) && c.d.Cfg.Seams.Host.KillFn != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: mountinfo-hygiene EBUSY kill wedged shim pid=%d mount=%s uid=%s",
				inc.pid, inc.mount, inc.uid))
			if kerr := c.d.Cfg.Seams.Host.KillFn(inc.pid, syscall.SIGKILL); kerr != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: mountinfo-hygiene EBUSY kill shim pid=%d failed: %v",
					inc.pid, kerr))
			} else {
				c.d.Actions.WithLabelValues(wdeps.CheckMountinfo, "ebusy_shim_kill").Inc()
			}
		}
	}

	return !inconclusive
}

func (c *MountinfoCheck) ebusyLazyUmount(ctx context.Context, inc shimWedgeIncident) bool {
	out, err := c.d.Cfg.Systemd.Exec(ctx, "umount", "-l", inc.mount)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: mountinfo-hygiene EBUSY umount -l %s (uid=%s, pid=%d) failed: %v (%s)",
			inc.mount, inc.uid, inc.pid, err, strings.TrimSpace(out)))
		return false
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: mountinfo-hygiene EBUSY umount -l dead-pod mount %s (uid=%s, pid=%d)",
		inc.mount, inc.uid, inc.pid))
	c.d.Actions.WithLabelValues(wdeps.CheckMountinfo, "ebusy_umount").Inc()
	return true
}

// Shared /proc parsing helpers for the workerhygiene process guards.
// Split out of dstate_scopes.go (pure move).

package guards

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// podUIDForPID extracts the pod UID owning a pid via
// /proc/<pid>/cgroup — kubepods slices embed the uid with
// underscores; normalized to the dashed form. The parse assumes
// the cgroup-v2 unified hierarchy (the `0::/kubepods...` line and
// kubepods*.slice naming — k0s hosts are v2; on v1 the per-
// hierarchy lines differ and pod_uid resolves "unknown"). The
// canonical parse lives in wdeps.PodUIDForPID — the inotify
// pressure check attributes the same way.
func podUIDForPID(d *wdeps.Deps, pid int) string {
	if uid, ok := wdeps.PodUIDForPID(d, pid); ok {
		return uid
	}
	return "unknown"
}

// podUIDForPIDChecked extracts the pod UID owning a pid via
// /proc/<pid>/cgroup and reports nonENOENT=true when reading the
// cgroup file failed for a reason other than ENOENT (e.g. EACCES /
// ENOTDIR / EISDIR) rather than being a non-pod cgroup or exited PID.
func podUIDForPIDChecked(d *wdeps.Deps, pid int) (uid string, nonENOENT bool) {
	if u, ok := wdeps.PodUIDForPID(d, pid); ok {
		return u, false
	}
	if procFileNonENOENT(d, pid, "cgroup") {
		return "unknown", true
	}
	return "unknown", false
}

// ZombieParent keys one storm streak: pid alone lies after PID
// reuse — the /proc/<pid>/stat starttime (field 22, jiffies since
// boot) tags the process generation so a recycled ppid restarts at
// streak 0 instead of inheriting a dead parent's count and holding
// the latch open for a storm that ended with it. An unreadable
// starttime leaves the zero value — streaks then merge on pid
// alone (same as the pre-key behaviour: the pid still has to stay
// over threshold to accumulate).
type ZombieParent struct {
	pid   int
	start string // /proc/<pid>/stat field 22
}

// procStartTime reads /proc/<pid>/stat field 22 (starttime) — the
// generation tag inside ZombieParent. "" when the stat is
// unreadable or truncated (the parent exited mid-sweep).
func procStartTime(st procfs.Stat, ok bool) string {
	// Fields after ')' start at field 3: Fields[0]=state,
	// Fields[1]=ppid, … Fields[19]=starttime (field 22).
	if !ok || len(st.Fields) <= 19 {
		return ""
	}
	return st.Fields[19]
}

// statFor returns the pid's parsed /proc stat — the cycle's shared
// StatsOnce snapshot when the env carries one (the production
// Cycle always does), else a direct read for hand-built test envs.
// A missing map entry is the same ok=false Stat returned.
func statFor(e *wdeps.CycleEnv, d *wdeps.Deps, pid int) (procfs.Stat, bool) {
	if e.StatsOnce != nil {
		st, ok := e.StatsOnce()[pid]
		return st, ok
	}
	return d.Proc.Stat(pid)
}

// procStatCommState returns the pid's comm and stat state from the
// cycle's shared snapshot (statFor) — ZombieStorm and Dstate read
// the same parse instead of re-reading /proc/<pid>/stat. ok=false
// when the stat is unreadable or carries no comm.
func procStatCommState(e *wdeps.CycleEnv, d *wdeps.Deps, pid int) (comm, state string, ok bool) {
	st, ok := statFor(e, d, pid)
	if !ok || !st.HasComm {
		return "", "", false
	}
	return st.Comm, st.Fields[0], true
}

// procWchan returns the kernel function a task is sleeping inside —
// /proc/<pid>/wchan names it; "0" (running/not-sleeping) and
// unreadable files report "". Read live (wchan is not part of the
// stat snapshot) — it feeds only the small ACTION-line sample.
func procWchan(d *wdeps.Deps, pid int) string {
	w, _ := procWchanChecked(d, pid)
	return w
}

// procWchanChecked reads /proc/<pid>/wchan and reports nonENOENT=true
// when the read failed for a reason other than ENOENT (e.g. EACCES /
// ENOTDIR / EISDIR).
func procWchanChecked(d *wdeps.Deps, pid int) (wchan string, nonENOENT bool) {
	data, err := os.ReadFile(d.Proc.File(pid, "wchan"))
	if err != nil {
		return "", !os.IsNotExist(err)
	}
	w := strings.TrimSpace(string(data))
	if w == "0" {
		return "", false
	}
	return w, false
}

// statNonENOENT reports whether /proc/<pid>/stat failed for a reason
// other than ENOENT (e.g. EACCES / ENOTDIR / EISDIR) when statFor
// returned ok=false. An exited PID (ENOENT) returns false.
func statNonENOENT(d *wdeps.Deps, pid int) bool {
	return procFileNonENOENT(d, pid, "stat")
}

// procFileNonENOENT reports whether /proc/<pid>/<elem> failed to open
// or read for a reason other than ENOENT (e.g. EACCES / ENOTDIR / EISDIR).
func procFileNonENOENT(d *wdeps.Deps, pid int, elem string) bool {
	f, err := os.Open(d.Proc.File(pid, elem))
	if err != nil {
		return !os.IsNotExist(err)
	}
	var b [1]byte
	_, rerr := f.Read(b[:])
	_ = f.Close()
	return rerr != nil && !errors.Is(rerr, io.EOF) && !os.IsNotExist(rerr)
}

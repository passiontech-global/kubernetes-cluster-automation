// Shared /proc parsing helpers for the workerhygiene process guards.
// Split out of dstate_scopes.go (pure move).

package guards

import (
	"os"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

var (
	// Pod UID inside a /proc/<pid>/cgroup path — kubepods slices
	// embed it with underscores
	// (kubepods-burstable-pod<8_4_4_4_12>.slice), some runtimes keep
	// dashes; both normalize to the dashed form.
	podUIDCgroupRe = regexp.MustCompile(`pod([0-9a-fA-F_-]{36})`)
)

// podUIDForPID extracts the pod UID owning a pid via
// /proc/<pid>/cgroup — kubepods slices embed the uid with
// underscores; normalized to the dashed form. The parse assumes
// the cgroup-v2 unified hierarchy (the `0::/kubepods...` line and
// kubepods*.slice naming — k0s hosts are v2; on v1 the per-
// hierarchy lines differ and pod_uid resolves "unknown").
func podUIDForPID(d *wdeps.Deps, pid int) string {
	data, err := os.ReadFile(d.Proc.File(pid, "cgroup"))
	if err != nil {
		return "unknown"
	}
	if m := podUIDCgroupRe.FindSubmatch(data); m != nil {
		return strings.ReplaceAll(string(m[1]), "_", "-")
	}
	return "unknown"
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
	data, err := os.ReadFile(d.Proc.File(pid, "wchan"))
	if err != nil {
		return ""
	}
	w := strings.TrimSpace(string(data))
	if w == "0" {
		return ""
	}
	return w
}

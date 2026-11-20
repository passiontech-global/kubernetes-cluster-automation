// runtime_kernel_net_shim.go — the kernel-net-shim-hygiene guard:
// two gray-failure detectors on one check.
//
//  1. Kernel socket/softnet drops — /proc/net/netstat TcpExt
//     ListenDrops (accept-queue overflows) and the per-CPU
//     /proc/net/softnet_stat dropped + time_squeeze columns are
//     accumulating kernel counters; a monotonic RISE for
//     kernelDropStreakNeeded consecutive cycles means a starved
//     accept queue or a softirq-scheduled RX path (the
//     ksoftirqd-storm class), not a one-off burst. On breach the
//     check latches state-kernel-net-shim-degraded and reads back
//     the two sysctl ceilings (somaxconn, netdev_max_backlog) into
//     the latch evidence so the watchdog line already carries the
//     current tuning.
//  2. containerd-shim RSS — a shim above shimRSSMaxBytes (200MiB)
//     or a total above shimRSSTotalBytes (1.5GiB) is the
//     shim-memory-leak / stuck-task class that otherwise only
//     surfaces at cgroup OOM. The watchdog warning carries the shim
//     PID and its task id (the -id argv) so ops can `ctr tasks` it.
//
// Both halves degrade the SAME latch: a node losing socket drops
// AND leaking shims is one "node degraded" signal, and the latch
// exits only when both halves are clean again.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// kernelDropStreakNeeded is the consecutive-rising-cycle budget
	// — a one-off drop burst is normal; two rising cycles is a
	// starved queue.
	kernelDropStreakNeeded = 2
	// shimRSSMaxBytes trips the latch on a single shim's VmRSS —
	// a healthy containerd-shim-runc-v2 sits at tens of MiB.
	shimRSSMaxBytes = 200 << 20 // 200 MiB
	// shimRSSTotalBytes trips on the node-wide shim RSS sum.
	shimRSSTotalBytes = 1536 << 20 // 1.5 GiB
)

// KernelNetShimCheck is the kernel drop + shim RSS guard. It keeps
// the previous kernel counters + the rising streak in memory — an
// agent restart just re-arms the two-cycle debounce.
type KernelNetShimCheck struct {
	d           *wdeps.Deps
	prevListen  int64
	prevSoftnet int64
	havePrev    bool
	haveNetstat bool
	haveSoftnet bool
	riseStreak  int
}

// Name returns the check label / WD_SIG key.
func (c *KernelNetShimCheck) Name() string { return wdeps.CheckKernelNetShim }

// Run executes one kernel-net-shim-hygiene round.
func (c *KernelNetShimCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	d := c.d
	if d.Gated(e, wdeps.CheckKernelNetShim) {
		return
	}
	degraded := false
	var evidence []string

	// --- half 1: kernel socket listen drops + softnet drops ---
	listenDrops, listenOvfl, netstatOK, netstatErr := c.tcpExtListenStats()
	softDrops, softSqueeze, softnetOK, softnetErr := c.softnetStats()
	dropInconclusive := netstatErr || softnetErr ||
		(c.haveNetstat && !netstatOK) || (c.haveSoftnet && !softnetOK)
	if netstatOK {
		d.Series.KernelListenDrops = listenDrops
	}
	if softnetOK {
		d.Series.KernelSoftnetDrops = softDrops
		d.Series.KernelSoftnetTimeSqueeze = softSqueeze
	}
	if !dropInconclusive && c.havePrev && (netstatOK || softnetOK) {
		rising := (netstatOK && listenDrops > c.prevListen) ||
			(softnetOK && softDrops > c.prevSoftnet)
		if rising {
			c.riseStreak++
		} else {
			c.riseStreak = 0
		}
	}
	if netstatOK {
		c.prevListen = listenDrops
		c.haveNetstat = true
	}
	if softnetOK {
		c.prevSoftnet = softDrops
		c.haveSoftnet = true
	}
	if !c.havePrev {
		c.havePrev = netstatOK || softnetOK
	}
	if c.riseStreak >= kernelDropStreakNeeded {
		degraded = true
		evidence = append(evidence, fmt.Sprintf(
			"kernel drops rising %d cycles: listen_drops=%d listen_overflows=%d "+
				"softnet_dropped=%d softnet_time_squeeze=%d somaxconn=%s netdev_max_backlog=%s",
			c.riseStreak, listenDrops, listenOvfl, softDrops, softSqueeze,
			readProcInt(d.Cfg.ProcRoot, "sys/net/core/somaxconn"),
			readProcInt(d.Cfg.ProcRoot, "sys/net/core/netdev_max_backlog")))
	}

	// --- half 2: containerd-shim-runc-v2 RSS ---
	pids, pidsOK := d.CyclePIDs(e)
	if !pidsOK {
		d.CycleResult(wdeps.CheckKernelNetShim, "inconclusive")
		return
	}
	var maxRSS, totalRSS int64
	worstPID, worstTask := 0, ""
	shimInconclusive := false
	for _, pid := range pids {
		isShim, readErr := isContainerdShimChecked(d, e, pid)
		if readErr {
			shimInconclusive = true
			continue
		}
		if !isShim {
			continue
		}
		rss, rssOK, readErr := shimRSSBytes(d, pid)
		if readErr {
			shimInconclusive = true
			continue
		}
		if !rssOK {
			continue
		}
		totalRSS += rss
		if rss > maxRSS {
			maxRSS = rss
			worstPID = pid
			worstTask = shimTaskID(d, pid)
		}
	}
	if !shimInconclusive {
		d.Series.ContainerdShimMaxRSSBytes = maxRSS
		d.Series.ContainerdShimTotalRSSBytes = totalRSS
	}
	switch {
	case maxRSS > shimRSSMaxBytes:
		degraded = true
		evidence = append(evidence, fmt.Sprintf(
			"shim pid=%d task=%s rss=%dMiB over %dMiB",
			worstPID, worstTask, maxRSS>>20, shimRSSMaxBytes>>20))
		d.State.AppendLogWarn(fmt.Sprintf(
			"kernel-net-shim: containerd-shim pid=%d task=%s VmRSS=%dMiB exceeds %dMiB",
			worstPID, worstTask, maxRSS>>20, shimRSSMaxBytes>>20))
	case totalRSS > shimRSSTotalBytes:
		degraded = true
		evidence = append(evidence, fmt.Sprintf(
			"shim total rss=%dMiB over %dMiB (worst pid=%d task=%s)",
			totalRSS>>20, shimRSSTotalBytes>>20, worstPID, worstTask))
		d.State.AppendLogWarn(fmt.Sprintf(
			"kernel-net-shim: containerd-shim total VmRSS=%dMiB exceeds %dMiB (worst pid=%d task=%s)",
			totalRSS>>20, shimRSSTotalBytes>>20, worstPID, worstTask))
	}

	inconclusive := dropInconclusive || shimInconclusive
	if degraded {
		d.State.Enter(latchdefs.LatchKernelNetShim,
			strings.Join(evidence, "; "))
	} else if !inconclusive {
		d.State.Exit(latchdefs.LatchKernelNetShim, nil)
	}
	if inconclusive {
		d.CycleResult(wdeps.CheckKernelNetShim, "abort")
		return
	}
	d.CycleResult(wdeps.CheckKernelNetShim, "ok")
}

// tcpExtListenStats returns (ListenDrops, ListenOverflows, ok, readErr) from
// <ProcRoot>/1/net/netstat — the file holds alternating "TcpExt:
// <names>" / "TcpExt: <values>" line pairs; each pair maps column
// name to value. init's netns (not <ProcRoot>/net) is what the
// counters describe: /proc/net is the READER's netns — inside the
// DaemonSet pod that is the pod netns, whose drops say nothing about
// the host's accept queues. hostPID makes /proc/1 the host init.
// Absent (ENOENT) returns ok=false, readErr=false; non-ENOENT errors
// return ok=false, readErr=true so callers abort instead of clearing.
func (c *KernelNetShimCheck) tcpExtListenStats() (int64, int64, bool, bool) {
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, "1", "net", "netstat"))
	if err != nil {
		return 0, 0, false, !os.IsNotExist(err)
	}
	var names []string
	for ln := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || f[0] != "TcpExt:" {
			continue
		}
		if names == nil {
			names = f[1:]
			continue
		}
		// Value row — pair the columns against the cached names.
		m := map[string]int64{}
		for i, v := range f[1:] {
			if i < len(names) {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					m[names[i]] = n
				}
			}
		}
		drops, dok := m["ListenDrops"]
		ovfl, ook := m["ListenOverflows"]
		if dok || ook {
			return drops, ovfl, true, false
		}
		names = nil // value row consumed; next header re-arms
	}
	return 0, 0, false, false
}

// softnetStats sums /proc/net/softnet_stat across the per-CPU rows:
// column 1 is packets processed, column 2 (index 1) the drop count
// and column 3 (index 2) the time_squeeze count — all hexadecimal.
func (c *KernelNetShimCheck) softnetStats() (int64, int64, bool, bool) {
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, "net", "softnet_stat"))
	if err != nil {
		return 0, 0, false, !os.IsNotExist(err)
	}
	var drops, squeeze int64
	seen := false
	for ln := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		d, errD := strconv.ParseInt(f[1], 16, 64)
		s, errS := strconv.ParseInt(f[2], 16, 64)
		if errD != nil && errS != nil {
			continue
		}
		if errD == nil {
			drops += d
		}
		if errS == nil {
			squeeze += s
		}
		seen = true
	}
	return drops, squeeze, seen, false
}

// isContainerdShim reports whether the pid's comm (truncated to 15
// bytes "containerd-shim" by TASK_COMM_LEN on Linux) and argv[0]
// basename identify a containerd-shim-runc-v2 process — not a
// cmdline substring (a pod could carry the string in its own argv).
// The comm comes from the cycle's StatsOnce snapshot when present —
// a known non-shim comm skips both the comm-file and cmdline reads;
// an unknown comm falls back to the comm file (fake-proc parity).
func isContainerdShim(d *wdeps.Deps, e *wdeps.CycleEnv, pid int) bool {
	isShim, _ := isContainerdShimChecked(d, e, pid)
	return isShim
}

func shimFileReadNonENOENT(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return !os.IsNotExist(err)
	}
	var b [1]byte
	_, rerr := f.Read(b[:])
	_ = f.Close()
	return rerr != nil && !errors.Is(rerr, io.EOF) && !os.IsNotExist(rerr)
}

func isContainerdShimChecked(d *wdeps.Deps, e *wdeps.CycleEnv, pid int) (isShim, readErr bool) {
	var comm string
	var state string
	known := false
	if e != nil && e.StatsOnce != nil {
		if st, ok := e.StatsOnce()[pid]; ok && st.HasComm {
			comm, known = st.Comm, true
			if len(st.Fields) > 0 {
				state = st.Fields[0]
			}
		}
	} else if st, ok := d.Proc.Stat(pid); ok && st.HasComm {
		comm, known = st.Comm, true
		if len(st.Fields) > 0 {
			state = st.Fields[0]
		}
	}
	if !known {
		if st, ok := d.Proc.Stat(pid); ok {
			if len(st.Fields) > 0 {
				state = st.Fields[0]
			}
			if st.HasComm {
				comm, known = st.Comm, true
			}
		}
	}
	if !known {
		if shimFileReadNonENOENT(d.Proc.File(pid, "stat")) {
			return false, true
		}
		data, err := os.ReadFile(d.Proc.File(pid, "comm"))
		if err != nil {
			return false, !os.IsNotExist(err)
		}
		comm = strings.TrimSpace(string(data))
	}
	if comm != "containerd-shim" && comm != "containerd-shim-runc-v2" {
		return false, false
	}
	if st, ok := d.Proc.Stat(pid); ok {
		if len(st.Fields) > 0 {
			state = st.Fields[0]
		}
	} else if shimFileReadNonENOENT(d.Proc.File(pid, "stat")) {
		return false, true
	}
	if state == "D" || state == "Z" {
		// D/Z-state cmdline is mm-backed and would hang on mmap_lock.
		return true, false
	}
	if state == "X" || state == "x" {
		return false, false
	}
	args := d.Proc.Cmdline(pid)
	if len(args) > 0 && args[0] != "" {
		return filepath.Base(args[0]) == "containerd-shim-runc-v2", false
	}
	if st, ok := d.Proc.Stat(pid); ok && len(st.Fields) > 0 {
		if st.Fields[0] == "D" || st.Fields[0] == "Z" {
			return true, false
		}
		if st.Fields[0] == "X" || st.Fields[0] == "x" {
			return false, false
		}
	} else if shimFileReadNonENOENT(d.Proc.File(pid, "stat")) {
		return false, true
	}
	if shimFileReadNonENOENT(d.Proc.File(pid, "cmdline")) {
		return false, true
	}
	return true, false
}

// shimRSSBytes reads VmRSS out of /proc/<pid>/status — bytes; ok=false
// when the process exited mid-scan or the field is absent; readErr=true
// on non-ENOENT read errors (EACCES/ENOTDIR/EIO) so callers abort
// instead of clobbering gauges or clearing the latch.
func shimRSSBytes(d *wdeps.Deps, pid int) (bytes int64, ok, readErr bool) {
	data, err := os.ReadFile(d.Proc.File(pid, "status"))
	if err != nil {
		return 0, false, !os.IsNotExist(err)
	}
	for ln := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(ln, "VmRSS:") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) >= 2 {
			if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return kb << 10, true, false
			}
		}
	}
	return 0, false, false
}

// shimTaskID pulls the containerd task id out of the shim argv —
// `containerd-shim-runc-v2 -namespace k8s.io -id <id> -address ...`.
func shimTaskID(d *wdeps.Deps, pid int) string {
	if st, ok := d.Proc.Stat(pid); ok {
		if len(st.Fields) > 0 &&
			(st.Fields[0] == "D" || st.Fields[0] == "Z" || st.Fields[0] == "X" || st.Fields[0] == "x") {
			return "unknown"
		}
	} else if shimFileReadNonENOENT(d.Proc.File(pid, "stat")) {
		return "unknown"
	}
	args := d.Proc.Cmdline(pid)
	for i, a := range args {
		if a == "-id" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return "unknown"
}

// readProcInt returns a sysctl file's trimmed contents under
// ProcRoot — "?" when unreadable (evidence only, never an action).
func readProcInt(procRoot, elem string) string {
	data, err := os.ReadFile(filepath.Join(procRoot, elem))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}

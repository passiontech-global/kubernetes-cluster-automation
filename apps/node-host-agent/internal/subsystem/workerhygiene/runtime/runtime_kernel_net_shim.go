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
	"fmt"
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
	listenDrops, listenOvfl, netstatOK := c.tcpExtListenStats()
	softDrops, softSqueeze, softnetOK := c.softnetStats()
	if netstatOK {
		d.Series.KernelListenDrops = listenDrops
	}
	if softnetOK {
		d.Series.KernelSoftnetDrops = softDrops
		d.Series.KernelSoftnetTimeSqueeze = softSqueeze
	}
	if c.havePrev && (netstatOK || softnetOK) {
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
	}
	if softnetOK {
		c.prevSoftnet = softDrops
	}
	c.havePrev = netstatOK || softnetOK
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
	var maxRSS, totalRSS int64
	worstPID, worstTask := 0, ""
	for _, pid := range e.PidsOnce() {
		if !isContainerdShim(d, pid) {
			continue
		}
		rss := shimRSSBytes(d, pid)
		totalRSS += rss
		if rss > maxRSS {
			maxRSS = rss
			worstPID = pid
			worstTask = shimTaskID(d, pid)
		}
	}
	d.Series.ContainerdShimMaxRSSBytes = maxRSS
	d.Series.ContainerdShimTotalRSSBytes = totalRSS
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

	if degraded {
		d.State.Enter(latchdefs.LatchKernelNetShim,
			strings.Join(evidence, "; "))
	} else {
		d.State.Exit(latchdefs.LatchKernelNetShim, nil)
	}
	d.CycleResult(wdeps.CheckKernelNetShim, "ok")
}

// tcpExtListenStats returns (ListenDrops, ListenOverflows, ok) from
// <ProcRoot>/net/netstat — the file holds alternating "TcpExt:
// <names>" / "TcpExt: <values>" line pairs; each pair maps column
// name to value.
func (c *KernelNetShimCheck) tcpExtListenStats() (int64, int64, bool) {
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, "net", "netstat"))
	if err != nil {
		return 0, 0, false
	}
	var names []string
	for _, ln := range strings.Split(string(data), "\n") {
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
			return drops, ovfl, true
		}
		names = nil // value row consumed; next header re-arms
	}
	return 0, 0, false
}

// softnetStats sums /proc/net/softnet_stat across the per-CPU rows:
// column 1 is packets processed, column 2 (index 1) the drop count
// and column 3 (index 2) the time_squeeze count — all hexadecimal.
func (c *KernelNetShimCheck) softnetStats() (int64, int64, bool) {
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, "net", "softnet_stat"))
	if err != nil {
		return 0, 0, false
	}
	var drops, squeeze int64
	seen := false
	for _, ln := range strings.Split(string(data), "\n") {
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
	return drops, squeeze, seen
}

// isContainerdShim reports whether /proc/<pid>/comm (truncated to 15
// bytes "containerd-shim" by TASK_COMM_LEN on Linux) and argv[0]
// basename identify a containerd-shim-runc-v2 process — not a
// cmdline substring (a pod could carry the string in its own argv).
func isContainerdShim(d *wdeps.Deps, pid int) bool {
	data, err := os.ReadFile(d.Proc.File(pid, "comm"))
	if err != nil {
		return false
	}
	comm := strings.TrimSpace(string(data))
	if comm != "containerd-shim" && comm != "containerd-shim-runc-v2" {
		return false
	}
	args := d.Proc.Cmdline(pid)
	if len(args) > 0 && args[0] != "" {
		return filepath.Base(args[0]) == "containerd-shim-runc-v2"
	}
	return true
}

// shimRSSBytes reads VmRSS out of /proc/<pid>/status — bytes; 0 when
// the process exited mid-scan or the field is absent.
func shimRSSBytes(d *wdeps.Deps, pid int) int64 {
	data, err := os.ReadFile(d.Proc.File(pid, "status"))
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(ln, "VmRSS:") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) >= 2 {
			if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return kb << 10
			}
		}
	}
	return 0
}

// shimTaskID pulls the containerd task id out of the shim argv —
// `containerd-shim-runc-v2 -namespace k8s.io -id <id> -address ...`.
func shimTaskID(d *wdeps.Deps, pid int) string {
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

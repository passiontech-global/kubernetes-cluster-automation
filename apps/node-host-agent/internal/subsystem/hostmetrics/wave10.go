// wave10.go — shared Wave-10 kernel deep-failure contract: the
// cross-domain constants, the host-command seam and the state-dir
// latch helpers the domain files (kmsg.go, pidfd.go, clockskew.go,
// fsreadonly.go) share. Split out of kernel_failure_latches.go —
// the latch ticker itself (refreshLatches) stays in latches.go and
// calls into the domain updaters.
package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hostexec"
)

// ===========================================================================
// Wave-10 — kernel deep-failure modes (W10-KR1/KR2/KR5, W10-ST1)
//
// The domain files extend the latch ticker with the Wave-10 contract:
//
//   - W10-KR1 checkKernelDmesg (kmsg.go): /dev/kmsg drain (dmesg -T
//     fallback) classifying filesystem/block errors, nf_conntrack
//     table-full drops and host-level OOM kills into stateDir
//     evidence markers. workerhygiene consumes the OOM markers for
//     the SystemOOMVictim node event; kmsg.go owns the latches +
//     counters.
//   - W10-KR2 updatePidFDPressure (pidfd.go): pid/thread/fd
//     utilization ratios → state-pid-fd-pressure
//     (KernelResourceExhaustion) + the node_agent_*_utilization_ratio
//     textfile gauges (the W10 metric channel — same convention the
//     controllerhygiene textfile channel uses; prometheus descs
//     can't be added outside hostmetrics.go's New()).
//   - W10-KR5 checkClockSkew (clockskew.go): chronyc tracking
//     (adjtimex offset fallback) → state-clock-skew
//     (ClockSkewDetected) + a rate-limited `chronyc makestep`.
//   - W10-ST1 updateFSReadonlyEvidence (fsreadonly.go): ro
//     ext4/xfs/btrfs mounts under the PVC provisioner roots parsed
//     out of /proc/<pid>/mounts → state-fs-readonly
//     (FilesystemReadOnly) ahead of statfs.
// ===========================================================================

// --- shared Wave-10 helpers ---

// kmsgFsErrorFile is the cross-domain evidence marker: kmsg.go's
// noteKernelFsError writes it and fsreadonly.go's
// updateFSReadonlyEvidence consumes it. Marker/state file names live
// inside WatchdogStateDir — shared with workerhygiene (the
// SystemOOMVictim consumer) by convention.
const kmsgFsErrorFile = "kmsg-fs-error"

// runHostCmd executes a host binary for the Wave-10 probes that have
// no Config seam (chronyc, dmesg) — a package var so tests stub it.
// The 30s cap matches the nethealth runHostCmd convention; the exec
// itself is hostexec.RunCombined — capped output + WaitDelay, no
// second timeout stacked underneath.
var runHostCmd = func(ctx context.Context, argv ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return hostexec.RunCombined(cctx, argv...)
}

func (l *Latches) statePath(name string) string {
	return filepath.Join(l.c.cfg.WatchdogStateDir, name)
}

// ensureStateLatch installs a state latch when absent (epoch content,
// atomic tmp+rename — the updateKernelKeysLatch pattern) and logs
// the transition once; BUG-H6's refresh loop owns the mtime while
// held.
func (l *Latches) ensureStateLatch(path, name, evidence string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	content := strconv.FormatInt(l.c.cfg.nowFn().Unix(), 10) + "\n"
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		logger().Warn("hostmetrics: "+name+" latch write failed",
			"path", path, "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		logger().Warn("hostmetrics: "+name+" latch install failed",
			"path", path, "error", err)
		return
	}
	logger().Warn("hostmetrics: "+name+" latch set — "+evidence,
		"path", path)
}

// --- small Wave-10 helpers (uniquely named per file rules) ---
//
// The last-* rate budgets (conntrackBumpBudgetFile,
// clockStepBudgetFile) go through l.c.state — the shared hoststate
// rateOK/rateSpend parity (atomic spend, same file format).

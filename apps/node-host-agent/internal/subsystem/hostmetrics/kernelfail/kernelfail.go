// Package kernelfail is the Wave-10 kernel deep-failure engine the
// hostmetrics latch ticker drives. It lives in a subpackage because
// it produces NO prometheus series — every check below writes the
// watchdog state-dir contract (state-* latches, evidence markers,
// counter files) or the node-exporter textfile channel, so the
// scrape-time Collector stays free of file-contract machinery.
// Split out of hostmetrics — the workerhygiene wdeps precedent.
//
// The contract the checks implement:
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
//     controllerhygiene textfile channel uses; a new prometheus desc
//     would mean a domainTable row in the parent's domains.go, the
//     textfile channel needs no registry change).
//   - W10-KR5 checkClockSkew (clockskew.go): chronyc tracking
//     (adjtimex offset fallback) → state-clock-skew
//     (ClockSkewDetected) + a rate-limited `chronyc makestep`.
//   - W10-ST1 updateFSReadonlyEvidence (fsreadonly.go): ro
//     ext4/xfs/btrfs mounts under the PVC provisioner roots parsed
//     out of /proc/<pid>/mounts → state-fs-readonly
//     (FilesystemReadOnly) ahead of statfs.
//   - cpu-steal-guard + kernel-entropy-check (steal_entropy.go):
//     /proc/stat steal-column delta → state-cpu-steal-pressure
//     (CPUStealPressure) + the node_agent_cpu_steal_ratio /
//     node_agent_kernel_entropy_avail_bits textfile gauges.
//
// Every new latch ensureStateLatch installs also lands a
// "STATE-ENTER: <name> (<evidence>)" line in the shared watchdog
// log via the Store — nodereporter's events.go tails that file and
// maps the line onto a Kubernetes Event.
package kernelfail

import (
	"context"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kmsg"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Deps is everything the engine needs from the hostmetrics
// Collector — the exported Config fields it reads, the shared
// hoststate.Store and clock cell, and the three seams that used to
// be package-level test stubs. The seams cross as fields (late-
// bound closures the parent wires in New) so both packages' test
// suites keep their stub points: hostmetrics stubs its own
// runHostCmd/kmsgDevicePaths vars exactly as pre-split, and this
// package's tests set the Deps fields directly.
type Deps struct {
	// StateDir is the watchdog state dir — latch, marker and
	// counter files land here (the l.c.cfg.WatchdogStateDir half of
	// the old statePath join).
	StateDir string
	// ProcRoot is the host /proc — boot_id, the pid sweep, loadavg,
	// /proc/1/mounts and /proc/stat all read under it.
	ProcRoot string
	// HostRoot prefixes the kmsg device fallback and the
	// node-exporter textfile dir.
	HostRoot string
	// ConntrackMaxFile is the nf_conntrack_max sysctl the
	// table-full bump doubles.
	ConntrackMaxFile string
	// FileNRFile is /proc/sys/fs/file-nr — the fd half of the
	// pid/thread/fd pressure ratios.
	FileNRFile string
	// OpenEBSLocalDir is the LocalPV hostPath root — one of the PVC
	// provisioner roots the ro-mount evidence scans.
	OpenEBSLocalDir string

	// TickInterval is the latch ticker's expected cadence — carried
	// into the warp ACTION line's "tick=" evidence text. <=0 →
	// defaultTickInterval.
	TickInterval time.Duration

	// WarpDelta computes the wall-vs-monotonic gap between two tick
	// stamps — the checkClockWarp threshold input. nil → warpDelta.
	// A seam because the public time API cannot synthesize two
	// stamps whose monotonic advance differs from their wall advance
	// (both must come from real clock reads), so a fake clock can
	// only ever produce a zero warp; tests inject controlled gaps
	// through this.
	WarpDelta func(now, prev time.Time) time.Duration

	// Store is the shared watchdog-state contract handle — the
	// state-* latches, last-* rate budgets, counter files and
	// STATE-ENTER watchdog-log appends all go through it so the
	// on-disk format stays the lib.sh parity every subsystem
	// shares.
	Store *hoststate.Store
	// Clock is the shared timex.Cell — the same pointer the
	// Collector's cfg.Clock carries, so a post-New Clock.Set lands
	// here exactly like the old cfg.Clock.Now() reads did.
	Clock *timex.Cell

	// Adjtimex reads kernel clock-sync state for the chronyc
	// fallback — the one Config seam private to the parent
	// package, so it crosses as a bound closure over cfg (late
	// stubs via cfg.adjtimexFn still land).
	Adjtimex func(*unix.Timex) (int, error)
	// RunHostCmd executes a host binary for the Wave-10 probes
	// that have no Config seam (chronyc, dmesg). Nil selects
	// defaultRunHostCmd — the 30s-cap hostexec.RunCombined
	// convention nethealth shares.
	RunHostCmd func(ctx context.Context, argv ...string) (string, error)
	// KmsgDevicePaths returns the /dev/kmsg candidates — nil
	// selects defaultKmsgDevicePaths ("/dev/kmsg" plus the
	// HostRoot variant).
	KmsgDevicePaths func(hostRoot string) []string
}

// Runner is the per-Collector kernel-failure engine. It owns the
// two pieces of cross-tick state the W10 checks carry — the kmsg
// tail session + cross-line OOM pairing, and the cpu-steal jiffie
// baseline — which is why New() builds it once on the Collector
// rather than inside the recreated-per-call Latches wrapper: a
// keyed side-map would pin the session (and its /dev/kmsg fd) for
// the process lifetime. Only the latch-ticker goroutine drives the
// Runner, so its state needs no lock beyond stealDelta's own.
type Runner struct {
	deps  Deps
	kscan kernelScanState // kmsg.go — tail session + OOM pairing
	steal stealDelta      // steal_entropy.go — jiffie baseline
	warp  clockWarpState  // clockskew.go — wall-clock jump detector
}

// defaultTickInterval is the latch ticker cadence the warp detector
// assumes when Deps.TickInterval is unset — the parent wires the
// real LatchInterval; the constant only covers bare-New tests.
const defaultTickInterval = 30 * time.Second

// warpDelta resolves the Deps seam — nil field → the real
// wall-minus-monotonic computation.
func (d Deps) warpDelta(now, prev time.Time) time.Duration {
	if d.WarpDelta != nil {
		return d.WarpDelta(now, prev)
	}
	return warpDelta(now, prev)
}

// New applies the seam defaults and returns the engine.
func New(d Deps) *Runner {
	if d.RunHostCmd == nil {
		d.RunHostCmd = defaultRunHostCmd
	}
	if d.KmsgDevicePaths == nil {
		d.KmsgDevicePaths = defaultKmsgDevicePaths
	}
	if d.TickInterval <= 0 {
		d.TickInterval = defaultTickInterval
	}
	return &Runner{deps: d}
}

// Refresh runs the W10 latch-maintenance block once — the same
// order refreshLatches ran pre-split: the kmsg drain FIRST (it
// writes the kmsg-fs-error / conntrack-drop / host-OOM /
// page-alloc evidence the later steps consume — workerhygiene's
// SystemOOMVictim and vm.compact_memory triggers included), then
// the pid/fd pressure, steal/entropy, clock-skew and
// fs-readonly-evidence updaters.
func (r *Runner) Refresh() {
	r.checkKernelDmesg()
	r.updatePidFDPressure()
	r.updateStealEntropy()
	r.checkClockSkew()
	r.checkClockWarp()
	r.updateFSReadonlyEvidence()
}

// Close releases the /dev/kmsg fd the session holds — the
// latch-ticker Run defers it so subsystem shutdown doesn't leak
// the descriptor. Only the ticker goroutine owns the scan, so this
// needs no lock.
func (r *Runner) Close() {
	r.closeKMSSession(&r.kscan)
}

// defaultRunHostCmd is the nil-seam default — a 30s cap over
// hostexec.RunCombined (capped output + WaitDelay, no second
// timeout stacked underneath), the nethealth runHostCmd
// convention.
func defaultRunHostCmd(ctx context.Context, argv ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return hostexec.RunCombined(cctx, argv...)
}

// defaultKmsgDevicePaths is the nil-seam default — the real
// /dev/kmsg plus the HostRoot variant for standalone layouts where
// only the host tree is mounted.
func defaultKmsgDevicePaths(hostRoot string) []string {
	return kmsg.DevicePaths("/dev/kmsg", hostRoot)
}

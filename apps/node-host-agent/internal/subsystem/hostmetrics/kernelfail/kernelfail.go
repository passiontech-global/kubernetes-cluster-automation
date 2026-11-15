// Package kernelfail is the kernel deep-failure engine the
// hostmetrics latch ticker drives. It lives in a subpackage because
// it produces NO prometheus series — every check below writes the
// watchdog state-dir contract (state-* latches, evidence markers,
// counter files) or the node-exporter textfile channel, so the
// scrape-time Collector stays free of file-contract machinery.
// Split out of hostmetrics — the workerhygiene wdeps precedent.
//
// The contract the checks implement:
//
//   - kernel-dmesg checkKernelDmesg (kmsg.go): /dev/kmsg drain (dmesg -T
//     fallback) classifying filesystem/block errors, nf_conntrack
//     table-full drops and host-level OOM kills into stateDir
//     evidence markers. workerhygiene consumes the OOM markers for
//     the SystemOOMVictim node event; kmsg.go owns the latches +
//     counters.
//   - pid-fd-pressure updatePidFDPressure (pidfd.go): pid/thread/fd
//     utilization ratios → state-pid-fd-pressure
//     (KernelResourceExhaustion) + the node_agent_*_utilization_ratio
//     textfile gauges (the node_agent metric channel — same convention the
//     controllerhygiene textfile channel uses; a new prometheus desc
//     would mean a domainTable row in the parent's domains.go, the
//     textfile channel needs no registry change).
//   - clock-skew checkClockSkew (clockskew.go): chronyc tracking
//     (adjtimex offset fallback) → state-clock-skew
//     (ClockSkewDetected) + a rate-limited `chronyc makestep`.
//   - fs-readonly updateFSReadonlyEvidence (fsreadonly.go): ro
//     ext4/xfs/btrfs mounts under the PVC provisioner roots parsed
//     out of /proc/<pid>/mounts → state-fs-readonly
//     (FilesystemReadOnly) ahead of statfs.
//   - cpu-steal-guard + kernel-entropy-check (steal_entropy.go):
//     /proc/stat steal-column delta → state-cpu-steal-pressure
//     (CPUStealPressure) + the node_agent_cpu_steal_ratio /
//     node_agent_kernel_entropy_avail_bits textfile gauges.
//   - hardware-health updateHardwareHealth (hardware.go):
//     /proc/meminfo HardwareCorrupted + EDAC ue/ce counters + the
//     kmsg acute signatures (uncorrected MCE, PCIe AER fatal,
//     >=3 NVMe controller resets/10m, NVIDIA fatal Xid) →
//     state-hardware-corrupted / state-gpu-hardware-error.
//   - neighbor-table updateNeighborTable (neighbor.go): ARP/NDISC
//     fill vs gc_thresh3 (or a kmsg "neighbor table overflow") →
//     rate-limited gc_thresh{1,2,3} doubling + `ip neigh flush nud
//     failed`.
//   - nic-health updateNICHealth (nic_health.go): the physical
//     default-route iface's carrier_changes / rx_crc+rx_frame
//     counters and NETDEV WATCHDOG TX timeouts over sliding windows
//     → state-host-network-problems.
//
// Every new latch ensureStateLatch installs also lands a
// "STATE-ENTER: <name> (<evidence>)" line in the shared watchdog
// log via the Store — nodereporter's events.go tails that file and
// maps the line onto a Kubernetes Event.
package kernelfail

import (
	"context"
	"errors"
	"path/filepath"
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
	// TextfileDir overrides promfile.TextfileDir(HostRoot) when non-empty.
	TextfileDir string
	// ConntrackMaxFile is the nf_conntrack_max sysctl the
	// table-full bump doubles.
	ConntrackMaxFile string
	// FileNRFile is /proc/sys/fs/file-nr — the fd half of the
	// pid/thread/fd pressure ratios.
	FileNRFile string
	// OpenEBSLocalDir is the LocalPV hostPath root — one of the PVC
	// provisioner roots the ro-mount evidence scans.
	OpenEBSLocalDir string

	// Ext4ErrorsGlob globs the per-filesystem ext4 error counters
	// (roadmap A5) — /sys/fs/ext4/<dev>/errors_count, the
	// superblock-resident count that survives agent restarts AND
	// remounts; > 0 means the kernel logged metadata errors on that
	// filesystem at some point. Empty → the default glob
	// HostRoot-joined (pod mode reads /host/sys/...).
	Ext4ErrorsGlob string
	// NVMeSmartGlob globs the NVMe controller SMART sysfs pages —
	// /sys/class/nvme/nvme*/smart_log, the packed nvme_smart_log
	// struct where mainline kernels ship it (vendor kernels do; the
	// missing-attribute case falls back to `nvme smart-log` via
	// RunHostCmd). Empty → the default glob HostRoot-joined.
	NVMeSmartGlob string

	// EDACGlob globs the EDAC memory-controller dirs
	// ("/sys/devices/system/edac/mc/mc*") — hardware.go reads
	// ue_count/ce_count under each. Empty → the HostRoot-joined
	// default; zero matches = no EDAC (VM passthrough), fail-safe.
	EDACGlob string
	// SysClassNetDir is the host /sys/class/net — nic_health.go
	// reads <iface>/carrier_changes and
	// <iface>/statistics/{rx_crc_errors,rx_frame_errors} under it.
	// Empty → the HostRoot-joined default.
	SysClassNetDir string
	// RouteFile is the host default-route table nic_health.go picks
	// the physical uplink iface from. Empty → "/proc/1/net/route".
	RouteFile string
	// NeighIPv4Dir/NeighIPv6Dir are the host-netns neighbor sysctl
	// dirs holding gc_thresh{1,2,3} — neighbor.go reads the current
	// triplet and writes the doubled one in thresh3→thresh2→thresh1
	// order (the kernel EINVALs any write that breaks
	// thresh1 <= thresh2 <= thresh3). Empty → ProcRoot-joined
	// "sys/net/<fam>/neigh/default" (hostPID makes /proc the host's
	// and the DaemonSet is hostNetwork, so the writes land in the
	// host netns; standalone "/" reads the same way).
	NeighIPv4Dir string
	NeighIPv6Dir string
	// NeighIPv4Table/NeighIPv6Stats are the host-netns
	// neighbor-table views neighbor.go counts entries from:
	// /proc/1/net/arp (one line per IPv4 entry) and
	// /proc/1/net/stat/ndisc_cache (the "entries" column carries the
	// IPv6 neighbor count). Empty → ProcRoot-joined "1/net/...".
	NeighIPv4Table string
	NeighIPv6Stats string
	// NeighGCThresh{1,2,3}Ceiling cap the neighbor-table bump — the
	// triplet doubles per 30m spend up to these. <=0 → defaults
	// 1024/4096/8192.
	NeighGCThresh1Ceiling int
	NeighGCThresh2Ceiling int
	NeighGCThresh3Ceiling int
	// NICCarrierFlapThreshold is the carrier_changes delta per 5m
	// window that arms HostNetworkProblems; NICTxTimeoutThreshold
	// the NETDEV WATCHDOG TX-timeout count per 10m; NICCRErrorThreshold
	// the rx_crc+rx_frame delta required in EACH of two consecutive
	// 5m windows. <=0 → defaults 4/2/50.
	NICCarrierFlapThreshold int
	NICTxTimeoutThreshold   int
	NICCRErrorThreshold     int

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
	// RunHostCmd executes a host binary for the deep-failure probes
	// that have no Config seam (chronyc, dmesg, nvme smart-log).
	// Nil selects defaultRunHostCmd — a hostexec.Runner entering
	// every host PID-1 namespace (nsenter -t 1 -m -u -i -n -p),
	// HostRoot-aware so standalone layouts run unwrapped.
	RunHostCmd func(ctx context.Context, argv ...string) (string, error)
	// KmsgDevicePaths returns the /dev/kmsg candidates — nil
	// selects defaultKmsgDevicePaths ("/dev/kmsg" plus the
	// HostRoot variant).
	KmsgDevicePaths func(hostRoot string) []string
}

// Runner is the per-Collector kernel-failure engine. It owns the
// two pieces of cross-tick state the kernelfail checks carry — the kmsg
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
	// nvmeCLI is the cached `nvme smart-log` fallback result
	// (diskprefail.go) — the per-controller fork runs at most once
	// per nvmeCLITTL instead of every 30s latch tick. Only the
	// ticker goroutine touches it, like every other Runner field.
	nvmeCLI   []nvmeSmart
	nvmeCLIAt time.Time
	// hw is hardware.go's cross-tick state — the acute kmsg evidence
	// stamps and the NVMe controller-reset streak.
	hw hwScanState
	// neigh is neighbor.go's pending-overflow family set — fam name
	// to the kmsg stamp that armed it; nic is nic_health.go's uplink
	// sample ring + TX-timeout stamps. All three are touched only by
	// the latch-ticker goroutine, like every other Runner field.
	neigh map[string]time.Time
	nic   nicState
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
		d.RunHostCmd = defaultRunHostCmd(d.HostRoot)
	}
	if d.KmsgDevicePaths == nil {
		d.KmsgDevicePaths = defaultKmsgDevicePaths
	}
	if d.TickInterval <= 0 {
		d.TickInterval = defaultTickInterval
	}
	// The sysfs globs are host-side paths — HostRoot-joined like the
	// clocksource/bpffs defaults so pod mode reads /host/sys/... and
	// standalone "/" stays /sys/... . An explicitly-set glob is used
	// verbatim (tests point them at fixture trees; a caller that
	// wants the host view passes the joined path itself).
	if d.Ext4ErrorsGlob == "" {
		d.Ext4ErrorsGlob = filepath.Join(d.HostRoot, defaultExt4ErrorsGlob)
	}
	if d.NVMeSmartGlob == "" {
		d.NVMeSmartGlob = filepath.Join(d.HostRoot, defaultNVMeSmartGlob)
	}
	// Same HostRoot-join for the hardware/NIC sysfs seams — pod mode
	// reads /host/sys/..., standalone "/" stays /sys/... .
	if d.EDACGlob == "" {
		d.EDACGlob = filepath.Join(d.HostRoot, defaultEDACGlob)
	}
	if d.SysClassNetDir == "" {
		d.SysClassNetDir = filepath.Join(d.HostRoot, defaultSysClassNetDir)
	}
	// ProcRoot-relative defaults for the neighbor sysctl dirs and
	// the host-netns table views — "/proc" joined yields the same
	// literal paths the DaemonSet's hostPID/hostNetwork layout reads.
	procRoot := d.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	if d.RouteFile == "" {
		d.RouteFile = filepath.Join(procRoot, "1", "net", "route")
	}
	if d.NeighIPv4Dir == "" {
		d.NeighIPv4Dir = filepath.Join(procRoot, "sys", "net", "ipv4", "neigh", "default")
	}
	if d.NeighIPv6Dir == "" {
		d.NeighIPv6Dir = filepath.Join(procRoot, "sys", "net", "ipv6", "neigh", "default")
	}
	if d.NeighIPv4Table == "" {
		d.NeighIPv4Table = filepath.Join(procRoot, "1", "net", "arp")
	}
	if d.NeighIPv6Stats == "" {
		d.NeighIPv6Stats = filepath.Join(procRoot, "1", "net", "stat", "ndisc_cache")
	}
	// Threshold defaults — the env knobs land through Config; these
	// cover bare-New tests and unset knobs.
	if d.NeighGCThresh1Ceiling <= 0 {
		d.NeighGCThresh1Ceiling = DefaultNeighGCThresh1Ceiling
	}
	if d.NeighGCThresh2Ceiling <= 0 {
		d.NeighGCThresh2Ceiling = DefaultNeighGCThresh2Ceiling
	}
	if d.NeighGCThresh3Ceiling <= 0 {
		d.NeighGCThresh3Ceiling = DefaultNeighGCThresh3Ceiling
	}
	if d.NICCarrierFlapThreshold <= 0 {
		d.NICCarrierFlapThreshold = DefaultNICCarrierFlapThreshold
	}
	if d.NICTxTimeoutThreshold <= 0 {
		d.NICTxTimeoutThreshold = DefaultNICTxTimeoutThreshold
	}
	if d.NICCRErrorThreshold <= 0 {
		d.NICCRErrorThreshold = DefaultNICCRErrorThreshold
	}
	if d.Clock == nil {
		d.Clock = timex.NewCell(nil)
	}
	if d.Store == nil && d.StateDir != "" {
		d.Store = hoststate.New(d.StateDir, "", nil, nil)
	}
	return &Runner{deps: d}
}

// Refresh runs the deep-failure latch-maintenance block once — the same
// order refreshLatches ran pre-split: the kmsg drain FIRST (it
// writes the kmsg-fs-error / conntrack-drop / host-OOM /
// page-alloc evidence the later steps consume — workerhygiene's
// SystemOOMVictim and vm.compact_memory triggers included), then
// the pid/fd pressure, steal/entropy, clock-skew and
// fs-readonly-evidence updaters. ctx cancels the in-flight host
// commands (dmesg fallback, chronyc) when the ticker's ctx dies.
func (r *Runner) Refresh(ctx context.Context) {
	r.checkKernelDmesg(ctx)
	r.updatePidFDPressure()
	r.updateStealEntropy()
	r.checkClockSkew(ctx)
	r.checkClockWarp()
	r.updateFSReadonlyEvidence()
	// disk-pre-fail (A5) — ext4 errors_count + NVMe SMART early
	// indicators: the death-bed warning BEFORE the filesystem
	// aborts read-only, while the LocalPV data is still evacuable.
	// ctx rides through so the nvme-cli fallback probes cancel with
	// the ticker instead of pinning context.Background().
	r.updateDiskPreFailEvidence(ctx)
	// Self-healing wave — appended AFTER the pre-existing updaters
	// so the established check order is untouched:
	//   - hardware.go: ECC/EDAC + MCE/PCIe-AER/NVMe-reset + NVIDIA
	//     fatal-Xid evidence → state-hardware-corrupted /
	//     state-gpu-hardware-error (P0-#3, P2-#12).
	//   - neighbor.go: ARP/NDISC table fill ≥ gc_thresh3*80% or a
	//     kmsg overflow record → bounded gc_thresh{1,2,3} bump +
	//     `ip neigh flush nud failed` (P1-#6).
	//   - nic_health.go: physical-uplink carrier/CRC/TX-timeout
	//     windows → state-host-network-problems (P1-#7).
	r.updateHardwareHealth()
	r.updateNeighborTable(ctx)
	r.updateNICHealth()
}

// Close releases the /dev/kmsg fd the session holds — the
// latch-ticker Run defers it so subsystem shutdown doesn't leak
// the descriptor. Only the ticker goroutine owns the scan, so this
// needs no lock.
func (r *Runner) Close() {
	r.closeKMSSession(&r.kscan)
}

// defaultRunHostCmd builds the nil-seam host-command executor for
// hostRoot — a hostexec.Runner entering EVERY host PID-1 namespace
// (NSAll: mount for /dev/nvme nodes and the host fs view, network
// for chronyc's /var/run/chrony socket and DNS, pid for process
// tools), with HostRoot "/" collapsing to an unwrapped exec on
// standalone hosts. The probes it serves are HOST probes — a
// container-side RunCombined would resolve chronyc/nvme against
// the pod's namespaces and silently misread (or miss) the host
// state they exist to check. The 30s cap sits on top of the
// runner's own Config.Timeout default.
func defaultRunHostCmd(hostRoot string) func(ctx context.Context, argv ...string) (string, error) {
	runner := hostexec.New(hostexec.Config{HostRoot: hostRoot,
		ScrubSystemdEnv: true})
	return func(ctx context.Context, argv ...string) (string, error) {
		if len(argv) == 0 {
			return "", errors.New("kernelfail: empty host argv")
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return runner.ExecCombined(cctx, hostexec.NSAll, argv[0], argv[1:]...)
	}
}

// defaultKmsgDevicePaths is the nil-seam default — the real
// /dev/kmsg plus the HostRoot variant for standalone layouts where
// only the host tree is mounted.
func defaultKmsgDevicePaths(hostRoot string) []string {
	return kmsg.DevicePaths("/dev/kmsg", hostRoot)
}

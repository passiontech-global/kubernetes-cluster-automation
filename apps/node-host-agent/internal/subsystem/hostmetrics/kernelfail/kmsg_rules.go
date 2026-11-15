// kmsg_rules.go — the classifier half of kernel-dmesg checkKernelDmesg:
// the kernel-message detector regexes, the cross-line OOM pairing
// context and the line→detector dispatch. This file answers "what
// does this message mean"; the plumbing it dispatches into (the
// kmsg session/cursor machinery, the marker writes, the dmesg
// fallback, the conntrack sysctl bump) stays in kmsg.go. The
// kernelfail contract overview lives in kernelfail.go.
package kernelfail

import (
	"regexp"
	"strings"
)

// --- kernel-message detectors (kernel-dmesg) ---

var (
	// Filesystem/block error signatures — the plan's literal set,
	// plus the selfheal-alert-coverage XFS structural-corruption family: "Metadata I/O
	// error" alone misses the B+tree/AG corruption verdicts XFS
	// prints when it force-shuts a filesystem down (the node is
	// about to go read-only — the latch must arm NOW, not after
	// the shutdown line). BTRFS: error covers the same verdict on
	// btrfs nodes.
	fsErrorRe = regexp.MustCompile(
		`blk_update_request: I/O error|Buffer I/O error on dev|` +
			`EXT4-fs error|XFS \([^)]*\): Metadata I/O error|XFS_ERROR|` +
			`XFS \([^)]*\): (?:Metadata corruption detected|Internal error|` +
			`Corruption of in-memory data|Shutting down filesystem)|` +
			`xfs_force_shutdown|BTRFS: error`)
	// nf_conntrack table-full — packets are being DROPPED.
	conntrackFullRe = regexp.MustCompile(`nf_conntrack: table full`)
	// "Out of memory: Killed process <pid> (<comm>) ..." — global
	// OOM — and "Memory cgroup out of memory: Killed process ..."
	// — the memcg variant the kernel prints for cgroup OOMs, which
	// is the COMMON case under kubepods pressure.
	oomKillRe = regexp.MustCompile(
		`(?i)(?:memory cgroup )?out of memory: killed process \d+ \(([^)]+)\)`)
	// The constraint line printed just before the kill line —
	// carries oom_memcg/task_memcg, the cgroup verdict's evidence.
	oomConstraintRe = regexp.MustCompile(`oom-kill:constraint=`)
	oomMemcgRe      = regexp.MustCompile(`(?:oom_memcg|task_memcg)=([^\s,]+)`)
	oomTaskRe       = regexp.MustCompile(`(?:^|,)task=([^\s,]+)`)
	// kernel-pressure: higher-order page allocation failure — the buddy
	// allocator can't find a contiguous order>=1 block for
	// sk_buff/WireGuard/XFS even while MemAvailable stays high.
	// order:0 failures are routine pressure noise; order:[1-9] is
	// the fragmentation signature workerhygiene defragments via
	// vm.compact_memory.
	pageAllocFailRe = regexp.MustCompile(`page allocation failure: order:[1-9]`)
	// Clocksource fallback: the kernel giving up on a clocksource —
	// "Marking clocksource 'tsc' as unstable" or the
	// "clocksource: ... unstable" family line. After this the kernel
	// falls back to a slower clocksource (hpet/acpi_pm) and every
	// vDSO clock read degrades.
	clocksourceUnstableRe = regexp.MustCompile(
		`Marking clocksource '.*' as unstable|clocksource:.*unstable`)
	// --- self-healing wave: hardware / neighbor / NIC signatures ---
	// hwCorruptRe is the fatal-memory-error family — uncorrected or
	// fatal MCE, an EDAC uncorrectable-error report, or a memory-
	// failure SIGBUS/recovery-failure line. Corrected errors stay
	// out: they are noise, not corruption evidence. Same spelling
	// as nodereporter's NPD HardwareMemoryError rule.
	hwCorruptRe = regexp.MustCompile(
		`mce: \[Hardware Error\].*(?:Uncorrected|Fatal|PCC=1)|` +
			`EDAC MC\d+: [1-9]\d* UE|` +
			`Memory failure: 0x[0-9a-f]+: (?:Sending SIGBUS|recovery action .* Failed)`)
	// pcieNVMeResetRe covers the PCIe AER fatal family and the NVMe
	// controller-reset loop — PCIeBusError parity with the NPD rule.
	pcieNVMeResetRe = regexp.MustCompile(
		`PCIe Bus Error: severity=Uncorrected|AER: (?:Uncorrected|Fatal)|` +
			`nvme nvme\d+: I/O \d+ .* timeout, resetting controller`)
	// pcieAERFatalRe / nvmeResetRe split pcieNVMeResetRe's arms so
	// the handler can tell an acute AER event (evidence stamp) from
	// a controller reset (streak counter).
	pcieAERFatalRe = regexp.MustCompile(
		`PCIe Bus Error: severity=Uncorrected|AER: (?:Uncorrected|Fatal)`)
	nvmeResetRe = regexp.MustCompile(
		`nvme nvme\d+: I/O \d+ .* timeout, resetting controller`)
	// gpuFatalXidRe captures the fatal NVIDIA Xid code — the same
	// fatal set the NPD GPUXidError rule fires on. Non-fatal Xids
	// (31 MMU fault, 43 channel error) stay OUT: they are warning
	// events for NPD, not latch-grade hardware faults.
	gpuFatalXidRe = regexp.MustCompile(
		`NVRM: Xid \(PCI:[^)]+\): (48|74|79|94|95|119|120),`)
	// gpuUVHangRe is the nvidia-uvm driver-hang signature — UVM
	// channel errors and global fatal errors precede the same
	// GPUHardwareError latch the fatal Xids feed (the latchdefs
	// contract names "nvidia-uvm driver hang" explicitly). Real
	// kmsg spellings: "uvm encountered global fatal error 0x..",
	// "uvm_channel.c:.. Detected a channel error", "Encountered a
	// global fatal error".
	gpuUVHangRe = regexp.MustCompile(
		`uvm[^\n]*(?:global fatal error|channel error)`)
	// neighOverflowRe is the kernel's neighbor-table-full record —
	// (arp|ndisc) names the family neighbor.go bumps.
	neighOverflowRe = regexp.MustCompile(
		`neighbour: (arp|ndisc)_cache: neighbor table overflow`)
	// netdevTxTimeoutRe captures the iface from a NETDEV WATCHDOG
	// transmit-queue timeout — nic_health counts them per uplink.
	netdevTxTimeoutRe = regexp.MustCompile(
		`NETDEV WATCHDOG: ([^\s(:]+).*transmit queue \d+ timed out`)
)

// oomKillCtx is the pending constraint-line state — the kernel prints
// "oom-kill:constraint=..." immediately before "Out of memory:
// Killed process ..."; the pair classifies one kill event.
type oomKillCtx struct {
	memcg string // first memcg path seen (oom_memcg preferred)
	comm  string // task= comm when present
}

// classifyKernelLine feeds one kernel message into the detectors.
// Order matters: the oom-kill constraint line is captured as pending
// context for the kill line that follows it.
func (r *Runner) classifyKernelLine(msg string, st *kernelScanState) {
	switch {
	case oomConstraintRe.MatchString(msg):
		st.oomPending = parseOOMConstraint(msg)
	case oomKillRe.MatchString(msg):
		r.noteHostOOMKill(msg, st)
	case fsErrorRe.MatchString(msg):
		r.noteKernelFsError(msg)
	case conntrackFullRe.MatchString(msg):
		r.noteConntrackFull()
	case pageAllocFailRe.MatchString(msg):
		r.notePageAllocFailure(msg)
	case clocksourceUnstableRe.MatchString(msg):
		r.noteClocksourceUnstable(msg)
	case hwCorruptRe.MatchString(msg):
		r.noteHardwareCorrupt(msg)
	case gpuFatalXidRe.MatchString(msg):
		r.noteGPUXid(msg)
	case gpuUVHangRe.MatchString(msg):
		r.noteGPUUVHang(msg)
	case pcieNVMeResetRe.MatchString(msg):
		r.notePCIeNVMeReset(msg)
	case neighOverflowRe.MatchString(msg):
		r.noteNeighborOverflow(msg)
	case netdevTxTimeoutRe.MatchString(msg):
		r.noteNetdevTxTimeout(msg)
	}
}

// parseOOMConstraint extracts the memcg + task fields from an
// "oom-kill:constraint=..." line.
func parseOOMConstraint(msg string) *oomKillCtx {
	ctx := &oomKillCtx{}
	if m := oomMemcgRe.FindStringSubmatch(msg); m != nil {
		ctx.memcg = m[1]
	}
	if m := oomTaskRe.FindStringSubmatch(msg); m != nil {
		ctx.comm = m[1]
	}
	return ctx
}

// isHostOOMComm reports whether comm names a host-level daemon —
// the containerd/k0s/kubelet set plus the kernel-pressure infra daemons
// (nebula, haproxy on the api-lb VM, the coredns host stub, the
// postgres/pgbouncer pair on db-vm, every cilium daemon and the
// agent itself) whose kernel-OOM death is as load-bearing as the
// kubelet's. comm is TASK_COMM_LEN truncated (15 chars), so
// prefix/substring matching is required ("cilium-operator" and
// "node-host-agent" are exactly 15).
func isHostOOMComm(comm string) bool {
	switch comm {
	case "kubelet", "nebula", "haproxy", "coredns", "postgres",
		"pgbouncer", "node-host-agent":
		return true
	}
	return strings.HasPrefix(comm, "k0s") ||
		strings.HasPrefix(comm, "cilium-") ||
		strings.Contains(comm, "containerd")
}

func ctxMemcg(ctx *oomKillCtx) string {
	if ctx == nil {
		return ""
	}
	return ctx.memcg
}

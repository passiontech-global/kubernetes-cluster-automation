// kmsg_markers.go — kernel-dmesg: the evidence-marker writers and
// handlers the drain dispatches into — host-OOM victim + count
// markers (workerhygiene's SystemOOMVictim consumer), the fs/block
// error marker fsreadonly's evidence scan consumes, the
// page-alloc-failure and clocksource-unstable latches, and the
// rate-limited nf_conntrack_max sysctl bump. Pure move out of
// kmsg.go (per-concern file split).
package kernelfail

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// --- kernel-log handlers (kernel-dmesg) ---

const (
	// conntrackBumpEvery rate-limits the nf_conntrack_max doubling —
	// table-full bursts must not ratchet the sysctl every tick.
	conntrackBumpEvery = 30 * time.Minute
	// conntrackMaxCeiling caps the sysctl bump (nf_conntrack_max).
	conntrackMaxCeiling = 4 << 20
)

// Marker/state file names inside the watchdog state dir — shared
// with workerhygiene (the SystemOOMVictim consumer) by convention.
const (
	kmsgConntrackDropsFile  = "kmsg-conntrack-drops"
	kmsgOOMVictimFile       = "kmsg-host-oom-victim"
	kmsgOOMCountFile        = "kmsg-host-oom-count"
	conntrackBumpBudgetFile = "last-conntrack-bump"
)

// noteHostOOMKill classifies one "Out of memory: Killed process"
// record: host-level when the victim's memcg sits OUTSIDE the
// kubepods hierarchy, or the victim comm is a host daemon
// (containerd/k0s/kubelet). Pod-cgroup kills are routine kubelet
// eviction traffic — they must not fire SystemOOMVictim.
func (r *Runner) noteHostOOMKill(msg string, st *kernelScanState) {
	m := oomKillRe.FindStringSubmatch(msg)
	if m == nil {
		return
	}
	comm := m[1]
	ctx := st.oomPending
	st.oomPending = nil
	host := false
	if ctx != nil && ctx.memcg != "" {
		host = !strings.Contains(ctx.memcg, "kubepods")
	}
	if isHostOOMComm(comm) || (ctx != nil && isHostOOMComm(ctx.comm)) {
		host = true
	}
	if !host {
		return
	}
	r.deps.Store.Incr(kmsgOOMCountFile)
	now := r.deps.Clock.Now()
	p := r.statePath(kmsgOOMVictimFile)
	content := strconv.FormatInt(now.Unix(), 10) + " " + comm + "\n"
	if err := hostutil.WriteFileAtomicBytes(p, []byte(content)); err != nil {
		logger().Warn("hostmetrics: host-oom victim marker write failed",
			"path", p, "error", err)
	}
	logger().Warn("hostmetrics: host-level OOM kill observed",
		"comm", comm, "memcg", ctxMemcg(ctx))
}

// noteKernelFsError records the latest kernel filesystem/block error —
// updateFSReadonlyEvidence turns a fresh marker into state-fs-readonly.
func (r *Runner) noteKernelFsError(msg string) {
	detail := msg
	if len(detail) > 200 {
		detail = detail[:200]
	}
	p := r.statePath(kmsgFsErrorFile)
	content := strconv.FormatInt(r.deps.Clock.Now().Unix(), 10) + " " +
		detail + "\n"
	if err := hostutil.WriteFileAtomicBytes(p, []byte(content)); err != nil {
		logger().Warn("hostmetrics: kmsg fs-error marker write failed",
			"path", p, "error", err)
	}
}

// notePageAllocFailure latches state-page-alloc-failure on a
// higher-order (order>=1) page allocation failure — fragmentation
// evidence: MemAvailable can still read GBs free while the buddy
// allocator fails to find a contiguous block for sk_buff,
// WireGuard (cilium_wg0) or XFS metadata. The latch is the
// hostmetrics→workerhygiene hand-off for the kernel-pressure
// vm.compact_memory trigger (the compact itself + its cooldown live
// in workerhygiene); Enter is idempotent, so repeat failure lines
// only refresh the latch mtime and never spam STATE-ENTER lines —
// the latch exits when workerhygiene's compaction or the janitor's
// max-age reaper clears it, which is also the re-arm for the next
// fragmentation episode.
func (r *Runner) notePageAllocFailure(msg string) {
	detail := msg
	if len(detail) > 200 {
		detail = detail[:200]
	}
	// NPD contract: the ACTION entry line feeds
	// KernelPageAllocFailure (events.go) — ActionEntryRe parses
	// it. Once per episode: repeat kmsg records only refresh the
	// latch mtime, so gate the line on the latch being absent.
	fresh := !r.deps.Store.Exists(latchdefs.LatchPageAllocFailure)
	r.deps.Store.Enter(latchdefs.LatchPageAllocFailure,
		"page allocation failure: "+detail)
	if fresh {
		r.deps.Store.AppendLog(latchdefs.ActionEntryPrefix(
			latchdefs.LatchPageAllocFailure) + detail)
	}
}

// noteClocksourceUnstable latches state-clocksource-unstable on a
// kernel clocksource-unstable kmsg record — the kernel
// demoted its clock (typically tsc) to a slower fallback, so every
// vDSO clock_gettime degrades and clock-skew false positives follow.
// Like the nodereporter soft-lockup evidence latches this is a
// permanent-class latch: Enter is idempotent (repeat records only
// refresh the mtime) and only the janitor's max-age reaper clears it
// once the signature stops recurring.
func (r *Runner) noteClocksourceUnstable(msg string) {
	detail := msg
	if len(detail) > 200 {
		detail = detail[:200]
	}
	r.deps.Store.Enter(latchdefs.LatchClocksourceUnstable,
		"clocksource unstable: "+detail)
}

// noteConntrackFull counts table-full records and — bounded by
// the rate budget + ceiling — doubles nf_conntrack_max so the table
// stops dropping packets. A failed sysctl write is a Warn, never
// fatal (read-only /proc/sys in unprivileged pods just logs).
func (r *Runner) noteConntrackFull() {
	r.deps.Store.Incr(kmsgConntrackDropsFile)
	r.maybeBumpConntrackMax()
}

// maybeBumpConntrackMax doubles ConntrackMaxFile when a table-full
// record lands — rate-limited and ceiling-capped. The write targets
// the sysctl path directly; containerized agents without a writable
// /proc/sys get a Warn and move on.
func (r *Runner) maybeBumpConntrackMax() {
	// RateTrySpend not RateOK+RateSpend: check-and-spend must be one
	// atomic budget decision — two callers racing the window could
	// otherwise both pass RateOK and double-bump inside 30m. A
	// failed sysctl write spends the window too: retrying a
	// permanently read-only /proc every tick is not better than
	// waiting out the budget.
	if !r.deps.Store.RateTrySpend(conntrackBumpBudgetFile, conntrackBumpEvery) {
		return
	}
	cur, ok := hostutil.ReadUintFile(r.deps.ConntrackMaxFile)
	if !ok || cur == 0 || cur >= conntrackMaxCeiling {
		return
	}
	next := cur * 2
	if next > conntrackMaxCeiling {
		next = conntrackMaxCeiling
	}
	if err := os.WriteFile(r.deps.ConntrackMaxFile,
		[]byte(strconv.FormatUint(next, 10)+"\n"), 0o644); err != nil {
		logger().Warn("hostmetrics: nf_conntrack_max bump failed",
			"path", r.deps.ConntrackMaxFile, "error", err)
		return
	}
	logger().Warn("hostmetrics: nf_conntrack table full — bumped "+
		"nf_conntrack_max",
		"from", cur, "to", next)
}

// kernel.go — the kernel-monitor port (upstream
// kernel-monitor.json, kmsg plugin): drains the host kernel ring
// buffer — the DaemonSet bind-mounts host /dev/kmsg at /dev/kmsg
// (CharDevice, ro), with <HostRoot>/dev/kmsg as the fallback path —
// via O_NONBLOCK reads through the shared platform/kmsg Tailer
// (lazy open over the device candidates, byte-capped drain,
// partial-line carry, and the first-scan backlog gates). When kmsg
// cannot be opened the monitor falls back to `journalctl -k` for
// the process lifetime. kmsg records carry µs-since-boot
// timestamps, so the backlog replays through the same 5m lookback
// converted via /proc/uptime (hostPID -> host uptime) — kept armed
// across drains until the ring is drained to EAGAIN (the 4MiB
// per-cycle cap can slice a big backlog); the journald fallback is
// already cursor-bounded. KernelDeadlock is a PERMANENT condition:
// once latched it stays True for the agent lifetime (NPD parity —
// permanent conditions never clear). The
// kernel-softlockup-monitor additions extend the deadlock class to
// the watchdog soft-lockup and RCU-stall signatures — each is also
// a temporary rule (counter + Event) and Enters an evidence latch
// KernelHungTasks' altStateKeys probe (the parent's
// conditions.go).
package npd

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kmsg"
)

// kernelSoftLockupRe / kernelRCUStallRe are the
// kernel-softlockup-monitor signatures — a CPU spinning inside a
// kernel critical section (watchdog soft lockup) or an RCU grace
// period that never completes. Both feed a temporary rule
// (counter + Event), the permanent KernelDeadlock latch (the
// signatures are compiled into kernelDeadlockRe too) and the
// KernelHungTasks evidence latches below.
var (
	kernelSoftLockupRe = regexp.MustCompile(`watchdog: BUG: soft lockup - CPU#\d+ stuck for \d+s!`)
	kernelRCUStallRe   = regexp.MustCompile(`INFO: rcu_(?:sched|preempt|bh) (?:self-)?detected stall on CPU`)
)

// kernel-monitor.json temporary rules (the upstream set, trimmed to
// the reasons kept by this deployment's alert rules), plus the
// kernel-softlockup-monitor pair at the tail.
var kernelTempRules = []rule{
	{"OOMKilling", regexp.MustCompile(`Killed process \d+ .* out of memory|Out of memory: Killed process`)},
	{"TaskHung", regexp.MustCompile(`task [\S ]+:\w+ blocked for more than \w+ seconds`)},
	{"KernelOops", regexp.MustCompile(`BUG: unable to handle kernel|kernel BUG at|Oops:`)},
	{"Ext4Error", regexp.MustCompile(`EXT4-fs error`)},
	{"Ext4Warning", regexp.MustCompile(`EXT4-fs warning`)},
	{"ConntrackTableFull", regexp.MustCompile(`nf_conntrack.*table full`)},
	{"FilesystemIOError", regexp.MustCompile(`Buffer I/O error on dev|XFS.*[Mm]etadata I/O error`)},
	{"KernelSoftLockup", kernelSoftLockupRe},
	{"KernelRCUStall", kernelRCUStallRe},
	// W13-KR1 additions — the fragmentation/neighbour/NIC/TCP
	// signatures hostmetrics' kmsg drain also classifies into
	// state-dir latches; here they are temporary rules (counter +
	// Event) like the upstream kernel-monitor set.
	{"PageAllocFailure", regexp.MustCompile(`page allocation failure: order:[1-9]`)},
	{"NeighborTableOverflow", regexp.MustCompile(`neighbour: (?:arp|ndisc)_cache: neighbor table overflow`)},
	{"NetdevTxTimeout", regexp.MustCompile(`NETDEV WATCHDOG: .* transmit queue [0-9]+ timed out`)},
	{"TCPMemoryPressure", regexp.MustCompile(`TCP: out of memory -- consider tuning tcp_mem`)},
}

// kernelDeadlockRe is the permanent KernelDeadlock rule — the
// hung-task watcher's "INFO: task ... blocked" output plus the
// soft-lockup/RCU-stall signatures: all three are the same deadlock
// class (a CPU wedged in kernel or a stalled RCU grace period blocks
// every task queued behind it).
var kernelDeadlockRe = regexp.MustCompile(`INFO: task .* blocked for more than` +
	`|watchdog: BUG: soft lockup - CPU#\d+ stuck for \d+s!` +
	`|INFO: rcu_(?:sched|preempt|bh) (?:self-)?detected stall on CPU`)

// kernelSoftLockupLatch / kernelRCUStallLatch are the KernelHungTasks
// evidence latches the kernel monitor Enters on a soft-lockup /
// RCU-stall signature — the same hang class as the workerhygiene
// D-state storm, surfaced through KernelHungTasks' altStateKeys in
// the parent's conditions.go. The reporter owns the latch names (no
// hygiene check produces kmsg lines) and never Exits them: a
// lockup/stall is permanent-class evidence, so only the janitor's
// max-age reaper clears a latch whose signature stopped recurring.
const (
	kernelSoftLockupLatch = hoststate.LatchKernelSoftLockup
	kernelRCUStallLatch   = hoststate.LatchKernelRCUStall
)

// kernelHungLatchRules map a kernel-hang signature regex to the
// evidence latch it Enters — evaluated in processKernelLine after
// the temporary rules, same table shape as the rule sets above.
var kernelHungLatchRules = []struct {
	re    *regexp.Regexp
	latch string
}{
	{kernelSoftLockupRe, kernelSoftLockupLatch},
	{kernelRCUStallRe, kernelRCUStallLatch},
}

const (
	// maxKmsgReadBytes bounds one kmsg drain per cycle — a printk
	// flood is sliced across cycles instead of slurping the whole
	// ring.
	maxKmsgReadBytes = 4 << 20
	// maxKmsgPendingBytes bounds the carried partial record — a
	// line that never terminates cannot grow the carry forever
	// (same bound the watchdog filelog tail uses).
	maxKmsgPendingBytes = 64 << 10
)

// The KernelDeadlock NodeCondition and its upstream strings
// (kernel-monitor.json conditions[]).
const (
	condKernelDeadlock corev1.NodeConditionType = "KernelDeadlock"

	kernelDeadlockDefaultReason = "KernelHasNoDeadlock"
	kernelDeadlockDefaultMsg    = "kernel has no deadlock"
	kernelDeadlockProblemReason = "KernelDeadlock"
)

// kernelLines returns new kernel records and whether they must pass
// the first-scan lookback filter. kmsg path: the tailer lazily opens
// the device (a reopen after a read error re-arms the lookback
// replay so the ring backlog isn't re-emitted live). The filter
// stays armed until the ring is drained to EAGAIN — the 4MiB
// per-drain cap can slice a big backlog across cycles, and backlog
// past the cap is still replay, not live history (a stale hung-task
// line would otherwise latch a PERMANENT KernelDeadlock on a fresh
// agent start). Journald fallback: permanent once kmsg cannot be
// opened, bounded by its own cursor so replay is never needed.
// Records come back as kmsg.Record — Msg is the payload text,
// Usec the µs-since-boot timestamp (-1 when unknown, e.g. the
// journald path where the cursor already bounds the window).
func (m *Monitor) kernelLines(ctx context.Context) ([]kmsg.Record, bool, error) {
	for {
		if m.kmsgJournalMode {
			entries, err := m.fetchJournal(ctx, &m.kernelJournalUS, "-k")
			if err != nil {
				return nil, false, err
			}
			lines := make([]kmsg.Record, 0, len(entries))
			for _, e := range entries {
				lines = append(lines, kmsg.Record{Msg: e.Msg, Usec: -1})
			}
			return lines, false, nil
		}
		raw, res, err := m.kmsgTail.Read()
		switch {
		case errors.Is(err, kmsg.ErrNoDevice):
			// No openable kmsg device — permanent journalctl -k
			// fallback for the process lifetime.
			m.kmsgJournalMode = true
			logger().Warn("nodereporter: /dev/kmsg unreadable, kernel monitor "+
				"falls back to journalctl -k for the process lifetime",
				"kmsg", m.cfg().KmsgFile, "hostRoot", m.cfg().HostRoot)
			continue
		case err != nil:
			m.closeKmsg() // reopen next cycle → lookback re-armed
			return nil, false, fmt.Errorf("read %s: %w", m.cfg().KmsgFile, err)
		}
		replay := res.Backlog
		// kmsgScanned is "caught up at least once on this handle"
		// (the field name predates the EAGAIN semantics); the
		// tailer's post-read flag mirrors it.
		m.kmsgScanned = res.CaughtUp
		lines := make([]kmsg.Record, 0, len(raw))
		for _, l := range raw {
			lines = append(lines, kmsg.ParseRecord(l))
		}
		return lines, replay, nil
	}
}

// closeKmsg releases the lazily-opened kmsg handle — the read-error
// path above uses it to force a fresh open next cycle (the
// partial-line carry survives inside the tailer; only the handle is
// dropped).
func (m *Monitor) closeKmsg() {
	m.kmsgTail.Close()
}

// SyncKernelMonitor is the kernel-monitor port: new kernel lines →
// temporary rules (counter + Event) plus the permanent KernelDeadlock
// latch.
func (m *Monitor) SyncKernelMonitor(ctx context.Context, s Sink) error {
	lines, replay, err := m.kernelLines(ctx)
	if err != nil {
		return err
	}
	uptime := float64(-1)
	if replay {
		// hostUptimeSeconds read the first field of /proc/uptime —
		// under hostPID this is the HOST uptime, which converts kmsg
		// µs-since-boot timestamps into ages for the first-scan
		// lookback (hostutil.UptimeSeconds is the shared parser).
		if u, e := hostutil.UptimeSeconds(m.cfg().ProcUptimeFile); e == nil {
			uptime = u
		}
	}
	for _, l := range lines {
		if replay {
			// kmsg records: age = uptime - usec. Unknown ts or an
			// unreadable uptime → drop the backlog line rather than
			// replay ancient ring history as live (filelog parity).
			if l.Usec <= 0 || uptime < 0 {
				continue
			}
			if uptime-float64(l.Usec)/1e6 > m.cfg().LogLookback.Seconds() {
				continue
			}
		}
		m.processKernelLine(ctx, s, l.Msg)
	}
	return nil
}

// processKernelLine applies the temporary kernel rules plus the
// permanent KernelDeadlock latch to one kernel message. The
// soft-lockup/RCU-stall signatures additionally Enter their
// KernelHungTasks evidence latches — the sink's state store carries
// an empty LogFile, so the STATE-ENTER never circles back into the
// filelog rules the reporter tails.
func (m *Monitor) processKernelLine(ctx context.Context, s Sink, msg string) {
	m.matchEventRules(ctx, s, kernelTempRules, msg)
	if kernelDeadlockRe.MatchString(msg) {
		s.BumpCounter(kernelDeadlockProblemReason)
		if !m.kernelDeadlock {
			// Permanent: latch True for the agent lifetime (NPD
			// permanent-rule parity) and emit the transition Event.
			m.kernelDeadlock = true
			m.kernelDeadlockMsg = msg
			if err := s.EmitEvent(ctx, kernelDeadlockProblemReason, msg); err != nil {
				logger().Error("nodereporter: event emit failed",
					"reason", kernelDeadlockProblemReason, "error", err)
			}
		}
	}
	for _, hr := range kernelHungLatchRules {
		if hr.re.MatchString(msg) {
			s.EnterLatch(hr.latch, msg)
		}
	}
}

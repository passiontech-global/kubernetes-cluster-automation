// npd_kernel.go — the kernel-monitor port (upstream
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
// KernelHungTasks' altStateKeys probe (conditions.go).
package nodereporter

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
var kernelTempRules = []logRule{
	{"OOMKilling", regexp.MustCompile(`Killed process \d+ .* out of memory|Out of memory: Killed process`)},
	{"TaskHung", regexp.MustCompile(`task [\S ]+:\w+ blocked for more than \w+ seconds`)},
	{"KernelOops", regexp.MustCompile(`BUG: unable to handle kernel|kernel BUG at|Oops:`)},
	{"Ext4Error", regexp.MustCompile(`EXT4-fs error`)},
	{"Ext4Warning", regexp.MustCompile(`EXT4-fs warning`)},
	{"ConntrackTableFull", regexp.MustCompile(`nf_conntrack.*table full`)},
	{"FilesystemIOError", regexp.MustCompile(`Buffer I/O error on dev|XFS.*[Mm]etadata I/O error`)},
	{"KernelSoftLockup", kernelSoftLockupRe},
	{"KernelRCUStall", kernelRCUStallRe},
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
// conditions.go. The reporter owns the latch names (no hygiene check
// produces kmsg lines) and never Exits them: a lockup/stall is
// permanent-class evidence, so only the janitor's max-age reaper
// clears a latch whose signature stopped recurring.
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

// maxKmsgReadBytes bounds one kmsg drain per cycle — a printk flood
// is sliced across cycles instead of slurping the whole ring.
const maxKmsgReadBytes = 4 << 20

// The KernelDeadlock NodeCondition and its upstream strings
// (kernel-monitor.json conditions[]).
const (
	condKernelDeadlock corev1.NodeConditionType = "KernelDeadlock"

	kernelDeadlockDefaultReason = "KernelHasNoDeadlock"
	kernelDeadlockDefaultMsg    = "kernel has no deadlock"
	kernelDeadlockProblemReason = "KernelDeadlock"
)

// kernelLine is one kernel record: the message text plus its
// µs-since-boot timestamp (-1 when unknown, e.g. journald path where
// the cursor already bounds the window).
type kernelLine struct {
	msg  string
	usec int64
}

// parseKmsgRecord splits a /dev/kmsg record "pri,seq,usec,flags;msg"
// into its message and boot-relative timestamp. Lines without the
// kmsg header pass through whole with an unknown timestamp.
func parseKmsgRecord(line []byte) kernelLine {
	r := kmsg.ParseRecord(line)
	return kernelLine{msg: r.Msg, usec: r.Usec}
}

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
func (r *Reporter) kernelLines(ctx context.Context) ([]kernelLine, bool, error) {
	for {
		if r.kmsgJournalMode {
			entries, err := r.fetchJournal(ctx, &r.kernelJournalUS, "-k")
			if err != nil {
				return nil, false, err
			}
			lines := make([]kernelLine, 0, len(entries))
			for _, e := range entries {
				lines = append(lines, kernelLine{msg: e.Msg, usec: -1})
			}
			return lines, false, nil
		}
		raw, res, err := r.kmsgTail.Read()
		switch {
		case errors.Is(err, kmsg.ErrNoDevice):
			// No openable kmsg device — permanent journalctl -k
			// fallback for the process lifetime.
			r.kmsgJournalMode = true
			logger().Warn("nodereporter: /dev/kmsg unreadable, kernel monitor "+
				"falls back to journalctl -k for the process lifetime",
				"kmsg", r.cfg.KmsgFile, "hostRoot", r.cfg.HostRoot)
			continue
		case err != nil:
			r.closeKmsg() // reopen next cycle → lookback re-armed
			return nil, false, fmt.Errorf("read %s: %w", r.cfg.KmsgFile, err)
		}
		replay := res.Backlog
		// kmsgScanned is "caught up at least once on this handle"
		// (the field name predates the EAGAIN semantics); the
		// tailer's post-read flag mirrors it.
		r.kmsgScanned = res.CaughtUp
		lines := make([]kernelLine, 0, len(raw))
		for _, l := range raw {
			lines = append(lines, parseKmsgRecord(l))
		}
		return lines, replay, nil
	}
}

// closeKmsg releases the lazily-opened kmsg handle — the read-error
// path above uses it to force a fresh open next cycle (the
// partial-line carry survives inside the tailer; only the handle is
// dropped).
func (r *Reporter) closeKmsg() {
	r.kmsgTail.Close()
}

// syncKernelMonitor is the kernel-monitor port: new kernel lines →
// temporary rules (counter + Event) plus the permanent KernelDeadlock
// latch.
func (r *Reporter) syncKernelMonitor(ctx context.Context) error {
	lines, replay, err := r.kernelLines(ctx)
	if err != nil {
		return err
	}
	uptime := float64(-1)
	if replay {
		// hostUptimeSeconds read the first field of /proc/uptime —
		// under hostPID this is the HOST uptime, which converts kmsg
		// µs-since-boot timestamps into ages for the first-scan
		// lookback (hostutil.UptimeSeconds is the shared parser).
		if u, e := hostutil.UptimeSeconds(r.cfg.ProcUptimeFile); e == nil {
			uptime = u
		}
	}
	for _, l := range lines {
		if replay {
			// kmsg records: age = uptime - usec. Unknown ts or an
			// unreadable uptime → drop the backlog line rather than
			// replay ancient ring history as live (filelog parity).
			if l.usec <= 0 || uptime < 0 {
				continue
			}
			if uptime-float64(l.usec)/1e6 > r.cfg.LogLookback.Seconds() {
				continue
			}
		}
		r.processKernelLine(ctx, l.msg)
	}
	return nil
}

// processKernelLine applies the temporary kernel rules plus the
// permanent KernelDeadlock latch to one kernel message. The
// soft-lockup/RCU-stall signatures additionally Enter their
// KernelHungTasks evidence latches — r.state carries an empty
// LogFile, so the STATE-ENTER never circles back into the filelog
// rules this same reporter tails.
func (r *Reporter) processKernelLine(ctx context.Context, msg string) {
	r.matchEventRules(ctx, kernelTempRules, msg)
	if kernelDeadlockRe.MatchString(msg) {
		r.problemCounter.WithLabelValues(kernelDeadlockProblemReason).Inc()
		if !r.kernelDeadlock {
			// Permanent: latch True for the agent lifetime (NPD
			// permanent-rule parity) and emit the transition Event.
			r.kernelDeadlock = true
			r.kernelDeadlockMsg = msg
			if err := r.emitEvent(ctx, kernelDeadlockProblemReason, msg); err != nil {
				logger().Error("nodereporter: event emit failed",
					"reason", kernelDeadlockProblemReason, "error", err)
			}
		}
	}
	for _, hr := range kernelHungLatchRules {
		if hr.re.MatchString(msg) {
			r.state.Enter(hr.latch, msg)
		}
	}
}

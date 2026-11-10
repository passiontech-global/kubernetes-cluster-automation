package nethealth

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
)

const (
	ntpRestartInterval = 30 * time.Minute

	// clockMaxEsterrorUS: an adjtimex estimated error above this
	// (microseconds, 500ms) counts the clock as unsynchronized even
	// while the kernel has not set STA_UNSYNC — a drifting clock
	// breaks TLS/cert checks long before the discipline gives up.
	clockMaxEsterrorUS = 500_000
)

// --- Check: clock-sync (H1) ---

// checkClockSync — H1: the kernel's own clock discipline via a
// read-only adjtimex(2) (modes==0 needs no CAP_SYS_TIME). The clock
// is unhealthy when the kernel reports STA_UNSYNC (no sync source
// achieved) or the estimated error exceeds 500ms — a silently
// drifting clock breaks TLS/cert verification and raft leases long
// before anything else on the node notices.
//
// Consecutive failing cycles >= ConsecNeeded arm the clock-unsync
// latch and — under the 30m last-ntp-restart budget — restart the
// node's sync daemon (whichever of timesyncd/chrony/chronyd is
// installed). An adjtimex error aborts the cycle WITHOUT touching
// the counter: an EPERM/seccomp-blocked read must not false-latch.
func (n *NetHealth) checkClockSync(ctx context.Context) {
	var tx unix.Timex
	if _, err := n.cfg.adjtimexFn(&tx); err != nil {
		n.state.SuspectLog("clock-adjtimex",
			fmt.Sprintf("clock-sync: adjtimex failed: %v", err),
			suspectLogCadence)
		n.cycles.WithLabelValues(checkClock, "abort").Inc()
		return
	}
	bad := ""
	switch {
	case tx.Status&unix.STA_UNSYNC != 0:
		bad = "kernel reports STA_UNSYNC"
	case tx.Esterror > clockMaxEsterrorUS:
		bad = fmt.Sprintf("esterror %dus exceeds %dus",
			tx.Esterror, clockMaxEsterrorUS)
	}
	if bad == "" {
		n.clockFails = 0
		n.stateExit(latchdefs.LatchClockUnsync)
		n.cycles.WithLabelValues(checkClock, "ok").Inc()
		return
	}
	if checkkit.Pending(n.cfg.ConsecNeeded, &n.clockFails,
		"suspect: clock-unsync "+bad, n.state.AppendLog) {
		n.cycles.WithLabelValues(checkClock, "ok").Inc()
		return
	}
	n.state.Enter(latchdefs.LatchClockUnsync, bad)
	if n.state.RateOK("last-ntp-restart", ntpRestartInterval) {
		n.restartNTPDaemon(ctx)
	} else {
		n.state.SuspectLog(latchdefs.LatchClockUnsync, "suspect: clock-unsync persists "+
			"but ntp restart cooldown (<30m), skip", suspectLogCadence)
	}
	n.cycles.WithLabelValues(checkClock, "ok").Inc()
}

// restartNTPDaemon restarts whichever clock-sync daemon the node
// runs — systemd-timesyncd (Debian/Ubuntu) or chrony/chronyd — under
// the last-ntp-restart budget. The budget is spent on the restart
// attempt itself; a node without any sync unit only gets the latch
// (the daemon may be managed by other means).
func (n *NetHealth) restartNTPDaemon(ctx context.Context) {
	if n.cfg.Systemd == nil {
		n.state.SuspectLog("ntp-no-systemd",
			"ntp restart skipped — no systemd client", suspectLogCadence)
		return
	}
	// Pick the node's ACTUAL sync daemon, not just an installed one:
	// timesyncd's unit file ships with systemd on every
	// Debian/Ubuntu host — installed ≠ in use — so UnitExists alone
	// would restart a disabled timesyncd on a chrony node and give
	// the box two clock-discipline daemons fighting over adjtimex.
	// Preference: enabled+active (the live daemon), then
	// enabled-only (crashed — needs the restart most), then
	// active-only (live but unmanaged enablement). A unit that
	// merely exists never qualifies. The candidate list is the
	// shared latchdefs.ClockRestartUnits — the restart line below
	// and the ClockUnsynchronized filelog rule derive from the same
	// slice.
	pick := ""
	for _, u := range latchdefs.ClockRestartUnits {
		if n.unitEnabledActive(ctx, u) {
			pick = u
			break
		}
	}
	if pick == "" {
		for _, u := range latchdefs.ClockRestartUnits {
			if n.cfg.Systemd.IsEnabled(ctx, u) {
				pick = u
				break
			}
		}
	}
	if pick == "" {
		for _, u := range latchdefs.ClockRestartUnits {
			if n.cfg.Systemd.IsActive(ctx, u) {
				pick = u
				break
			}
		}
	}
	if pick == "" {
		// The restart budget is intentionally NOT spent here —
		// there is nothing to restart — but the line is cadence-
		// throttled so a unit-less node doesn't re-log every cycle.
		n.state.SuspectLog("no-sync-unit", "clock-unsync but no "+
			"enabled/active sync unit found (timesyncd/chrony/"+
			"chronyd all disabled or absent)", suspectLogCadence)
		return
	}
	n.state.AppendLog(fmt.Sprintf(
		latchdefs.ActionPrefix+"restarting %s - clock unsynchronized (persisted %dx)",
		pick, n.clockFails))
	n.state.RateSpend("last-ntp-restart")
	if err := n.cfg.Systemd.Restart(ctx, pick); err != nil {
		n.state.AppendLog(fmt.Sprintf("%s restart failed: %v", pick, err))
		return
	}
	n.actions.WithLabelValues(checkClock, "restart").Inc()
}

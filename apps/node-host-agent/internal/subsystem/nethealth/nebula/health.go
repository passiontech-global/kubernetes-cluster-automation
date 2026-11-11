// health.go — the nebula-health check proper (13-nebula-health.sh):
// socket bound, tun addressed, stats answering, plus the restart /
// timesyncd remedies. Moved verbatim out of the parent nethealth
// package's nebula_health.go.
package nebula

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
)

const (
	// nebulaNTPRestartInterval is the timesyncd restart budget when
	// a clock latch accompanies a Nebula failure — tighter than
	// checkClockSync's own 30m because the broken handshake is the
	// live outage; the latch just explains it.
	nebulaNTPRestartInterval = 10 * time.Minute
)

// udpSocketBound parses /proc/net/udp[6] for a socket bound to port —
// `ss -uHln "sport = :PORT"` parity (UNCONN sockets included — a raw
// parse of the hex local_address field).
func (n *Deps) udpSocketBound(port int) bool {
	want := fmt.Sprintf(":%04X", port)
	for _, f := range []string{n.ProcNetUDP(), n.ProcNetUDP6()} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasSuffix(fields[1], want) {
				return true
			}
		}
	}
	return false
}

// hasIPv4Addr mirrors `ip -4 -o addr show dev <dev> | grep .` — a
// tun that failed to init has no address.
func (n *Deps) hasIPv4Addr(ctx context.Context, dev string) bool {
	out, err := n.IP(ctx, "-4", "-o", "addr", "show", "dev", dev)
	return err == nil && strings.TrimSpace(out) != ""
}

// NebulaRestart restarts nebula@<net> through the shared
// last-nebula-restart budget.
func (n *Deps) NebulaRestart(ctx context.Context) {
	net := n.Watchdog().NebulaNet
	if n.Systemd() == nil {
		n.State.SuspectLog("nebula-no-systemd",
			"nebula restart skipped — no systemd client", suspectLogCadence)
		return
	}
	if err := n.Systemd().Restart(ctx, "nebula@"+net); err != nil {
		n.State.AppendLog(fmt.Sprintf("nebula@%s restart failed: %v", net, err))
		return
	}
	n.Actions.WithLabelValues(checkNebula, "restart").Inc()
	// DNS flows pinned to conntrack entries through the dead tunnel
	// stay blackholed until expiry — flush them now.
	n.FlushStaleUDPConntrack(ctx, checkNebula)
}

// rmFiles removes every state-dir file matching glob — the module's
// `rm -f $STATE_DIR/<pattern>` cleanup when its unit is inactive.
func (n *Deps) rmFiles(pattern string) {
	for _, f := range n.EgressFiles(pattern) {
		_ = os.Remove(f)
	}
}

// CheckNebulaHealth — module 13: socket bound, tun addressed, stats
// answering, dataplane probes (only while nebula is the ACTIVE
// overlay — probing over tinc rules would misjudge the warm standby).
func (n *Deps) CheckNebulaHealth(ctx context.Context) {
	wd := n.Watchdog()
	net := wd.NebulaNet
	if !n.UnitEnabledActive(ctx, "nebula@"+net) {
		// Nebula disabled/left mesh → drop this module's states
		// (stale files feed phantom gauges). Egress state is module
		// 12's own business.
		n.rmFiles(latchdefs.LatchFilePrefix + "nebula-")
		n.NebulaFails, n.NebulaDpFail, n.NebulaDeg = 0, 0, 0
		n.PMTUFails = 0
		n.SiteedgeRun = 0
		n.Cycles.WithLabelValues(checkNebula, "gated").Inc()
		return
	}
	reason := ""
	dpFail := false // dataplane-dead counts its own counter
	switch {
	case !n.udpSocketBound(wd.NebulaPort):
		reason = fmt.Sprintf("nebula-no-socket udp/%d not bound", wd.NebulaPort)
	case !n.hasIPv4Addr(ctx, wd.NebulaDev):
		reason = "nebula-no-tun-addr dev=" + wd.NebulaDev
	case wd.NebulaStatsURL != "":
		if err := n.ProbeHTTP(ctx, wd.NebulaStatsURL, 5*time.Second); err != nil {
			reason = fmt.Sprintf("nebula-stats-dead %s: %v",
				wd.NebulaStatsURL, err)
		}
	}

	// Dataplane probes — ONLY while nebula is the active overlay.
	if reason == "" && wd.OverlayActive == "nebula" &&
		(len(wd.OverlayProbeTargets)+len(wd.OverlayProbeMarkers)) > 0 {
		targets, results := n.ProbeNebulaOverlay(ctx, wd)
		reason, dpFail = n.evalNebulaOverlay(ctx, wd, targets, results)
	} else {
		// overlay != nebula (or no probe config): don't probe through
		// the other overlay — clear leftover dataplane states.
		n.NebulaDeg = 0
		n.PMTUFails = 0
		n.SiteedgeRun = 0
		n.StateExit(latchdefs.LatchNebulaDegraded)
		n.StateExit(latchdefs.LatchNebulaSlowpath)
		n.StateExit(latchdefs.LatchNebulaSiteedge)
		n.StateExit(latchdefs.LatchNebulaIsolated)
		n.StateExit(latchdefs.LatchNebulaPMTUBlackhole)
	}

	if reason == "" {
		n.NebulaFails, n.NebulaDpFail = 0, 0
		n.Cycles.WithLabelValues(checkNebula, "ok").Inc()
		return
	}
	// nebula-conntrack-flush: a skewed/unsynced clock wedges the Nebula handshake
	// (cert not-yet-valid / replay window) — when a clock latch is
	// armed and Nebula is failing, bounce timesyncd under the
	// shared last-ntp-restart budget rather than only cycling
	// nebula.service.
	n.RestartTimesyncdOnClockLatch(ctx)
	fails := &n.NebulaFails
	if dpFail {
		fails = &n.NebulaDpFail
	}
	suspect := func(msg string) {
		// Key on the reason's leading token so a persisting cause
		// throttles to the cadence while a NEW cause still logs at
		// once.
		n.State.SuspectLog(strings.SplitN(reason, " ", 2)[0],
			msg, suspectLogCadence)
	}
	if checkkit.Pending(n.ConsecNeeded(), fails,
		"suspect: "+reason, suspect) {
		n.Cycles.WithLabelValues(checkNebula, "ok").Inc()
		return
	}
	if n.State.RateOK("last-nebula-restart", n.MinRestart()) {
		n.State.AppendLog(fmt.Sprintf(latchdefs.ActionNebulaRestart+
			"%s - %s (persisted %dx)", net, reason, *fails))
		n.State.RateSpend("last-nebula-restart")
		n.NebulaFails, n.NebulaDpFail = 0, 0
		n.NebulaRestart(ctx)
	} else {
		// Confirmed streak but the restart budget is spent — the
		// suspect line still re-reminds at cadence.
		suspect("suspect: " + reason +
			checkkit.Progress(*fails, n.ConsecNeeded()))
	}
	n.Cycles.WithLabelValues(checkNebula, "ok").Inc()
}

// RestartTimesyncdOnClockLatch — nebula-conntrack-flush: when the Nebula check is
// failing AND a clock latch (clock-unsync from the H1 check or the
// hostmetrics clock-skew latch) is armed, the handshake's
// not-before/replay-window math is a prime suspect. Restart
// systemd-timesyncd under the 10m last-ntp-restart budget — the
// budget file is shared with checkClockSync so the two remedies
// can't double-fire.
func (n *Deps) RestartTimesyncdOnClockLatch(ctx context.Context) {
	if !n.State.Exists(latchdefs.LatchClockUnsync) &&
		!n.State.Exists(latchdefs.LatchClockSkew) {
		return
	}
	if n.Systemd() == nil {
		return
	}
	// Never wake a dormant timesyncd: its unit file ships installed
	// on every Debian/Ubuntu host, so on a chrony node restart
	// would put a SECOND clock-discipline daemon on the box and the
	// two fight over adjtimex (restartNTPDaemon's pick logic
	// enforces the same installed ≠ in use rule). Enabled counts —
	// an enabled-but-crashed unit is the node's real daemon.
	if !n.Systemd().IsEnabled(ctx, "systemd-timesyncd.service") &&
		!n.Systemd().IsActive(ctx, "systemd-timesyncd.service") {
		return
	}
	if !n.State.RateTrySpend("last-ntp-restart", nebulaNTPRestartInterval) {
		return
	}
	n.State.AppendLog("ACTION: restarting " + latchdefs.ClockRestartUnits[0] +
		" — clock latch active while nebula unhealthy")
	if err := n.Systemd().Restart(ctx, latchdefs.ClockRestartUnits[0]); err != nil {
		n.State.AppendLog(fmt.Sprintf(
			latchdefs.ClockRestartUnits[0]+" restart failed: %v", err))
		return
	}
	n.Actions.WithLabelValues(checkNebula, "ntp_restart").Inc()
}

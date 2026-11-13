package nethealth

import (
	"context"
	"fmt"
	"slices"
	"time"
)

const corednsRestartInterval = 5 * time.Minute

// --- Check: coredns-stub (21-coredns-stub.sh) ---

// checkCoreDNSStub restarts the coredns local stub when resolv.conf
// points at 127.0.0.1 but the unit is down — the port adds a 5m
// cooldown (shell restarted every run; a crashlooping stub otherwise
// burns a restart every cycle).
func (n *NetHealth) checkCoreDNSStub(ctx context.Context) {
	loopback := slices.Contains(
		nameservers(n.cfg.HostResolvConf, 16), "127.0.0.1")
	if !loopback || n.cfg.Systemd == nil {
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	// Fail closed on probe errors: an unanswerable `cat`/is-active
	// used to read as absent/active — an error now counts as
	// present+active so a broken systemctl can never trigger (or
	// skip-gate) a coredns restart on a lie.
	exists, err := n.cfg.Systemd.Exists(ctx, "coredns.service")
	if err != nil {
		logger().Warn("nethealth: coredns existence probe failed — "+
			"treating unit as present this cycle (fail closed)",
			"unit", "coredns.service",
			"error", err)
		exists = true
	}
	if !exists {
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	active, err := n.cfg.Systemd.Active(ctx, "coredns.service")
	if err != nil {
		logger().Warn("nethealth: coredns is-active probe failed — "+
			"treating unit as active this cycle (fail closed)",
			"unit", "coredns.service",
			"error", err)
		active = true
	}
	if active {
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	if !n.state.RateOK("last-coredns-restart", corednsRestartInterval) {
		n.state.SuspectLog("coredns-cooldown",
			"suspect: coredns stub dead but restart cooldown (<5m), skip",
			suspectLogCadence)
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	n.state.AppendLog("ACTION: restarting coredns - stub dead but resolv.conf points at 127.0.0.1")
	n.state.RateSpend("last-coredns-restart")
	if err := n.cfg.Systemd.Restart(ctx, "coredns.service"); err != nil {
		n.state.AppendLog(fmt.Sprintf("coredns restart failed: %v", err))
	} else {
		n.actions.WithLabelValues(checkCoreDNS, "restart").Inc()
		n.flushStaleUDPConntrack(ctx, checkCoreDNS)
	}
	n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
}

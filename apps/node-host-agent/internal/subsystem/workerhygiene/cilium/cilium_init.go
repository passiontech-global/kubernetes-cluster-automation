// cilium_init.go — sig15 cilium-init-stuck check (CiliumInitCheck):
// endpoints stuck in reserved:init while healthz stays green →
// latch + SIGKILL the agent (informer resync on restart).
package cilium

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// CiliumInitCheck — sig15: endpoints stuck in reserved:init
// while healthz stays green (informer wedge — every new pod gets a
// black-holed datapath). The shell ran `cilium-dbg endpoint list` via
// ctr exec; the agent reads the same data from the cilium agent unix
// socket (/v1/endpoint) — reserved:init counting is identical.
// Inconclusive (socket/exec fail) → keep counters, never reset.
// Fails is the consecutive stuck-endpoints streak (ex-Deps.
// CiliumInitFails) — tests poke it via the named Hygiene field.
type CiliumInitCheck struct {
	d     *wdeps.Deps
	Fails int
}

// Name returns the check label / WD_SIG key.
func (c *CiliumInitCheck) Name() string { return wdeps.CheckCiliumInit }

// Run executes one cilium-init-stuck round.
func (c *CiliumInitCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCiliumInit) {
		return
	}
	tasks, reachable := ciliumAgentTasks(c.d, e)
	if !reachable {
		c.d.CycleResult(wdeps.CheckCiliumInit, "abort")
		return
	}
	if len(tasks) == 0 {
		c.d.CycleResult(wdeps.CheckCiliumInit, "ok")
		return
	}
	body, err := c.d.Cfg.Seams.Cilium.UnixGet(ctx, c.d.Cfg.Cilium.Socket, "/v1/endpoint")
	if err != nil {
		// Endpoint list unreadable — inconclusive: don't count, don't
		// reset (shell: tasks exec fail → exit 0).
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck endpoint query on %s failed: %v — inconclusive, keeping state",
			c.d.Cfg.Cilium.Socket, err))
		c.d.CycleResult(wdeps.CheckCiliumInit, "abort")
		return
	}
	initEps := strings.Count(string(body), "reserved:init")
	if initEps == 0 {
		c.Fails = 0
		c.d.State.Exit(latchdefs.LatchCiliumInitStuck, nil)
		c.d.CycleResult(wdeps.CheckCiliumInit, "ok")
		return
	}
	if c.d.StreakPending(&c.Fails,
		fmt.Sprintf("suspect: cilium-init-stuck init_eps=%d", initEps)) {
		c.d.CycleResult(wdeps.CheckCiliumInit, "ok")
		return
	}
	// Wedge confirmed — latch before any gate like the shell.
	c.d.State.Enter(latchdefs.LatchCiliumInitStuck, fmt.Sprintf("init_eps=%d", initEps))
	switch {
	case !e.APIOK:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but API unreachable — skip kill (agent still cannot resync even after restart)",
			initEps, c.Fails))
	case c.d.State.Exists(latchdefs.LatchNodeOverloaded):
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but node overloaded — skip kill",
			initEps, c.Fails))
	case !c.d.State.RateTrySpend("last-cilium-restart", c.d.Cfg.MinRestartInterval):
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but restart cooldown — skip kill",
			initEps, c.Fails))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		if killCiliumAgent(c.d, tasks) {
			c.d.State.AppendLog(fmt.Sprintf(latchdefs.ActionCiliumAgentKill+
				" container - init_eps=%d %dx (kubelet will restart -> informer resync)",
				initEps, c.Fails))
			c.Fails = 0
			c.d.Actions.WithLabelValues(wdeps.CheckCiliumInit, "sigkill").Inc()
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cilium-init-stuck init_eps=%d %dx, no running task to kill (kubelet retries itself)",
				initEps, c.Fails))
		}
	}
	c.d.CycleResult(wdeps.CheckCiliumInit, "ok")
}

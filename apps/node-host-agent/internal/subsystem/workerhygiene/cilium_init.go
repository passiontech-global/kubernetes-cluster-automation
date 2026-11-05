// cilium_init.go — sig15 cilium-init-stuck check (ciliumInitCheck):
// endpoints stuck in reserved:init while healthz stays green →
// latch + SIGKILL the agent (informer resync on restart).
package workerhygiene

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// ciliumInitCheck — sig15: endpoints stuck in reserved:init
// while healthz stays green (informer wedge — every new pod gets a
// black-holed datapath). The shell ran `cilium-dbg endpoint list` via
// ctr exec; the agent reads the same data from the cilium agent unix
// socket (/v1/endpoint) — reserved:init counting is identical.
// Inconclusive (socket/exec fail) → keep counters, never reset. The
// streak stays on deps (ciliumInitFails) — pre-Check tests poke
// it directly.
type ciliumInitCheck struct{ d *deps }

// Name returns the check label / WD_SIG key.
func (c *ciliumInitCheck) Name() string { return checkCiliumInit }

// Run executes one cilium-init-stuck round.
func (c *ciliumInitCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.d.cycles.WithLabelValues(checkCiliumInit, "gated").Inc()
		return
	}
	tasks, reachable := c.d.ciliumAgentTasks()
	if !reachable {
		c.d.cycles.WithLabelValues(checkCiliumInit, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		c.d.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	body, err := c.d.cfg.Seams.unixGet(ctx, c.d.cfg.Cilium.Socket, "/v1/endpoint")
	if err != nil {
		// Endpoint list unreadable — inconclusive: don't count, don't
		// reset (shell: tasks exec fail → exit 0).
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck endpoint query on %s failed: %v — inconclusive, keeping state",
			c.d.cfg.Cilium.Socket, err))
		c.d.cycles.WithLabelValues(checkCiliumInit, "abort").Inc()
		return
	}
	initEps := strings.Count(string(body), "reserved:init")
	if initEps == 0 {
		c.d.ciliumInitFails = 0
		c.d.state.Exit(hoststate.LatchCiliumInitStuck, nil)
		c.d.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	c.d.ciliumInitFails++
	if c.d.ciliumInitFails < c.d.cfg.ConsecNeeded {
		c.d.state.AppendLog(fmt.Sprintf("suspect: cilium-init-stuck init_eps=%d (check %d/%d)",
			initEps, c.d.ciliumInitFails, c.d.cfg.ConsecNeeded))
		c.d.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	// Wedge confirmed — latch before any gate like the shell.
	c.d.state.Enter(hoststate.LatchCiliumInitStuck, fmt.Sprintf("init_eps=%d", initEps))
	switch {
	case !e.apiOK:
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but API unreachable — skip kill (agent still cannot resync even after restart)",
			initEps, c.d.ciliumInitFails))
	case c.d.state.Exists(hoststate.LatchNodeOverloaded):
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but node overloaded — skip kill",
			initEps, c.d.ciliumInitFails))
	case !c.d.state.RateTrySpend("last-cilium-restart", c.d.cfg.MinRestartInterval):
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but restart cooldown — skip kill",
			initEps, c.d.ciliumInitFails))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		if c.d.killCiliumAgent(tasks) {
			c.d.state.AppendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - init_eps=%d %dx (kubelet will restart -> informer resync)",
				initEps, c.d.ciliumInitFails))
			c.d.ciliumInitFails = 0
			c.d.actions.WithLabelValues(checkCiliumInit, "sigkill").Inc()
		} else {
			c.d.state.AppendLog(fmt.Sprintf(
				"suspect: cilium-init-stuck init_eps=%d %dx, no running task to kill (kubelet retries itself)",
				initEps, c.d.ciliumInitFails))
		}
	}
	c.d.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
}

// cilium_init.go — sig15 cilium-init-stuck check (ciliumInitCheck):
// endpoints stuck in reserved:init while healthz stays green →
// latch + SIGKILL the agent (informer resync on restart).
package workerhygiene

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
)

// ciliumInitCheck — sig15: endpoints stuck in reserved:init
// while healthz stays green (informer wedge — every new pod gets a
// black-holed datapath). The shell ran `cilium-dbg endpoint list` via
// ctr exec; the agent reads the same data from the cilium agent unix
// socket (/v1/endpoint) — reserved:init counting is identical.
// Inconclusive (socket/exec fail) → keep counters, never reset. The
// streak stays on Hygiene (ciliumInitFails) — pre-Check tests poke
// it directly.
type ciliumInitCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *ciliumInitCheck) Name() string { return checkCiliumInit }

// Run executes one cilium-init-stuck round.
func (c *ciliumInitCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumInit, "gated").Inc()
		return
	}
	tasks, reachable := c.h.ciliumAgentTasks()
	if !reachable {
		c.h.cycles.WithLabelValues(checkCiliumInit, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		c.h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	body, err := c.h.cfg.Seams.unixGet(ctx, c.h.cfg.Cilium.Socket, "/v1/endpoint")
	if err != nil {
		// Endpoint list unreadable — inconclusive: don't count, don't
		// reset (shell: tasks exec fail → exit 0).
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck endpoint query on %s failed: %v — inconclusive, keeping state",
			c.h.cfg.Cilium.Socket, err))
		c.h.cycles.WithLabelValues(checkCiliumInit, "abort").Inc()
		return
	}
	initEps := strings.Count(string(body), "reserved:init")
	if initEps == 0 {
		c.h.ciliumInitFails = 0
		c.h.state.Exit(hoststate.LatchCiliumInitStuck, nil)
		c.h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	c.h.ciliumInitFails++
	if c.h.ciliumInitFails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf("suspect: cilium-init-stuck init_eps=%d (check %d/%d)",
			initEps, c.h.ciliumInitFails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	// Wedge confirmed — latch before any gate like the shell.
	c.h.state.Enter(hoststate.LatchCiliumInitStuck, fmt.Sprintf("init_eps=%d", initEps))
	switch {
	case !e.apiOK:
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but API unreachable — skip kill (agent still cannot resync even after restart)",
			initEps, c.h.ciliumInitFails))
	case c.h.state.Exists(hoststate.LatchNodeOverloaded):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but node overloaded — skip kill",
			initEps, c.h.ciliumInitFails))
	case !c.h.state.RateTrySpend("last-cilium-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but restart cooldown — skip kill",
			initEps, c.h.ciliumInitFails))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		if c.h.killCiliumAgent(tasks) {
			c.h.state.AppendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - init_eps=%d %dx (kubelet will restart -> informer resync)",
				initEps, c.h.ciliumInitFails))
			c.h.ciliumInitFails = 0
			c.h.actions.WithLabelValues(checkCiliumInit, "sigkill").Inc()
		} else {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: cilium-init-stuck init_eps=%d %dx, no running task to kill (kubelet retries itself)",
				initEps, c.h.ciliumInitFails))
		}
	}
	c.h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
}

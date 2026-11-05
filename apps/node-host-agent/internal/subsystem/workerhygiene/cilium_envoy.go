// cilium_envoy.go — B1/W7-H3 cilium-envoy guard (ciliumEnvoyCheck):
// envoy admin /ready down or xDS update_rejected deltas climbing →
// latch + restart the envoy container — plus the healthz-subsystem
// walker and the /stats update_rejected parser it reads.
package workerhygiene

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// ciliumUnhealthySubsystems lists healthz subsystem paths whose
// state is neither Ok nor Disabled — nested maps are walked so
// {"cluster":{"cilium":{"state":"Failure"}}} resolves too.
func ciliumUnhealthySubsystems(body []byte) []string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	var bad []string
	var walk func(path string, n any)
	walk = func(path string, n any) {
		m, ok := n.(map[string]any)
		if !ok {
			return
		}
		if s, ok := m["state"].(string); ok && s != "Ok" && s != "Disabled" {
			bad = append(bad, path+"="+s)
		}
		for k, c := range m {
			child := k
			if path != "" {
				child = path + "." + k
			}
			walk(child, c)
		}
	}
	walk("", v)
	sort.Strings(bad)
	return bad
}

// ciliumEnvoyCheck is the B1/W7-H3 envoy guard as a Check. It owns
// the /ready fail streak and the xDS NACK bookkeeping
// (ex-Hygiene.envoyFails/.envoyXDS*). The ciliumAgentKilled flag
// stays on Hygiene — it's shared state: any of the cilium,
// cilium-init or wg-peers checks can set it through
// killCiliumAgent earlier in the same Cycle.
type ciliumEnvoyCheck struct {
	h        *Hygiene
	fails    int    // consecutive /ready fails (ConsecNeeded → kill)
	xdsInit  bool   // baseline update_rejected sum established
	xdsLast  uint64 // last-seen update_rejected sum
	xdsFails int    // consecutive cycles the sum grew
}

// Name returns the check label / WD_SIG key.
func (c *ciliumEnvoyCheck) Name() string { return checkCiliumEnvoy }

// Run executes one cilium-envoy round.
func (c *ciliumEnvoyCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "gated").Inc()
		return
	}
	tasks, reachable := c.h.ciliumNamedTasks("cilium-envoy")
	if !reachable {
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		// No cilium-envoy container — older cilium or no L7 proxy:
		// clear any stale latch like checkCilium does.
		c.fails = 0
		c.h.state.Exit(hoststate.LatchCiliumEnvoyDown, nil)
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	// 2.5: subsystem/datapath health off the agent socket is
	// evidence only — an unreadable socket must not block the envoy
	// verdict (the admin port is the primary signal).
	if body, err := c.h.cfg.Seams.unixGet(ctx, c.h.cfg.Cilium.Socket, "/v1/healthz"); err == nil {
		if bad := ciliumUnhealthySubsystems(body); len(bad) > 0 {
			c.h.state.AppendLog(
				"suspect: cilium subsystem health degraded: " +
					strings.Join(bad, ","))
		}
	}
	// Trigger 1: the agent was SIGKILLed this cycle — envoy may hold
	// the stale socket, restart it alongside (B1).
	if c.h.ciliumAgentKilled {
		c.killCiliumEnvoy(tasks, "cilium-agent restarted this cycle")
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	// W7-H3: xDS NACK guard — envoy can answer /ready=200 while
	// rejecting every config push (cds/lds/rds update_rejected
	// climbing → Gateway/Gateway API routes 404/503 while their API
	// objects report Accepted:True). Positive deltas for
	// ConsecNeeded consecutive cycles latch
	// state-cilium-envoy-xds-reject and restart envoy through the
	// same last-cilium-envoy-restart budget. Runs BEFORE the ready
	// probe's early-return so a green /ready can't hide the wedge.
	if reject, inconclusive := c.evalEnvoyXDS(ctx); inconclusive {
		// Stats page unreadable — inconclusive, keep the streak
		// (a dead envoy fails its own ready probe next).
	} else if reject {
		c.xdsFails++
	} else {
		c.xdsFails = 0
		c.h.state.Exit(hoststate.LatchCiliumEnvoyXDSReject, nil)
	}
	if c.xdsFails >= c.h.cfg.ConsecNeeded {
		c.h.state.Enter(hoststate.LatchCiliumEnvoyXDSReject,
			fmt.Sprintf("update_rejected=%d fails=%d",
				c.xdsLast, c.xdsFails))
		c.killCiliumEnvoy(tasks,
			fmt.Sprintf("xDS update_rejected deltas %d consecutive cycles",
				c.xdsFails))
	}
	code, err := c.h.cfg.Seams.probeHTTPStatus(ctx,
		c.h.cfg.Cilium.EnvoyReadyURL, "", ciliumProbeTime)
	if err == nil && code == http.StatusOK {
		c.fails = 0
		c.h.state.Exit(hoststate.LatchCiliumEnvoyDown, nil)
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-envoy-down ready probe code=%d err=%v (check %d/%d)",
			code, err, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	c.h.state.Enter(hoststate.LatchCiliumEnvoyDown,
		fmt.Sprintf("ready_probe_fails=%d", c.fails))
	c.killCiliumEnvoy(tasks,
		fmt.Sprintf("unready %d consecutive cycles", c.fails))
	c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
}

// checkCiliumEnvoy forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumEnvoy(ctx context.Context, workerActive bool) {
	h.ciliumEnvoy.Run(ctx, &cycleEnv{workerActive: workerActive})
}

// killCiliumEnvoy restarts the envoy container through its init
// pids — kubelet rebuilds it like the agent path. The dedicated
// budget keeps envoy kills from eating the agent's restart rate.
func (c *ciliumEnvoyCheck) killCiliumEnvoy(tasks []ctrTask, why string) {
	if !c.h.state.RateTrySpend("last-cilium-envoy-restart", c.h.cfg.MinRestartInterval) {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-envoy kill skipped (%s) — restart cooldown (<30m)", why))
		return
	}
	if c.h.killNamedTasks(tasks, "cilium-envoy") {
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION: killed cilium-envoy container - %s (kubelet will restart -> xDS resync)", why))
		c.fails = 0
		c.h.actions.WithLabelValues(checkCiliumEnvoy, "sigkill").Inc()
	} else {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-envoy kill skipped (%s) — no running task to kill", why))
	}
}

// parseEnvoyXDSRejected sums the cds/lds/rds update_rejected
// counters out of `envoy admin /stats?filter=update_rejected` —
// lines look like "cluster_manager.cds.update_rejected: 3". A stat
// counts toward the xDS NACK total when one dotted segment is
// cds/lds/rds AND the name ends in update_rejected.
func parseEnvoyXDSRejected(body []byte) uint64 {
	var total uint64
	for _, line := range strings.Split(string(body), "\n") {
		name, val, ok := strings.Cut(line, ":")
		if !ok || !strings.HasSuffix(strings.TrimSpace(name), "update_rejected") {
			continue
		}
		match := false
		for _, seg := range strings.Split(name, ".") {
			if seg == "cds" || seg == "lds" || seg == "rds" {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if v, err := strconv.ParseUint(strings.TrimSpace(val), 10, 64); err == nil {
			total += v
		}
	}
	return total
}

// evalEnvoyXDS fetches the envoy admin update_rejected page and
// reports whether the summed reject counters GREW since the last
// successful read — the delta is the wedge signal (a node can carry
// old rejects forever; only new NACKs mean pushes are failing now).
// The first successful read only establishes the baseline.
// inconclusive=true means the page could not be evaluated — the
// caller keeps the streak untouched (a dead envoy also fails its
// /ready probe and the B1 path owns that verdict).
func (c *ciliumEnvoyCheck) evalEnvoyXDS(ctx context.Context) (reject, inconclusive bool) {
	if c.h.cfg.Cilium.EnvoyAdminURL == "" {
		return false, true
	}
	body, err := c.h.cfg.Seams.httpGetBody(ctx, c.h.cfg.Cilium.EnvoyAdminURL, ciliumProbeTime)
	if err != nil {
		return false, true
	}
	total := parseEnvoyXDSRejected(body)
	if !c.xdsInit {
		c.xdsInit = true
		c.xdsLast = total
		return false, false
	}
	reject = total > c.xdsLast
	c.xdsLast = total
	return reject, false
}

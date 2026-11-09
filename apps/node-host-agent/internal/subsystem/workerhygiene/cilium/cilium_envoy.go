// cilium_envoy.go — B1/W7-H3 cilium-envoy guard (CiliumEnvoyCheck):
// envoy admin /ready down or xDS update_rejected deltas climbing →
// latch + restart the envoy container — plus the healthz-subsystem
// walker and the /stats update_rejected parser it reads.
package cilium

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
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

// CiliumEnvoyCheck is the B1/W7-H3 envoy guard as a Check. It owns
// the /ready fail streak and the xDS NACK bookkeeping
// (ex-Hygiene.envoyFails/.envoyXDS*). The ciliumAgentKilled flag
// stays on deps — it's shared state: any of the cilium,
// cilium-init or wg-peers checks can set it through
// killCiliumAgent earlier in the same Cycle.
type CiliumEnvoyCheck struct {
	d        *wdeps.Deps
	fails    int    // consecutive /ready fails (ConsecNeeded → kill)
	xdsInit  bool   // baseline update_rejected sum established
	xdsLast  uint64 // last-seen update_rejected sum
	xdsFails int    // consecutive cycles the sum grew
}

// Name returns the check label / WD_SIG key.
func (c *CiliumEnvoyCheck) Name() string { return wdeps.CheckCiliumEnvoy }

// Run executes one cilium-envoy round.
func (c *CiliumEnvoyCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCiliumEnvoy) {
		return
	}
	tasks, reachable := ciliumNamedTasks(c.d, e, "cilium-envoy")
	if !reachable {
		c.d.CycleResult(wdeps.CheckCiliumEnvoy, "abort")
		return
	}
	if len(tasks) == 0 {
		// No cilium-envoy container — older cilium or no L7 proxy:
		// clear any stale latch like wdeps.CheckCilium does. The xDS
		// bookkeeping resets too: the baseline sum belonged to a
		// container that no longer exists, and carrying it into the
		// next envoy's fresh counters would misread its first pushes
		// (xdsFails streak dies with the container either way).
		c.fails = 0
		c.xdsFails = 0
		c.xdsInit = false
		c.d.State.Exit(latchdefs.LatchCiliumEnvoyDown, nil)
		c.d.CycleResult(wdeps.CheckCiliumEnvoy, "ok")
		return
	}
	// 2.5: subsystem/datapath health off the agent socket is
	// evidence only — an unreadable socket must not block the envoy
	// verdict (the admin port is the primary signal).
	if body, err := c.d.Cfg.Seams.Cilium.UnixGet(ctx, c.d.Cfg.Cilium.Socket, "/v1/healthz"); err == nil {
		if bad := ciliumUnhealthySubsystems(body); len(bad) > 0 {
			c.d.State.AppendLog(
				"suspect: cilium subsystem health degraded: " +
					strings.Join(bad, ","))
		}
	}
	// Trigger 1: the agent was SIGKILLed this cycle — envoy may hold
	// the stale socket, restart it alongside (B1).
	if c.d.CiliumAgentKilled {
		c.killCiliumEnvoy(tasks, "cilium-agent restarted this cycle")
		c.d.CycleResult(wdeps.CheckCiliumEnvoy, "ok")
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
		c.d.State.Exit(latchdefs.LatchCiliumEnvoyXDSReject, nil)
	}
	if c.xdsFails >= c.d.Cfg.ConsecNeeded {
		c.d.State.Enter(latchdefs.LatchCiliumEnvoyXDSReject,
			fmt.Sprintf("update_rejected=%d fails=%d",
				c.xdsLast, c.xdsFails))
		c.killCiliumEnvoy(tasks,
			fmt.Sprintf("xDS update_rejected deltas %d consecutive cycles",
				c.xdsFails))
		// The kill just SIGKILLed envoy — fall through to the /ready
		// probe and it would probe the corpse, instantly burn a
		// /ready fail (and risk a second kill next cycle on a streak
		// the restart was meant to clear). The cycle ends here, same
		// shape as the agent-restart kill above.
		c.d.CycleResult(wdeps.CheckCiliumEnvoy, "ok")
		return
	}
	code, err := c.d.Cfg.Seams.Probe.ProbeHTTPStatus(ctx,
		c.d.Cfg.Cilium.EnvoyReadyURL, "", ciliumProbeTime)
	if err == nil && code == http.StatusOK {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchCiliumEnvoyDown, nil)
		c.d.CycleResult(wdeps.CheckCiliumEnvoy, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: cilium-envoy-down ready probe code=%d err=%v",
		code, err)) {
		c.d.CycleResult(wdeps.CheckCiliumEnvoy, "ok")
		return
	}
	c.d.State.Enter(latchdefs.LatchCiliumEnvoyDown,
		fmt.Sprintf("ready_probe_fails=%d", c.fails))
	c.killCiliumEnvoy(tasks,
		fmt.Sprintf("unready %d consecutive cycles", c.fails))
	c.d.CycleResult(wdeps.CheckCiliumEnvoy, "ok")
}

// killCiliumEnvoy restarts the envoy container through its init
// pids — kubelet rebuilds it like the agent path. The dedicated
// budget keeps envoy kills from eating the agent's restart rate.
// The xDS bookkeeping resets on a successful kill: the replacement
// envoy starts its update_rejected counters from zero, so the old
// baseline sum and streak must not leak into its first reads.
func (c *CiliumEnvoyCheck) killCiliumEnvoy(tasks []wdeps.CtrTask, why string) {
	if !c.d.State.RateTrySpend("last-cilium-envoy-restart", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-envoy kill skipped (%s) — restart cooldown (<30m)", why))
		return
	}
	if killNamedTasks(c.d, tasks, "cilium-envoy") {
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: killed cilium-envoy container - %s (kubelet will restart -> xDS resync)", why))
		c.fails = 0
		c.xdsFails = 0
		c.xdsInit = false
		c.d.Actions.WithLabelValues(wdeps.CheckCiliumEnvoy, "sigkill").Inc()
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"suspect: cilium-envoy kill skipped (%s) — no running task to kill", why))
}

// ParseEnvoyXDSRejected sums the cds/lds/rds update_rejected
// counters out of `envoy admin /stats?filter=update_rejected` —
// lines look like "cluster_manager.cds.update_rejected: 3". A stat
// counts toward the xDS NACK total when one dotted segment is
// cds/lds/rds AND the name ends in update_rejected.
func ParseEnvoyXDSRejected(body []byte) uint64 {
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
func (c *CiliumEnvoyCheck) evalEnvoyXDS(ctx context.Context) (reject, inconclusive bool) {
	if c.d.Cfg.Cilium.EnvoyAdminURL == "" {
		return false, true
	}
	body, err := c.d.Cfg.Seams.Probe.HTTPGetBody(ctx, c.d.Cfg.Cilium.EnvoyAdminURL, ciliumProbeTime)
	if err != nil {
		return false, true
	}
	total := ParseEnvoyXDSRejected(body)
	if !c.xdsInit {
		c.xdsInit = true
		c.xdsLast = total
		return false, false
	}
	reject = total > c.xdsLast
	c.xdsLast = total
	return reject, false
}

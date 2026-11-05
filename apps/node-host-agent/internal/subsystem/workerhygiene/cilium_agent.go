// cilium_agent.go — sig9 cilium-agent healthz check (ciliumCheck):
// :9879 healthz down → latch + SIGKILL the agent container — plus
// the W8-NM3 BPF map-pressure probe that rides inside it on a green
// healthz.
package workerhygiene

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

const (
	// defaultBPFMapHighRatio is the critical BPF map fill ratio
	// (W8-NM3) — past it the bpf-maps sub-check latches.
	defaultBPFMapHighRatio = 0.90
)

// ciliumCheck — sig9: cilium-agent :9879 healthz down → latch
// cilium-agent-down + SIGKILL the agent container (kubelet restarts
// it immediately, bypassing CrashLoopBackOff). Gates: apiOK (restart
// while the API is dead can't resync), node-overloaded, shared
// last-cilium-restart 30m budget. The W8-NM3 BPF map-pressure probe
// rides inside this check (checkBPFMaps) — it only runs on a green
// healthz, off the same agent socket. fails is the healthz streak
// (ex-Hygiene.ciliumFails).
type ciliumCheck struct {
	d     *deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *ciliumCheck) Name() string { return checkCilium }

// Run executes one cilium round.
func (c *ciliumCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.d.cycles.WithLabelValues(checkCilium, "gated").Inc()
		return
	}
	tasks, reachable := c.d.ciliumAgentTasks()
	if !reachable {
		// ctr unreachable → inconclusive, keep everything.
		c.d.cycles.WithLabelValues(checkCilium, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		// No cilium-agent container → this node runs no cilium
		// (calico cluster, hub): clear any false-positive state.
		c.fails = 0
		c.d.state.Exit(hoststate.LatchCiliumAgentDown, nil)
		c.d.cycles.WithLabelValues(checkCilium, "ok").Inc()
		return
	}
	err := c.d.probeHTTPSeries(ctx, c.d.cfg.Cilium.HealthzURL,
		probeAttempts, ciliumProbeTime, c.d.cfg.ProbeGap)
	if err == nil {
		c.fails = 0
		c.d.state.Exit(hoststate.LatchCiliumAgentDown, nil)
		// W8-NM3: a healthy healthz doesn't prove the datapath —
		// conntrack/SNAT/LB BPF maps can sit at capacity while the
		// agent still answers 200. Evaluate the map fill ratios on
		// the same agent socket.
		c.checkBPFMaps(ctx)
		c.d.cycles.WithLabelValues(checkCilium, "ok").Inc()
		return
	}
	c.d.state.Enter(hoststate.LatchCiliumAgentDown, "")
	c.fails++
	switch {
	case !e.apiOK:
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-agent-down healthz fail %dx but API unreachable — skip kill (agent still cannot sync even after restart)",
			c.fails))
	case c.fails >= c.d.cfg.ConsecNeeded &&
		!c.d.state.Exists(hoststate.LatchNodeOverloaded) &&
		c.d.state.RateTrySpend("last-cilium-restart", c.d.cfg.MinRestartInterval):
		// Budget spent atomically BEFORE acting (rate_spend
		// parity): a missed kill still consumed it — the feeder
		// goroutine competes for the same file.
		if c.d.killCiliumAgent(tasks) {
			c.d.state.AppendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - healthz down %dx (kubelet will restart)",
				c.fails))
			c.fails = 0
			c.d.actions.WithLabelValues(checkCilium, "sigkill").Inc()
		} else {
			c.d.state.AppendLog(fmt.Sprintf(
				"suspect: cilium-agent-down healthz fail %dx, no running task to kill (kubelet retries itself)",
				c.fails))
		}
	default:
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-agent-down healthz 127.0.0.1:9879 fail (check %d/%d)",
			c.fails, c.d.cfg.ConsecNeeded))
	}
	c.d.cycles.WithLabelValues(checkCilium, "ok").Inc()
}

// --- W8-NM3: cilium BPF map pressure ---
// The datapath dies silently long before the agent does: once the
// conntrack, SNAT or LB-service maps hit maxEntries, new flows are
// dropped/blackholed while :9879/healthz keeps returning 200. The
// check reads `GET /v1/map` off the agent socket and latches
// state-cilium-bpf-map-pressure when any critical map exceeds
// BPFMapHighRatio of its capacity — the latch is what NPD/NHC sees;
// no remedy is attempted (map growth needs a datapath
// restart/resize decision a node agent must not take alone).

// ciliumBPFMapCritical is the map set whose fill ratio gates the
// latch — the v4 conntrack pair, the SNAT pool and the v2 LB
// services map hit hard maxEntries first and each blackholes a
// different traffic class when full.
var ciliumBPFMapCritical = map[string]bool{
	"cilium_ct4_global":       true,
	"cilium_ct_any4_global":   true,
	"cilium_snat_v4_external": true,
	"cilium_lb4_services_v2":  true,
}

// parseCiliumBPFMaps extracts name → [used, max] from a /v1/map
// body. Wire shapes differ across agent versions: entries are
// objects carrying either "name" or "path" (the map name is the
// path basename), the used count arrives as a "used"/"entries"/
// "count" number or a "cache" array whose length is the live
// entries, and capacity as "size"/"max"/"maxSize"/"capacity". A map
// with no readable used+max pair is skipped — pressure can only be
// claimed on both numbers.
func parseCiliumBPFMaps(body []byte) map[string][2]int64 {
	var top any
	if json.Unmarshal(body, &top) != nil {
		return nil
	}
	numOf := func(m map[string]any, keys ...string) (int64, bool) {
		for _, k := range keys {
			if f, ok := m[k].(float64); ok {
				return int64(f), true
			}
		}
		return 0, false
	}
	out := map[string][2]int64{}
	var walk func(n any)
	walk = func(n any) {
		switch t := n.(type) {
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			name, _ := t["name"].(string)
			if name == "" {
				if p, _ := t["path"].(string); p != "" {
					name = filepath.Base(p)
				}
			}
			if name != "" && ciliumBPFMapCritical[name] {
				used, uok := numOf(t, "used", "entries", "count")
				if !uok {
					// Entry arrays carry the live count as their
					// length ("cache" on the /v1/map wire;
					// "entries" on some dumps).
					for _, k := range []string{"cache", "entries"} {
						if arr, ok := t[k].([]any); ok {
							used, uok = int64(len(arr)), true
							break
						}
					}
				}
				max, mok := numOf(t, "max", "maxSize", "max-size", "capacity", "size")
				if uok && mok && max > 0 {
					out[name] = [2]int64{used, max}
				}
			}
			// Map collections may be nested under "maps"/
			// "dynamicMaps"/"staticMaps" keys.
			for _, v := range t {
				walk(v)
			}
		}
	}
	walk(top)
	return out
}

// checkBPFMaps reads the map fill ratios off the agent socket
// and latches state-cilium-bpf-map-pressure when a critical map
// exceeds BPFMapHighRatio. An unreadable socket or unparseable body
// is inconclusive (the cilium checks' keep-state rule) — the latch
// is neither entered nor cleared on missing evidence.
func (c *ciliumCheck) checkBPFMaps(ctx context.Context) {
	body, err := c.d.cfg.Seams.unixGet(ctx, c.d.cfg.Cilium.Socket, "/v1/map")
	if err != nil {
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-bpf-maps map query on %s failed: %v — inconclusive, keeping state",
			c.d.cfg.Cilium.Socket, err))
		c.d.cycles.WithLabelValues(checkCiliumBPF, "abort").Inc()
		return
	}
	maps := parseCiliumBPFMaps(body)
	var over []string
	for name, um := range maps {
		if float64(um[0]) >= c.d.cfg.Cilium.BPFMapHighRatio*float64(um[1]) {
			over = append(over, fmt.Sprintf("%s=%d/%d", name, um[0], um[1]))
		}
	}
	if len(over) == 0 {
		c.d.state.Exit(hoststate.LatchCiliumBPFMapPressure, nil)
		c.d.cycles.WithLabelValues(checkCiliumBPF, "ok").Inc()
		return
	}
	sort.Strings(over)
	c.d.state.Enter(hoststate.LatchCiliumBPFMapPressure, strings.Join(over, " "))
	c.d.cycles.WithLabelValues(checkCiliumBPF, "ok").Inc()
}

// checkCiliumBPFMaps forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumBPFMaps(ctx context.Context) {
	h.cilium.checkBPFMaps(ctx)
}

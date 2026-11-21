// cilium_fqdn.go — #5A Cilium toFQDNs DNS-proxy & endpoint regeneration guard
// (detect-only): probes Cilium's Unix socket (/v1/fqdn/cache, /v1/endpoint)
// and local Prometheus metrics (:9962/metrics), sets node_agent_cilium_fqdn_pressure
// and emits a cooldown-gated Warning Event when waiting-to-regenerate > 0
// persists for >= 3 cycles or cilium_fqdn_gc_deletions_total surges with
// tofqdns pressure. Never restarts or kills cilium-agent.
package cilium

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	fqdnConsecNeeded         = 3
	fqdnGCDeletionSurgeDelta = 50.0
	fqdnEventCooldown        = 30 * time.Minute
	fqdnEventBudget          = "last-cilium-fqdn-event"
	fqdnEventReason          = "CiliumFQDNPressure"
)

// CiliumFQDNCheck detects Cilium endpoint regeneration stalls and
// toFQDNs GC deletion surges on the local node (detect-only).
type CiliumFQDNCheck struct {
	d         *wdeps.Deps
	fails     int
	prevGCDel float64
	gcDelSeen bool
}

// Name returns the check label / WD_SIG key.
func (c *CiliumFQDNCheck) Name() string { return wdeps.CheckCiliumFQDN }

// Run executes one cilium-fqdn round.
func (c *CiliumFQDNCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCiliumFQDN) {
		return
	}
	if ctx.Err() != nil {
		c.d.CycleResult(wdeps.CheckCiliumFQDN, "abort")
		return
	}
	tasks, reachable := ciliumAgentTasks(c.d, e)
	if !reachable {
		c.d.CycleResult(wdeps.CheckCiliumFQDN, "abort")
		return
	}
	if len(tasks) == 0 {
		c.fails = 0
		c.prevGCDel = 0
		c.gcDelSeen = false
		c.d.Series.CiliumFQDNPressure = 0
		c.d.CycleResult(wdeps.CheckCiliumFQDN, "ok")
		return
	}

	var (
		epOK           bool
		epWaiting      int
		fqdnCacheOK    bool
		hasFQDNEntries bool
	)
	if c.d.Cfg.Seams.Cilium.UnixGet != nil {
		if epBody, err := c.d.Cfg.Seams.Cilium.UnixGet(ctx, c.d.Cfg.Cilium.Socket, "/v1/endpoint"); err == nil {
			if eps, perr := ParseCiliumEndpoints(epBody); perr == nil {
				epOK = true
				for i := range eps {
					if strings.EqualFold(eps[i].TopState, "waiting-to-regenerate") ||
						strings.EqualFold(eps[i].State, "waiting-to-regenerate") {
						epWaiting++
					}
				}
			}
		}
		if cacheBody, err := c.d.Cfg.Seams.Cilium.UnixGet(ctx, c.d.Cfg.Cilium.Socket, "/v1/fqdn/cache"); err == nil {
			if entries, ok := parseFQDNCacheArray(cacheBody); ok {
				fqdnCacheOK = true
				hasFQDNEntries = entries > 0
			}
		}
	}

	var (
		metricsOK bool
		mSample   ciliumFQDNMetrics
	)
	if c.d.Cfg.Cilium.MetricsURL != "" && c.d.Cfg.Seams.Probe.HTTPGetBody != nil {
		if body, err := c.d.Cfg.Seams.Probe.HTTPGetBody(ctx, c.d.Cfg.Cilium.MetricsURL, ciliumProbeTime); err == nil {
			metricsOK = true
			mSample = parseCiliumFQDNMetrics(string(body))
		}
	}

	if ctx.Err() != nil {
		c.d.CycleResult(wdeps.CheckCiliumFQDN, "abort")
		return
	}
	if !epOK && !fqdnCacheOK && !metricsOK {
		c.d.CycleResult(wdeps.CheckCiliumFQDN, "abort")
		return
	}

	waitingToRegen := epWaiting
	if int(mSample.waitingToRegen) > waitingToRegen {
		waitingToRegen = int(mSample.waitingToRegen)
	}

	var gcDelta float64
	if mSample.hasGCDeletions {
		if c.gcDelSeen && mSample.gcDeletions >= c.prevGCDel {
			gcDelta = mSample.gcDeletions - c.prevGCDel
		}
		c.prevGCDel = mSample.gcDeletions
		c.gcDelSeen = true
	}

	tofqdnsPressure := hasFQDNEntries || waitingToRegen > 0 || mSample.hasFQDNPressure
	gcSurge := gcDelta >= fqdnGCDeletionSurgeDelta && tofqdnsPressure

	waitingConfirmed := false
	if waitingToRegen > 0 {
		if !checkkit.Pending(fqdnConsecNeeded, &c.fails,
			fmt.Sprintf("suspect: cilium-fqdn-pressure waiting_to_regenerate=%d fqdn_gc_del_delta=%.0f",
				waitingToRegen, gcDelta),
			c.d.State.AppendLog) {
			waitingConfirmed = true
		}
	} else {
		c.fails = 0
	}

	if !waitingConfirmed && !gcSurge {
		c.d.Series.CiliumFQDNPressure = 0
		c.d.CycleResult(wdeps.CheckCiliumFQDN, "ok")
		return
	}

	c.d.Series.CiliumFQDNPressure = 1
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: cilium-fqdn-pressure waiting_to_regenerate=%d fqdn_gc_del_delta=%.0f fails=%d (detect-only)",
		waitingToRegen, gcDelta, c.fails))
	if c.d.Cfg.Client != nil && c.d.State.RateTrySpend(fqdnEventBudget, fqdnEventCooldown) {
		now := c.d.Cfg.Seams.Host.Clock.Now()
		_ = c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
			Name:      fmt.Sprintf("%s.cilium-fqdn-pressure.%x", c.d.Cfg.NodeName, now.UnixNano()),
			Namespace: c.d.Cfg.Host.EventNamespace,
			Reason:    fqdnEventReason,
			Note: fmt.Sprintf(
				"Cilium toFQDNs / endpoint regeneration pressure detected (waiting_to_regenerate=%d, fqdn_gc_deletions_delta=%.0f)",
				waitingToRegen, gcDelta),
			When: now,
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Node",
				Name:       c.d.Cfg.NodeName,
			},
			Owner: "node " + c.d.Cfg.NodeName,
		})
	}
	c.d.CycleResult(wdeps.CheckCiliumFQDN, "ok")
}

// parseFQDNCacheArray reports the entry count when body is a JSON array
// (or JSON null -> 0, true), and (0, false) for non-array JSON / errors.
func parseFQDNCacheArray(body []byte) (int, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return 0, false
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return 0, true
	}
	var entries []any
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		return 0, false
	}
	return len(entries), true
}

type ciliumFQDNMetrics struct {
	waitingToRegen  float64
	gcDeletions     float64
	hasGCDeletions  bool
	hasFQDNPressure bool
}

func parseCiliumFQDNMetrics(body string) ciliumFQDNMetrics {
	var s ciliumFQDNMetrics
	for line := range strings.SplitSeq(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		var metricPart, valPart string
		if rb := strings.LastIndexByte(trimmed, '}'); rb >= 0 {
			metricPart = trimmed[:rb+1]
			fields := strings.Fields(trimmed[rb+1:])
			if len(fields) == 0 {
				continue
			}
			valPart = fields[0]
		} else {
			fields := strings.Fields(trimmed)
			if len(fields) < 2 {
				continue
			}
			metricPart = fields[0]
			valPart = fields[1]
		}
		v, err := strconv.ParseFloat(valPart, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		name := metricPart
		if lb := strings.IndexByte(name, '{'); lb >= 0 {
			name = name[:lb]
		}
		switch name {
		case "cilium_endpoint_state":
			if strings.Contains(metricPart, `endpoint_state="waiting-to-regenerate"`) {
				s.waitingToRegen += v
			}
		case "cilium_fqdn_gc_deletions_total":
			s.gcDeletions += v
			s.hasGCDeletions = true
		case "cilium_fqdn_active_names",
			"cilium_fqdn_alive_zombie_connections",
			"cilium_proxy_datapath_update_timeout_total":
			if v > 0 {
				s.hasFQDNPressure = true
			}
		}
	}
	return s
}

// cilium_agent.go — sig9 cilium-agent healthz check (CiliumCheck):
// :9879 healthz down → latch + SIGKILL the agent container — plus
// the mesh-net-guards BPF map-pressure probe that rides inside it on a green
// healthz.
package cilium

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"slices"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
// defaultBPFMapHighRatio is the critical BPF map fill ratio
// (mesh-net-guards) — past it the bpf-maps sub-check latches.
)

// CiliumCheck — sig9: cilium-agent :9879 healthz down → latch
// cilium-agent-down + SIGKILL the agent container (kubelet restarts
// it immediately, bypassing CrashLoopBackOff). Gates: apiOK (restart
// while the API is dead can't resync), node-overloaded, shared
// last-cilium-restart 30m budget. The mesh-net-guards BPF map-pressure probe
// rides inside this check (CheckBPFMaps) — it only runs on a green
// healthz, off the same agent socket. fails is the healthz streak
// (ex-Hygiene.ciliumFails).
type CiliumCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *CiliumCheck) Name() string { return wdeps.CheckCilium }

// Run executes one cilium round.
func (c *CiliumCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCilium) {
		return
	}
	tasks, reachable := ciliumAgentTasks(c.d, e)
	if !reachable {
		// ctr unreachable → inconclusive, keep everything.
		c.d.CycleResult(wdeps.CheckCilium, "abort")
		return
	}
	if len(tasks) == 0 {
		// No cilium-agent container → this node runs no cilium
		// (calico cluster, hub): clear any false-positive state.
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchCiliumAgentDown, nil)
		c.d.CycleResult(wdeps.CheckCilium, "ok")
		return
	}
	err := c.d.ProbeHTTPSeries(ctx, c.d.Cfg.Cilium.HealthzURL,
		wdeps.ProbeAttempts, ciliumProbeTime, c.d.Cfg.ProbeGap)
	if err == nil {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchCiliumAgentDown, nil)
		// mesh-net-guards: a healthy healthz doesn't prove the datapath —
		// conntrack/SNAT/LB BPF maps can sit at capacity while the
		// agent still answers 200. Evaluate the map fill ratios on
		// the same agent socket.
		if !c.d.Gated(e, wdeps.CheckCiliumBPF) {
			c.CheckBPFMaps(ctx)
		}
		c.d.CycleResult(wdeps.CheckCilium, "ok")
		return
	}
	c.d.State.Enter(latchdefs.LatchCiliumAgentDown, "")
	c.fails++
	switch {
	case !e.APIOK:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-agent-down healthz fail %dx but API unreachable — skip kill (agent still cannot sync even after restart)",
			c.fails))
	case c.fails >= c.d.Cfg.ConsecNeeded &&
		!c.d.State.Exists(latchdefs.LatchNodeOverloaded) &&
		c.d.HoldEmergencyHeal(ctx):
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-agent-down healthz fail %dx — emergency restart held by maintenance window, skip",
			c.fails))
	case c.fails >= c.d.Cfg.ConsecNeeded &&
		!c.d.State.Exists(latchdefs.LatchNodeOverloaded) &&
		c.d.State.RateTrySpend("last-cilium-restart", c.d.Cfg.MinRestartInterval):
		c.d.StampLocalRemediation(ctx)
		// Budget spent atomically BEFORE acting (rate_spend
		// parity): a missed kill still consumed it — the feeder
		// goroutine competes for the same file.
		if killCiliumAgent(c.d, tasks) {
			c.d.State.AppendLog(fmt.Sprintf(latchdefs.ActionCiliumAgentKill+
				" container - healthz down %dx (kubelet will restart)",
				c.fails))
			c.fails = 0
			c.d.Actions.WithLabelValues(wdeps.CheckCilium, "sigkill").Inc()
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cilium-agent-down healthz fail %dx, no running task to kill (kubelet retries itself)",
				c.fails))
		}
	default:
		c.d.State.AppendLog(
			"suspect: cilium-agent-down healthz 127.0.0.1:9879 fail" +
				checkkit.Progress(c.fails, c.d.Cfg.ConsecNeeded))
	}
	c.d.CycleResult(wdeps.CheckCilium, "ok")
}

// --- mesh-net-guards: cilium BPF map pressure ---
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
	// cilium-pod-map-pressure: per-pod endpoint/identity maps — exhaustion here
	// blackholes new pod datapath even when conntrack looks fine.
	"cilium_lxc": true,
}

// ParseCiliumBPFMaps extracts name → [used, max] from a /v1/map
// body. Wire shapes differ across agent versions: entries are
// objects carrying either "name" or "path" (the map name is the
// path basename), the used count arrives as a "used"/"entries"/
// "count" number or a "cache" array whose length is the live
// entries, and capacity as "size"/"max"/"maxSize"/"capacity". A map
// with no readable used+max pair is skipped — pressure can only be
// claimed on both numbers.
func ParseCiliumBPFMaps(body []byte) map[string][2]int64 {
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	tok, err := dec.ReadToken()
	if err != nil {
		return nil
	}
	out := map[string][2]int64{}
	if err := walkBPFMapsValue(dec, tok, out); err != nil {
		return nil
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return nil
	}
	return out
}

func jsonTokenInt64(tok jsontext.Token) (int64, error) {
	if tok.Kind() != '0' {
		return 0, fmt.Errorf("unexpected JSON token kind %v", tok.Kind())
	}
	if v, err := tok.Int(); err == nil {
		return v, nil
	}
	f, err := tok.Float()
	if err != nil {
		return 0, err
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("non-finite JSON number %v", f)
	}
	// 0x1p63 == float64(math.MaxInt64) because IEEE-754 float64 rounds
	// 2^63-1 up to 2^63; int64(0x1p63) wraps to math.MinInt64. Clamp
	// outside (-2^63, 2^63) so saturation never flips sign.
	const maxInt64Float = 0x1p63
	if f >= maxInt64Float {
		return math.MaxInt64, nil
	}
	if f <= -maxInt64Float {
		return math.MinInt64, nil
	}
	return int64(f), nil
}

func countJSONArray(dec *jsontext.Decoder) (int64, error) {
	var count int64
	for dec.PeekKind() != ']' {
		if err := dec.SkipValue(); err != nil {
			return 0, err
		}
		count++
	}
	if _, err := dec.ReadToken(); err != nil {
		return 0, err
	}
	return count, nil
}

func walkBPFMapsValue(dec *jsontext.Decoder, tok jsontext.Token, out map[string][2]int64) error {
	switch tok.Kind() {
	case '[':
		for dec.PeekKind() != ']' {
			elemTok, err := dec.ReadToken()
			if err != nil {
				return err
			}
			if err := walkBPFMapsValue(dec, elemTok, out); err != nil {
				return err
			}
		}
		_, err := dec.ReadToken()
		return err
	case '{':
		var name, path string
		var usedVal, entriesNumVal, countVal int64
		var hasUsed, hasEntriesNum, hasCount bool
		var cacheLen, entriesArrLen int64
		var hasCacheArr, hasEntriesArr bool
		var maxVal, maxSizeVal, maxDashVal, capVal, sizeVal int64
		var hasMax, hasMaxSize, hasMaxDash, hasCap, hasSize bool

		for dec.PeekKind() != '}' {
			keyTok, err := dec.ReadToken()
			if err != nil {
				return err
			}
			key := keyTok.String()
			valTok, err := dec.ReadToken()
			if err != nil {
				return err
			}
			switch valTok.Kind() {
			case '[':
				switch key {
				case "cache":
					n, err := countJSONArray(dec)
					if err != nil {
						return err
					}
					cacheLen, hasCacheArr = n, true
				case "entries":
					n, err := countJSONArray(dec)
					if err != nil {
						return err
					}
					entriesArrLen, hasEntriesArr = n, true
				default:
					if err := walkBPFMapsValue(dec, valTok, out); err != nil {
						return err
					}
				}
			case '{':
				if err := walkBPFMapsValue(dec, valTok, out); err != nil {
					return err
				}
			case '"':
				switch key {
				case "name":
					name = valTok.String()
				case "path":
					path = valTok.String()
				}
			case '0':
				n, err := jsonTokenInt64(valTok)
				if err != nil {
					return err
				}
				switch key {
				case "used":
					usedVal, hasUsed = n, true
				case "entries":
					entriesNumVal, hasEntriesNum = n, true
				case "count":
					countVal, hasCount = n, true
				case "max":
					maxVal, hasMax = n, true
				case "maxSize":
					maxSizeVal, hasMaxSize = n, true
				case "max-size":
					maxDashVal, hasMaxDash = n, true
				case "capacity":
					capVal, hasCap = n, true
				case "size":
					sizeVal, hasSize = n, true
				}
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		if name == "" && path != "" {
			name = filepath.Base(path)
		}
		if name != "" && ciliumBPFMapCritical[name] {
			var used int64
			var uok bool
			switch {
			case hasUsed:
				used, uok = usedVal, true
			case hasEntriesNum:
				used, uok = entriesNumVal, true
			case hasCount:
				used, uok = countVal, true
			case hasCacheArr:
				used, uok = cacheLen, true
			case hasEntriesArr:
				used, uok = entriesArrLen, true
			}
			var maxCap int64
			var mok bool
			switch {
			case hasMax:
				maxCap, mok = maxVal, true
			case hasMaxSize:
				maxCap, mok = maxSizeVal, true
			case hasMaxDash:
				maxCap, mok = maxDashVal, true
			case hasCap:
				maxCap, mok = capVal, true
			case hasSize:
				maxCap, mok = sizeVal, true
			}
			if uok && mok && maxCap > 0 {
				out[name] = [2]int64{used, maxCap}
			}
		}
		return nil
	default:
		if tok.Kind() == '0' {
			if _, err := jsonTokenInt64(tok); err != nil {
				return err
			}
		}
		return nil
	}
}

// CheckBPFMaps reads the map fill ratios off the agent socket
// and latches state-cilium-bpf-map-pressure when a critical map
// exceeds BPFMapHighRatio. An unreadable socket or unparseable body
// is inconclusive (the cilium checks' keep-state rule) — the latch
// is neither entered nor cleared on missing evidence.
func (c *CiliumCheck) CheckBPFMaps(ctx context.Context) {
	body, err := c.d.Cfg.Seams.Cilium.UnixGet(ctx, c.d.Cfg.Cilium.Socket, "/v1/map")
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-bpf-maps map query on %s failed: %v — inconclusive, keeping state",
			c.d.Cfg.Cilium.Socket, err))
		c.d.CycleResult(wdeps.CheckCiliumBPF, "abort")
		return
	}
	maps := ParseCiliumBPFMaps(body)
	if maps == nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-bpf-maps map query on %s returned unparseable JSON (%d bytes) — inconclusive, keeping state",
			c.d.Cfg.Cilium.Socket, len(body)))
		c.d.CycleResult(wdeps.CheckCiliumBPF, "abort")
		return
	}
	var over []string
	for name, um := range maps {
		if float64(um[0]) >= c.d.Cfg.Cilium.BPFMapHighRatio*float64(um[1]) {
			over = append(over, fmt.Sprintf("%s=%d/%d", name, um[0], um[1]))
		}
	}
	if len(over) == 0 {
		c.d.State.Exit(latchdefs.LatchCiliumBPFMapPressure, nil)
		c.d.CycleResult(wdeps.CheckCiliumBPF, "ok")
		return
	}
	slices.Sort(over)
	c.d.State.Enter(latchdefs.LatchCiliumBPFMapPressure, strings.Join(over, " "))
	c.d.CycleResult(wdeps.CheckCiliumBPF, "ok")
}

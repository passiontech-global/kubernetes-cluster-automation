// clockskew.go — clock-skew checkClockSkew: adjtimex first (a
// modes==0 read needs no fork), `chronyc tracking` only when the
// kernel discipline does NOT prove a stably synced clock →
// state-clock-skew (ClockSkewDetected) + a rate-limited
// `chronyc makestep`. The kernelfail contract overview lives in
// kernelfail.go.
package kernelfail

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// clockSkew thresholds (clock-skew): makestep fires above 0.5s or
// on "Not synchronised"; the latch needs >2.0s for 5 ticks.
const (
	clockSkewStepOffset  = 0.5
	clockSkewLatchOffset = 2.0
	clockSkewLatchNeeded = 5
	clockSkewMakestepGap = 10 * time.Minute
)

// Marker/state file names inside the watchdog state dir.
const (
	clockSkewCountFile     = "clock-skew-count"
	clockStepBudgetFile    = "last-clock-makestep"
	clockSteppedMarkerFile = "clock-stepped-at"
)

// --- clock-skew: clock skew ---

// clockSkewProbe returns (offsetSeconds, synchronized, ok). The
// adjtimex read goes FIRST — a modes==0 syscall needs no fork and
// no privilege, and a stably synced clock (sync bit set, offset
// inside the makestep band) needs no chronyc verdict at all: the
// fork is skipped outright on healthy nodes, which is every tick
// on a disciplined host. Anything else — unsynced, offset past the
// step threshold, or adjtimex failure — falls through to
// `chronyc tracking`, whose "System time" offset is the measured
// skew and "Leap status" the sync verdict; adjtimex's own numbers
// remain the last resort when chronyc is absent or unparseable
// (Timex.Offset µs is the kernel's offset estimate, STA_UNSYNC the
// sync verdict — enough to makestep and, past 2s, to latch).
func (r *Runner) clockSkewProbe(ctx context.Context) (float64, bool, bool) {
	var tx unix.Timex
	txOK := false
	if _, err := r.deps.Adjtimex(&tx); err == nil {
		txOK = true
		off := float64(tx.Offset) / 1e6
		if tx.Status&unix.STA_UNSYNC == 0 &&
			math.Abs(off) <= clockSkewStepOffset {
			return off, true, true
		}
	}
	out, err := r.deps.RunHostCmd(ctx, "chronyc", "tracking")
	if err == nil {
		if off, synced, ok := parseChronycTracking(out); ok {
			return off, synced, true
		}
	}
	if !txOK {
		return 0, false, false
	}
	return float64(tx.Offset) / 1e6,
		tx.Status&unix.STA_UNSYNC == 0, true
}

// chronycSystemTimeRe parses "System time     : 0.0012 seconds fast
// of NTP time" — signed seconds, fast positive.
var chronycSystemTimeRe = regexp.MustCompile(
	`System time\s*:\s*([0-9.]+)\s+seconds\s+(fast|slow)`)

// parseChronycTracking extracts offset + sync state; ok=false when
// the output lacks the expected fields (wrong chronyc version,
// partial capture).
func parseChronycTracking(out string) (float64, bool, bool) {
	var off float64
	found := false
	for ln := range strings.SplitSeq(out, "\n") {
		if m := chronycSystemTimeRe.FindStringSubmatch(ln); m != nil {
			v, err := strconv.ParseFloat(m[1], 64)
			if err != nil {
				continue
			}
			if m[2] == "slow" {
				v = -v
			}
			off, found = v, true
		}
	}
	if !found {
		return 0, false, false
	}
	synced := !strings.Contains(out, "Not synchronised")
	return off, synced, true
}

// checkClockSkew drives state-clock-skew (clock-skew →
// ClockSkewDetected): |offset| > 2.0s for clockSkewLatchNeeded
// consecutive ticks. A >0.5s offset OR an unsynchronised clock earns
// a `chronyc makestep` — rate-limited to one per 10m. Inconclusive
// probes (no chronyc, adjtimex failure) leave count+latch alone.
func (r *Runner) checkClockSkew(ctx context.Context) {
	off, synced, ok := r.clockSkewProbe(ctx)
	if !ok {
		return
	}
	if (!synced || math.Abs(off) > clockSkewStepOffset) &&
		r.deps.Store.RateTrySpend(clockStepBudgetFile, clockSkewMakestepGap) {
		out, err := r.deps.RunHostCmd(ctx, "chronyc", "makestep")
		if err != nil {
			logger().Warn("hostmetrics: chronyc makestep failed",
				"error", err, "out", strings.TrimSpace(out))
		} else {
			logger().Warn("hostmetrics: ACTION chronyc makestep — "+
				"clock offset beyond step threshold",
				"offset", off, "synced", synced)
			// clock-jump-session-healer marker: a stepped clock
			// breaks cached ServiceAccount tokens and TLS sessions
			// (konnectivity 401/x509 bursts right after a jump) —
			// the healer pairs fresh auth failures with this stamp.
			// Written on SUCCESS only: a failed makestep stepped
			// nothing and must not arm the correlation window.
			r.deps.Store.WriteEpochFile(
				r.statePath(clockSteppedMarkerFile), r.deps.Clock.Now().Unix())
		}
	}
	latchPath := r.deps.Store.Path(latchdefs.LatchClockSkew)
	if math.Abs(off) > clockSkewLatchOffset {
		// Store.Incr — the shared consecutive-counter core: locked
		// read+increment+write on the same <state dir>/clock-skew-count
		// file; absent/garbage content restarts the count at 1, a
		// failed write loses the streak (never invents one) and the
		// Store logs the failure.
		n := r.deps.Store.Incr(clockSkewCountFile)
		if n >= clockSkewLatchNeeded {
			r.ensureStateLatch(latchPath, latchdefs.LatchFilePrefix+latchdefs.LatchClockSkew,
				fmt.Sprintf("offset=%.3fs synced=%v", off, synced))
		}
		return
	}
	r.deps.Store.ResetCounter(clockSkewCountFile)
	// Exit self-gates on the file existing and logs STATE-EXIT.
	r.deps.Store.Exit(latchdefs.LatchClockSkew, nil)
}

// --- clock-warp: wall-clock jump detector (G5) ---

// clockWarpThreshold is the |elapsed_wall - expected_tick| budget —
// a VM pause / live-migration / suspend freezes the vCPU so the
// ticker fires LATE, and an NTP step can also make a tick fire
// early. 2.0s covers scheduler jitter without masking a real jump.
const clockWarpThreshold = 2 * time.Second

// clockWarpState is the detector's cross-tick baseline — the
// previous tick's wall-clock stamp and the cumulative warp counter
// the textfile exports.
type clockWarpState struct {
	prev   time.Time
	events int64
}

// checkClockWarp detects wall-clock jumps the NTP discipline never
// reports: a hypervisor pause or live-migration freezes the vCPU so
// the wall clock drifts ahead of the (equally frozen) monotonic
// clock, and an NTP step moves wall while monotonic stands still —
// the detector compares the two deltas per tick, so both shapes
// surface as warp without the tick cadence ever entering the math.
// On a warp it stamps clock-stepped-at (the same marker
// workerhygiene's clock-jump-session-healer correlates
// konnectivity 401/x509 bursts with), counts the event into
// node_agent_clock_warp_events_total, and lands an
// "ACTION clock-warp:" line in the watchdog log that nodereporter
// maps onto the NodeClockWarpDetected Kubernetes Event.
func (r *Runner) checkClockWarp() {
	now := r.deps.Clock.Now()
	prev := r.warp.prev
	r.warp.prev = now
	if !prev.IsZero() {
		delta := r.deps.warpDelta(now, prev)
		if math.Abs(float64(delta)) > float64(clockWarpThreshold) {
			r.warp.events++
			r.deps.Store.WriteEpochFile(
				r.statePath(clockSteppedMarkerFile), now.Unix())
			r.deps.Store.AppendLogWarn(fmt.Sprintf(
				latchdefs.ActionEntryPrefix(latchdefs.ActionClockWarp)+
					"delta=%.1fs tick=%s — VM pause / live-migration / NTP step suspected (events=%d)",
				delta.Seconds(), r.deps.TickInterval, r.warp.events))
		}
	}
	r.writeClockWarpProm()
}

// warpDelta is the wall-vs-monotonic gap between two tick stamps —
// the warp the NTP discipline never reports. now.Sub(prev) rides the
// monotonic reading when both stamps carry one — which freezes
// through a VM pause/suspend exactly like the ticker does, so a
// monotonic-only delta reads ~0 on the precise incident this
// detector exists for. Round(0) strips the monotonic reading (pure
// wall clock); the difference of the two deltas is the jump: a
// paused/migrated vCPU (wall jumps forward on resume) or an NTP step
// (wall ±step, monotonic untouched). When either stamp lacks a
// monotonic reading (a synthetic test clock, a value that crossed a
// serialization boundary) Sub falls back to wall for BOTH halves —
// the gap collapses to 0: a clock with no monotonic readings reports
// no warp rather than a false positive.
func warpDelta(now, prev time.Time) time.Duration {
	return now.Round(0).Sub(prev.Round(0)) - now.Sub(prev)
}

// writeClockWarpProm emits node_agent_clock_warp_events_total into
// the node-exporter textfile — every refresh, not only on a warp,
// so the series exists at 0 and post-restart scrapes keep a value.
func (r *Runner) writeClockWarpProm() {
	var b promfile.Builder
	b.HeaderType("node_agent_clock_warp_events_total",
		"Wall-clock jumps detected between latch ticks (VM pause, live-migration, NTP step) — kernel-net clock-warp detector.",
		"counter")
	b.Line(fmt.Sprintf("node_agent_clock_warp_events_total %d",
		r.warp.events))
	dir := r.textfileDir()
	_ = promfile.WriteLogged(dir, "node-agent-clockwarp.prom",
		[]byte(b.String()), func(dir, _ string, err error) {
			logger().Warn("hostmetrics: clock-warp textfile install failed",
				"dir", dir, "error", err)
		})
}

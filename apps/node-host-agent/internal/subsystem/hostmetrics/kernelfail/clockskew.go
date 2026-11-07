// clockskew.go — W10-KR5 checkClockSkew: chronyc tracking (adjtimex
// offset fallback) → state-clock-skew (ClockSkewDetected) + a
// rate-limited `chronyc makestep`. The Wave-10 contract overview
// lives in kernelfail.go.
package kernelfail

import (
	"context"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// clockSkew thresholds (W10-KR5): makestep fires above 0.5s or
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

// --- W10-KR5: clock skew ---

// clockSkewProbe returns (offsetSeconds, synchronized, ok). Primary
// source is `chronyc tracking` — its "System time" offset is the
// measured skew and "Leap status" the sync verdict. Fallback is a
// read-only adjtimex: Timex.Offset (µs) is the kernel's offset
// estimate and STA_UNSYNC the sync verdict — enough to makestep and
// (when the estimate exceeds 2s) to latch.
func (r *Runner) clockSkewProbe() (float64, bool, bool) {
	out, err := r.deps.RunHostCmd(context.Background(), "chronyc", "tracking")
	if err == nil {
		if off, synced, ok := parseChronycTracking(out); ok {
			return off, synced, true
		}
	}
	var tx unix.Timex
	if _, err := r.deps.Adjtimex(&tx); err != nil {
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
	for _, ln := range strings.Split(out, "\n") {
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

// checkClockSkew drives state-clock-skew (W10-KR5 →
// ClockSkewDetected): |offset| > 2.0s for clockSkewLatchNeeded
// consecutive ticks. A >0.5s offset OR an unsynchronised clock earns
// a `chronyc makestep` — rate-limited to one per 10m. Inconclusive
// probes (no chronyc, adjtimex failure) leave count+latch alone.
func (r *Runner) checkClockSkew() {
	off, synced, ok := r.clockSkewProbe()
	if !ok {
		return
	}
	if (!synced || math.Abs(off) > clockSkewStepOffset) &&
		r.deps.Store.RateTrySpend(clockStepBudgetFile, clockSkewMakestepGap) {
		out, err := r.deps.RunHostCmd(context.Background(), "chronyc", "makestep")
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
	countPath := r.statePath(clockSkewCountFile)
	latchPath := r.deps.Store.Path(hoststate.LatchClockSkew)
	if math.Abs(off) > clockSkewLatchOffset {
		n := int64(1)
		if b, err := os.ReadFile(countPath); err == nil {
			if v, perr := strconv.ParseInt(
				strings.TrimSpace(string(b)), 10, 64); perr == nil {
				n = v + 1
			}
		}
		if err := os.WriteFile(countPath,
			[]byte(strconv.FormatInt(n, 10)+"\n"), 0o644); err != nil {
			logger().Debug("hostmetrics: clock-skew count write failed",
				"path", countPath, "error", err)
		}
		if n >= clockSkewLatchNeeded {
			r.ensureStateLatch(latchPath, hoststate.LatchFilePrefix+hoststate.LatchClockSkew,
				fmt.Sprintf("offset=%.3fs synced=%v", off, synced))
		}
		return
	}
	_ = os.Remove(countPath)
	// Exit self-gates on the file existing and logs STATE-EXIT.
	r.deps.Store.Exit(hoststate.LatchClockSkew, nil)
}

// clockskew.go — W10-KR5 checkClockSkew: chronyc tracking (adjtimex
// offset fallback) → state-clock-skew (ClockSkewDetected) + a
// rate-limited `chronyc makestep`. The Wave-10 contract overview
// lives in wave10.go.
package hostmetrics

import (
	"context"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
	"golang.org/x/sys/unix"
)

// clockSkew thresholds (W10-KR5): makestep fires above 0.5s or
// on "Not synchronised"; the latch needs >2.0s for 5 ticks.
const (
	clockSkewStepOffset  = 0.5
	clockSkewLatchOffset = 2.0
	clockSkewLatchNeeded = 5
	clockSkewMakestepGap = 10 * time.Minute
)

// Marker/state file names inside WatchdogStateDir.
const (
	clockSkewCountFile  = "clock-skew-count"
	clockStepBudgetFile = "last-clock-makestep"
)

// --- W10-KR5: clock skew ---

// clockSkewProbe returns (offsetSeconds, synchronized, ok). Primary
// source is `chronyc tracking` — its "System time" offset is the
// measured skew and "Leap status" the sync verdict. Fallback is a
// read-only adjtimex: Timex.Offset (µs) is the kernel's offset
// estimate and STA_UNSYNC the sync verdict — enough to makestep and
// (when the estimate exceeds 2s) to latch.
func (l *Latches) clockSkewProbe() (float64, bool, bool) {
	out, err := runHostCmd(context.Background(), "chronyc", "tracking")
	if err == nil {
		if off, synced, ok := parseChronycTracking(out); ok {
			return off, synced, true
		}
	}
	var tx unix.Timex
	if _, err := l.c.cfg.adjtimexFn(&tx); err != nil {
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
func (l *Latches) checkClockSkew() {
	off, synced, ok := l.clockSkewProbe()
	if !ok {
		return
	}
	if (!synced || math.Abs(off) > clockSkewStepOffset) &&
		l.c.state.RateTrySpend(clockStepBudgetFile, clockSkewMakestepGap) {
		out, err := runHostCmd(context.Background(), "chronyc", "makestep")
		if err != nil {
			logger().Warn("hostmetrics: chronyc makestep failed",
				"error", err, "out", strings.TrimSpace(out))
		} else {
			logger().Warn("hostmetrics: ACTION chronyc makestep — "+
				"clock offset beyond step threshold",
				"offset", off, "synced", synced)
		}
	}
	countPath := l.statePath(clockSkewCountFile)
	latchPath := l.c.state.Path(hoststate.LatchClockSkew)
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
			l.ensureStateLatch(latchPath, hoststate.LatchFilePrefix+hoststate.LatchClockSkew,
				fmt.Sprintf("offset=%.3fs synced=%v", off, synced))
		}
		return
	}
	_ = os.Remove(countPath)
	if _, err := os.Stat(latchPath); err == nil {
		if rerr := os.Remove(latchPath); rerr != nil {
			logger().Warn("hostmetrics: clock-skew latch remove failed",
				"path", latchPath, "error", rerr)
		} else {
			logger().Info("hostmetrics: clock-skew latch cleared",
				"offset", off, "path", latchPath)
		}
	}
}

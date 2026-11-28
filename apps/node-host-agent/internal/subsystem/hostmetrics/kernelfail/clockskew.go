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
	"os"
	"os/exec"
	"path/filepath"
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
// hostHasBinary reports whether the host mount namespace actually ships a
// given binary (e.g. chronyc or timedatectl). Checking host presence avoids
// unconditional exit-127 forks on nodes that don't install the tool.
func (r *Runner) hostHasBinary(name string) bool {
	if r.deps.HostRoot == "/" {
		_, err := exec.LookPath(name)
		return err == nil
	}
	root := strings.TrimRight(r.deps.HostRoot, "/")
	if root == "" {
		// Matches hostexec.DefaultHostRoot when HostRoot is left empty.
		root = "/host"
	}
	for _, rel := range []string{
		filepath.Join("usr", "bin", name),
		filepath.Join("usr", "sbin", name),
		filepath.Join("bin", name),
		filepath.Join("sbin", name),
		filepath.Join("usr", "local", "bin", name),
	} {
		if fi, err := os.Stat(filepath.Join(root, rel)); err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

// hostHasChronyc reports whether the host mount namespace actually ships a
// chronyc binary. Hosts running systemd-timesyncd (the default on cluster
// nodes) do not install chrony, so probing/stepping with chronyc would
// unconditionally fail with exit 127 ("No such file or directory").
func (r *Runner) hostHasChronyc() bool {
	return r.hostHasBinary("chronyc")
}

// hostHasTimedatectl reports whether the host mount namespace ships
// timedatectl for probing systemd-timesyncd status.
func (r *Runner) hostHasTimedatectl() bool {
	return r.hostHasBinary("timedatectl")
}

// timexOffsetSeconds converts unix.Timex.Offset to seconds. Per Linux
// adjtimex(2), Offset is in nanoseconds when STA_NANO is set in Status
// (systemd-timesyncd sets ADJ_NANO on modern kernels) and microseconds
// otherwise. Dividing a STA_NANO offset by 1e6 inflates normal sub-50ms
// jitter by 1,000x into fake multi-second clock skew and causes periodic
// systemd-timesyncd restarts every 10 minutes.
func timexOffsetSeconds(tx *unix.Timex) float64 {
	if tx.Status&unix.STA_NANO != 0 {
		return float64(tx.Offset) / 1e9
	}
	return float64(tx.Offset) / 1e6
}

// probeTimesyncdOffset queries `timedatectl timesync-status` via the host
// command transport to detect silent systemd-timesyncd stalls (where the
// kernel's adjtimex STA_UNSYNC stays 0 and Offset decays near 0 even though
// timesyncd has a large measured offset, lost its Server, or received 0
// packets). Returns ok=false when timedatectl is absent, errors out, or
// produces unparseable output so callers safely fall back to adjtimex.
func (r *Runner) probeTimesyncdOffset(ctx context.Context) (float64, bool, bool) {
	if !r.hostHasTimedatectl() {
		return 0, false, false
	}
	out, err := r.deps.RunHostCmd(ctx, "timedatectl", "timesync-status")
	if err != nil {
		return 0, false, false
	}
	return parseTimesyncStatusOffset(out)
}

func (r *Runner) clockSkewProbe(ctx context.Context) (float64, bool, bool) {
	var tx unix.Timex
	txOK := false
	var txOff float64
	var txSynced bool
	if _, err := r.deps.Adjtimex(&tx); err == nil {
		txOK = true
		txOff = timexOffsetSeconds(&tx)
		txSynced = tx.Status&unix.STA_UNSYNC == 0
	}
	hasChronyc := r.hostHasChronyc()
	if txOK && txSynced && math.Abs(txOff) <= clockSkewStepOffset {
		if hasChronyc {
			return txOff, true, true
		}
		// Without chronyc, systemd-timesyncd can silently stall under CPU
		// steal while adjtimex still reports STA_UNSYNC==0 and a tiny offset.
		// Cross-check timedatectl timesync-status when available.
		if tsOff, tsSynced, tsOK := r.probeTimesyncdOffset(ctx); tsOK {
			off := txOff
			if math.Abs(tsOff) > math.Abs(txOff) {
				off = tsOff
			}
			return off, txSynced && tsSynced, true
		}
		return txOff, true, true
	}
	if hasChronyc {
		out, err := r.deps.RunHostCmd(ctx, "chronyc", "tracking")
		if err == nil {
			if off, synced, ok := parseChronycTracking(out); ok {
				return off, synced, true
			}
		}
	}
	// Chronyc absent or failed — consult timedatectl timesync-status before
	// falling back to raw adjtimex.
	if tsOff, tsSynced, tsOK := r.probeTimesyncdOffset(ctx); tsOK {
		if !txOK {
			return tsOff, tsSynced, true
		}
		off := txOff
		if math.Abs(tsOff) > math.Abs(txOff) {
			off = tsOff
		}
		return off, txSynced && tsSynced, true
	}
	if !txOK {
		return 0, false, false
	}
	return txOff, txSynced, true
}

// timesyncDurationTokenRe matches one token of systemd's format_timespan
// output (e.g. "1.238ms", "40.430ms", "7.803s", "500us", "2min", "1h", "1d").
var timesyncDurationTokenRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(min|ms|us|µs|μs|s|h|d)$`)

// parseTimesyncDuration parses a signed systemd timespan string such as
// "+1.238ms", "-40.430ms", "-7.803s", "+500us", "-2min", or compound spans
// like "-1min 7.803s" into signed seconds.
func parseTimesyncDuration(raw string) (float64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	sign := 1.0
	switch s[0] {
	case '+':
		s = strings.TrimSpace(s[1:])
	case '-':
		sign = -1.0
		s = strings.TrimSpace(s[1:])
	}
	if s == "" {
		return 0, false
	}
	if s == "0" {
		return 0, true
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, false
	}
	var total float64
	for _, tok := range fields {
		m := timesyncDurationTokenRe.FindStringSubmatch(tok)
		if m == nil {
			return 0, false
		}
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		switch m[2] {
		case "us", "µs", "μs":
			total += v * 1e-6
		case "ms":
			total += v * 1e-3
		case "s":
			total += v
		case "min":
			total += v * 60
		case "h":
			total += v * 3600
		case "d":
			total += v * 86400
		}
	}
	return sign * total, true
}

// parseTimesyncStatusOffset extracts (offsetSeconds, synced, ok) from
// `timedatectl timesync-status` output.
//   - Offset: signed seconds parsed from the `Offset:` line (us/ms/s/min/h/d).
//   - synced: false whenever `Server:` is missing/empty/n/a/(null) OR
//     `Packet count:` is 0 (silent timesyncd stall indicators).
//   - ok: false on empty/garbage output or when status claims synced without
//     a parseable `Offset:` line.
func parseTimesyncStatusOffset(out string) (float64, bool, bool) {
	var (
		off             float64
		hasOffset       bool
		sawOffsetLine   bool
		sawStatus       bool
		serverOK        bool
		packetCountZero bool
	)
	for ln := range strings.SplitSeq(out, "\n") {
		key, val, found := strings.Cut(strings.TrimSpace(ln), ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "Server":
			sawStatus = true
			lower := strings.ToLower(val)
			if val != "" && lower != "n/a" && lower != "(null)" && lower != "none" {
				serverOK = true
			}
		case "Packet count":
			sawStatus = true
			if n, err := strconv.ParseInt(val, 10, 64); err == nil && n == 0 {
				packetCountZero = true
			}
		case "Poll interval":
			sawStatus = true
		case "Offset":
			sawOffsetLine = true
			if v, ok := parseTimesyncDuration(val); ok {
				off = v
				hasOffset = true
				sawStatus = true
			}
		}
	}
	if !sawStatus {
		return 0, false, false
	}
	synced := serverOK && !packetCountZero
	if sawOffsetLine && !hasOffset && synced {
		return 0, false, false
	}
	if !hasOffset && synced {
		return 0, false, false
	}
	return off, synced, true
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
		var (
			out         string
			err         error
			triedChrony bool
		)
		if r.hostHasChronyc() {
			triedChrony = true
			out, err = r.deps.RunHostCmd(ctx, "chronyc", "makestep")
		}
		if !triedChrony || err != nil {
			// On hosts running systemd-timesyncd instead of chrony,
			// chronyc is absent or fails — fall back to restarting
			// systemd-timesyncd ONLY when it is active or enabled so we
			// never start a dormant timesyncd alongside chrony.
			// Prefer systemd.Client (D-Bus) over forking 3 nsenter
			// systemctl processes when available.
			const timesyncdUnit = "systemd-timesyncd.service"
			var (
				timesyncdManaged bool
				rout             string
				rerr             error
			)
			if r.deps.Systemd != nil {
				act, aerr := r.deps.Systemd.Active(ctx, timesyncdUnit)
				timesyncdManaged = aerr == nil && act
				if !timesyncdManaged {
					en, eerr := r.deps.Systemd.Enabled(ctx, timesyncdUnit)
					timesyncdManaged = eerr == nil && en
				}
				if timesyncdManaged {
					rerr = r.deps.Systemd.Restart(ctx, timesyncdUnit)
				}
			} else {
				_, actErr := r.deps.RunHostCmd(ctx, "systemctl", "is-active", "--quiet", "systemd-timesyncd")
				timesyncdManaged = actErr == nil
				if !timesyncdManaged {
					_, enErr := r.deps.RunHostCmd(ctx, "systemctl", "is-enabled", "--quiet", "systemd-timesyncd")
					timesyncdManaged = enErr == nil
				}
				if timesyncdManaged {
					rout, rerr = r.deps.RunHostCmd(ctx, "systemctl", "restart", "systemd-timesyncd")
				}
			}
			if timesyncdManaged {
				if rerr != nil {
					attrs := []any{
						"triedChronyc", triedChrony,
						"restartError", rerr, "restartOut", strings.TrimSpace(rout),
					}
					if triedChrony {
						attrs = append(attrs, "chronycError", err, "chronycOut", strings.TrimSpace(out))
					}
					logger().Warn("hostmetrics: systemd-timesyncd restart failed", attrs...)
				} else {
					attrs := []any{
						"offset", off, "synced", synced,
						"triedChronyc", triedChrony,
					}
					if triedChrony {
						attrs = append(attrs, "chronycError", err)
					}
					logger().Warn("hostmetrics: ACTION systemctl restart systemd-timesyncd — "+
						"clock offset beyond step threshold", attrs...)
					r.deps.Store.WriteEpochFile(
						r.statePath(clockSteppedMarkerFile), r.deps.Clock.Now().Unix())
				}
			} else if triedChrony {
				logger().Warn("hostmetrics: chronyc makestep failed",
					"error", err, "out", strings.TrimSpace(out))
			} else {
				logger().Warn("hostmetrics: clock offset beyond step threshold — neither chronyc nor systemd-timesyncd available",
					"offset", off, "synced", synced)
			}
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

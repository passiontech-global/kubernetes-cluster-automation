// kubelet_syncloop.go — the A4 PLEG probes the :10250 healthz check
// cannot see: /healthz/syncloop (kubelet sync-loop freeze) and the
// containerd unix socket hang check, plus the SA bearer reader the
// authenticated kubelet probes share.
package kubelet

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// A4 (PLEG/containerd probes) wiring defaults — same /host mount
// convention as the other seams.
const (
	unixSockProbeTimeout = 5 * time.Second
	// plegRelistHighSec is the kubelet_pleg_relist_duration_seconds
	// threshold — a per-scrape avg (Δsum/Δcount), a summary
	// quantile, or new >5s relists in the histogram tail above it
	// means the PLEG relist itself is degrading.
	plegRelistHighSec = 5.0
	// plegLastSeenHighSec is the age of the
	// kubelet_pleg_last_seen_seconds TIMESTAMP above which PLEG has
	// stopped observing state changes at all — the metric is the
	// wall-clock instant PLEG was last active, not a lag.
	plegLastSeenHighSec = 30.0
)

// --- Check: kubelet syncloop / containerd socket (A4) ---
// 05's :10250 /healthz probe can stay green through a PLEG freeze —
// kubelet exposes /healthz/syncloop specifically for the sync loop
// (returns 500 the moment PLEG dies). The containerd unix socket is
// the other half: a hung containerd wedges PLEG while every HTTP
// endpoint still answers. Both latches now self-heal (BUG-H4): at
// ConsecNeeded fails they run the shared k0sworker restart gates
// (overload / settle / last-restart budget) instead of waiting for
// 05/T15 to notice.

// SyncloopCheck is the A4 PLEG probe as a Check; it owns the
// consecutive-fail streak and the unauth-logged flag (ex-Hygiene
// .syncloopFails/.syncloopUnauth), plus the PLEG-metrics early
// warning streak (plegFails/prevDiscard): the /metrics relist and
// last-seen series degrade a full cycle before /healthz/syncloop
// ever answers 500, so the metrics half latches
// state-kubelet-pleg-unhealthy for nodereporter's
// KubeletPLEGUnhealthy condition while the sync loop still replies.
type SyncloopCheck struct {
	d           *wdeps.Deps
	fails       int
	unauth      bool    // last probe was 401/403 — log the streak once
	plegFails   int     // consecutive over-threshold PLEG metric cycles
	prevDiscard int64   // last kubelet_pleg_discard_events read
	discardSeen bool    // prevDiscard holds a real baseline
	prevSum     float64 // last relist_duration_seconds_sum read
	prevCount   float64 // last relist_duration_seconds_count read
	prevFast    float64 // last fast-relist cumulative count read
	relistSeen  bool    // prev*/prevFast hold a real baseline
}

// Name returns the check label / WD_SIG key.
func (c *SyncloopCheck) Name() string { return wdeps.CheckSyncloop }

// Run executes one kubelet-syncloop round.
func (c *SyncloopCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckSyncloop) {
		return
	}
	// The /metrics PLEG series degrade before /healthz/syncloop ever
	// answers 500 — run the early-warning scrape every cycle,
	// independent of the syncloop verdict below.
	c.probePLEG(ctx)
	var lastErr error
	alive := false
	unauth := false
	// The bearer token is re-read every cycle — the file is small
	// and bound SA tokens rotate.
	bearer := kubeletBearer(c.d)
	for i := 0; i < wdeps.ProbeAttempts; i++ {
		code, err := c.d.Cfg.Seams.Probe.ProbeHTTPStatus(ctx,
			c.d.Cfg.Kubelet.SyncloopURL, bearer, wdeps.ProbeTimeout)
		if err == nil {
			switch {
			case code == http.StatusOK:
				alive = true
			case code == http.StatusUnauthorized || code == http.StatusForbidden:
				// Kubelet answered but won't divulge the verdict —
				// retrying the same credentials won't help.
				unauth = true
			default:
				lastErr = fmt.Errorf("syncloop status %d", code)
			}
		} else {
			lastErr = err
		}
		if alive || unauth {
			break
		}
		if i+1 < wdeps.ProbeAttempts {
			select {
			case <-ctx.Done():
				c.d.CycleResult(wdeps.CheckSyncloop, "abort")
				return
			case <-time.After(c.d.Cfg.ProbeGap):
			}
		}
	}
	if unauth {
		// The verdict is unknowable without working credentials —
		// inconclusive like the other keep-state paths, NOT a down
		// signal. Logged once per unauth streak so a permanently
		// unauthenticated deployment doesn't spam every cycle.
		if !c.unauth {
			c.d.State.AppendLog("suspect: kubelet-syncloop-down probe unauthorized " +
				"(401/403 — token missing or RBAC nonResourceURL /healthz/* not " +
				"granted) — inconclusive, keeping state")
			c.unauth = true
		}
		c.d.CycleResult(wdeps.CheckSyncloop, "inconclusive")
		return
	}
	c.unauth = false
	if alive {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchKubeletSyncloopDown, nil)
		c.d.CycleResult(wdeps.CheckSyncloop, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: kubelet-syncloop-down /healthz/syncloop fail (PLEG?) err=%v",
		lastErr)) {
		c.d.CycleResult(wdeps.CheckSyncloop, "ok")
		return
	}
	// BUG-H4: a frozen PLEG is a kubelet stall the 05 probe can't
	// see — confirmed consecutive fails now self-heal through the
	// shared k0sworker restart gates (overload / settle /
	// last-restart budget), checkKubeletStall parity.
	overloaded := c.d.State.Exists(latchdefs.LatchNodeOverloaded)
	if !overloaded {
		c.d.State.Enter(latchdefs.LatchKubeletSyncloopDown,
			fmt.Sprintf("pleg-frozen last_err=%v", lastErr))
	} else if !c.d.State.Exists(latchdefs.LatchKubeletSyncloopDown) {
		// A stall under CPU starvation is a symptom — latching
		// would escalate to NHC→SNR and dump 100% of the load
		// onto the survivors (amplifier). Log-only.
		c.d.State.AppendLog(fmt.Sprintf(
			"kubelet-syncloop-down suppressed-overloaded - pleg-frozen last_err=%v", lastErr))
	}
	switch {
	case overloaded:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down - node overloaded, skip restart k0sworker (err=%v)", lastErr))
	case !k0sWorkerSettled(c.d, ctx):
		c.d.State.AppendLog("suspect: kubelet-syncloop-down - k0sworker not settled (<180s), skip restart")
	case c.d.HoldLocalAction(ctx):
		// L1↔L3 maintenance hold — BEFORE the budget spend so a held
		// restart never burns the shared last-restart cooldown.
		c.d.State.AppendLog("suspect: kubelet-syncloop-down - cluster maintenance in progress, skip restart k0sworker")
	case !c.d.State.RateTrySpend("last-restart", c.d.Cfg.MinRestartInterval):
		c.d.State.AppendLog("suspect: kubelet-syncloop-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		c.d.State.AppendLog(fmt.Sprintf(latchdefs.ActionK0sworkerRestart+
			" - kubelet-syncloop-down pleg-frozen (persisted %dx)",
			c.fails))
		c.fails = 0
		if err := restartK0sWorker(c.d, ctx); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.d.Actions.WithLabelValues(wdeps.CheckSyncloop, "restart").Inc()
		}
	}
	c.d.CycleResult(wdeps.CheckSyncloop, "ok")
}

// --- PLEG relist-latency early warning (kubelet /metrics) ---
// kubelet_pleg_relist_duration_seconds (a summary on older kubelets,
// a histogram on newer — _bucket/_sum/_count),
// kubelet_pleg_last_seen_seconds (gauge carrying the Unix TIMESTAMP
// PLEG was last active — not an age) and kubelet_pleg_discard_events
// (counter) tell the PLEG-health story a full cycle before
// /healthz/syncloop dies: a recent relist avg >5s, any new relist
// slower than 5s, or a last-seen stamp >30s old means the relist
// loop is starving. The scrape goes through the KubeletMetricsFn
// seam — same :10250 listener and SA bearer as the healthz probe. A
// scrape error or a body without PLEG series is inconclusive
// (streak and latch kept — never count, never clear on missing
// evidence). ConsecNeeded consecutive over-threshold cycles enter
// state-kubelet-pleg-unhealthy so nodereporter flips
// KubeletPLEGUnhealthy early; a healthy scrape clears both.

// plegSample is one parsed scrape of the PLEG series plus the
// disk-slow-io storage-operation error counter the same :10250
// exposition carries.
type plegSample struct {
	relistSum      float64 // relist_duration_seconds_sum (lifetime)
	relistCount    float64 // relist_duration_seconds_count (lifetime)
	relistQuant    float64 // worst quantile sample (summary form only)
	relistFastCum  float64 // histogram: count at the highest le <= plegRelistHighSec
	lastSeen       float64 // pleg_last_seen_seconds — Unix timestamp
	discard        int64   // pleg_discard_events counter
	storageErrs    float64 // storage_operation_errors_total summed over labels
	hasRelist      bool
	hasLastSeen    bool
	hasDiscard     bool
	hasStorageErrs bool
	hasFastCum     bool
}

// parsePLEGMetrics picks the PLEG series out of a kubelet /metrics
// text exposition. Sample lines are "<name>{labels} value" or
// "<name> value"; HELP/TYPE comments are skipped. Older kubelets
// expose the relist duration as a summary (quantile rows plus
// _sum/_count); newer ones emit a histogram (_bucket/_sum/_count) —
// either way _sum/_count carry the lifetime avg and the cumulative
// bucket counts carry the fast/slow split.
func parsePLEGMetrics(body string) plegSample {
	var s plegSample
	for _, line := range strings.Split(body, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := f[0]
		if i := strings.IndexByte(name, '{'); i >= 0 {
			name = name[:i]
		}
		v, err := strconv.ParseFloat(f[len(f)-1], 64)
		if err != nil {
			continue
		}
		switch name {
		case "kubelet_pleg_relist_duration_seconds":
			// Summary quantile rows — worst wins; non-quantile
			// label rows don't exist upstream but guard anyway.
			if strings.Contains(f[0], "quantile=") {
				s.hasRelist = true
				if v > s.relistQuant {
					s.relistQuant = v
				}
			}
		case "kubelet_pleg_relist_duration_seconds_bucket":
			// Histogram form: cumulative bucket counts. The count
			// at the highest le <= plegRelistHighSec is the "fast"
			// total; count - fastCum is the slow tail. Cumulative
			// counts are monotonic in le so the max over the
			// qualifying buckets IS that bucket's count.
			if le, ok := plegBucketLE(f[0]); ok &&
				le <= plegRelistHighSec && v > s.relistFastCum {
				s.relistFastCum, s.hasFastCum = v, true
			}
			s.hasRelist = true
		case "kubelet_pleg_relist_duration_seconds_sum":
			s.relistSum, s.hasRelist = v, true
		case "kubelet_pleg_relist_duration_seconds_count":
			s.relistCount, s.hasRelist = v, true
		case "kubelet_pleg_last_seen_seconds":
			s.lastSeen, s.hasLastSeen = v, true
		case "kubelet_pleg_discard_events":
			s.discard, s.hasDiscard = int64(v), true
		case "storage_operation_errors_total":
			// disk-slow-io: mount/attach/device-operation failures
			// kubelet reports per volume_plugin+operation —
			// every labelled sample sums into the one node-level
			// counter (node_kubelet_storage_operation_errors_total).
			s.storageErrs += v
			s.hasStorageErrs = true
		}
	}
	return s
}

// plegBucketLE pulls the le="X" bound out of a histogram bucket
// sample name ("...+Inf" parses to +Inf and is dropped by the
// caller's range check).
func plegBucketLE(name string) (float64, bool) {
	i := strings.Index(name, `le="`)
	if i < 0 {
		return 0, false
	}
	rest := name[i+len(`le="`):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(rest[:j], 64)
	return v, err == nil
}

// probePLEG scrapes kubelet /metrics once and updates the PLEG
// streak + latch plus the exported gauges. Called at the head of
// every Run so the early-warning verdict is independent of the
// syncloop probe's outcome.
func (c *SyncloopCheck) probePLEG(ctx context.Context) {
	body, err := c.d.Cfg.Seams.Probe.KubeletMetricsFn(ctx,
		c.d.Cfg.Kubelet.MetricsURL, kubeletBearer(c.d), wdeps.ProbeTimeout)
	if err != nil {
		// Unreachable/unauthorized /metrics says nothing about
		// PLEG — inconclusive like the other failed-probe paths.
		return
	}
	s := parsePLEGMetrics(body)
	// disk-slow-io: the storage error counter exports even when the
	// PLEG family is absent — the series is independent of PLEG
	// health.
	if s.hasStorageErrs {
		c.d.KubeletStorageOperationErrors = int64(s.storageErrs)
	}
	if !s.hasRelist && !s.hasLastSeen {
		// The endpoint answered but the PLEG family isn't there —
		// inconclusive (metrics stripped/downgraded), keep state.
		return
	}
	// kubelet_pleg_last_seen_seconds is a Unix timestamp — the
	// wall-clock instant PLEG was last active — NOT an age: the lag
	// is host-clock minus the stamp. A stamp <=0 means PLEG never
	// ran since kubelet start — inconclusive, don't flag on it.
	var lastSeenAge float64
	lastSeenOK := false
	if s.hasLastSeen && s.lastSeen > 0 {
		lastSeenAge = c.d.Cfg.Seams.Host.Clock.Now().Sub(
			time.Unix(int64(s.lastSeen), 0)).Seconds()
		if lastSeenAge < 0 {
			lastSeenAge = 0 // stamp in the future — treat as just-seen
		}
		c.d.KubeletPLEGLastSeenAgeSec = lastSeenAge
		lastSeenOK = true
	}
	discardDelta := int64(0)
	if s.hasDiscard {
		c.d.KubeletPLEGDiscardEvents = s.discard
		if c.discardSeen && s.discard >= c.prevDiscard {
			discardDelta = s.discard - c.prevDiscard
		}
		c.prevDiscard, c.discardSeen = s.discard, true
	}
	// The lifetime avg (sum/count since kubelet start) can never
	// move on a long-lived kubelet, so verdicts come from
	// per-scrape deltas: Δsum/Δcount plus the new >plegRelistHighSec
	// tail growth (count − fastCum). The first scrape after
	// (re)start only seeds the baseline — unless the lifetime avg
	// itself is already over, which still flags.
	relistAvg := 0.0
	relistOver := s.relistQuant > plegRelistHighSec
	if s.relistCount > 0 {
		relistAvg = s.relistSum / s.relistCount
		switch {
		case c.relistSeen && s.relistCount > c.prevCount:
			relistAvg = (s.relistSum - c.prevSum) / (s.relistCount - c.prevCount)
			if relistAvg > plegRelistHighSec ||
				(s.hasFastCum && s.relistCount-s.relistFastCum >
					c.prevCount-c.prevFast) {
				relistOver = true
			}
		case !c.relistSeen && relistAvg > plegRelistHighSec:
			relistOver = true
		}
		c.prevSum, c.prevCount, c.relistSeen = s.relistSum, s.relistCount, true
		if s.hasFastCum {
			c.prevFast = s.relistFastCum
		}
	}
	over := relistOver ||
		(lastSeenOK && lastSeenAge > plegLastSeenHighSec)
	if !over {
		c.plegFails = 0
		c.d.State.Exit(latchdefs.LatchKubeletPLEGUnhealthy, nil)
		return
	}
	if c.d.StreakPending(&c.plegFails, fmt.Sprintf(
		"suspect: kubelet-pleg-unhealthy relist_avg=%.2f relist_q=%.2f last_seen_age=%.1f discards=+%d",
		relistAvg, s.relistQuant, lastSeenAge, discardDelta)) {
		return
	}
	c.d.State.Enter(latchdefs.LatchKubeletPLEGUnhealthy, fmt.Sprintf(
		"relist_avg=%.2f relist_q=%.2f last_seen_age=%.1f discards=+%d",
		relistAvg, s.relistQuant, lastSeenAge, discardDelta))
}

// kubeletBearer reads the service-account token kubelet's :10250
// webhook auth accepts — re-read every call so bound-token rotation
// needs no caching logic. Missing/unreadable file → "" (the probe
// runs unauthenticated and 401/403 marks the check inconclusive).
func kubeletBearer(d *wdeps.Deps) string {
	b, err := os.ReadFile(d.Cfg.Kubelet.TokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// CtrsockCheck is the A4 containerd-socket hang probe as a Check;
// it owns the consecutive-fail streak (ex-Hygiene.ctrsockFails).
type CtrsockCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *CtrsockCheck) Name() string { return wdeps.CheckCtrSock }

// Run executes one containerd-sock round.
func (c *CtrsockCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCtrSock) {
		return
	}
	err := c.d.Cfg.Seams.Probe.ProbeUnixSock(ctx, c.d.Cfg.CtrSocket, unixSockProbeTimeout)
	if err == nil {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchContainerdSockDown, nil)
		c.d.CycleResult(wdeps.CheckCtrSock, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: containerd-sock-down %s probe fail: %v",
		c.d.Cfg.CtrSocket, err)) {
		c.d.CycleResult(wdeps.CheckCtrSock, "ok")
		return
	}
	// BUG-H4: a hung containerd socket wedges PLEG and every pod
	// lifecycle op — confirmed consecutive fails self-heal through
	// the shared k0sworker restart gates, checkKubeletSyncloop
	// parity.
	overloaded := c.d.State.Exists(latchdefs.LatchNodeOverloaded)
	if !overloaded {
		c.d.State.Enter(latchdefs.LatchContainerdSockDown,
			fmt.Sprintf("probe_err=%v", err))
	} else if !c.d.State.Exists(latchdefs.LatchContainerdSockDown) {
		c.d.State.AppendLog(fmt.Sprintf(
			"containerd-sock-down suppressed-overloaded - probe_err=%v", err))
	}
	switch {
	case overloaded:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: containerd-sock-down - node overloaded, skip restart k0sworker (err=%v)", err))
	case !k0sWorkerSettled(c.d, ctx):
		c.d.State.AppendLog("suspect: containerd-sock-down - k0sworker not settled (<180s), skip restart")
	case c.d.HoldLocalAction(ctx):
		// L1↔L3 maintenance hold — BEFORE the budget spend so a held
		// restart never burns the shared last-restart cooldown.
		c.d.State.AppendLog("suspect: containerd-sock-down - cluster maintenance in progress, skip restart k0sworker")
	case !c.d.State.RateTrySpend("last-restart", c.d.Cfg.MinRestartInterval):
		c.d.State.AppendLog("suspect: containerd-sock-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		c.d.State.AppendLog(fmt.Sprintf(latchdefs.ActionK0sworkerRestart+
			" - containerd-sock-down %s (persisted %dx)",
			c.d.Cfg.CtrSocket, c.fails))
		c.fails = 0
		if err := restartK0sWorker(c.d, ctx); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.d.Actions.WithLabelValues(wdeps.CheckCtrSock, "restart").Inc()
		}
	}
	c.d.CycleResult(wdeps.CheckCtrSock, "ok")
}

// cp_freeze_heal.go — W8-CP3/W10-FIX1 control-plane freeze
// auto-heal:
//
//	KCM/scheduler freeze auto-heal. k0s hosts
//	kube-controller-manager (:10257) and kube-scheduler
//	(:10259) inside k0scontroller — when either /healthz
//	stays dead for CPFreezeCycles consecutive cycles, or the
//	KCM workqueue shows a stalled backlog (W10-FIX1) for
//	longer than CPFreezeQuietFor, while the peer apiserver
//	still answers, the component (not the apiserver) is
//	frozen → restart k0scontroller.service under the
//	last-cp-restart budget.
//
// Also hosts the ungated-cycle dispatch slot: the W10-CP2
// kine-storage and W10-CP5 kubeconfig-cert checks ride this
// entry point (see checkCPFreeze).
package controllerhygiene

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// checkCPFreeze is the prometheus `check` label + log context for
// the KCM/scheduler freeze auto-heal.
const checkCPFreeze = "cp-freeze"

// fileKCMQueueSnap is the persisted KCM workqueue snapshot under
// WatchdogStateDir (W10 bookkeeping).
const fileKCMQueueSnap = "kcm-queue-snapshot.json"

// W10-FIX1 stall thresholds — a stalled KCM workqueue, never an
// idle one. depthSum==0 (the healthy idle reading) can NEVER fire.
const (
	kcmStallDepthSum     = 50  // (a) total queued items across queues
	kcmStallQueueDepth   = 20  // (b) single-queue depth for retry storm
	kcmStallRetriesDelta = 200 // (b) retries_total growth per window
	// kcmStallAddsEpsilon is "increased by ~0" for arm (a): counter
	// deltas are integer-valued, so <1 enqueue across ALL queues in
	// the window counts as flat (tolerates float noise).
	kcmStallAddsEpsilon = 0.5
	// kcmSnapshotMaxGap bounds how old the previous snapshot may be
	// — the delta math only means "no progress" between consecutive
	// scrapes; a stale baseline (agent restart, missed cycles) is
	// inconclusive.
	kcmSnapshotMaxGap = 15 * time.Minute
)

// The cpHealthFn/kcmMetricsFn defaults live in platform/probee
// (HTTP2xx / HTTPBodyInsecure) — same insecure client, same drains.

// kcmQueueSnapshot is one scrape of the KCM /metrics workqueue
// state, persisted under WatchdogStateDir so consecutive scrapes
// can be compared for stall evidence (W10-FIX1).
type kcmQueueSnapshot struct {
	At       int64              `json:"at"` // scrape epoch (nowFn)
	Leader   bool               `json:"leader"`
	DepthSum float64            `json:"depth_sum"`
	Depths   map[string]float64 `json:"depths"`
	Adds     map[string]float64 `json:"adds"`
	Retries  map[string]float64 `json:"retries"`
}

var (
	kcmLeaderRe = regexp.MustCompile(
		`(?m)^leader_election_master_status(?:\{[^}]*\})?\s+([0-9.]+)`)
	// workqueue_{depth,adds_total,retries_total}{labels} value —
	// the three series the stall predicate needs.
	kcmWorkqueueRe = regexp.MustCompile(
		`(?m)^workqueue_(depth|adds_total|retries_total)(\{[^}]*\})?\s+([0-9.eE+-]+)`)
	kcmQueueNameRe = regexp.MustCompile(`name="([^"]+)"`)
)

// kcmQueueKey extracts the workqueue name from a metric label set —
// `name="..."` is the queue identifier shared by all three series;
// the raw label text is the fallback so differently-labelled
// variants still join consistently between scrapes.
func kcmQueueKey(labels string) string {
	if labels == "" {
		return ""
	}
	if m := kcmQueueNameRe.FindStringSubmatch(labels); m != nil {
		return m[1]
	}
	return labels
}

// parseKCMQueueSnapshot extracts leader state + per-queue
// workqueue depth/adds/retries from a KCM /metrics body. parsed=false
// when the leader metric is absent — inconclusive, same contract
// the old kcmLeaderIdle had.
func parseKCMQueueSnapshot(body string, at int64) (*kcmQueueSnapshot, bool) {
	lm := kcmLeaderRe.FindStringSubmatch(body)
	if lm == nil {
		return nil, false
	}
	lv, _ := strconv.ParseFloat(lm[1], 64)
	snap := &kcmQueueSnapshot{
		At:      at,
		Leader:  lv >= 1,
		Depths:  map[string]float64{},
		Adds:    map[string]float64{},
		Retries: map[string]float64{},
	}
	for _, m := range kcmWorkqueueRe.FindAllStringSubmatch(body, -1) {
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		key := kcmQueueKey(m[2])
		switch m[1] {
		case "depth":
			snap.Depths[key] += v
			snap.DepthSum += v
		case "adds_total":
			snap.Adds[key] += v
		case "retries_total":
			snap.Retries[key] += v
		}
	}
	return snap, true
}

// kcmDeltas returns per-queue counter deltas (cur - prev) over the
// queues present in BOTH snapshots. ok=false when any shared
// counter decreased — a KCM restart resets every counter and the
// delta math is meaningless.
func kcmDeltas(prev, cur map[string]float64) (map[string]float64, bool) {
	out := make(map[string]float64, len(cur))
	for q, cv := range cur {
		pv, ok := prev[q]
		if !ok {
			continue
		}
		d := cv - pv
		if d < 0 {
			return nil, false
		}
		out[q] = d
	}
	return out, true
}

// kcmQueueStalled is the W10-FIX1 stall predicate — true ONLY when
// this node is the KCM leader (leader_election_master_status >= 1)
// AND the workqueue shows a backlog with zero forward progress
// across two consecutive scrapes:
//
//	(a) depthSum > kcmStallDepthSum while adds_total grew by ~0 —
//	    items queued, nothing new arriving, workers not draining; or
//	(b) one queue depth > kcmStallQueueDepth with retries_total up
//	    > kcmStallRetriesDelta and that queue's depth not draining.
//
// Healthy idle (depthSum == 0) NEVER fires — that was the
// kcmLeaderIdle false-positive that restarted k0scontroller hourly.
// A counter reset, a non-leader scrape, or a stale prev snapshot
// makes the comparison inconclusive → false.
func kcmQueueStalled(prev, cur *kcmQueueSnapshot) bool {
	if prev == nil || cur == nil || !cur.Leader {
		return false
	}
	// Consecutive-scrape window only: "no progress" is only proven
	// between adjacent scrapes — a stale baseline (agent restart,
	// missed cycles, metrics outage) is inconclusive.
	gap := cur.At - prev.At
	if gap <= 0 || gap > int64(kcmSnapshotMaxGap.Seconds()) {
		return false
	}
	adds, ok := kcmDeltas(prev.Adds, cur.Adds)
	if !ok {
		return false
	}
	retries, ok := kcmDeltas(prev.Retries, cur.Retries)
	if !ok {
		return false
	}
	// (a) deep backlog with ~zero new enqueues — requires at least
	// one queue giving a real adds comparison: an empty baseline is
	// inconclusive, not "zero progress".
	var addsDelta float64
	for _, d := range adds {
		addsDelta += d
	}
	if cur.DepthSum > kcmStallDepthSum && len(adds) > 0 &&
		addsDelta <= kcmStallAddsEpsilon {
		return true
	}
	// (b) single-queue retry storm with zero depth drain.
	for q, depth := range cur.Depths {
		if depth <= kcmStallQueueDepth {
			continue
		}
		if retries[q] <= kcmStallRetriesDelta {
			continue
		}
		prevDepth, ok := prev.Depths[q]
		if !ok || depth < prevDepth {
			continue // drain observed (or no baseline) — not stalled
		}
		return true
	}
	return false
}

// loadKCMSnapshot returns the previous scrape's snapshot, or nil
// when the file is absent/corrupt — inconclusive, never fires.
func (c *cpFreezeCheck) loadKCMSnapshot() *kcmQueueSnapshot {
	data := c.d.readState(fileKCMQueueSnap)
	if data == "" {
		return nil
	}
	var s kcmQueueSnapshot
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return nil
	}
	return &s
}

// saveKCMSnapshot persists the scrape atomically (tmp+rename — the
// writeEpochFile contract; a torn JSON just reads as "no baseline"
// next cycle).
func (c *cpFreezeCheck) saveKCMSnapshot(s *kcmQueueSnapshot) {
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	dir := c.d.state.Dir
	tmp := filepath.Join(dir, ".tmp-"+fileKCMQueueSnap)
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		logger().Warn("controllerhygiene: kcm snapshot write failed",
			"path", tmp, "error", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, fileKCMQueueSnap)); err != nil {
		logger().Warn("controllerhygiene: kcm snapshot install failed",
			"error", err)
	}
}

// peerHealthy reports whether the OTHER apiserver answers — the W8-CP3
// gate that proves only the controller components froze, not the whole
// control plane. Falls back to the local apiserver when no peer is
// configured (single-hub).
func (c *cpFreezeCheck) peerHealthy(ctx context.Context) bool {
	ep := c.d.cfg.Hub.PeerAPI
	if ep == "" {
		ep = c.d.cfg.Hub.SelfEndpoint
	}
	// ANY HTTP code = the apiserver event loop is alive
	// (probee.HTTPAnyCode parity — a wedged apiserver is the wedge
	// guard's problem, not this check's).
	return c.d.cfg.probeFn(ctx, "https://"+ep+"/readyz")
}

// cpFreezeCheck is the W8-CP3/W10-FIX1 freeze auto-heal as a
// Check — its only in-memory state is the kcmQuietSince stamp kept
// on deps; everything else is the consecutive-cp-freeze / kcm-queue
// snapshot bookkeeping. It also owns the ungated-cycle dispatch
// slot the W10-CP2 kine-storage and W10-CP5 kubeconfig-cert checks
// ride (initChecks wires them in).
type cpFreezeCheck struct {
	d           *deps
	kineStorage *kineStorageCheck
	kubeCert    *kubeCertCheck
}

// Name returns the check label / log context.
func (c *cpFreezeCheck) Name() string { return checkCPFreeze }

// Run — W8-CP3. Restart evidence is (a) KCM or scheduler healthz dead
// for CPFreezeCycles consecutive cycles, or (b) a stalled KCM
// workqueue (W10-FIX1 kcmQueueStalled) persisting past
// CPFreezeQuietFor. The restart only fires while the peer apiserver
// stays healthy and honors Sig13Mode.
func (c *cpFreezeCheck) Run(ctx context.Context) {
	// W10-CP2/W10-CP5 ride this ungated cycle slot: Cycle()
	// dispatch lives in check.go, so those checks are invoked
	// from the first W8-CP entry point — same pre-uptime-gate
	// position, every cycle.
	c.kineStorage.Run(ctx)
	c.kubeCert.Run(ctx)

	kcmOK := c.d.cfg.cpHealthFn(ctx, c.d.cfg.CPFreeze.KCMHealthURL)
	schedOK := c.d.cfg.cpHealthFn(ctx, c.d.cfg.CPFreeze.SchedHealthURL)

	frozen := false
	reason := ""
	switch {
	case !kcmOK || !schedOK:
		n := c.d.state.Incr(fileCtrCPFreeze)
		if n >= c.d.cfg.CPFreeze.Cycles {
			frozen = true
			reason = fmt.Sprintf("healthz dead %dx (kcm=%v sched=%v)",
				n, kcmOK, schedOK)
		} else {
			c.d.cycles.WithLabelValues(checkCPFreeze, "suspect").Inc()
			return
		}
	default:
		c.d.state.ResetCounter(fileCtrCPFreeze)
	}

	// Leader-with-a-stalled-workqueue is an OR-condition: even with
	// a healthy healthz a frozen KCM scheduler loop shows up as a
	// leader holding a backlog with zero forward progress (W10-FIX1
	// — the old leader+zero-depth reading fired on every healthy
	// idle cluster). Only evaluated when the fast path didn't
	// already fire; every successful scrape refreshes the snapshot
	// the next scrape compares against.
	if !frozen {
		body, err := c.d.cfg.kcmMetricsFn(ctx, c.d.cfg.CPFreeze.KCMMetricsURL)
		stalled := false
		if err == nil {
			if snap, parsed := parseKCMQueueSnapshot(
				body, c.d.cfg.nowFn().Unix()); parsed {
				stalled = kcmQueueStalled(c.loadKCMSnapshot(), snap)
				c.saveKCMSnapshot(snap)
			}
		}
		if stalled {
			if c.d.kcmQuietSince.IsZero() {
				c.d.kcmQuietSince = c.d.cfg.nowFn()
				c.d.state.Incr(fileCtrKCMQuiet)
			}
			if c.d.cfg.nowFn().Sub(c.d.kcmQuietSince) >= c.d.cfg.CPFreeze.QuietFor {
				frozen = true
				reason = fmt.Sprintf("kcm workqueue stalled >%s",
					c.d.cfg.CPFreeze.QuietFor)
			}
		} else {
			c.d.kcmQuietSince = time.Time{}
			c.d.state.ResetCounter(fileCtrKCMQuiet)
		}
	}

	if !frozen {
		c.d.stateExit(stateCPComponentFrozen)
		c.d.cycles.WithLabelValues(checkCPFreeze, "ok").Inc()
		return
	}
	c.d.state.Enter(stateCPComponentFrozen, reason)
	// Gate: the peer apiserver must still answer — otherwise the
	// outage is bigger than a frozen component and the wedge guard
	// owns the restart story.
	if !c.peerHealthy(ctx) {
		c.d.state.SuspectLog(stateCPComponentFrozen, fmt.Sprintf(
			"suspect: cp-component-frozen %s but peer apiserver unhealthy — wedge guard owns this, skip",
			reason), c.d.cfg.SuspectLogCadence)
		c.d.cycles.WithLabelValues(checkCPFreeze, "gated").Inc()
		return
	}
	if !c.d.state.RateOK(fileRateCPRestart,
		c.d.cfg.CPFreeze.MinRestart) {
		c.d.state.SuspectLog(stateCPComponentFrozen, fmt.Sprintf(
			"suspect: cp-component-frozen %s but in restart cooldown (<%dm), skip",
			reason, int(c.d.cfg.CPFreeze.MinRestart.Minutes())),
			c.d.cfg.SuspectLogCadence)
		c.d.cycles.WithLabelValues(checkCPFreeze, "cooldown").Inc()
		return
	}
	switch c.d.cfg.Sig13.Mode {
	case ModeEnforce:
		c.d.state.AppendLog(
			"ACTION: restarting k0scontroller - cp-component-frozen " +
				reason)
		c.d.state.RateSpend(fileRateCPRestart)
		c.d.state.ResetCounter(fileCtrCPFreeze)
		c.d.state.ResetCounter(fileCtrKCMQuiet)
		c.d.kcmQuietSince = time.Time{}
		if err := c.d.cfg.restartFn(ctx, c.d.cfg.RestartUnit); err != nil {
			c.d.state.AppendLogWarn(fmt.Sprintf(
				"suspect: restart %s failed: %v", c.d.cfg.RestartUnit, err))
		}
		c.d.actions.WithLabelValues(checkCPFreeze, "restart_controller").Inc()
	case ModeDryRun:
		c.d.state.AppendLog(
			"DRY-RUN: would restart k0scontroller - cp-component-frozen " +
				reason)
		c.d.actions.WithLabelValues(checkCPFreeze, "dryrun_restart").Inc()
	}
	c.d.cycles.WithLabelValues(checkCPFreeze, "ok").Inc()
}

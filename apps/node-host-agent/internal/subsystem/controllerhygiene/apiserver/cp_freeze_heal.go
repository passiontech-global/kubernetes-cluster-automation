// cp_freeze_heal.go — cp-freeze-heal/kcm-queue-stall control-plane freeze
// auto-heal:
//
//	KCM/scheduler freeze auto-heal. k0s hosts
//	kube-controller-manager (:10257) and kube-scheduler
//	(:10259) inside k0scontroller — when either /healthz
//	stays dead for CPFreezeCycles consecutive cycles, or the
//	KCM workqueue shows a stalled backlog (kcm-queue-stall) for
//	longer than CPFreezeQuietFor, while the peer apiserver
//	still answers, the component (not the apiserver) is
//	frozen → restart k0scontroller.service under the
//	last-cp-restart budget.
//
// This file owns the freeze-heal duty itself: the
// KCMQueueSnapshot parse/stall predicate, the FreezeCheck
// Check type and its Run phases. The APF queue-starvation
// probe (probeAPF) and the konnectivity-server probe/heal
// that used to live alongside them moved to apf_probe.go
// and konnectivity_heal.go in this package. The ungated-
// cycle dispatch slot still rides this entry point: the
// kine-storage kine-storage and kubeconfig-cert-expiry kubeconfig-cert checks
// (see cdeps.CheckCPFreeze) are dispatched from Run.
package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// kcm-queue-stall stall thresholds — a stalled KCM workqueue, never an
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

// KCMQueueSnapshot is one scrape of the KCM /metrics workqueue
// state, persisted under WatchdogStateDir so consecutive scrapes
// can be compared for stall evidence (kcm-queue-stall).
type KCMQueueSnapshot struct {
	At       int64              `json:"at"` // scrape epoch (Clock)
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

// ParseKCMQueueSnapshot extracts leader state + per-queue
// workqueue depth/adds/retries from a KCM /metrics body. parsed=false
// when the leader metric is absent — inconclusive, same contract
// the old kcmLeaderIdle had.
func ParseKCMQueueSnapshot(body string, at int64) (*KCMQueueSnapshot, bool) {
	lm := kcmLeaderRe.FindStringSubmatch(body)
	if lm == nil {
		return nil, false
	}
	lv, _ := strconv.ParseFloat(lm[1], 64)
	snap := &KCMQueueSnapshot{
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

// KCMQueueStalled is the kcm-queue-stall stall predicate — true ONLY when
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
func KCMQueueStalled(prev, cur *KCMQueueSnapshot) bool {
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
func (c *FreezeCheck) loadKCMSnapshot() *KCMQueueSnapshot {
	data := c.d.ReadState(cdeps.FileKCMQueueSnap)
	if data == "" {
		return nil
	}
	var s KCMQueueSnapshot
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return nil
	}
	return &s
}

// saveKCMSnapshot persists the scrape atomically — the
// fsx.WriteFileAtomic contract (a torn JSON just reads as
// "no baseline" next cycle; the shared primitive adds the payload
// fsync + dir sync the hand-rolled tmp+rename lacked).
func (c *FreezeCheck) saveKCMSnapshot(s *KCMQueueSnapshot) {
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	path := filepath.Join(c.d.State.Dir, cdeps.FileKCMQueueSnap)
	if err := fsx.WriteFileAtomicBytes(path, b); err != nil {
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"kcm snapshot write failed path=%s error=%v", path, err))
	}
}

// peerHealthy reports whether the OTHER apiserver answers — the cp-freeze-heal
// gate that proves only the controller components froze, not the whole
// control plane. Falls back to the local apiserver when no peer is
// configured (single-hub).
func (c *FreezeCheck) peerHealthy(ctx context.Context) bool {
	ep := c.d.Cfg.Hub.PeerAPI
	if ep == "" {
		ep = c.d.Cfg.Hub.SelfEndpoint
	}
	// ANY HTTP code = the apiserver event loop is alive
	// (probee.HTTPAnyCode parity — a wedged apiserver is the wedge
	// guard's problem, not this check's).
	return c.d.Cfg.ProbeFn(ctx, "https://"+ep+"/readyz")
}

// FreezeCheck is the cp-freeze-heal/kcm-queue-stall freeze auto-heal as a
// Check — its only in-memory state is the kcmQuietSince stamp +
// the APF reject baseline, both kept on the check itself;
// everything else is the consecutive-cp-freeze / kcm-queue
// snapshot bookkeeping. It also owns the ungated-cycle dispatch
// slot the kine-storage kine-storage and kubeconfig-cert-expiry kubeconfig-cert checks
// ride (initChecks wires them in).
type FreezeCheck struct {
	d        *cdeps.Deps
	Storage  cdeps.Check
	KubeCert cdeps.Check

	// kcmQuietSince is the first cycle the KCM read
	// leader+stalled-queue — leader-without-progress only counts as
	// frozen after CPFreezeQuietFor (cp-freeze-heal/kcm-queue-stall). In-memory:
	// an agent restart just re-arms the quiet window.
	kcmQuietSince time.Time

	// APFMetricsFn is the apiserver /metrics scrape seam behind
	// ProbeAPF (apf_probe.go) — nil → the mTLS GET over
	// deps.ensureClient (the secure :6443 /metrics needs client
	// credentials, so the insecure kcmMetricsFn probe client cannot
	// serve it).
	APFMetricsFn func(ctx context.Context) (string, error)
	// apfPrevRejected is the last scrape's
	// apiserver_flowcontrol_rejected_requests_total per
	// (flow_schema, priority_level) — the reject-delta baseline.
	// In-memory like kcmQuietSince: a restart simply re-baselines
	// on the first scrape (inconclusive, never fires).
	apfPrevRejected map[APFSeriesKey]float64
	// apiserverRSS/apiserverRSSSeen carry the last scrape's
	// process_resident_memory_bytes into EmitAPFMetrics — the
	// node_host_agent_apiserver_rss_bytes series (apiserver-rss-gauge) lets
	// Prometheus watch kube-apiserver RSS growth without a
	// go_gc or cgroup scrape of the static pod.
	apiserverRSS     float64
	apiserverRSSSeen bool

	// konnBadCycles is the konnectivity-server unhealthy streak —
	// cycles where the UDS was missing or the :8091 scrape returned
	// ready_backend_connections==0 (konnectivity_heal.go). In-memory
	// like the other streaks: a restart just re-arms the 3-cycle
	// debounce.
	konnBadCycles int
}

// Name returns the check label / log context.
func (c *FreezeCheck) Name() string { return cdeps.CheckCPFreeze }

// Run — cp-freeze-heal. Restart evidence is (a) KCM or scheduler healthz dead
// for CPFreezeCycles consecutive cycles, or (b) a stalled KCM
// workqueue (kcm-queue-stall KCMQueueStalled) persisting past
// CPFreezeQuietFor. The restart only fires while the peer apiserver
// stays healthy and honors Sig13Mode. The phases: runSlot (the
// ungated-cycle dispatch riders), probeFreeze (healthz + workqueue
// scrape), decideFreeze (streak/quiet bookkeeping → frozen+reason),
// healFreeze (the gated restart).
func (c *FreezeCheck) Run(ctx context.Context) {
	c.runSlot(ctx)
	frozen, reason, suspect := c.decideFreeze(ctx)
	if suspect {
		// The healthz-dead-below-streak path bare-returns the way
		// the monolithic Run did: no STATE-EXIT (an episode's
		// latch stays until a healthy cycle clears it, and Enter's
		// mtime refresh is the janitor-reap defence) and no "ok"
		// outcome on top of the suspect counter.
		return
	}
	if !frozen {
		c.d.StateExit(cdeps.StateCPComponentFrozen)
		c.d.Cycles.WithLabelValues(cdeps.CheckCPFreeze, "ok").Inc()
		return
	}
	c.healFreeze(ctx, reason)
}

// runSlot runs the ungated-cycle riders: kine-storage/kubeconfig-cert-expiry ride
// this slot (Cycle() dispatch lives in check.go, so those checks
// are invoked from the first controllerhygiene entry point — same
// pre-uptime-gate position, every cycle). The APF queue-starvation
// probe (apf_probe.go) and the konnectivity-server probe + heal
// (konnectivity_heal.go) ride the same slot — read-only scrape +
// metric mirror and an independent child-process heal, both must
// run every cycle including the early-return suspect paths.
func (c *FreezeCheck) runSlot(ctx context.Context) {
	c.Storage.Run(ctx)
	c.KubeCert.Run(ctx)
	c.ProbeAPF(ctx)
	c.probeKonnectivityServer(ctx)
}

// decideFreeze probes healthz + the KCM workqueue and decides
// whether the control-plane component is frozen. It mutates the
// suspect-streak bookkeeping (FileCtrCPFreeze, kcmQuietSince) the
// same way the monolithic Run did. The suspect flag reports the
// monolithic Run's bare-return path (healthz dead below the streak):
// Run must skip both the STATE-EXIT and the "ok" outcome for that
// cycle, exactly as the early return used to.
func (c *FreezeCheck) decideFreeze(ctx context.Context) (bool, string, bool) {
	kcmOK := c.d.Cfg.CPHealthFn(ctx, c.d.Cfg.CPFreeze.KCMHealthURL)
	schedOK := c.d.Cfg.CPHealthFn(ctx, c.d.Cfg.CPFreeze.SchedHealthURL)

	frozen := false
	reason := ""
	switch {
	case !kcmOK || !schedOK:
		n := c.d.State.Incr(cdeps.FileCtrCPFreeze)
		if n >= c.d.StreakCycles(c.d.Cfg.CPFreeze.Cycles) {
			frozen = true
			reason = fmt.Sprintf("healthz dead %dx (kcm=%v sched=%v)",
				n, kcmOK, schedOK)
		} else {
			c.d.Cycles.WithLabelValues(cdeps.CheckCPFreeze, "suspect").Inc()
			return false, "", true
		}
	default:
		c.d.State.ResetCounter(cdeps.FileCtrCPFreeze)
	}

	// Leader-with-a-stalled-workqueue is an OR-condition: even with
	// a healthy healthz a frozen KCM scheduler loop shows up as a
	// leader holding a backlog with zero forward progress (kcm-queue-stall
	// — the old leader+zero-depth reading fired on every healthy
	// idle cluster). Only evaluated when the fast path didn't
	// already fire; every successful scrape refreshes the snapshot
	// the next scrape compares against.
	if !frozen {
		body, err := c.d.Cfg.KCMMetricsFn(ctx, c.d.Cfg.CPFreeze.KCMMetricsURL)
		stalled := false
		if err == nil {
			if snap, parsed := ParseKCMQueueSnapshot(
				body, c.d.Cfg.Clock.Now().Unix()); parsed {
				stalled = KCMQueueStalled(c.loadKCMSnapshot(), snap)
				c.saveKCMSnapshot(snap)
			}
		}
		if stalled {
			if c.kcmQuietSince.IsZero() {
				c.kcmQuietSince = c.d.Cfg.Clock.Now()
				c.d.State.Incr(cdeps.FileCtrKCMQuiet)
			}
			if c.d.Cfg.Clock.Now().Sub(c.kcmQuietSince) >= c.d.Cfg.CPFreeze.QuietFor {
				frozen = true
				reason = fmt.Sprintf("kcm workqueue stalled >%s",
					c.d.Cfg.CPFreeze.QuietFor)
			}
		} else {
			c.kcmQuietSince = time.Time{}
			c.d.State.ResetCounter(cdeps.FileCtrKCMQuiet)
		}
	}
	return frozen, reason, false
}

// healFreeze enters the state latch and restarts k0scontroller
// under the last-cp-restart budget — gated on the peer apiserver
// staying healthy and the restart cooldown, honoring Sig13Mode.
func (c *FreezeCheck) healFreeze(ctx context.Context, reason string) {
	c.d.State.Enter(cdeps.StateCPComponentFrozen, reason)
	// Gate: the peer apiserver must still answer — otherwise the
	// outage is bigger than a frozen component and the wedge guard
	// owns the restart story.
	if !c.peerHealthy(ctx) {
		c.d.State.SuspectLog(cdeps.StateCPComponentFrozen, fmt.Sprintf(
			"suspect: cp-component-frozen %s but peer apiserver unhealthy — wedge guard owns this, skip",
			reason), c.d.Cfg.SuspectLogCadence)
		c.d.Cycles.WithLabelValues(cdeps.CheckCPFreeze, "gated").Inc()
		return
	}
	// FileRateRestart — the shared k0scontroller budget — not a
	// check-private file: a sig13 wedge restart seconds earlier
	// must cool this heal down too (and vice versa).
	outcome, _ := c.d.RestartWithGates(ctx, cdeps.RestartGateSpec{
		Check:       cdeps.CheckCPFreeze,
		State:       cdeps.StateCPComponentFrozen,
		Budget:      cdeps.FileRateRestart,
		Cooldown:    c.d.Cfg.CPFreeze.MinRestart,
		NeedQuorum:  true,
		HoldPrefix:  "cp-component-frozen " + reason,
		Unit:        c.d.Cfg.RestartUnit,
		Mode:        c.d.Cfg.Sig13.Mode,
		ActionLine:  "ACTION: restarting k0scontroller - cp-component-frozen " + reason,
		DryRunLine:  "DRY-RUN: would restart k0scontroller - cp-component-frozen " + reason,
		ActionLabel: "restart_controller",
		DryRunLabel: "dryrun_restart",
		BeforeRestart: func() {
			c.d.State.ResetCounter(cdeps.FileCtrCPFreeze)
			c.d.State.ResetCounter(cdeps.FileCtrKCMQuiet)
			c.kcmQuietSince = time.Time{}
		},
	})
	c.d.Cycles.WithLabelValues(cdeps.CheckCPFreeze, outcome).Inc()
}

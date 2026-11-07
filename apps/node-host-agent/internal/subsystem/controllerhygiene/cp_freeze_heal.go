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
// entry point (see checkCPFreeze), and so does the apiserver
// APF (API Priority & Fairness) queue-starvation probe — a
// read-only scrape of the local apiserver's /metrics that
// mirrors apiserver_flowcontrol_rejected_requests_total and
// apiserver_flowcontrol_current_inqueue_requests per
// (flow_schema, priority_level) into the node-exporter
// textfile channel and names the client group whose queue is
// rejecting when the counters grow (see probeAPF).
package controllerhygiene

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
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
// Check — its only in-memory state is the kcmQuietSince stamp +
// the APF reject baseline, both kept on the check itself;
// everything else is the consecutive-cp-freeze / kcm-queue
// snapshot bookkeeping. It also owns the ungated-cycle dispatch
// slot the W10-CP2 kine-storage and W10-CP5 kubeconfig-cert checks
// ride (initChecks wires them in).
type cpFreezeCheck struct {
	d           *deps
	kineStorage *kineStorageCheck
	kubeCert    *kubeCertCheck

	// kcmQuietSince is the first cycle the KCM read
	// leader+stalled-queue — leader-without-progress only counts as
	// frozen after CPFreezeQuietFor (W8-CP3/W10-FIX1). In-memory:
	// an agent restart just re-arms the quiet window.
	kcmQuietSince time.Time

	// apfMetricsFn is the apiserver /metrics scrape seam behind
	// probeAPF — nil → the mTLS GET over deps.ensureClient (the
	// secure :6443 /metrics needs client credentials, so the
	// insecure kcmMetricsFn probe client cannot serve it).
	apfMetricsFn func(ctx context.Context) (string, error)
	// apfPrevRejected is the last scrape's
	// apiserver_flowcontrol_rejected_requests_total per
	// (flow_schema, priority_level) — the reject-delta baseline.
	// In-memory like kcmQuietSince: a restart simply re-baselines
	// on the first scrape (inconclusive, never fires).
	apfPrevRejected map[apfSeriesKey]float64
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
	// The APF queue-starvation probe rides the same ungated slot —
	// read-only scrape + metric mirror, it must run every cycle
	// including the early-return suspect paths below.
	c.probeAPF(ctx)

	kcmOK := c.d.cfg.cpHealthFn(ctx, c.d.cfg.CPFreeze.KCMHealthURL)
	schedOK := c.d.cfg.cpHealthFn(ctx, c.d.cfg.CPFreeze.SchedHealthURL)

	frozen := false
	reason := ""
	switch {
	case !kcmOK || !schedOK:
		n := c.d.state.Incr(fileCtrCPFreeze)
		if n >= c.d.streakCycles(c.d.cfg.CPFreeze.Cycles) {
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
			if c.kcmQuietSince.IsZero() {
				c.kcmQuietSince = c.d.cfg.nowFn()
				c.d.state.Incr(fileCtrKCMQuiet)
			}
			if c.d.cfg.nowFn().Sub(c.kcmQuietSince) >= c.d.cfg.CPFreeze.QuietFor {
				frozen = true
				reason = fmt.Sprintf("kcm workqueue stalled >%s",
					c.d.cfg.CPFreeze.QuietFor)
			}
		} else {
			c.kcmQuietSince = time.Time{}
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
		c.kcmQuietSince = time.Time{}
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

// ---------------------------------------------------------------------------
// APF queue-starvation probe
// ---------------------------------------------------------------------------
//
// The kube-apiserver's API Priority & Fairness layer sheds requests
// with 429s when a flow schema's queues overflow — the mirror image
// of the KCM workqueue stall above: instead of the controller's own
// workqueue stalling, one client GROUP's queue saturates and its
// requests are rejected while the rest of the apiserver stays
// healthy. apiserver_flowcontrol_rejected_requests_total and
// apiserver_flowcontrol_current_inqueue_requests carry
// flow_schema + priority_level labels — the labels that name the
// congesting client group — so the probe mirrors both into
// node-agent-apiserver-apf.prom (node-exporter textfile channel:
// the subsystem registry is owned by controllerhygiene.go's New(),
// outside this file — see textfile_prom.go) and suspect-logs the
// offending pairs whenever the reject counters grow between
// consecutive scrapes.

const (
	// apfRejectedMetric mirrors the apiserver's cumulative reject
	// counter per flow_schema+priority_level — increase() over it
	// names the client group being 429'd.
	apfRejectedMetric = "node_host_agent_apiserver_apf_rejected_total"
	// apfInqueueMetric mirrors the live queue depth per
	// flow_schema+priority_level — the leading edge before rejects.
	apfInqueueMetric = "node_host_agent_apiserver_apf_inqueue_requests"
	apfPromFile      = "node-agent-apiserver-apf.prom"
	// terminatedWatchersMetric mirrors the apiserver's cumulative
	// apiserver_terminated_watchers_total — the W13-CP1 410-Gone
	// relist-storm signature (watch clients relisting en masse).
	terminatedWatchersMetric = "node_host_agent_apiserver_terminated_watchers"
	// logKeyAPFStarve keys the suspectLog dedupe budget for the
	// reject-growth lines — no dedicated latch, same role as
	// logKeyDeadFallbk.
	logKeyAPFStarve = "apf-starvation"
	// apfOffenderSample caps the flow-schema list in one suspect
	// line — the rest still land in the textfile series.
	apfOffenderSample = 5
)

// apfSeriesKey identifies one APF series — the
// (flow_schema, priority_level) label pair shared by the rejected
// and inqueue families.
type apfSeriesKey struct {
	flowSchema    string
	priorityLevel string
}

// apfOffender is one (flow_schema, priority_level) pair whose reject
// counter grew since the previous scrape.
type apfOffender struct {
	key     apfSeriesKey
	delta   float64
	inqueue float64
}

var (
	// apfSeriesRe matches the two apiserver_flowcontrol families the
	// probe needs — same scrape-line grammar as kcmWorkqueueRe.
	apfSeriesRe = regexp.MustCompile(
		`(?m)^apiserver_flowcontrol_(rejected_requests_total|current_inqueue_requests)` +
			`(\{[^}]*\})?\s+([0-9.eE+-]+)`)
	apfFlowSchemaRe = regexp.MustCompile(`flow_schema="([^"]*)"`)
	apfPriorityRe   = regexp.MustCompile(`priority_level="([^"]*)"`)
	// terminatedWatchersRe extracts the apiserver's 410-Gone
	// terminated-watch counter (all label variants summed).
	terminatedWatchersRe = regexp.MustCompile(
		`(?m)^apiserver_terminated_watchers_total(\{[^}]*\})?\s+([0-9.eE+-]+)`)
)

// apfLabel extracts one label value from a `{...}` label set — ""
// when absent, which still groups consistently.
func apfLabel(labels string, re *regexp.Regexp) string {
	if m := re.FindStringSubmatch(labels); m != nil {
		return m[1]
	}
	return ""
}

// parseAPFMetrics extracts the rejected_requests_total counters and
// current_inqueue_requests gauges, keyed by (flow_schema,
// priority_level). Missing APF families (a scraped endpoint that
// never served flowcontrol) yield empty maps — inconclusive, not a
// failure.
func parseAPFMetrics(body string) (rejected, inqueue map[apfSeriesKey]float64) {
	rejected = map[apfSeriesKey]float64{}
	inqueue = map[apfSeriesKey]float64{}
	for _, m := range apfSeriesRe.FindAllStringSubmatch(body, -1) {
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		k := apfSeriesKey{
			flowSchema:    apfLabel(m[2], apfFlowSchemaRe),
			priorityLevel: apfLabel(m[2], apfPriorityRe),
		}
		switch m[1] {
		case "rejected_requests_total":
			rejected[k] += v
		case "current_inqueue_requests":
			inqueue[k] += v
		}
	}
	return rejected, inqueue
}

// parseTerminatedWatchers sums the apiserver's
// apiserver_terminated_watchers_total counter across its label
// sets — W13-CP1 relist-storm evidence. seen=false when the family
// is absent (older apiserver / non-flowcontrol endpoint).
func parseTerminatedWatchers(body string) (total float64, seen bool) {
	for _, m := range terminatedWatchersRe.FindAllStringSubmatch(body, -1) {
		v, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			continue
		}
		total += v
		seen = true
	}
	return total, seen
}

// apfKeysSorted returns the map keys in a stable order — the
// textfile content stays byte-stable between scrapes.
func apfKeysSorted(m map[apfSeriesKey]float64) []apfSeriesKey {
	keys := make([]apfSeriesKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].flowSchema != keys[j].flowSchema {
			return keys[i].flowSchema < keys[j].flowSchema
		}
		return keys[i].priorityLevel < keys[j].priorityLevel
	})
	return keys
}

// apfMetrics fetches the local apiserver /metrics body. The default
// path reuses the mTLS client the rv probe already builds from the
// admin credentials (the secure :6443 /metrics endpoint requires
// client auth — the insecure healthz/metrics probe client would get
// a 401). ensureClient()==nil is "not a controller / no creds" —
// inconclusive, same posture as the hub check.
func (c *cpFreezeCheck) apfMetrics(ctx context.Context) (string, error) {
	if c.apfMetricsFn != nil {
		return c.apfMetricsFn(ctx)
	}
	client := c.d.ensureClient()
	if client == nil {
		return "", errors.New("no apiserver client credentials")
	}
	qctx, cancel := context.WithTimeout(ctx, c.d.cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+c.d.cfg.Hub.SelfEndpoint+"/metrics", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return "", fmt.Errorf("apiserver /metrics status %d", resp.StatusCode)
	}
	// The apiserver /metrics body is a few MiB on a healthy cluster —
	// 16MiB bounds it like the journal capture cap.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// probeAPF scrapes the local apiserver /metrics, mirrors the APF
// rejected/inqueue series into the textfile, and suspect-logs the
// (flow_schema, priority_level) pairs whose reject counter grew —
// the observable signature of APF queue overflow (requests denied
// with 429). A scrape failure degrades to headers-only emission so
// the series goes absent rather than pinning a stale counter.
func (c *cpFreezeCheck) probeAPF(ctx context.Context) {
	body, err := c.apfMetrics(ctx)
	if err != nil {
		c.emitAPFMetrics(nil, nil, 0, false)
		logger().Debug("controllerhygiene: apf metrics scrape failed",
			"error", err)
		return
	}
	rejected, inqueue := parseAPFMetrics(body)
	tw, twOK := parseTerminatedWatchers(body)
	c.emitAPFMetrics(rejected, inqueue, tw, twOK)

	// Reject deltas vs the previous scrape — the APF counters are
	// cumulative, so a growth window is what proves CURRENT
	// congestion (same consecutive-scrape posture as
	// kcmQueueStalled). No baseline → inconclusive.
	var offenders []apfOffender
	if c.apfPrevRejected != nil {
		reset := false
		for k, cur := range rejected {
			prev, ok := c.apfPrevRejected[k]
			if !ok {
				continue
			}
			d := cur - prev
			switch {
			case d > 0:
				offenders = append(offenders, apfOffender{
					key: k, delta: d, inqueue: inqueue[k]})
			case d < 0:
				reset = true // counter reset — apiserver restarted
			}
		}
		if reset {
			logger().Debug("controllerhygiene: apf reject counters went backwards — apiserver restarted, re-baselining")
		}
	}
	c.apfPrevRejected = rejected
	if len(offenders) == 0 {
		return
	}
	sort.Slice(offenders, func(i, j int) bool {
		return offenders[i].delta > offenders[j].delta
	})
	if len(offenders) > apfOffenderSample {
		offenders = offenders[:apfOffenderSample]
	}
	parts := make([]string, 0, len(offenders))
	for _, o := range offenders {
		parts = append(parts, fmt.Sprintf(
			"flow_schema=%s priority_level=%s +%.0f rejects (inqueue %.0f)",
			o.key.flowSchema, o.key.priorityLevel, o.delta, o.inqueue))
	}
	c.d.state.SuspectLog(logKeyAPFStarve,
		"suspect: apiserver APF queue starvation — flow-schema queues rejecting requests: "+
			strings.Join(parts, "; "), c.d.cfg.SuspectLogCadence)
}

// emitAPFMetrics renders node-agent-apiserver-apf.prom — the
// rejected family as a mirrored counter (TYPE counter: the apiserver
// series is cumulative), the inqueue family as a gauge. nil maps
// emit headers only so a blind scrape drops the series instead of
// leaving a stale reading live.
func (c *cpFreezeCheck) emitAPFMetrics(rejected, inqueue map[apfSeriesKey]float64,
	terminatedWatchers float64, twSeen bool) {
	var p promfile.Builder
	p.HeaderType(apfRejectedMetric,
		"apiserver_flowcontrol_rejected_requests_total mirrored from the "+
			"local apiserver — APF queue-overflow rejects by flow_schema "+
			"and priority_level.", "counter")
	for _, k := range apfKeysSorted(rejected) {
		p.Line(fmt.Sprintf("%s{flow_schema=\"%s\",priority_level=\"%s\"} %s",
			apfRejectedMetric,
			promfile.EscapeLabelValue(k.flowSchema),
			promfile.EscapeLabelValue(k.priorityLevel),
			strconv.FormatFloat(rejected[k], 'f', -1, 64)))
	}
	inqueueHelp := "apiserver_flowcontrol_current_inqueue_requests " +
		"mirrored from the local apiserver — APF queue depth by " +
		"flow_schema and priority_level."
	if len(inqueue) == 0 {
		p.Header(apfInqueueMetric, inqueueHelp)
	}
	for _, k := range apfKeysSorted(inqueue) {
		p.GaugeLabels(apfInqueueMetric, inqueueHelp, fmt.Sprintf(
			"flow_schema=\"%s\",priority_level=\"%s\"",
			promfile.EscapeLabelValue(k.flowSchema),
			promfile.EscapeLabelValue(k.priorityLevel)), inqueue[k])
	}
	// W13-CP1: the terminated-watchers counter rides the same
	// textfile — headers-only when the family wasn't in the
	// scrape so a blind scrape drops the series rather than
	// pinning a stale reading.
	twHelp := "apiserver_terminated_watchers_total mirrored from the " +
		"local apiserver — watches dropped with 410 Gone (relist-storm signal)."
	if !twSeen {
		p.HeaderType(terminatedWatchersMetric, twHelp, "counter")
	} else {
		p.HeaderType(terminatedWatchersMetric, twHelp, "counter")
		p.Line(fmt.Sprintf("%s %s", terminatedWatchersMetric,
			strconv.FormatFloat(terminatedWatchers, 'f', -1, 64)))
		c.d.terminatedWatchers.Set(terminatedWatchers)
	}
	c.d.writeTextfileProm(apfPromFile, p.String())
}

// nats_jetstream_signals.go — the evidence half of the
// nats-jetstream-health sweep: natsSweep accumulates every wedge
// reason observed per member pod (podReasons) split by whether it
// may emit this sweep already (emitNow — the Prometheus-derived
// subset, the metric IS the state) or must wait out the 10m
// first-seen window (log markers carry no timestamp, so the window
// IS their persistence clock). promSignals runs the three
// Prometheus wedges, logScan tails the Running members' logs for
// the wedge markers, and applyPersistence/emitPodFindings turn the
// raw reasons into the live set the report and the bounce read.
// Split out of nats_jetstream_health.go — see that file for the
// check.
package datastore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
)

// natsSweep carries one sweep's evidence state: the census, the
// report namespace-scope findings emit into directly, the per-pod
// reason union, the emit-now subset, and the window-lapsed subset
// applyPersistence computes.
type natsSweep struct {
	p          *natsJetstreamHealthCheck
	log        logr.Logger
	now        time.Time
	census     *natsCensus
	rep        *probefw.SweepReport
	podReasons map[string]map[string]bool // "ns/name" -> reasons
	emitNow    map[string]map[string]bool // reasons allowed to emit this sweep
	past       map[string]map[string]bool // reasons whose 10m window lapsed
}

func newNatsSweep(p *natsJetstreamHealthCheck, log logr.Logger,
	now time.Time, census *natsCensus,
	rep *probefw.SweepReport) *natsSweep {
	return &natsSweep{
		p:          p,
		log:        log,
		now:        now,
		census:     census,
		rep:        rep,
		podReasons: map[string]map[string]bool{},
		emitNow:    map[string]map[string]bool{},
	}
}

// addReason records one wedge reason against a member pod; emitNow
// marks the Prometheus-derived subset — those report this sweep,
// while log-only markers wait out the first-seen window.
func (s *natsSweep) addReason(key, reason string, emitNow bool) {
	if s.podReasons[key] == nil {
		s.podReasons[key] = map[string]bool{}
	}
	s.podReasons[key][reason] = true
	if emitNow {
		if s.emitNow[key] == nil {
			s.emitNow[key] = map[string]bool{}
		}
		s.emitNow[key][reason] = true
	}
}

// promSignals runs the Prometheus wedges — skipped entirely when no
// endpoint resolves (same "no endpoint configured, skip" gate the
// other metrics-backed checks use). Each query's failure only
// disables its own signal — a Prometheus outage must not blind the
// pod paths.
func (s *natsSweep) promSignals(ctx context.Context) {
	// (a) JetStream disabled on a RUNNING member — the binary is up,
	// core NATS serves, JetStream never came online.
	if disabled, err := s.p.PromQuery(ctx,
		`nats_jetstream_server_jetstream_disabled > 0`); err != nil {
		s.log.Info("WARN: nats jetstream-disabled query failed — signal skipped",
			"error", err)
	} else {
		for _, series := range disabled {
			podName := series.Label("pod", "pod_name")
			pod := s.census.resolvePod(series.Label("namespace"), podName)
			if pod == nil || pod.DeletionTimestamp != nil {
				continue // stale series or a non-member — not ours
			}
			s.addReason(pod.Namespace+"/"+pod.Name,
				natsReasonJetStreamDisabled, true)
		}
	}

	// (b) Leaderless meta-group: count>0 of the per-pod
	// nats_jetstream_meta_leader while the namespace sum is 0 —
	// diffed client-side across two instant queries (the literal
	// `and` form never matches: a ==0 comparison produces an empty
	// vector on the leader side, and PromQL `and` intersects it
	// away).
	counts, errC := s.p.PromQuery(ctx,
		`count by (namespace) (nats_jetstream_meta_leader)`)
	sums, errS := s.p.PromQuery(ctx,
		`sum by (namespace) (nats_jetstream_meta_leader)`)
	if errC != nil || errS != nil {
		s.log.Info("WARN: nats meta-leader queries failed — leaderless signal skipped",
			"countErr", errC, "sumErr", errS)
	} else {
		sumByNS := map[string]float64{}
		for _, series := range sums {
			sumByNS[series.Label("namespace")] = series.Value
		}
		for _, series := range counts {
			ns := series.Label("namespace")
			if ns == "" || !s.census.namespaces[ns] || series.Value <= 0 {
				continue
			}
			if sumByNS[ns] != 0 {
				continue // a meta leader exists — healthy
			}
			s.rep.Emit(natsJetstreamUnhealthyGauge,
				ns+"/"+natsReasonMetaLeaderless,
				[]string{ns, "", natsReasonMetaLeaderless},
				ns+"(meta_leaderless: "+
					fmt.Sprintf("%.0f members report no leader)", series.Value))
		}
	}

	// (b2) stream-leaderless — stream leader loss: members publish the
	// per-stream nats_jetstream_stream_leader gauge; a namespace
	// whose MINIMUM series value is 0 has at least one tracked stream
	// group that lost its leader — `min by` (not `sum by`) because a
	// namespace running several streams stays sum-positive while one
	// stream is leaderless, hiding the partial loss. Diffed
	// client-side across the same two instant queries as the meta
	// check (the literal `and` form never matches: a ==0 comparison
	// produces an empty vector on the leader side, and PromQL `and`
	// intersects it away). Pod-resolvable findings join the
	// windowed/healable pod-local path (bounce only under the
	// >=2-Ready-siblings quorum guard); series whose pod cannot be
	// resolved emit at namespace scope — a namespace-scope Raft
	// verdict has no single culprit pod. The pod-local stamp needs
	// PER-POD evidence — a member whose OWN per-stream minimum is 0,
	// i.e. some stream leader it reports is gone. A member whose
	// series are all positive still holds its leadership and must
	// never stamp: bounceWedged would delete the very member the
	// raft groups rally around, cascading leader loss (one bounce
	// per 30m loop).
	streamCounts, errSC := s.p.PromQuery(ctx,
		`nats_jetstream_stream_leader`)
	streamMins, errSM := s.p.PromQuery(ctx,
		`min by (namespace) (nats_jetstream_stream_leader)`)
	if errSC != nil || errSM != nil {
		s.log.Info("WARN: nats stream-leader queries failed — stream-leaderless signal skipped",
			"countErr", errSC, "minErr", errSM)
	} else {
		minByNS := map[string]float64{}
		for _, series := range streamMins {
			minByNS[series.Label("namespace")] = series.Value
		}
		podsByNS := map[string][]string{}
		// minByPod carries each member's OWN per-stream minimum — the
		// per-pod evidence the healable stamp requires (the
		// namespace-scope min by (namespace) above only proves SOME
		// member in the namespace lost a stream leader).
		minByPod := map[string]float64{} // "ns/pod" -> minimum
		for _, series := range streamCounts {
			ns := series.Label("namespace")
			if ns == "" {
				continue
			}
			if _, seen := podsByNS[ns]; !seen {
				podsByNS[ns] = nil // registered even without pod labels
			}
			if pod := series.Label("pod", "pod_name"); pod != "" {
				podsByNS[ns] = append(podsByNS[ns], pod)
				key := ns + "/" + pod
				if prev, seen := minByPod[key]; !seen || series.Value < prev {
					minByPod[key] = series.Value
				}
			}
		}
		for ns, podNames := range podsByNS {
			if !s.census.namespaces[ns] || minByNS[ns] != 0 {
				continue // every tracked stream has a leader — healthy, or not a NATS namespace
			}
			resolved := false
			for _, podName := range podNames {
				if minByPod[ns+"/"+podName] != 0 {
					continue // its own streams are all led — a leadership holder, never a bounce target
				}
				pod := s.census.resolvePod(ns, podName)
				if pod == nil || pod.DeletionTimestamp != nil {
					continue // stale series or a non-member — not ours
				}
				s.addReason(pod.Namespace+"/"+pod.Name,
					natsReasonStreamLeaderless, true)
				resolved = true
			}
			if !resolved {
				s.rep.Emit(natsJetstreamUnhealthyGauge,
					ns+"/"+natsReasonStreamLeaderless,
					[]string{ns, "", natsReasonStreamLeaderless},
					fmt.Sprintf("%s(stream_leaderless: %d stream-leader series, min 0)",
						ns, len(podNames)))
			}
		}
	}

	// positive max_ack_pending — every consumer flow-control stops
	// while nothing crashes. Joined client-side on the consumer
	// identity labels both counters share.
	pending, errP := s.p.PromQuery(ctx, `nats_consumer_num_ack_pending`)
	maxPend, errM := s.p.PromQuery(ctx, `nats_consumer_max_ack_pending`)
	if errP != nil || errM != nil {
		s.log.Info("WARN: nats consumer ack-floor queries failed — signal skipped",
			"pendingErr", errP, "maxErr", errM)
		return
	}
	maxByKey := map[string]float64{}
	for _, series := range maxPend {
		maxByKey[series.Label("namespace")+"/"+series.Label("pod", "pod_name")+"/"+
			series.Label("nats_stream_name", "stream_name", "stream")+"/"+
			series.Label("nats_consumer_name", "consumer_name", "consumer")] = series.Value
	}
	for _, series := range pending {
		key := series.Label("namespace") + "/" + series.Label("pod", "pod_name") + "/" +
			series.Label("nats_stream_name", "stream_name", "stream") + "/" +
			series.Label("nats_consumer_name", "consumer_name", "consumer")
		max := maxByKey[key]
		if max <= 0 || series.Value < max {
			continue
		}
		ns := series.Label("namespace")
		podName := series.Label("pod", "pod_name")
		pod := s.census.resolvePod(ns, podName)
		lvPod := ""
		if pod != nil {
			lvPod, ns = pod.Name, pod.Namespace
		}
		consumer := series.Label("nats_consumer_name", "consumer_name", "consumer")
		s.rep.Emit(natsJetstreamUnhealthyGauge,
			ns+"/"+lvPod+"/"+natsReasonConsumerAckFloor,
			[]string{ns, lvPod, natsReasonConsumerAckFloor},
			fmt.Sprintf("%s(%s consumer=%s ack_floor=%.0f/%.0f)",
				ns, lvPod, consumer, series.Value, max))
	}
}

// logScan runs the log-marker scan on Running members old enough
// for their JetStream startup to have settled — a fetch/read
// failure is inconclusive, not healthy (warn + skip). The fetches
// run through a bounded worker pool (max natsLogScanWorkers
// concurrent kubelet log streams); results apply serially below.
func (s *natsSweep) logScan(ctx context.Context) {
	type logScan struct {
		key    string
		reason string
		err    error
	}
	scanKeys := make([]string, 0, len(s.census.memberByName))
	for key, pod := range s.census.memberByName {
		if pod.Status.Phase != corev1.PodRunning ||
			s.now.Sub(pod.CreationTimestamp.Time) < natsLogScanMinPodAge {
			continue
		}
		scanKeys = append(scanKeys, key)
	}
	sort.Strings(scanKeys)
	scans := make([]logScan, len(scanKeys))
	g := errgroup.Group{}
	g.SetLimit(natsLogScanWorkers)
	for j, key := range scanKeys {
		pod := s.census.memberByName[key]
		g.Go(func() error {
			reason := ""
			hit, lerr := probefw.PodLogTail(ctx, s.p.CS, pod, "",
				probefw.DefaultTailLines, probefw.LogMaxBytes, probefw.LogTimeout,
				func(line string) bool {
					if r := natsLogReason(line); r != "" {
						reason = r // the first marker wins
						return true
					}
					return false
				})
			if lerr == nil && !hit {
				reason = "" // clean tail — no marker
			}
			scans[j] = logScan{key: key, reason: reason, err: lerr}
			return nil
		})
	}
	_ = g.Wait()
	for _, scan := range scans {
		if scan.err != nil {
			s.log.Info("WARN: nats pod log tail failed — wedge evidence inconclusive",
				"pod", scan.key, "error", scan.err)
			continue
		}
		if scan.reason != "" {
			s.addReason(scan.key, scan.reason, false)
		}
	}
}

// applyPersistence runs the per-reason persistence pass: every
// observed (pod,reason) shares the 10m first-seen clock — JetStream
// startup churn and Raft elections flap through these states on
// every rollout. It fills s.past (key -> reason -> window lapsed)
// and prunes the ledger down to the live signals.
func (s *natsSweep) applyPersistence() {
	seenKeep := map[string]bool{}
	s.past = map[string]map[string]bool{}
	for key, rs := range s.podReasons {
		for r := range rs {
			seenKey := key + "/" + r
			seenKeep[seenKey] = true
			if probefw.Persisted(&s.p.seen, seenKey, s.now, natsWedgeMinAge, s.log) {
				if s.past[key] == nil {
					s.past[key] = map[string]bool{}
				}
				s.past[key][r] = true
			}
		}
	}
	s.p.seen.Prune(func(k string) bool { return seenKeep[k] })
}

// emitPodFindings emits the pod-local findings: a Prometheus-sourced
// reason reports now; a log-only reason reports once its window
// lapses.
func (s *natsSweep) emitPodFindings() {
	for key, rs := range s.podReasons {
		pod := s.census.memberByName[key]
		var live []string
		for r := range rs {
			if s.emitNow[key][r] || s.past[key][r] {
				live = append(live, r)
			}
		}
		if len(live) == 0 {
			continue
		}
		sort.Strings(live)
		reason := strings.Join(live, "+")
		s.rep.Emit(natsJetstreamUnhealthyGauge, key+"/"+reason,
			[]string{pod.Namespace, pod.Name, reason},
			key+"("+reason+")")
	}
}

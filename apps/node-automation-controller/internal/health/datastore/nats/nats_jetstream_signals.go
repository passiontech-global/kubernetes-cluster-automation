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
package nats

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// natsSweep carries one sweep's evidence state: the census, the
// report namespace-scope findings emit into directly, the per-pod
// reason union, the emit-now subset, and the window-lapsed subset
// applyPersistence computes.
type natsSweep struct {
	p            *natsJetstreamHealthCheck
	log          logr.Logger
	now          time.Time
	census       *natsCensus
	rep          *probefw.SweepReport
	podReasons   map[string]map[string]bool // "ns/name" -> reasons
	emitNow      map[string]map[string]bool // reasons allowed to emit this sweep
	past         map[string]map[string]bool // reasons whose 10m window lapsed
	promDegraded bool                       // a PromQuery/endpoint failed — prom evidence unverifiable
	inconclusive map[string]bool            // member pods whose log tail failed this sweep
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
		s.promDegraded = true
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
		s.promDegraded = true
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

	// (b2) stream-leaderless — stream leader loss: in replicated
	// JetStream (e.g. R=3), 1 replica holds the stream leader (gauge=1)
	// while healthy followers report 0. Therefore we MUST aggregate per
	// (namespace, stream) client-side: a stream has lost its leader only
	// when count > 0 and sum == 0 across all replicas reporting it.
	// Emitted at namespace scope (pod="") so healthy followers are never
	// bounced; pod-local stream_leaderless bounces remain driven by
	// natsLogMarkers ("stream has no leader" / "group has no leader").
	streamSeries, errSL := s.p.PromQuery(ctx, `nats_jetstream_stream_leader`)
	if errSL != nil {
		s.log.Info("WARN: nats stream-leader query failed — stream-leaderless signal skipped",
			"error", errSL)
		s.promDegraded = true
	} else {
		type streamTally struct {
			stream string
			count  int
			sum    float64
		}
		byNSStream := map[string]map[string]*streamTally{}
		for _, series := range streamSeries {
			ns := series.Label("namespace")
			if ns == "" || !s.census.namespaces[ns] {
				continue
			}
			stream := series.Label("stream_name", "stream", "nats_stream_name")
			acct := series.Label("account", "account_name")
			streamKey := stream
			if acct != "" {
				streamKey = acct + "/" + stream
			}
			m := byNSStream[ns]
			if m == nil {
				m = map[string]*streamTally{}
				byNSStream[ns] = m
			}
			t := m[streamKey]
			if t == nil {
				t = &streamTally{stream: stream}
				m[streamKey] = t
			}
			t.count++
			t.sum += series.Value
		}
		for ns, streams := range byNSStream {
			var leaderless []string
			totalCount := 0
			hasLeaderless := false
			for _, t := range streams {
				if t.count > 0 && t.sum == 0 {
					hasLeaderless = true
					totalCount += t.count
					if t.stream != "" {
						leaderless = append(leaderless, t.stream)
					}
				}
			}
			if !hasLeaderless {
				continue
			}
			slices.Sort(leaderless)
			detail := fmt.Sprintf("%s(stream_leaderless: %d stream-leader series, sum 0)",
				ns, totalCount)
			if len(leaderless) > 0 {
				detail = fmt.Sprintf("%s(stream_leaderless: %d stream-leader series across [%s], sum 0)",
					ns, totalCount, strings.Join(leaderless, ","))
			}
			s.rep.Emit(natsJetstreamUnhealthyGauge,
				ns+"/"+natsReasonStreamLeaderless,
				[]string{ns, "", natsReasonStreamLeaderless},
				detail)
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
		s.promDegraded = true
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
		if !s.census.namespaces[ns] {
			continue // stale series from a namespace with no NATS
			// StatefulSet — same guard the sibling branches apply
		}
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
// run through the shared kube.ScanPodLogs bounded worker pool (max
// natsLogScanWorkers concurrent kubelet log streams); results apply
// serially below in scanKeys order.
func (s *natsSweep) logScan(ctx context.Context) {
	scanKeys := make([]string, 0, len(s.census.memberByName))
	for key, pod := range s.census.memberByName {
		if pod.Status.Phase != corev1.PodRunning ||
			s.now.Sub(pod.CreationTimestamp.Time) < natsLogScanMinPodAge {
			continue
		}
		scanKeys = append(scanKeys, key)
	}
	slices.Sort(scanKeys)
	// The scan clock only tracks pods actually tailed this sweep —
	// entries for pods that left the candidate set are dropped so a
	// pod re-entering later bootstraps against its own last read.
	if s.p.logScanAt != nil {
		inScan := make(map[string]bool, len(scanKeys))
		for _, k := range scanKeys {
			inScan[k] = true
		}
		for k := range s.p.logScanAt {
			if !inScan[k] {
				delete(s.p.logScanAt, k)
			}
		}
	}
	pods := make([]*corev1.Pod, len(scanKeys))
	for j, key := range scanKeys {
		pods[j] = s.census.memberByName[key]
	}
	scans := kube.ScanPodLogs(ctx, pods, natsLogScanWorkers,
		func(ctx context.Context, pod *corev1.Pod) (natsLogScan, error) {
			out := natsLogScan{}
			matched, newest, streamNewest, err := kube.ReadPodLogTailTimed(ctx, s.p.CS, pod, kube.PodLogOpts{
				TailLines:    probefw.DefaultTailLines,
				SinceSeconds: 360,
				MaxBytes:     probefw.LogMaxBytes,
				Timeout:      probefw.LogTimeout,
				Timestamps:   true,
			}, func(line string) bool {
				if r := natsLogReason(line); r != "" {
					out.reason = r // last match wins — the tail is
					// chronological, so the freshest marker is the
					// live signal the freshness gate will weigh.
					return true
				}
				return false
			})
			if err == nil {
				out.newest = newest
				out.streamNewest = streamNewest
				if !matched {
					out.reason = "" // clean tail — no marker
				}
			}
			return out, err
		})
	inconclusive := map[string]bool{}
	for j, scan := range scans {
		key := scanKeys[j]
		if scan.Err != nil {
			s.log.Info("WARN: nats pod log tail failed — wedge evidence inconclusive",
				"pod", key, "error", scan.Err)
			inconclusive[key] = true
			continue
		}
		if s.p.logScanAt == nil {
			s.p.logScanAt = map[string]time.Time{}
		}
		prevScan, scanned := s.p.logScanAt[key]
		// The boundary advances in the KUBELET's clock domain —
		// streamNewest is the newest stamp on any line read; s.now
		// (controller clock) is only the fallback for a stream
		// that carried no parseable timestamp at all.
		if scan.Value.streamNewest.IsZero() {
			s.p.logScanAt[key] = s.now
		} else {
			s.p.logScanAt[key] = scan.Value.streamNewest
		}
		// Freshness gate: the marker must have a line newer than
		// this pod's previous scan — the 360s window overlaps
		// across 300s sweeps, so without it an error that stopped
		// minutes ago re-flags for extra cycles. An unparseable
		// stamp counts as fresh — fail toward alerting.
		if scan.Value.reason != "" &&
			(!scanned || scan.Value.newest.IsZero() || scan.Value.newest.After(prevScan)) {
			s.addReason(key, scan.Value.reason, false)
		}
	}
	s.inconclusive = inconclusive
}

// natsLogScan is one pod's log-tail verdict: the wedge reason of the
// freshest matching line plus that line's kubelet timestamp (zero
// when no matching line carried a parseable stamp), and
// streamNewest — the newest stamp on ANY line read, the scan
// boundary stored in the kubelet's clock domain.
type natsLogScan struct {
	reason       string
	newest       time.Time
	streamNewest time.Time
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
	// A degraded evidence channel must not read as "resolved": keep
	// the first-seen clocks the sweep could not re-evaluate — every
	// entry of a pod whose log tail failed, and prom-sourceable
	// reasons cluster-wide while Prometheus is down (the reason
	// strings overlap the log markers, so the suffix match is the
	// only attribution available).
	s.p.seen.Prune(func(k string) bool {
		if seenKeep[k] {
			return true
		}
		// seen keys are "ns/pod/reason" — recover the pod key.
		i := strings.LastIndex(k, "/")
		if i <= 0 {
			return false
		}
		podKey := k[:i]
		if s.inconclusive[podKey] {
			return true
		}
		if s.promDegraded &&
			strings.HasSuffix(k, "/"+natsReasonJetStreamDisabled) {
			if _, ok := s.census.memberByName[podKey]; ok {
				return true
			}
		}
		return false
	})
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
		slices.Sort(live)
		reason := strings.Join(live, "+")
		s.rep.Emit(natsJetstreamUnhealthyGauge, key+"/"+reason,
			[]string{pod.Namespace, pod.Name, reason},
			key+"("+reason+")")
	}
}

// carryUnverifiable freezes last sweep's emitted series for evidence
// the sweep could not re-evaluate — a Prometheus outage or a failed
// pod-log tail must not read as "resolved" (one API flap would
// otherwise prune live wedge series and reset their first-seen
// clocks). Pods/members that left the census are genuinely gone and
// their series still drop.
func (s *natsSweep) carryUnverifiable() {
	if !s.promDegraded && len(s.inconclusive) == 0 {
		return
	}
	for k, lv := range s.p.emitted.Last() {
		parts := strings.SplitN(k, "/", 3)
		podKey := ""
		if len(parts) == 3 && parts[1] != "" {
			podKey = parts[0] + "/" + parts[1]
			if _, ok := s.census.memberByName[podKey]; !ok {
				continue // member gone — genuinely resolved
			}
			// A pod with fresh evidence emits its own series; only
			// freeze pods whose evaluation was inconclusive.
			if !s.promDegraded && !s.inconclusive[podKey] {
				continue
			}
		} else {
			// Namespace-scope series are all Prometheus-derived —
			// carry while the channel is degraded and the namespace
			// still hosts NATS members.
			if !s.promDegraded || !s.census.namespaces[parts[0]] {
				continue
			}
		}
		s.rep.Carry(k, lv)
		if podKey == "" || len(s.podReasons[podKey]) == 0 {
			s.rep.Find(k + " (carried — evidence channel unavailable)")
		}
	}
}

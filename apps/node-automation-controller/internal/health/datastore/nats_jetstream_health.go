// nats_jetstream_health.go — the nats-jetstream-health check
// (W12-ST1): NATS JetStream wedge signatures the Ready gate cannot
// see. Core NATS pub/sub keeps answering on :4222 while the
// JetStream Raft layer is brain-dead, so member pods report
// Ready=True through every one of the signatures below. The check
// reads Prometheus for a pod running with JetStream disabled, a
// namespace whose meta-group lost its leader (count>0, sum==0 of
// nats_jetstream_meta_leader), and a consumer pinned at its
// ack-floor (num_ack_pending >= max_ack_pending > 0); it also scans
// Running members' log tails for the wedge markers ("JetStream not
// enabled", "no meta leader", "raft: lost leadership"). Pod-local
// wedges emit after the 10m persistence window and bounce ONLY when
// >=2 OTHER members of the same StatefulSet stay Ready — a delete
// that would drop the cluster under Raft quorum never fires.
package datastore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// natsJetstreamHealthCheck is the W12-ST1 JetStream wedge watchdog.
type natsJetstreamHealthCheck struct {
	*probefw.Deps

	// seen: "ns/pod/reason" → first sweep a pod-local wedge
	// signature held — the 10m persistence window before a
	// log-marker finding emits and before ANY wedge member is
	// bounced (in-RAM: a restart re-arms, the safe direction).
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted state.GaugeLedger[string]
}

// NewNatsJetstreamHealthCheck builds the W12-ST1 check — its state
// is the seen/emitted ledgers (zero value usable); pod-delete
// cooldowns ride the shared Deps.Heals set via DeletePodHeal.
func NewNatsJetstreamHealthCheck(d *probefw.Deps) probefw.Check {
	return &natsJetstreamHealthCheck{Deps: d}
}

const (
	CheckNameNatsJetstreamHealth = "nats-jetstream-health"

	// W12-ST1 — nats-jetstream-health knobs.
	natsAppLabelValue    = "nats" // app.kubernetes.io/name
	natsWedgeMinAge      = 10 * time.Minute
	natsLogScanMinPodAge = 5 * time.Minute
	natsHealCool         = 30 * time.Minute
)

// The reason values node_automation_nats_jetstream_unhealthy
// carries — one per wedge class the check flags.
const (
	natsReasonJetStreamDisabled  = "jetstream_disabled"
	natsReasonMetaLeaderless     = "meta_leaderless"
	natsReasonNoMetaLeader       = "no_meta_leader"
	natsReasonRaftLostLeadership = "raft_lost_leadership"
	natsReasonConsumerAckFloor   = "consumer_ack_floor"
	// W16-ST2 — a JetStream stream (or its raft group) lost its
	// leader: replicas report the stream-leader gauge but none holds
	// leadership, so publishes to the stream stall while the server
	// itself stays Ready.
	natsReasonStreamLeaderless = "stream_leaderless"
)

// natsHealableReasons is the whitelist of pod-local wedges that
// justify a member bounce — each clears on a fresh start. NOT
// meta_leaderless (a namespace-scope Raft verdict — no single pod is
// the culprit) and NOT consumer_ack_floor (a client/consumption
// stall a restart cannot move).
var natsHealableReasons = map[string]bool{
	natsReasonJetStreamDisabled:  true,
	natsReasonNoMetaLeader:       true,
	natsReasonRaftLostLeadership: true,
	// W16-ST2 — a member that lost its stream leaders recovers them
	// by rejoining the raft groups on a fresh start. Still gated on
	// the >=2-Ready-siblings quorum census below.
	natsReasonStreamLeaderless: true,
}

// natsLogMarkers are the log signatures of a wedged JetStream member
// — the pod stays Running while its Raft layer complains.
var natsLogMarkers = []struct{ marker, reason string }{
	{"jetstream not enabled", natsReasonJetStreamDisabled},
	{"no meta leader", natsReasonNoMetaLeader},
	{"raft: lost leadership", natsReasonRaftLostLeadership},
	// W16-ST2 — stream-level leader loss: the server keeps serving
	// core NATS while every replica of a stream group reports no
	// leader.
	{"stream has no leader", natsReasonStreamLeaderless},
	{"group has no leader", natsReasonStreamLeaderless},
}

var (
	// W12-ST1 — one series per (namespace, pod, reason) wedge. The
	// pod label is empty for namespace-scope findings
	// (meta_leaderless) and consumer findings whose owner pod the
	// series cannot resolve.
	natsJetstreamUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_nats_jetstream_unhealthy",
		Help: "1 while a NATS JetStream pod/cluster reports a wedge signature (jetstream_disabled, meta_leaderless, stream_leaderless, no_meta_leader, raft_lost_leadership, consumer_ack_floor) — W12-ST1/W16-ST2.",
	}, []string{"namespace", "pod", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		natsJetstreamUnhealthyGauge)
}

// natsSTSKey resolves the StatefulSet name owning a NATS member pod
// — the per-cluster quorum-census grouping (two NATS clusters in one
// namespace must never pool Ready members). Controller owner ref
// first; the "<sts>-<ordinal>" name shape is the fallback for a pod
// whose owner ref was stripped.
func natsSTSKey(pod *corev1.Pod) string {
	if ref := metav1.GetControllerOf(pod); ref != nil && ref.Kind == "StatefulSet" {
		return pod.Namespace + "/" + ref.Name
	}
	if idx := strings.LastIndex(pod.Name, "-"); idx > 0 {
		return pod.Namespace + "/" + pod.Name[:idx]
	}
	return pod.Namespace + "/" + pod.Name
}

// natsLogReason maps one log line to its wedge reason ("" = no
// marker) — pure, so the marker table is testable without a log
// stream.
func natsLogReason(line string) string {
	l := strings.ToLower(line)
	for _, m := range natsLogMarkers {
		if strings.Contains(l, m.marker) {
			return m.reason
		}
	}
	return ""
}

// checkNatsJetstreamHealth runs the W12-ST1 sweep: StatefulSet
// discovery (absence tolerated — no NATS on this cluster is a clean
// pass), then Prometheus for the disabled/meta-leaderless/ack-floor
// signatures, then the Running-member log scan. Prometheus-derived
// findings emit immediately (the metric IS the state); log markers
// carry no timestamp so the 10m first-seen window IS their
// persistence clock. A pod-local wedge past the window bounces the
// member under the >=2-Ready-siblings quorum guard.
func (p *natsJetstreamHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	// Discover the NATS StatefulSets — the app.kubernetes.io/name=nats
	// label is the canonical helm marker. Absence means no NATS
	// deployed: tolerate, pass clean, and (importantly) never pay
	// the pods List on clusters without it.
	stss, err := p.CS.AppsV1().StatefulSets(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=" + natsAppLabelValue})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nats statefulsets: %w", err)}
	}
	if len(stss.Items) == 0 {
		// No NATS on this cluster — still reconcile the ledgers: a
		// tuple emitted while NATS existed (or a removed deployment
		// that left wedge evidence behind) must DeleteLabelValues,
		// and the first-seen entries drop so a redeploy starts a
		// fresh window. Returning Pass early leaks a stale 1.
		var rep probefw.SweepReport
		p.seen.Prune(func(string) bool { return false })
		return rep.Result(&p.emitted, natsJetstreamUnhealthyGauge.DeleteLabelValues,
			"nats jetstream wedge signatures: ", ", ")
	}
	natsNamespaces := map[string]bool{}
	for i := range stss.Items {
		natsNamespaces[stss.Items[i].Namespace] = true
	}

	// Member pods: the same canonical label, one cluster-wide read
	// serving the log scan, the prom pod mapping and the quorum
	// census. A list failure on a populated cluster is Infra — the
	// census cannot be proven.
	pods, err := p.PodsMatching(ctx, metav1.NamespaceAll,
		"app.kubernetes.io/name="+natsAppLabelValue)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nats pods: %w", err)}
	}
	memberByName := map[string]*corev1.Pod{} // "ns/name"
	memberByShort := map[string]*corev1.Pod{}
	readyBySTS := map[string]int{} // "ns/stsName" -> Running+Ready members
	for i := range pods {
		pod := pods[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		memberByName[pod.Namespace+"/"+pod.Name] = pod
		if memberByShort[pod.Name] == nil {
			memberByShort[pod.Name] = pod
		}
		if probefw.PodRunningReady(pod) {
			readyBySTS[natsSTSKey(pod)]++
		}
	}
	resolvePod := func(ns, name string) *corev1.Pod {
		if ns != "" {
			return memberByName[ns+"/"+name]
		}
		return memberByShort[name] // series without a namespace label
	}

	var rep probefw.SweepReport
	// podReasons is the union of wedge reasons observed per member
	// pod; emitNow marks the Prometheus-derived subset — those emit
	// this sweep, while log-only markers wait out the first-seen
	// window before they count.
	podReasons := map[string]map[string]bool{}
	emitNow := map[string]map[string]bool{}
	addReason := func(key, reason string, now bool) {
		if podReasons[key] == nil {
			podReasons[key] = map[string]bool{}
		}
		podReasons[key][reason] = true
		if now {
			if emitNow[key] == nil {
				emitNow[key] = map[string]bool{}
			}
			emitNow[key][reason] = true
		}
	}

	// Prometheus signatures — skipped entirely when no endpoint
	// resolves (same "no endpoint configured, skip" gate the other
	// metrics-backed checks use).
	if _, err := p.PromEndpoint(); err == nil {
		p.natsPromSignals(ctx, log, resolvePod, natsNamespaces, &rep, addReason)
	}

	// Log-marker scan on Running members old enough for their
	// JetStream startup to have settled — a fetch/read failure is
	// inconclusive, not healthy (warn + skip).
	for key, pod := range memberByName {
		if pod.Status.Phase != corev1.PodRunning ||
			now.Sub(pod.CreationTimestamp.Time) < natsLogScanMinPodAge {
			continue
		}
		reason := ""
		hit, lerr := probefw.PodLogTail(ctx, p.CS, pod, "",
			probefw.DefaultTailLines, probefw.LogMaxBytes, probefw.LogTimeout,
			func(line string) bool {
				if r := natsLogReason(line); r != "" {
					reason = r // the first marker wins
					return true
				}
				return false
			})
		if lerr != nil {
			log.Info("WARN: nats pod log tail failed — wedge evidence inconclusive",
				"pod", key, "error", lerr)
			continue
		}
		if hit {
			addReason(key, reason, false)
		}
	}

	// Per-reason persistence: every observed (pod,reason) shares the
	// 10m first-seen clock — JetStream startup churn and Raft
	// elections flap through these states on every rollout.
	seenKeep := map[string]bool{}
	past := map[string]map[string]bool{} // key -> reason -> window lapsed
	for key, rs := range podReasons {
		for r := range rs {
			seenKey := key + "/" + r
			seenKeep[seenKey] = true
			if probefw.Persisted(&p.seen, seenKey, now, natsWedgeMinAge, log) {
				if past[key] == nil {
					past[key] = map[string]bool{}
				}
				past[key][r] = true
			}
		}
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })

	// Emit pod-local findings: a Prometheus-sourced reason reports
	// now; a log-only reason reports once its window lapses.
	for key, rs := range podReasons {
		pod := memberByName[key]
		var live []string
		for r := range rs {
			if emitNow[key][r] || past[key][r] {
				live = append(live, r)
			}
		}
		if len(live) == 0 {
			continue
		}
		sort.Strings(live)
		reason := strings.Join(live, "+")
		rep.Emit(natsJetstreamUnhealthyGauge, key+"/"+reason,
			[]string{pod.Namespace, pod.Name, reason},
			key+"("+reason+")")
	}

	// Quorum-safe bounce: a wedged member may still report Ready
	// (the gray-failure shape), so the sibling count self-discounts
	// — >=2 OTHER Ready members of the SAME StatefulSet or the
	// delete could drop the cluster under Raft quorum. At most ONE
	// member is bounced per cycle even when several qualify — a
	// fleet-wide wedge must heal one member at a time so a bad
	// verdict can never halve the cluster in a single pass. The
	// key sort makes WHICH member goes first deterministic — map
	// order would bounce a random one, and the ledger stamp going
	// from missing/stale to `now` is how a DELIVERED delete reads
	// (DeletePodHeal swallows cooldown/mutex/delete failures).
	healed := false
	bounceKeys := make([]string, 0, len(podReasons))
	for key := range podReasons {
		bounceKeys = append(bounceKeys, key)
	}
	sort.Strings(bounceKeys)
	for _, key := range bounceKeys {
		rs := podReasons[key]
		pod := memberByName[key]
		healable := false
		for r := range rs {
			if natsHealableReasons[r] && past[key][r] {
				healable = true
				break
			}
		}
		if !healable || healed {
			continue
		}
		other := readyBySTS[natsSTSKey(pod)]
		if probefw.PodRunningReady(pod) {
			other--
		}
		if other < 2 {
			log.Info("skip nats jetstream heal: fewer than 2 other Ready "+
				"members — a delete would break Raft quorum",
				"pod", key, "otherReady", other)
			continue
		}
		hk := probefw.SelfHealKey(CheckNameNatsJetstreamHealth, key)
		before, _ := p.Heals.Last(hk)
		p.DeletePodHeal(ctx, log, CheckNameNatsJetstreamHealth,
			key, pod, natsHealCool, now)
		if stamp, ok := p.Heals.Last(hk); ok && stamp.After(before) {
			healed = true
		}
	}

	return rep.Result(&p.emitted, natsJetstreamUnhealthyGauge.DeleteLabelValues,
		"nats jetstream wedge signatures: ", ", ")
}

// natsPromSignals runs the three Prometheus wedges: a member running
// with JetStream disabled (pod-local — joins the windowed/healable
// reason set), a namespace whose meta-group is leaderless
// (namespace-scope, pod label left empty — no single culprit), and a
// consumer pinned at its ack-floor (consumption stall — the member
// bounce cannot move it). Each query's failure only disables its own
// signal — a Prometheus outage must not blind the pod paths.
func (p *natsJetstreamHealthCheck) natsPromSignals(ctx context.Context,
	log logr.Logger, resolvePod func(ns, name string) *corev1.Pod,
	natsNamespaces map[string]bool, rep *probefw.SweepReport,
	addReason func(key, reason string, emitNow bool)) {

	// (a) JetStream disabled on a RUNNING member — the binary is up,
	// core NATS serves, JetStream never came online.
	if disabled, err := p.PromQuery(ctx,
		`nats_jetstream_server_jetstream_disabled > 0`); err != nil {
		log.Info("WARN: nats jetstream-disabled query failed — signal skipped",
			"error", err)
	} else {
		for _, s := range disabled {
			podName := s.Label("pod", "pod_name")
			pod := resolvePod(s.Label("namespace"), podName)
			if pod == nil || pod.DeletionTimestamp != nil {
				continue // stale series or a non-member — not ours
			}
			addReason(pod.Namespace+"/"+pod.Name,
				natsReasonJetStreamDisabled, true)
		}
	}

	// (b) Leaderless meta-group: count>0 of the per-pod
	// nats_jetstream_meta_leader while the namespace sum is 0 —
	// diffed client-side across two instant queries (the literal
	// `and` form never matches: a ==0 comparison produces an empty
	// vector on the leader side, and PromQL `and` intersects it
	// away).
	counts, errC := p.PromQuery(ctx,
		`count by (namespace) (nats_jetstream_meta_leader)`)
	sums, errS := p.PromQuery(ctx,
		`sum by (namespace) (nats_jetstream_meta_leader)`)
	if errC != nil || errS != nil {
		log.Info("WARN: nats meta-leader queries failed — leaderless signal skipped",
			"countErr", errC, "sumErr", errS)
	} else {
		sumByNS := map[string]float64{}
		for _, s := range sums {
			sumByNS[s.Label("namespace")] = s.Value
		}
		for _, s := range counts {
			ns := s.Label("namespace")
			if ns == "" || !natsNamespaces[ns] || s.Value <= 0 {
				continue
			}
			if sumByNS[ns] != 0 {
				continue // a meta leader exists — healthy
			}
			rep.Emit(natsJetstreamUnhealthyGauge,
				ns+"/"+natsReasonMetaLeaderless,
				[]string{ns, "", natsReasonMetaLeaderless},
				ns+"(meta_leaderless: "+
					fmt.Sprintf("%.0f members report no leader)", s.Value))
		}
	}

	// (b2) W16-ST2 — stream leader loss: members publish the
	// per-stream nats_jetstream_stream_leader gauge; a namespace
	// whose series exist but sum to 0 has lost the leader of every
	// tracked stream group. Diffed client-side across the same two
	// instant queries as the meta check (the literal `and` form
	// never matches: a ==0 comparison produces an empty vector on
	// the leader side, and PromQL `and` intersects it away).
	// Pod-resolvable findings join the windowed/healable pod-local
	// path (bounce only under the >=2-Ready-siblings quorum guard);
	// series whose pod cannot be resolved emit at namespace scope —
	// a namespace-scope Raft verdict has no single culprit pod.
	streamCounts, errSC := p.PromQuery(ctx,
		`nats_jetstream_stream_leader`)
	streamSums, errSS := p.PromQuery(ctx,
		`sum by (namespace) (nats_jetstream_stream_leader)`)
	if errSC != nil || errSS != nil {
		log.Info("WARN: nats stream-leader queries failed — stream-leaderless signal skipped",
			"countErr", errSC, "sumErr", errSS)
	} else {
		sumByNS := map[string]float64{}
		for _, s := range streamSums {
			sumByNS[s.Label("namespace")] = s.Value
		}
		podsByNS := map[string][]string{}
		for _, s := range streamCounts {
			ns := s.Label("namespace")
			if ns == "" {
				continue
			}
			if _, seen := podsByNS[ns]; !seen {
				podsByNS[ns] = nil // registered even without pod labels
			}
			if pod := s.Label("pod", "pod_name"); pod != "" {
				podsByNS[ns] = append(podsByNS[ns], pod)
			}
		}
		for ns, podNames := range podsByNS {
			if !natsNamespaces[ns] || sumByNS[ns] != 0 {
				continue // a stream leader exists — healthy, or not a NATS namespace
			}
			resolved := false
			for _, podName := range podNames {
				pod := resolvePod(ns, podName)
				if pod == nil || pod.DeletionTimestamp != nil {
					continue // stale series or a non-member — not ours
				}
				addReason(pod.Namespace+"/"+pod.Name,
					natsReasonStreamLeaderless, true)
				resolved = true
			}
			if !resolved {
				rep.Emit(natsJetstreamUnhealthyGauge,
					ns+"/"+natsReasonStreamLeaderless,
					[]string{ns, "", natsReasonStreamLeaderless},
					fmt.Sprintf("%s(stream_leaderless: %d stream-leader series, sum 0)",
						ns, len(podNames)))
			}
		}
	}

	// positive max_ack_pending — every consumer flow-control stops
	// while nothing crashes. Joined client-side on the consumer
	// identity labels both counters share.
	pending, errP := p.PromQuery(ctx, `nats_consumer_num_ack_pending`)
	maxPend, errM := p.PromQuery(ctx, `nats_consumer_max_ack_pending`)
	if errP != nil || errM != nil {
		log.Info("WARN: nats consumer ack-floor queries failed — signal skipped",
			"pendingErr", errP, "maxErr", errM)
		return
	}
	maxByKey := map[string]float64{}
	for _, s := range maxPend {
		maxByKey[s.Label("namespace")+"/"+s.Label("pod", "pod_name")+"/"+
			s.Label("nats_stream_name", "stream_name", "stream")+"/"+
			s.Label("nats_consumer_name", "consumer_name", "consumer")] = s.Value
	}
	for _, s := range pending {
		key := s.Label("namespace") + "/" + s.Label("pod", "pod_name") + "/" +
			s.Label("nats_stream_name", "stream_name", "stream") + "/" +
			s.Label("nats_consumer_name", "consumer_name", "consumer")
		max := maxByKey[key]
		if max <= 0 || s.Value < max {
			continue
		}
		ns := s.Label("namespace")
		podName := s.Label("pod", "pod_name")
		pod := resolvePod(ns, podName)
		lvPod := ""
		if pod != nil {
			lvPod, ns = pod.Name, pod.Namespace
		}
		consumer := s.Label("nats_consumer_name", "consumer_name", "consumer")
		rep.Emit(natsJetstreamUnhealthyGauge,
			ns+"/"+lvPod+"/"+natsReasonConsumerAckFloor,
			[]string{ns, lvPod, natsReasonConsumerAckFloor},
			fmt.Sprintf("%s(%s consumer=%s ack_floor=%.0f/%.0f)",
				ns, lvPod, consumer, s.Value, max))
	}
}

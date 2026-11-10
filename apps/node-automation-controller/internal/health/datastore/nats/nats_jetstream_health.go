// nats_jetstream_health.go — the nats-jetstream-health check
// (nats-jetstream-health): NATS JetStream wedge signatures the Ready gate cannot
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
package nats

import (
	"context"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// natsJetstreamHealthCheck is the nats-jetstream-health JetStream wedge watchdog.
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

// NewNatsJetstreamHealthCheck builds the nats-jetstream-health check — its state
// is the seen/emitted ledgers (zero value usable); pod-delete
// cooldowns ride the shared Deps.Heals set via DeletePodHeal.
func NewNatsJetstreamHealthCheck(d *probefw.Deps) probefw.Check {
	return &natsJetstreamHealthCheck{Deps: d}
}

const (
	CheckNameNatsJetstreamHealth = "nats-jetstream-health"

	// The per-pod log-scan fan-out cap (Component 3 worker pool).
	natsLogScanWorkers = 4

	// nats-jetstream-health — nats-jetstream-health knobs.
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
	// stream-leaderless — a JetStream stream (or its raft group) lost its
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
	// stream-leaderless — a member that lost its stream leaders recovers them
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
	// stream-leaderless — stream-level leader loss: the server keeps serving
	// core NATS while every replica of a stream group reports no
	// leader.
	{"stream has no leader", natsReasonStreamLeaderless},
	{"group has no leader", natsReasonStreamLeaderless},
}

var (
	// nats-jetstream-health — one series per (namespace, pod, reason) wedge. The
	// pod label is empty for namespace-scope findings
	// (meta_leaderless) and consumer findings whose owner pod the
	// series cannot resolve.
	natsJetstreamUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_nats_jetstream_unhealthy",
		Help: "1 while a NATS JetStream pod/cluster reports a wedge signature (jetstream_disabled, meta_leaderless, stream_leaderless, no_meta_leader, raft_lost_leadership, consumer_ack_floor) — nats-jetstream-health/stream-leaderless.",
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

// checkNatsJetstreamHealth runs the nats-jetstream-health sweep:
// StatefulSet discovery (absence tolerated — no NATS on this
// cluster is a clean pass), then Prometheus for the
// disabled/meta-leaderless/ack-floor signatures, then the
// Running-member log scan. Prometheus-derived findings emit
// immediately (the metric IS the state); log markers carry no
// timestamp so the 10m first-seen window IS their persistence
// clock. A pod-local wedge past the window bounces the member
// under the >=2-Ready-siblings quorum guard. The sweep is collect
// (nats_jetstream_collect.go) → signals (nats_jetstream_signals.go)
// → heal (nats_jetstream_heals.go); Run below is only the
// orchestration.
func (p *natsJetstreamHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	census, err := collectNATS(ctx, p.Deps)
	if err != nil {
		return probefw.Result{Infra: err}
	}
	if census == nil {
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

	var rep probefw.SweepReport
	s := newNatsSweep(p, log, now, census, &rep)
	if _, err := p.PromEndpoint(); err == nil {
		s.promSignals(ctx)
	}
	s.logScan(ctx)
	s.applyPersistence()
	s.emitPodFindings()
	s.bounceWedged(ctx)

	return rep.Result(&p.emitted, natsJetstreamUnhealthyGauge.DeleteLabelValues,
		"nats jetstream wedge signatures: ", ", ")
}

// rabbitmq_quorum_health.go — the rabbitmq-quorum-health check
// (rabbitmq-quorum-health): RabbitMQ alarms / Mnesia partition signals from
// Prometheus plus the stuck-unready pod heal while >=2 siblings
// stay Ready.
package rabbitmq

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// rabbitMQQuorumHealthCheck is the RabbitMQ quorum-health watchdog.
type rabbitMQQuorumHealthCheck struct {
	*probefw.Deps

	// seen tracks each Prometheus-flagged pod's first-seen sweep —
	// the >=10m persistence window for the alarm/partition heal;
	// pruned when the signal clears so a later flap re-arms.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted state.GaugeLedger[string]
}

// newRabbitMQQuorumHealthCheck builds the rabbitmq-quorum-health check — its state
// is the seen/emitted ledgers (zero value usable); heal cooldowns
// ride the shared Deps.Heals set via deletePodHeal.
func NewRabbitMQQuorumHealthCheck(d *probefw.Deps) probefw.Check {
	return &rabbitMQQuorumHealthCheck{Deps: d}
}

const (
	CheckNameRabbitMQQuorum = "rabbitmq-quorum-health"

	// rabbitmq-quorum-health — rabbitmq-quorum-health knobs.
	rabbitUnreadyMinAge  = 10 * time.Minute
	rabbitQuorumHealCool = 30 * time.Minute
)

var (
	// rabbitmq-quorum-health — RabbitMQ quorum/partition signal.
	rabbitMQQuorumUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_rabbitmq_quorum_unhealthy",
		Help: "1 while the RabbitMQ pod/cluster reports an alarm, partition, stuck-unready, quorum-leaderless or term-skew signature — rabbitmq-quorum-health/quorum-raft-health.",
	}, []string{"namespace", "pod", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		rabbitMQQuorumUnhealthyGauge)
}

// isRabbitMQPod reports whether the pod belongs to a RabbitMQ
// cluster — the operator stamps app.kubernetes.io/part-of=rabbitmq
// (stable across per-cluster renames) and
// app.kubernetes.io/component=rabbitmq.
func isRabbitMQPod(pod *corev1.Pod) bool {
	return pod.Labels["app.kubernetes.io/part-of"] == "rabbitmq" ||
		pod.Labels["app.kubernetes.io/component"] == "rabbitmq"
}

// rabbitClusterKey is the per-RabbitmqCluster census key —
// "<ns>/<app.kubernetes.io/name>", the label the cluster operator
// stamps with the owning CR's name. "" when the label is absent:
// those pods fall back to controller-owner grouping (ReadyByOwner)
// so two clusters sharing a namespace still never pool their Ready
// members (rabbitmq-quorum-heal).
func rabbitClusterKey(pod *corev1.Pod) string {
	if name := pod.Labels["app.kubernetes.io/name"]; name != "" {
		return pod.Namespace + "/" + name
	}
	return ""
}

// rabbitHealableReasons is the whitelist of findings that justify a
// member-pod delete — each clears on a fresh start. NOT
// disk_watermark_alarm (rabbitmq-quorum-heal): a pod delete cannot free the
// PVC, and the restart replays the quorum-queue WAL onto a
// still-full disk; a future unknown reason defaults to alert-only
// too. quorum-raft-health's quorum_leaderless / quorum_skew land in that same
// alert-only bucket on purpose: a leaderless quorum queue's
// membership is already degraded, and deleting a term-skewed member
// can drop the queue under its own Raft quorum (the operator, not a
// pod bounce, re-forms queue leadership).
var rabbitHealableReasons = map[string]bool{
	"mnesia_partition":       true,
	"stuck_unready":          true,
	"fd_limit_alarm":         true,
	"memory_watermark_alarm": true,
}

// rabbitHealableFindings reports whether the pod's finding set
// holds at least one delete-worthy reason.
func rabbitHealableFindings(reasons map[string]bool) bool {
	for r := range reasons {
		if rabbitHealableReasons[r] {
			return true
		}
	}
	return false
}

// rabbitReadySiblings counts the Ready members of pod's OWN
// RabbitmqCluster excluding the pod itself. The self-discount is
// the gray-failure guard: a member under a Prometheus alarm keeps
// reporting Ready, and counting it would let a 3-node cluster at
// 2/3 Ready approve a delete that drops it to 1/3 — Raft quorum
// loss (rabbitmq-quorum-heal). An unlabeled pod resolves through its
// controller owner; unlabeled AND unowned reads 0 — no provable
// siblings, fail closed.
func rabbitReadySiblings(readyByCluster map[string]int,
	readyByOwner map[types.UID]int, pod *corev1.Pod) int {
	var ready int
	if key := rabbitClusterKey(pod); key != "" {
		ready = readyByCluster[key]
	} else if ref := metav1.GetControllerOf(pod); ref != nil {
		ready = readyByOwner[ref.UID]
	}
	// The target may itself still report Ready under an alarm —
	// discount self so the guard requires GENUINELY other members.
	if ready > 0 && probefw.PodRunningReady(pod) {
		ready--
	}
	return ready
}

// checkRabbitMQQuorumHealth watches RabbitMQ quorum/partition
// health two ways: Prometheus alarms (fd-limit / memory / disk
// watermarks, erlang dist node_state != connected) and the
// stuck-unready pod signature — a rabbitmq pod unready >=10m while
// >=2 siblings stay Ready gets deleted (30m cooldown) so the
// cluster re-forms quorum around it. The sweep is collect
// (rabbitmq_quorum_collect.go) → heal (rabbitmq_quorum_heals.go) →
// report; Run below is only the orchestration.
func (p *rabbitMQQuorumHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	census, err := collectRabbitCensus(ctx, p.Deps, log)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	findings := rabbitPromFindings(ctx, p.Deps, log, census)

	hp := newRabbitHealPass(p, log, now, census, findings)
	hp.scanUnready(ctx)
	hp.healPromFindings(ctx)
	hp.clearQuiet(ctx)

	var rep probefw.SweepReport
	for key, reasons := range findings {
		rs := make([]string, 0, len(reasons))
		for r := range reasons {
			rs = append(rs, r)
		}
		sort.Strings(rs)
		parts := strings.SplitN(key, "/", 2)
		ns := parts[0]
		if pod, ok := census.byName[key]; ok {
			joined := strings.Join(rs, "+")
			rep.Flag(rabbitMQQuorumUnhealthyGauge, key+"/"+joined,
				[]string{ns, pod.Name, joined})
		}
		rep.Find(key + "(" + strings.Join(rs, "+") + ")")
	}
	return rep.Result(&p.emitted, rabbitMQQuorumUnhealthyGauge.DeleteLabelValues,
		"rabbitmq quorum/partition signals: ", ", ")
}

// rabbitmq_quorum_health.go — the rabbitmq-quorum-health check
// (W10-ST3): RabbitMQ alarms / Mnesia partition signals from
// Prometheus plus the stuck-unready pod heal while >=2 siblings
// stay Ready.
package datastore

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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
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

// newRabbitMQQuorumHealthCheck builds the W10-ST3 check — its state
// is the seen/emitted ledgers (zero value usable); heal cooldowns
// ride the shared Deps.Heals set via deletePodHeal.
func NewRabbitMQQuorumHealthCheck(d *probefw.Deps) probefw.Check {
	return &rabbitMQQuorumHealthCheck{Deps: d}
}

const (
	CheckNameRabbitMQQuorum = "rabbitmq-quorum-health"

	// W10-ST3 — rabbitmq-quorum-health knobs.
	rabbitUnreadyMinAge  = 10 * time.Minute
	rabbitQuorumHealCool = 30 * time.Minute
)

var (
	// W10-ST3 — RabbitMQ quorum/partition signal.
	rabbitMQQuorumUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_rabbitmq_quorum_unhealthy",
		Help: "1 while the RabbitMQ pod/cluster reports an alarm, partition, stuck-unready, quorum-leaderless or term-skew signature — W10-ST3/W16-ST3.",
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
// members (W12 P0-2a).
func rabbitClusterKey(pod *corev1.Pod) string {
	if name := pod.Labels["app.kubernetes.io/name"]; name != "" {
		return pod.Namespace + "/" + name
	}
	return ""
}

// rabbitHealableReasons is the whitelist of findings that justify a
// member-pod delete — each clears on a fresh start. NOT
// disk_watermark_alarm (W12 P0-2c): a pod delete cannot free the
// PVC, and the restart replays the quorum-queue WAL onto a
// still-full disk; a future unknown reason defaults to alert-only
// too. W16-ST3's quorum_leaderless / quorum_skew land in that same
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
// loss (W12 P0-2b). An unlabeled pod resolves through its
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
// cluster re-forms quorum around it.
func (p *rabbitMQQuorumHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	// A RabbitmqCluster the go-kube-downscaler parked at
	// spec.replicas:0 is asleep on purpose — its members' absence
	// and any lingering alarm series are intent, not a quorum
	// failure. A list failure fails open (empty set): the pod
	// signatures keep their normal posture.
	crs, err := p.AllUnstructured(ctx, kube.GVRRabbitMQCluster)
	downscaled, err := downscaledClusterCRs(crs, err)
	if err != nil {
		log.Info("WARN: list rabbitmqclusters failed — downscaler awareness off",
			"error", err)
	}
	rabbitByName := map[string]*corev1.Pod{}
	rabbitByPodName := map[string]*corev1.Pod{}
	var memberPods []*corev1.Pod
	var unlabeledPods []corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if !isRabbitMQPod(pod) ||
			downscaledMemberPod(pod.Namespace, pod.Name, downscaled) {
			continue
		}
		rabbitByName[pod.Namespace+"/"+pod.Name] = pod
		rabbitByPodName[pod.Name] = pod // ns fallback for series w/o namespace label
		memberPods = append(memberPods, pod)
		if rabbitClusterKey(pod) == "" {
			unlabeledPods = append(unlabeledPods, *pod)
		}
	}

	// Prometheus alarm/partition signals.
	type sig struct{ q, reason string }
	queries := []sig{
		{`rabbitmq_alarms_file_descriptor_limit == 1`, "fd_limit_alarm"},
		{`rabbitmq_alarms_memory_used_watermark == 1`, "memory_watermark_alarm"},
		{`rabbitmq_alarms_free_disk_space_watermark == 1`, "disk_watermark_alarm"},
		{`erlang_vm_dist_node_state != 3`, "mnesia_partition"},
	}
	findings := map[string]map[string]bool{} // "ns/pod" -> reasons
	for _, q := range queries {
		series, err := p.PromQuery(ctx, q.q)
		if err != nil {
			log.Info("WARN: rabbitmq prom query failed — signal skipped",
				"query", q.q, "error", err)
			continue
		}
		for _, s := range series {
			podName := s.Label("pod", "pod_name")
			ns := s.Metric["namespace"]
			if ns == "" {
				if pod := rabbitByPodName[podName]; pod != nil {
					ns = pod.Namespace
				}
			}
			if podName != "" &&
				downscaledMemberPod(ns, podName, downscaled) {
				continue // parked cluster — stale series, not quorum evidence
			}
			key := ns + "/" + podName
			if podName == "" {
				key = "cluster/" + q.reason
			}
			if findings[key] == nil {
				findings[key] = map[string]bool{}
			}
			findings[key][q.reason] = true
		}
	}

	// W16-ST3 — quorum-queue Raft health, beyond the alarm queries:
	//
	// quorum_leaderless — a member publishes rabbitmq_raft_role
	// series for the quorum queues it replicates; when a member's
	// series exist but its sum is 0, none of those queues currently
	// sees it (or anyone, from this member's view) as leader — the
	// queue cannot accept writes. Diffed client-side across two
	// instant queries (the literal `and` form never matches: a ==0
	// comparison produces an empty vector on the leader side, and
	// PromQL `and` intersects it away) — same shape as the NATS
	// meta-leaderless check.
	counts, errC := p.PromQuery(ctx,
		`count by (namespace, pod) (rabbitmq_raft_role)`)
	sums, errS := p.PromQuery(ctx,
		`sum by (namespace, pod) (rabbitmq_raft_role)`)
	if errC != nil || errS != nil {
		log.Info("WARN: rabbitmq raft-role queries failed — quorum_leaderless signal skipped",
			"countErr", errC, "sumErr", errS)
	} else {
		sumByPod := map[string]float64{}
		for _, s := range sums {
			sumByPod[s.Label("namespace")+"/"+s.Label("pod", "pod_name")] = s.Value
		}
		for _, s := range counts {
			podName := s.Label("pod", "pod_name")
			ns := s.Metric["namespace"]
			if ns == "" {
				if pod := rabbitByPodName[podName]; pod != nil {
					ns = pod.Namespace
				}
			}
			if podName == "" || s.Value <= 0 {
				continue
			}
			if sumByPod[ns+"/"+podName] != 0 {
				continue // at least one queue leadership role held — healthy
			}
			if downscaledMemberPod(ns, podName, downscaled) {
				continue // parked cluster — stale series, not quorum evidence
			}
			key := ns + "/" + podName
			if findings[key] == nil {
				findings[key] = map[string]bool{}
			}
			findings[key]["quorum_leaderless"] = true
		}
	}

	// quorum_skew — severe Raft-term lag: a member whose max
	// rabbitmq_raft_term lags the namespace's highest term by >= 2
	// missed >= 2 elections — its WAL view is far behind the
	// cluster's, and its queue replicas cannot vote meaningfully.
	terms, errT := p.PromQuery(ctx,
		`max by (namespace, pod) (rabbitmq_raft_term)`)
	if errT != nil {
		log.Info("WARN: rabbitmq raft-term query failed — quorum_skew signal skipped",
			"error", errT)
	} else {
		// Pool the max term per RabbitmqCLUSTER, not per namespace —
		// two clusters sharing one namespace must not judge each
		// other's terms (same hazard as the Ready-sibling census
		// below, W12 P0-2a): the younger cluster's whole membership
		// would lag the older cluster's term and false-flag skew.
		// Pods we cannot group cluster-wise fall back to the
		// namespace bucket (fail-safe, may over-flag) rather than
		// being skipped silently.
		maxTermByCluster := map[string]float64{}
		for _, s := range terms {
			podName := s.Label("pod", "pod_name")
			ns := s.Metric["namespace"]
			pod := rabbitByPodName[podName]
			if ns == "" && pod != nil {
				ns = pod.Namespace
			}
			ck := ns
			if pod != nil {
				if k := rabbitClusterKey(pod); k != "" {
					ck = k
				}
			}
			if s.Value > maxTermByCluster[ck] {
				maxTermByCluster[ck] = s.Value
			}
		}
		for _, s := range terms {
			podName := s.Label("pod", "pod_name")
			ns := s.Metric["namespace"]
			pod := rabbitByPodName[podName]
			if ns == "" && pod != nil {
				ns = pod.Namespace
			}
			if podName == "" || s.Value <= 0 {
				continue
			}
			ck := ns
			if pod != nil {
				if k := rabbitClusterKey(pod); k != "" {
					ck = k
				}
			}
			// Only judge members of clusters with a real term spread.
			if maxTermByCluster[ck]-s.Value < 2 {
				continue
			}
			if downscaledMemberPod(ns, podName, downscaled) {
				continue
			}
			key := ns + "/" + podName
			if findings[key] == nil {
				findings[key] = map[string]bool{}
			}
			findings[key]["quorum_skew"] = true
		}
	}

	// Ready-sibling census per RabbitmqCluster — the quorum
	// precondition for every heal below (>=2 OTHER members Ready).
	// Grouping by namespace would pool the Ready members of two
	// clusters sharing one namespace into a single tally and "prove"
	// quorum that does not exist (W12 P0-2a). The primary grouping
	// is the operator's app.kubernetes.io/name label; pods missing
	// it fall back to controller-owner grouping via ReadyByOwner,
	// and an unlabeled AND unowned pod cannot prove siblings at all
	// (0 — fail closed).
	readyByCluster := map[string]int{}
	for _, pod := range memberPods {
		if key := rabbitClusterKey(pod); key != "" &&
			probefw.PodRunningReady(pod) {
			readyByCluster[key]++
		}
	}
	readyByOwner := probefw.ReadyByOwner(unlabeledPods)

	// W17 heal budget — at most ONE member pod per RabbitmqCluster
	// per sweep, and the Ready census is decremented the moment a
	// delete lands: a later candidate in the SAME sweep must see the
	// quorum the first delete actually left behind, not the census
	// taken before it. The cooldown keys on the CLUSTER (the
	// operator's app.kubernetes.io/name label), falling back to the
	// pod's controller key for unlabeled members — a pod-name key
	// dies with the pod, so a re-created member would re-heal every
	// sweep. The Heals stamp only lands on a DELIVERED delete
	// (heal.DeletePod's contract), so the missing→fresh stamp
	// transition is how success reads.
	healedCluster := map[string]bool{}
	tryQuorumHeal := func(pod *corev1.Pod) {
		ck := rabbitClusterKey(pod)
		if ck == "" {
			ck = kube.PodControllerKey(pod)
		}
		if healedCluster[ck] {
			return // one pod per cluster per sweep
		}
		hk := probefw.SelfHealKey(CheckNameRabbitMQQuorum, ck)
		before, _ := p.Heals.Last(hk)
		p.DeletePodHeal(ctx, log, CheckNameRabbitMQQuorum,
			ck, pod, rabbitQuorumHealCool, now)
		if stamp, ok := p.Heals.Last(hk); ok && stamp.After(before) {
			healedCluster[ck] = true
			// Only discount a pod the census counted Ready
			// (PodRunningReady): pass-1 deletes of already-unready
			// members never entered the tally, and decrementing
			// anyway would erase a Ready sibling that still exists —
			// the next candidate would then see a quorum that is
			// one short of reality and defer a legitimate heal.
			if probefw.PodRunningReady(pod) {
				if rck := rabbitClusterKey(pod); rck != "" {
					if readyByCluster[rck] > 0 {
						readyByCluster[rck]--
					}
				} else if ref := metav1.GetControllerOf(pod); ref != nil {
					if readyByOwner[ref.UID] > 0 {
						readyByOwner[ref.UID]--
					}
				}
			}
		}
	}

	// Stuck-unready pod signature — independent of Prometheus.
	seenKeep := map[string]bool{}
	for _, pod := range memberPods {
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		since, unready := probefw.PodUnreadySince(pod)
		if !unready {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		if now.Sub(since) < rabbitUnreadyMinAge {
			continue
		}
		if findings[key] == nil {
			findings[key] = map[string]bool{}
		}
		findings[key]["stuck_unready"] = true
		// Heal only when quorum survives: >=2 OTHER members of the
		// SAME cluster Ready — the unready pod itself is never
		// Ready, so the sibling count already excludes it.
		if rabbitReadySiblings(readyByCluster, readyByOwner, pod) >= 2 {
			tryQuorumHeal(pod)
		}
	}

	// Prometheus-flagged pods (alarm / Mnesia partition) get the same
	// heal once the signal persists >=10m and quorum survives — a
	// partitioned-but-Ready member is exactly the "partitioned >10m"
	// shape the plan calls out. The shared cooldown key dedupes pods
	// already healed via the unready path.
	for key := range findings {
		pod, ok := rabbitByName[key]
		if !ok || pod.DeletionTimestamp != nil {
			continue
		}
		sig := "prom/" + key
		seenKeep[sig] = true
		// The alarm/partition window gates a pod delete, so it runs
		// the persisted (annotation-backed) variant — the stamp on
		// the pod survives an operator restart that would otherwise
		// re-arm the full 10m while the signature still held.
		if !heal.FirstSeenPersisted(ctx, log, &p.seen, pod,
			kube.AnnoFirstSeenRabbitQuorum, sig, rabbitUnreadyMinAge,
			now, kube.PodMergePatcher(p.CS, pod)) {
			continue
		}
		// disk_watermark_alarm is deliberately non-healable (W12
		// P0-2c): deleting the pod cannot free its PVC, and the
		// restart replays the quorum-queue WAL onto a still-full
		// disk. The finding still FAILs the check and emits the
		// gauge below — it just never deletes.
		if !rabbitHealableFindings(findings[key]) {
			continue
		}
		// >=2 OTHER members of the same cluster Ready — the
		// alarmed pod may itself still report Ready (the
		// gray-failure shape), and counting it would let a 3-node
		// cluster at 2/3 Ready approve a delete that drops it to
		// 1/3 — Raft quorum loss (W12 P0-2b).
		if rabbitReadySiblings(readyByCluster, readyByOwner, pod) >= 2 {
			tryQuorumHeal(pod)
		}
	}
	// A member pod whose signal went quiet drops its persisted stamp
	// so a recurrence re-arms the full window — a stale stamp would
	// fast-trip the heal. Terminating pods are skipped (the stamp
	// dies with them); a clear failure is a tolerated sub-failure —
	// the ledger Forget already landed, the annotation retry is
	// Warn-only. The stuck_unready path's window is pod-carried
	// (PodUnreadySince) and needs no clear.
	for key, pod := range rabbitByName {
		if findings[key] != nil || pod.DeletionTimestamp != nil {
			continue
		}
		if err := heal.ClearPersistedFirstSeen(ctx, log, &p.seen, pod,
			kube.AnnoFirstSeenRabbitQuorum, "prom/"+key,
			kube.PodMergePatcher(p.CS, pod)); err != nil {
			log.Info("WARN: rabbitmq quorum first-seen clear failed",
				"pod", key, "error", err)
		}
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })

	var rep probefw.SweepReport
	for key, reasons := range findings {
		rs := make([]string, 0, len(reasons))
		for r := range reasons {
			rs = append(rs, r)
		}
		sort.Strings(rs)
		parts := strings.SplitN(key, "/", 2)
		ns := parts[0]
		if pod, ok := rabbitByName[key]; ok {
			joined := strings.Join(rs, "+")
			rep.Flag(rabbitMQQuorumUnhealthyGauge, key+"/"+joined,
				[]string{ns, pod.Name, joined})
		}
		rep.Find(key + "(" + strings.Join(rs, "+") + ")")
	}
	return rep.Result(&p.emitted, rabbitMQQuorumUnhealthyGauge.DeleteLabelValues,
		"rabbitmq quorum/partition signals: ", ", ")
}

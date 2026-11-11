// rabbitmq_quorum_heals.go — the heal half of the
// rabbitmq-quorum-health check: the Ready-sibling census that gates
// every member-pod delete, the one-pod-per-cluster-per-sweep budget
// with its post-delete census discount, the persisted first-seen
// windows, and the quiet-signal stamp clears. Split out of
// rabbitmq_quorum_health.go — see that file for the check and
// rabbitmq_quorum_collect.go for what the findings are.
package rabbitmq

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// rabbitHealPass carries one sweep's heal state: the census and
// findings the collect half produced, the Ready tallies every
// quorum decision reads (decremented the moment a delete lands so
// a later candidate sees the quorum the first delete actually left
// behind, not the census taken before it), and the per-cluster /
// per-pod dedupe sets.
type rabbitHealPass struct {
	p              *rabbitMQQuorumHealthCheck
	log            logr.Logger
	now            time.Time
	census         *rabbitCensus
	findings       map[string]map[string]bool
	readyByCluster map[string]int
	readyByOwner   map[types.UID]int
	healedCluster  map[string]bool
	seenKeep       map[string]bool
}

// newRabbitHealPass builds the pass and takes the Ready-sibling
// census per RabbitmqCluster — the quorum precondition for every
// heal below (>=2 OTHER members Ready). Grouping by namespace
// would pool the Ready members of two clusters sharing one
// namespace into a single tally and "prove" quorum that does not
// exist (rabbitmq-quorum-heal). The primary grouping is the
// operator's app.kubernetes.io/name label; pods missing it fall
// back to controller-owner grouping via ReadyByOwner, and an
// unlabeled AND unowned pod cannot prove siblings at all
// (0 — fail closed).
func newRabbitHealPass(p *rabbitMQQuorumHealthCheck, log logr.Logger,
	now time.Time, c *rabbitCensus,
	findings map[string]map[string]bool) *rabbitHealPass {
	h := &rabbitHealPass{
		p:              p,
		log:            log,
		now:            now,
		census:         c,
		findings:       findings,
		readyByCluster: map[string]int{},
		healedCluster:  map[string]bool{},
		seenKeep:       map[string]bool{},
	}
	for _, pod := range c.members {
		if key := rabbitClusterKey(pod); key != "" &&
			probefw.PodRunningReady(pod) {
			h.readyByCluster[key]++
		}
	}
	h.readyByOwner = probefw.ReadyByOwner(c.unlabeled)
	return h
}

// tryHeal is the heal-budget gate: at most ONE member pod per
// RabbitmqCluster per sweep. The cooldown keys on the CLUSTER (the
// operator's app.kubernetes.io/name label), falling back to the
// pod's controller key for unlabeled members — a pod-name key dies
// with the pod, so a re-created member would re-heal every sweep.
// The Heals stamp only lands on a DELIVERED delete (heal.DeletePod's
// contract), so the missing→fresh stamp transition is how success
// reads; a landed delete decrements the Ready census so the next
// candidate in this sweep sees the quorum actually left behind.
func (h *rabbitHealPass) tryHeal(ctx context.Context, pod *corev1.Pod) {
	ck := rabbitClusterKey(pod)
	if ck == "" {
		ck = kube.PodControllerKey(pod)
	}
	if h.healedCluster[ck] {
		return // one pod per cluster per sweep
	}
	hk := probefw.SelfHealKey(CheckNameRabbitMQQuorum, ck)
	before, _ := h.p.Heals.Last(hk)
	h.p.DeletePodHeal(ctx, h.log, CheckNameRabbitMQQuorum,
		ck, pod, rabbitQuorumHealCool, h.now)
	if stamp, ok := h.p.Heals.Last(hk); ok && stamp.After(before) {
		h.healedCluster[ck] = true
		// Only discount a pod the census counted Ready
		// (PodRunningReady): pass-1 deletes of already-unready
		// members never entered the tally, and decrementing
		// anyway would erase a Ready sibling that still exists —
		// the next candidate would then see a quorum that is
		// one short of reality and defer a legitimate heal.
		if probefw.PodRunningReady(pod) {
			if rck := rabbitClusterKey(pod); rck != "" {
				if h.readyByCluster[rck] > 0 {
					h.readyByCluster[rck]--
				}
			} else if ref := metav1.GetControllerOf(pod); ref != nil {
				if h.readyByOwner[ref.UID] > 0 {
					h.readyByOwner[ref.UID]--
				}
			}
		}
	}
}

// scanUnready runs the stuck-unready pod signature — independent of
// Prometheus: a rabbitmq pod unready >=10m while >=2 siblings of the
// SAME cluster stay Ready gets deleted so the cluster re-forms
// quorum around it. Each hit also lands a stuck_unready finding.
func (h *rabbitHealPass) scanUnready(ctx context.Context) {
	for _, pod := range h.census.members {
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
		if h.now.Sub(since) < rabbitUnreadyMinAge {
			continue
		}
		if h.findings[key] == nil {
			h.findings[key] = map[string]bool{}
		}
		h.findings[key]["stuck_unready"] = true
		// Heal only when quorum survives: >=2 OTHER members of the
		// SAME cluster Ready — the unready pod itself is never
		// Ready, so the sibling count already excludes it.
		if rabbitReadySiblings(h.readyByCluster, h.readyByOwner, pod) >= 2 {
			h.tryHeal(ctx, pod)
		}
	}
}

// healPromFindings runs the Prometheus-flagged heal pass: an
// alarm/partitioned member gets deleted once the signal persists
// >=10m and quorum survives — a partitioned-but-Ready member is
// exactly the "partitioned >10m" shape the plan calls out. The
// shared cooldown key dedupes pods already healed via the unready
// path.
func (h *rabbitHealPass) healPromFindings(ctx context.Context) {
	for key := range h.findings {
		pod, ok := h.census.byName[key]
		if !ok || pod.DeletionTimestamp != nil {
			continue
		}
		sig := "prom/" + key
		h.seenKeep[sig] = true
		// The alarm/partition window gates a pod delete, so it runs
		// the persisted (annotation-backed) variant — the stamp on
		// the pod survives an operator restart that would otherwise
		// re-arm the full 10m while the signature still held.
		if !heal.FirstSeenPersisted(ctx, h.log, &h.p.seen, pod,
			kube.AnnoFirstSeenRabbitQuorum, sig, rabbitUnreadyMinAge,
			h.now, kube.PodMergePatcher(h.p.CS, pod)) {
			continue
		}
		// disk_watermark_alarm is deliberately non-healable
		// (rabbitmq-quorum-heal): deleting the pod cannot free its
		// PVC, and the restart replays the quorum-queue WAL onto a
		// still-full disk. The finding still FAILs the check and
		// emits the gauge — it just never deletes.
		if !rabbitHealableFindings(h.findings[key]) {
			continue
		}
		// >=2 OTHER members of the same cluster Ready — the
		// alarmed pod may itself still report Ready (the
		// gray-failure shape), and counting it would let a 3-node
		// cluster at 2/3 Ready approve a delete that drops it to
		// 1/3 — Raft quorum loss (rabbitmq-quorum-heal).
		if rabbitReadySiblings(h.readyByCluster, h.readyByOwner, pod) >= 2 {
			h.tryHeal(ctx, pod)
		}
	}
}

// clearQuiet drops the persisted first-seen stamp of every member
// pod whose Prometheus signal went quiet so a recurrence re-arms
// the full window — a stale stamp would fast-trip the heal.
// Terminating pods are skipped (the stamp dies with them); a clear
// failure is a tolerated sub-failure — the ledger Forget already
// landed, the annotation retry is Warn-only. The stuck_unready
// path's window is pod-carried (PodUnreadySince) and needs no
// clear. seen.Prune then drops ledger keys no live signal kept.
func (h *rabbitHealPass) clearQuiet(ctx context.Context) {
	for key, pod := range h.census.byName {
		if h.findings[key] != nil || pod.DeletionTimestamp != nil {
			continue
		}
		if err := heal.ClearPersistedFirstSeen(ctx, h.log, &h.p.seen, pod,
			kube.AnnoFirstSeenRabbitQuorum, "prom/"+key,
			kube.PodMergePatcher(h.p.CS, pod)); err != nil {
			h.log.Info("WARN: rabbitmq quorum first-seen clear failed",
				"pod", key, "error", err)
		}
	}
	h.p.seen.Prune(func(k string) bool { return h.seenKeep[k] })
}

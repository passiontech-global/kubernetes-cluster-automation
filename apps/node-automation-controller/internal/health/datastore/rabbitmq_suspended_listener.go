// rabbitmq_suspended_listener.go — the rabbitmq-suspended-listener
// rabbitmq-suspended-listener healer: deletes a Running-but-never-
// Ready rabbit pod once the quorum-safe check passes.
package datastore

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// rabbitMQSuspendedCheck is the rabbitmq-suspended-listener suspended-listener healer.
type rabbitMQSuspendedCheck struct {
	*probefw.Deps

	// rabbitmq-suspended-listener watchdog state (serial sweep — unguarded):
	//   - rbSuspendedSince: "ns/pod/uid" → first sweep the pod
	//     showed the suspended-listener signature (uid in the key
	//     keeps a same-named replacement from inheriting the streak).
	//   - rbHealed: "ns/pod" → last delete — the 30m heal cooldown.
	rbSuspendedSince state.FirstSeenLedger
	rbHealed         state.CooldownSet
}

// newRabbitMQSuspendedCheck builds the rabbitmq-suspended-listener check — both ledgers
// arm lazily on first use.
func NewRabbitMQSuspendedCheck(d *probefw.Deps) probefw.Check {
	return &rabbitMQSuspendedCheck{Deps: d}
}

// rabbitmq-suspended-listener — rabbitmq-suspended-listener knobs.
const (
	// CheckNameRabbitMQSuspended is the check's kuberhealthy_check
	// label value — rabbitmq-suspended-listener; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNameRabbitMQSuspended = "rabbitmq-suspended-listener"
	rabbitComponentLabel       = "app.kubernetes.io/component=rabbitmq"
	rabbitSuspendedMinAge      = 10 * time.Minute
	rabbitHealCooldown         = 30 * time.Minute
)

var (
	// rabbitmq-suspended-listener — RabbitMQ pods deleted while running with a suspended
	// listener (started but never Ready). Counts delivered heals
	// only — the counter increments after a quorum-safe delete
	// landed.
	rabbitMQSuspendedHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_rabbitmq_suspended_heals_total",
		Help: "RabbitMQ pods deleted while running with a suspended listener (started but never Ready).",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		rabbitMQSuspendedHealsTotal)
}

// ---------------------------------------------------------------------------
// rabbitmq-suspended-listener (rabbitmq-suspended-listener) — suspended listener healer.
// ---------------------------------------------------------------------------

// rabbitSuspended reports the suspended-listener signature: the pod
// is Running and every container Started (kubelet launched them) but
// none ever went Ready — the rabbit listener sits on the
// ranch:suspended branch refusing port 5672 while the pod looks
// "almost healthy" to every coarse check.
func rabbitSuspended(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return false
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, s := range pod.Status.ContainerStatuses {
		if s.Started == nil || !*s.Started || s.Ready {
			return false
		}
	}
	return true
}

// rabbitQuorumSafe verifies deleting the suspended pod cannot break
// the cluster quorum: the pod must be owned by a StatefulSet whose
// every OTHER replica is Ready — a peer that is itself suspended or
// down means the delete could take the cluster below quorum, so the
// heal stands down and the FAIL series keeps alerting instead.
func (p *rabbitMQSuspendedCheck) rabbitQuorumSafe(ctx context.Context, pod *corev1.Pod) (bool, error) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "StatefulSet" {
		return false, nil // cannot verify peers — do not touch
	}
	sts, err := p.CS.AppsV1().StatefulSets(pod.Namespace).
		Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("get statefulset %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	sel, err := metav1.LabelSelectorAsSelector(sts.Spec.Selector)
	if err != nil {
		return false, fmt.Errorf("statefulset selector %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	peers, err := p.PodsMatching(ctx, pod.Namespace, sel.String())
	if err != nil {
		return false, fmt.Errorf("list peer pods of %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	// BUG-C2: quorum must be verified against the DESIRED membership,
	// not just "every listed peer is Ready" — a scaled-down or
	// mid-churn set where fewer than spec.replicas pods even exist
	// cannot prove the delete leaves quorum intact. Require the full
	// pod count AND replicas-1 READY peers (the suspended pod itself
	// holds the remaining vote). ReadySiblings counts Running+Ready
	// non-deleting pods sharing the pod's StatefulSet owner —
	// strictly stronger than a bare Ready-condition read (a
	// terminating-but-Ready peer cannot absorb traffic either).
	if sts.Spec.Replicas == nil {
		return false, nil
	}
	want := int(*sts.Spec.Replicas)
	if len(peers) < want {
		return false, nil
	}
	// ReadyByOwner takes values — the snapshot's pointer view is
	// read-only anyway, so a cheap deref keeps the shared helper.
	peerPods := make([]corev1.Pod, 0, len(peers))
	for _, peer := range peers {
		peerPods = append(peerPods, *peer)
	}
	if probefw.ReadySiblings(probefw.ReadyByOwner(peerPods), pod) < want-1 {
		return false, nil
	}
	return true, nil
}

// checkRabbitMQSuspendedPods heals the RabbitMQ suspended-listener
// wedge: a pod whose containers all started but never went Ready is
// partitioned from its own cluster while holding a peer slot. Stuck
// >=10m AND all other replicas Ready (quorum survives) → delete the
// pod so the StatefulSet controller brings up a clean replica; the
// rabbitMQSuspendedHealsTotal counter records each heal.
func (p *rabbitMQSuspendedCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	// rbHealed keys "ns/pod" — a deleted pod's name can never
	// suppress again once its window passed, so bound the map once
	// per sweep at the heal cooldown.
	p.rbHealed.PruneExpired(now, rabbitHealCooldown)

	pods, err := p.PodsMatching(ctx, metav1.NamespaceAll, rabbitComponentLabel)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list rabbitmq pods: %w", err)}
	}

	live := map[string]bool{} // "ns/pod/uid" suspended signatures this sweep
	var rep probefw.SweepReport
	var due []corev1.Pod
	for i := range pods {
		pod := pods[i]
		key := pod.Namespace + "/" + pod.Name + "/" + string(pod.UID)
		// The suspended-listener window gates a pod delete, so it
		// runs the persisted (annotation-backed) variant — the stamp
		// on the pod survives an operator restart that would
		// otherwise re-arm the full 10m mid-wedge. A pod that reads
		// healthy clears the stamp so a recurrence re-arms the full
		// window; a clear failure is tolerated (Warn only) — the
		// ledger Forget already landed, the durable half retries
		// next sweep.
		patch := kube.PodMergePatcher(p.CS, pod)
		if !rabbitSuspended(pod) {
			if err := heal.ClearPersistedFirstSeen(ctx, log,
				&p.rbSuspendedSince, pod,
				kube.AnnoFirstSeenRabbitSuspended, key,
				patch); err != nil {
				log.Info("WARN: suspended-listener first-seen clear failed",
					"pod", pod.Namespace+"/"+pod.Name, "error", err)
			}
			continue
		}
		live[key] = true
		if heal.FirstSeenPersisted(ctx, log, &p.rbSuspendedSince, pod,
			kube.AnnoFirstSeenRabbitSuspended, key,
			rabbitSuspendedMinAge, now, patch) {
			rep.Find(pod.Namespace + "/" + pod.Name)
			due = append(due, *pod)
		}
	}
	p.rbSuspendedSince.Prune(func(k string) bool { return live[k] })

	// Per-pod heal preamble — the quorum-safety read first, then
	// cooldown + maintenance mutex via HealAllowed like every
	// pod-delete heal in this sweep. The Deps-wide verdict memoizes
	// the mutex evaluation, so the loop still pays a single set of
	// API reads when several pods are due; "cannot verify" fails
	// closed.
	for i := range due {
		pod := &due[i]
		key := pod.Namespace + "/" + pod.Name
		// Quorum FIRST, cooldown/mutex second: the quorum-safety read
		// answers "may this pod ever be deleted" while the heal gate
		// only answers "may it be deleted NOW" — a pod that would
		// break the cluster must never consume the heal budget or
		// the Deps-wide maintenance-mutex verdict slot, so the
		// quorum guard runs before HealAllowed (heal-budget).
		safe, err := p.rabbitQuorumSafe(ctx, pod)
		if err != nil {
			metrics.IncError(p.Name)
			log.Info("WARN: quorum check failed — heal deferred",
				"pod", key, "error", err)
			continue
		}
		if !safe {
			log.Info("quorum unsafe — suspended rabbitmq pod kept (peers not all Ready)",
				"pod", key)
			continue
		}
		proceed, unverifiable := p.HealAllowed(ctx, log,
			&p.rbHealed, key, rabbitHealCooldown, now)
		if unverifiable {
			metrics.IncError(p.Name)
			continue
		}
		if !proceed {
			continue
		}
		if _, err := heal.DeletePod(ctx, p.CS, &p.rbHealed, key, pod, now); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "suspended rabbitmq pod delete failed", "pod", key)
			continue
		}
		p.InvalidatePods(ctx) // pod gone — drop the census
		rabbitMQSuspendedHealsTotal.
			WithLabelValues(pod.Namespace, pod.Name).Inc()
		log.Info("DELETE: suspended-listener rabbitmq pod — quorum verified",
			"pod", key)
	}

	return rep.Verdict(fmt.Sprintf(
		"rabbitmq pods running suspended >=%s: ",
		rabbitSuspendedMinAge), ", ")
}

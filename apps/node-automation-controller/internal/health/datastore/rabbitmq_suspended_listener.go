package datastore

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// rabbitMQSuspendedCheck is the W6.4 suspended-listener healer.
type rabbitMQSuspendedCheck struct {
	*probefw.Deps

	// W6.4 watchdog state (serial sweep — unguarded):
	//   - rbSuspendedSince: "ns/pod/uid" → first sweep the pod
	//     showed the suspended-listener signature (uid in the key
	//     keeps a same-named replacement from inheriting the streak).
	//   - rbHealed: "ns/pod" → last delete — the 30m heal cooldown.
	rbSuspendedSince state.FirstSeenLedger
	rbHealed         state.CooldownSet
	// verdict memoizes the maintenance-mutex evaluation the
	// per-pod heal preambles share — one evaluation per Verdict TTL
	// instead of three API reads per suspended pod.
	verdict kube.Verdict
}

// newRabbitMQSuspendedCheck builds the W6.4 check — both ledgers
// arm lazily on first use.
func NewRabbitMQSuspendedCheck(d *probefw.Deps) probefw.Check {
	return &rabbitMQSuspendedCheck{Deps: d}
}

// W6.4 — rabbitmq-suspended-listener knobs.
const (
	// CheckNameRabbitMQSuspended is the check's kuberhealthy_check
	// label value — W6.4; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNameRabbitMQSuspended = "rabbitmq-suspended-listener"
	rabbitComponentLabel       = "app.kubernetes.io/component=rabbitmq"
	rabbitSuspendedMinAge      = 10 * time.Minute
	rabbitHealCooldown         = 30 * time.Minute
)

var (
	// W6.4 — RabbitMQ pods deleted while running with a suspended
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
// rabbitmq-suspended-listener (W6.4) — suspended listener healer.
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
	peers, err := p.CS.CoreV1().Pods(pod.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
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
	if len(peers.Items) < want {
		return false, nil
	}
	if probefw.ReadySiblings(probefw.ReadyByOwner(peers.Items), pod) < want-1 {
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

	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{LabelSelector: rabbitComponentLabel})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list rabbitmq pods: %w", err)}
	}

	live := map[string]bool{} // "ns/pod/uid" suspended signatures this sweep
	var due []corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !rabbitSuspended(pod) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name + "/" + string(pod.UID)
		live[key] = true
		if probefw.Persisted(&p.rbSuspendedSince, key, now,
			rabbitSuspendedMinAge, log) {
			due = append(due, *pod)
		}
	}
	p.rbSuspendedSince.Prune(func(k string) bool { return live[k] })

	// Per-pod heal preamble — cooldown + maintenance mutex run by
	// heal.AllowedV like every pod-delete heal in this sweep. The
	// check's verdict memoizes the mutex evaluation, so the loop
	// still pays a single set of API reads when several pods are
	// due; "cannot verify" fails closed.
	for i := range due {
		pod := &due[i]
		key := pod.Namespace + "/" + pod.Name
		proceed, unverifiable := heal.AllowedV(ctx, log, &p.verdict,
			p.CS, p.Dyn, &p.rbHealed, key, rabbitHealCooldown, now)
		if unverifiable {
			metrics.IncError(p.Name)
			continue
		}
		if !proceed {
			continue
		}
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
		if _, err := heal.DeletePod(ctx, p.CS, &p.rbHealed, key, pod, now); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "suspended rabbitmq pod delete failed", "pod", key)
			continue
		}
		rabbitMQSuspendedHealsTotal.
			WithLabelValues(pod.Namespace, pod.Name).Inc()
		log.Info("DELETE: suspended-listener rabbitmq pod — quorum verified",
			"pod", key)
	}

	if len(due) == 0 {
		return probefw.Result{Pass: true}
	}
	names := make([]string, 0, len(due))
	for i := range due {
		names = append(names, due[i].Namespace+"/"+due[i].Name)
	}
	sort.Strings(names)
	return probefw.Result{Why: fmt.Sprintf(
		"rabbitmq pods running suspended >=%s: %s",
		rabbitSuspendedMinAge, strings.Join(names, ", "))}
}

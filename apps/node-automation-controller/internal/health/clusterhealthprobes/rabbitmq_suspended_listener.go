package clusterhealthprobes

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// rabbitMQSuspendedCheck is the W6.4 suspended-listener healer.
type rabbitMQSuspendedCheck struct {
	*deps

	// W6.4 watchdog state (under mu):
	//   - rbSuspendedSince: "ns/pod/uid" → first sweep the pod
	//     showed the suspended-listener signature (uid in the key
	//     keeps a same-named replacement from inheriting the streak).
	//   - rbHealed: "ns/pod" → last delete — the 30m heal cooldown.
	rbSuspendedSince map[string]time.Time
	rbHealed         map[string]time.Time
}

// W6.4 — rabbitmq-suspended-listener knobs.
const (
	rabbitComponentLabel  = "app.kubernetes.io/component=rabbitmq"
	rabbitSuspendedMinAge = 10 * time.Minute
	rabbitHealCooldown    = 30 * time.Minute
)

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
	sts, err := p.cs.AppsV1().StatefulSets(pod.Namespace).
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
	peers, err := p.cs.CoreV1().Pods(pod.Namespace).List(ctx,
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
	// holds the remaining vote).
	if sts.Spec.Replicas == nil {
		return false, nil
	}
	want := int(*sts.Spec.Replicas)
	if len(peers.Items) < want {
		return false, nil
	}
	readyPeers := 0
	for i := range peers.Items {
		peer := &peers.Items[i]
		if peer.UID == pod.UID {
			continue
		}
		if shared.PodReadyCond(peer) {
			readyPeers++
		}
	}
	if readyPeers < want-1 {
		return false, nil
	}
	return true, nil
}

// checkRabbitMQSuspendedPods heals the RabbitMQ suspended-listener
// wedge: a pod whose containers all started but never went Ready is
// partitioned from its own cluster while holding a peer slot. Stuck
// >=10m AND all other replicas Ready (quorum survives) → delete the
// pod so the StatefulSet controller brings up a clean replica; the
// RabbitMQSuspendedHealsTotal counter records each heal.
func (p *rabbitMQSuspendedCheck) run(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.rbSuspendedSince == nil {
		p.rbSuspendedSince = map[string]time.Time{}
	}
	if p.rbHealed == nil {
		p.rbHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{LabelSelector: rabbitComponentLabel})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list rabbitmq pods: %w", err)}
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
		p.mu.Lock()
		first, ok := p.rbSuspendedSince[key]
		if !ok {
			p.rbSuspendedSince[key] = now
		}
		p.mu.Unlock()
		if !ok {
			log.Info("rabbitmq suspended-listener signature — tracking first-seen",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		if now.Sub(first) >= rabbitSuspendedMinAge {
			due = append(due, *pod)
		}
	}
	p.mu.Lock()
	for k := range p.rbSuspendedSince {
		if !live[k] {
			delete(p.rbSuspendedSince, k)
		}
	}
	p.mu.Unlock()

	// Maintenance mutex — evaluated once per sweep and only when
	// there is something to delete: pod kills during a drain/upgrade
	// are exactly what the mutex exists to prevent; "cannot verify"
	// fails closed.
	var maintHeld bool
	var maintWhy string
	var maintErr error
	if len(due) > 0 {
		maintHeld, maintWhy, maintErr = shared.MaintenanceActive(ctx, p.cs, p.dyn)
		if maintErr != nil {
			metrics.IncError(clusterHealthQueue)
			log.Info("WARN: maintenance check unverifiable — heals deferred (fail closed)",
				"error", maintErr)
		}
	}
	for i := range due {
		pod := &due[i]
		key := pod.Namespace + "/" + pod.Name
		if maintErr != nil || maintHeld {
			log.Info("maintenance gate — suspended rabbitmq pod kept",
				"pod", key, "why", maintWhy)
			continue
		}
		p.mu.Lock()
		last, ok := p.rbHealed[key]
		p.mu.Unlock()
		if ok && now.Sub(last) < rabbitHealCooldown {
			log.Info("skip heal: rabbitmq pod inside cooldown",
				"pod", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		safe, err := p.rabbitQuorumSafe(ctx, pod)
		if err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Info("WARN: quorum check failed — heal deferred",
				"pod", key, "error", err)
			continue
		}
		if !safe {
			log.Info("quorum unsafe — suspended rabbitmq pod kept (peers not all Ready)",
				"pod", key)
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "suspended rabbitmq pod delete failed", "pod", key)
			continue
		}
		p.mu.Lock()
		p.rbHealed[key] = now
		p.mu.Unlock()
		metrics.RabbitMQSuspendedHealsTotal.
			WithLabelValues(pod.Namespace, pod.Name).Inc()
		log.Info("DELETE: suspended-listener rabbitmq pod — quorum verified",
			"pod", key)
	}

	if len(due) == 0 {
		return probeResult{pass: true}
	}
	names := make([]string, 0, len(due))
	for i := range due {
		names = append(names, due[i].Namespace+"/"+due[i].Name)
	}
	sort.Strings(names)
	return probeResult{why: fmt.Sprintf(
		"rabbitmq pods running suspended >=%s: %s",
		rabbitSuspendedMinAge, strings.Join(names, ", "))}
}

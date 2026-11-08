// pod_bounce.go — the W9-CP1 stage-1 remediation behind the C1
// circuit breaker: a webhook backend whose Ready endpoints ALL fail
// the TCP+TLS handshake has hung pods, not partitioned ones, so the
// sweep deletes the oldest Ready backing pod for its controller to
// recreate fresh — one bounce per service per BounceCooldown,
// gated by the shared maintenance mutex (fail closed).
package circuitbreaker

import (
	"context"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// bounceHungWebhookPods is the W9-CP1 stage-1 remediation: for every
// Service referenced by a webhook config whose census verdict is
// "unresponsive" (Ready endpoints on healthy nodes, ALL probed IPs
// failing TCP+TLS), delete the oldest Ready backing pod — its owner
// controller (Deployment/ReplicaSet) recreates it fresh, which is
// the rolling bounce a hung webhook process needs. One bounce per
// service per BounceCooldown; the whole pass is gated by the
// shared maintenance mutex and fails closed like every other pod
// kill in this module.
func (b *Breaker) bounceHungWebhookPods(ctx context.Context,
	snap *guardstate.Snapshot, ready guardstate.EndpointCensus) {
	g := snap.G
	log := logf.FromContext(ctx)
	now := g.Now.Now()
	// Distinct unresponsive webhook backend services, deduped across
	// configs and kinds — several webhooks routinely share one
	// Service, and one hung pod set is one bounce.
	var keys []string
	seen := map[string]bool{}
	add := func(svc *admissionv1.ServiceReference) {
		if svc == nil || svc.Namespace == "" || svc.Name == "" {
			return
		}
		key := svc.Namespace + "/" + svc.Name
		if seen[key] {
			return
		}
		if ready.Effective[key] <= 0 || !ready.Probed[key] || ready.Responsive[key] {
			return // not brownout-hung — healthy, partitioned or unprobed
		}
		if b.bounceAt.CooledDown(key, BounceCooldown, now) {
			return // inside the per-service cooldown
		}
		seen[key] = true
		keys = append(keys, key)
	}
	for _, views := range allHookViews(snap) {
		for _, h := range views {
			add(h.svc)
		}
	}
	if len(keys) == 0 {
		return
	}

	// The maintenance mutex gates the bounce (W7-C1 posture): a
	// cordon/drain/kured reboot or in-flight k0s upgrade defers the
	// pod kill, and "cannot verify" fails closed.
	held, why, err := g.MaintenanceActive(ctx)
	if err != nil {
		metrics.IncError(g.Queue)
		log.Info("WARN: maintenance check unverifiable — "+
			"DEFER: webhook pod bounce skipped (fail closed)",
			"error", err, "services", keys)
		return
	}
	if held {
		log.Info("DEFER: maintenance active — webhook pod bounce skipped",
			"why", why, "services", keys)
		return
	}
	for _, key := range keys {
		b.bounceOldestPod(ctx, snap, key, ready.BackingPods[key], now)
	}
}

// bounceOldestPod deletes the oldest Ready, non-terminating backing
// pod of an unresponsive webhook Service — "oldest" because the hung
// process is usually the longest-lived replica, and one pod per
// bounce keeps the rollout gentle. The delete carries the pod's UID
// as a precondition so a same-named replacement admitted between the
// census and the delete is never killed by mistake.
func (b *Breaker) bounceOldestPod(ctx context.Context, snap *guardstate.Snapshot, svcKey string,
	refs []guardstate.PodRef, now time.Time) {
	g := snap.G
	log := logf.FromContext(ctx)
	var oldest *corev1.Pod
	for _, r := range refs {
		p, getErr := g.CS.CoreV1().Pods(r.Namespace).Get(ctx, r.Name, metav1.GetOptions{})
		gone, err := kube.ConfirmAbsent(getErr)
		if err != nil {
			metrics.IncError(g.Queue)
			log.Error(err, "webhook backing pod get failed",
				"pod", r.Namespace+"/"+r.Name, "service", svcKey)
			continue
		}
		if gone {
			continue // endpoint ref already stale — the pod is gone
		}
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning ||
			!kube.PodReadyCond(p) {
			continue
		}
		if oldest == nil ||
			p.CreationTimestamp.Time.Before(oldest.CreationTimestamp.Time) {
			oldest = p
		}
	}
	if oldest == nil {
		log.Info("webhook bounce: no Ready backing pod found — endpoint refs are stale",
			"service", svcKey)
		return
	}
	log.Info("BOUNCE: deleting oldest Ready webhook pod — hung TCP+TLS handshake",
		"service", svcKey, "pod", oldest.Namespace+"/"+oldest.Name,
		"age", now.Sub(oldest.CreationTimestamp.Time).Truncate(time.Second))
	// heal.DeletePod stamps bounceAt on a DELIVERED bounce only — a
	// failed delete leaves the pod hung and the next sweep retries.
	if _, err := heal.DeletePod(ctx, g.CS, &b.bounceAt, svcKey,
		oldest, now); err != nil {
		metrics.IncError(g.Queue)
		log.Error(err, "webhook pod bounce delete failed",
			"pod", oldest.Namespace+"/"+oldest.Name, "service", svcKey)
		return
	}
}

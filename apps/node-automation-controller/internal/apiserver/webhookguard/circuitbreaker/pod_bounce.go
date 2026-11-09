// pod_bounce.go — the circuit-breaker-bounce stage-1 remediation behind the C1
// circuit breaker: a webhook backend whose Ready endpoints ALL fail
// the TCP+TLS handshake has hung pods, not partitioned ones, so the
// sweep deletes the oldest Ready backing pod for its controller to
// recreate fresh — one bounce per service per BounceCooldown, routed
// through the shared heal preamble (per-service cooldown + the
// maintenance mutex + the fleet-wide heal budget, all fail closed).
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

// bounceHungWebhookPods is the circuit-breaker-bounce stage-1 remediation: for every
// Service referenced by a webhook config whose census verdict is
// "unresponsive" (Ready endpoints on healthy nodes, ALL probed IPs
// failing TCP+TLS), delete the oldest Ready backing pod — its owner
// controller (Deployment/ReplicaSet) recreates it fresh, which is
// the rolling bounce a hung webhook process needs. One bounce per
// service per BounceCooldown; every bounce runs the shared heal
// preamble (heal.AllowedV) — the per-service cooldown on the shared
// bounceAt ledger, the maintenance mutex (a cordon/drain/kured reboot
// or an in-flight k0s upgrade defers the kill) and the fleet-wide
// heal budget — and all three fail closed like every other pod kill
// in this module.
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
	// The bounce target is confirmed LIVE before the heal preamble
	// runs: a stale census ref must not spend a budget grant or open
	// the per-service cooldown on nothing. The mutex evaluation is
	// memoized through the Guard verdict, so the pass pays ONE
	// maintenance check no matter how many services bounce.
	for _, key := range keys {
		target := b.oldestLiveBackingPod(ctx, snap, key, ready.BackingPods[key], now)
		if target == nil {
			log.Info("webhook bounce: no live Ready backing pod found — endpoint refs are stale",
				"service", key)
			continue
		}
		proceed, unverifiable := heal.AllowedV(ctx, log, &g.Verdict,
			g.CS, g.Dyn, &b.bounceAt, key, BounceCooldown, now)
		if unverifiable {
			metrics.IncError(g.Queue)
			continue
		}
		if !proceed {
			continue
		}
		b.deleteBouncePod(ctx, snap, key, target, now)
	}
}

// oldestLiveBackingPod resolves the oldest Ready, non-terminating,
// live backing pod of an unresponsive webhook Service — "oldest"
// because the hung process is usually the longest-lived replica, and
// one pod per bounce keeps the rollout gentle. Split from the delete
// so the bounce paths can confirm a target BEFORE spending the heal
// preamble's budget grant. Returns nil when nothing qualifies — the
// caller logs "no target" in its own wording.
func (b *Breaker) oldestLiveBackingPod(ctx context.Context, snap *guardstate.Snapshot,
	svcKey string, refs []guardstate.PodRef, now time.Time) *corev1.Pod {
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
	return oldest
}

// deleteBouncePod issues the UID-preconditioned delete of a
// pre-resolved bounce target. heal.DeletePod stamps bounceAt on a
// DELIVERED bounce only — a failed delete leaves the pod hung and the
// next sweep retries.
func (b *Breaker) deleteBouncePod(ctx context.Context, snap *guardstate.Snapshot,
	svcKey string, target *corev1.Pod, now time.Time) {
	g := snap.G
	log := logf.FromContext(ctx)
	log.Info("BOUNCE: deleting oldest Ready webhook pod — hung TCP+TLS handshake",
		"service", svcKey, "pod", target.Namespace+"/"+target.Name,
		"age", now.Sub(target.CreationTimestamp.Time).Truncate(time.Second))
	if _, err := heal.DeletePod(ctx, g.CS, &b.bounceAt, svcKey,
		target, now); err != nil {
		metrics.IncError(g.Queue)
		log.Error(err, "webhook pod bounce delete failed",
			"pod", target.Namespace+"/"+target.Name, "service", svcKey)
	}
}

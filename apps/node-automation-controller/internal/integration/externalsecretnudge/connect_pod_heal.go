// connect_pod_heal.go — the W9-GO1 1Password Connect auto-heal of
// externalsecret-nudge: when a ClusterSecretStore outage or an
// ExternalSecret failure storm persists past esConnectHealMinAge, the
// oldest running onepassword-connect pod is deleted — maintenance-
// gated, UID-preconditioned, and capped at one bounce per
// esConnectHealCooldown.
package externalsecretnudge

import (
	"context"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ---------------------------------------------------------------------------
// W9-GO1 — 1Password Connect auto-heal
// ---------------------------------------------------------------------------

// maybeHealConnect bounces the oldest running onepassword-connect pod
// when the ESO data path has been broken long enough that a stuck
// connect pod is the likely culprit: either a ClusterSecretStore has
// reported Ready=False for >=esConnectHealMinAge, or the ExternalSecret
// storm has persisted that long. The delete is maintenance-gated,
// UID-preconditioned, and capped at one bounce per
// esConnectHealCooldown — and it NEVER fires on a transient first
// observation, because both clocks only start after the first sweep
// that sees the bad state.
func (n *externalSecretNudge) maybeHealConnect(ctx context.Context,
	storm bool, now time.Time) {
	log := logf.FromContext(ctx)

	// Trigger 1 — a ClusterSecretStore (cluster-scoped only; a
	// namespaced SecretStore outage does not bounce the shared
	// connect pod) down past the persistence window. The ledger
	// cannot enumerate, so the check walks storeReady's CSS keys —
	// down-since entries prune alongside storeReady, so every
	// tracked-down store is still a known one.
	storeDown := false
	for key := range n.storeReady {
		if !strings.HasPrefix(key, "ClusterSecretStore/") {
			continue
		}
		if downFor, ok := n.storeDownSince.Seen(key, now); ok &&
			downFor >= esConnectHealMinAge {
			storeDown = true
			break
		}
	}
	// Trigger 2 — the ES storm itself persisting past the window.
	stormLong := storm && now.Sub(n.stormSince) >= esConnectHealMinAge
	if !storeDown && !stormLong {
		return
	}
	if now.Sub(n.connectHealAt) < esConnectHealCooldown {
		log.Info("DEFER: connect pod heal inside cooldown",
			"storeDown", storeDown, "stormLong", stormLong,
			"lastHeal", now.Sub(n.connectHealAt).Truncate(time.Minute))
		return
	}

	// Same fail-closed maintenance gate as every pod kill in this
	// module — cordon/drain/kured or an in-flight upgrade defers the
	// bounce, and "cannot verify" skips it.
	held, why, err := shared.MaintenanceActive(ctx, n.cs, n.dyn)
	if err != nil {
		metrics.IncError(n.queue)
		log.Info("WARN: maintenance check unverifiable — "+
			"DEFER: connect pod heal skipped (fail closed)", "error", err)
		return
	}
	if held {
		log.Info("DEFER: maintenance active — connect pod heal skipped",
			"why", why)
		return
	}

	pod := n.oldestConnectPod(ctx)
	if pod == nil {
		log.Info("connect heal: no running onepassword-connect pod found")
		return
	}
	log.Info("ACTION: deleting oldest running onepassword-connect pod — "+
		"sustained store outage/storm", "pod", pod.Namespace+"/"+pod.Name,
		"storeDown", storeDown, "stormLong", stormLong)
	uid := pod.UID
	if err := n.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		shared.UIDDeleteOptions(uid, "")); err != nil {
		metrics.IncError(n.queue)
		log.Error(err, "connect pod delete failed",
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	// Cooldown stamps on a DELIVERED delete only — a failed delete
	// leaves the pod stuck and the next sweep retries.
	n.connectHealAt = now
}

// oldestConnectPod returns the oldest Running pod named
// onepassword-connect* across the candidate namespaces, or nil when
// none qualifies. List errors other than NotFound are logged and
// skipped — an unverifiable namespace must not block the heal on the
// other one, but it also cannot produce a delete target.
func (n *externalSecretNudge) oldestConnectPod(ctx context.Context) *corev1.Pod {
	log := logf.FromContext(ctx)
	var oldest *corev1.Pod
	for _, ns := range esConnectNamespaces {
		pods, err := shared.ListAll(ctx,
			metav1.ListOptions{Limit: esListPageSize},
			shared.Pods(n.cs, ns))
		if err != nil {
			if !apierrors.IsNotFound(err) {
				metrics.IncError(n.queue)
				log.Error(err, "connect pod list failed", "namespace", ns)
			}
			continue
		}
		for i := range pods {
			p := &pods[i]
			if p.DeletionTimestamp != nil ||
				p.Status.Phase != corev1.PodRunning ||
				!strings.HasPrefix(p.Name, esConnectPodPrefix) {
				continue
			}
			if oldest == nil ||
				p.CreationTimestamp.Time.Before(oldest.CreationTimestamp.Time) {
				oldest = p
			}
		}
	}
	return oldest
}

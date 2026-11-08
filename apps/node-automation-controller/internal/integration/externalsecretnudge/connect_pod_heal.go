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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// W9-GO1 — 1Password Connect auto-heal
// ---------------------------------------------------------------------------

// maybeHealConnect bounces the oldest running onepassword-connect pod
// when the ESO data path has been broken long enough that a stuck
// connect pod is the likely culprit: either a ClusterSecretStore has
// reported Ready=False for >=esConnectHealMinAge, the ExternalSecret
// storm has persisted that long, or a connect-sync container has sat
// degraded that long. The delete is maintenance-gated,
// UID-preconditioned, and capped at one bounce per
// esConnectHealCooldown — and it NEVER fires on a transient first
// observation, because all three clocks only start after the first
// sweep that sees the bad state.
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

	// Trigger 3 — a connect-sync container degraded past the same
	// window. The census runs every sweep (it feeds the unhealthy
	// gauge and the persistence ledger) even when no other trigger
	// is armed: a wedged connect-sync leaves every store Ready=True
	// while connect-api answers from its stale SQLite cache — the
	// exact outage the heal exists for, invisible to triggers 1-2.
	degraded := n.scanConnectSyncPods(ctx, now)
	syncDegraded := false
	for key := range degraded {
		if age, ok := n.syncDegradedSince.Seen(key, now); ok &&
			age >= esConnectHealMinAge {
			syncDegraded = true
			break
		}
	}
	if !storeDown && !stormLong && !syncDegraded {
		return
	}
	// The cooldown check stays a manual CooledDown (not inside
	// heal.AllowedV) so the DEFER log keeps its trigger context —
	// storeDown/stormLong and the last-heal age the shared preamble
	// cannot know.
	if n.connectHeals.CooledDown(esConnectPodPrefix, esConnectHealCooldown, now) {
		lastHeal, _ := n.connectHeals.Last(esConnectPodPrefix)
		log.Info("DEFER: connect pod heal inside cooldown",
			"storeDown", storeDown, "stormLong", stormLong,
			"syncDegraded", syncDegraded,
			"lastHeal", now.Sub(lastHeal).Truncate(time.Minute))
		return
	}

	// Same fail-closed maintenance gate as every pod kill in this
	// module, via the shared preamble — cordon/drain/kured or an
	// in-flight upgrade defers the bounce, and "cannot verify"
	// (unverifiable) skips it AND IncErrors the queue.
	proceed, unverifiable := heal.AllowedV(ctx, log, &n.verdict, n.cs, n.dyn,
		&n.connectHeals, esConnectPodPrefix, esConnectHealCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(n.queue)
		return
	case !proceed:
		return
	}

	pod := n.oldestConnectPod(ctx)
	if pod == nil {
		log.Info("connect heal: no running onepassword-connect pod found")
		return
	}
	log.Info("ACTION: deleting oldest running onepassword-connect pod — "+
		"sustained store outage/storm/sync degradation", "pod",
		pod.Namespace+"/"+pod.Name,
		"storeDown", storeDown, "stormLong", stormLong,
		"syncDegraded", syncDegraded)
	// DeletePod UID-preconditions the delete and stamps the cooldown
	// on a DELIVERED delete only — a failed delete leaves the pod
	// stuck and the next sweep retries.
	if _, err := heal.DeletePod(ctx, n.cs, &n.connectHeals,
		esConnectPodPrefix, pod, now); err != nil {
		metrics.IncError(n.queue)
		log.Error(err, "connect pod delete failed",
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
}

// scanConnectSyncPods censuses the connect-sync container inside
// every Running onepassword-connect* pod across the candidate
// namespaces. A pod whose connect-sync container status reports
// !Ready or RestartCount >= esConnectSyncRestartMax is a stalled
// sync plane — connect-api keeps serving the stale SQLite cache, so
// pod-level readiness stays green while every secret pull ages out
// (the exact blind spot this module's storm census cannot see when
// the sync failure is not a store outage). Degraded pods stamp
// syncDegradedSince (the heal trigger's persistence clock) and emit
// node_automation_onepassword_connect_sync_unhealthy; a pod back to
// healthy, gone, or no longer Running forgets both. Returns the set
// of "ns/pod" keys degraded THIS pass. Per-namespace list failures
// are tolerated (IncError + carry-forward via the ledger's last
// emissions): an unverifiable namespace must not flap live series
// or the heal clock.
func (n *externalSecretNudge) scanConnectSyncPods(ctx context.Context,
	now time.Time) map[string]bool {

	log := logf.FromContext(ctx)
	degraded := map[string]bool{}
	n.syncUnhealthyEmitted.Begin() // drop an aborted pass's leftovers
	if n.cs == nil {
		return degraded // no typed client wired — cannot inspect pods
	}
	for _, ns := range esConnectNamespaces {
		pods, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.Pods(n.cs, ns))
		if err != nil {
			if !apierrors.IsNotFound(err) {
				metrics.IncError(n.queue)
				log.Error(err, "connect pod list failed", "namespace", ns)
			}
			continue
		}
		for i := range pods {
			p := &pods[i]
			key := ns + "/" + p.Name
			if p.DeletionTimestamp != nil ||
				p.Status.Phase != corev1.PodRunning ||
				!strings.HasPrefix(p.Name, esConnectPodPrefix) {
				n.syncDegradedSince.Forget(key)
				continue
			}
			if why, bad := connectSyncDegraded(p); bad {
				degraded[key] = true
				n.syncDegradedSince.Observe(key, now)
				n.syncUnhealthyEmitted.Set(
					metrics.OnePasswordConnectSyncUnhealthy, 1,
					key, ns, p.Name)
				if since, ok := n.syncDegradedSince.Seen(key, now); ok {
					log.Info("connect-sync degraded",
						"pod", key, "why", why,
						"degradedFor", since.Truncate(time.Minute))
				}
			} else {
				n.syncDegradedSince.Forget(key)
			}
		}
	}
	n.syncUnhealthyEmitted.Prune(
		metrics.OnePasswordConnectSyncUnhealthy.DeleteLabelValues)
	return degraded
}

// connectSyncDegraded reports whether the pod's connect-sync
// container is unhealthy — the status entry is !Ready, missing
// while the container is declared (kubelet never started it), or
// past the crashloop restart ceiling. Pods that do not declare a
// connect-sync container at all are skipped: a different connect
// image variant is not ours to judge.
func connectSyncDegraded(p *corev1.Pod) (why string, bad bool) {
	declared := false
	for _, c := range p.Spec.Containers {
		if c.Name == esConnectSyncContainer {
			declared = true
			break
		}
	}
	if !declared {
		return "", false
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Name != esConnectSyncContainer {
			continue
		}
		switch {
		case !cs.Ready:
			return "connect-sync container not Ready", true
		case cs.RestartCount >= esConnectSyncRestartMax:
			return "connect-sync container crashlooping", true
		}
		return "", false
	}
	return "connect-sync container status missing", true
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
		pods, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.Pods(n.cs, ns))
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

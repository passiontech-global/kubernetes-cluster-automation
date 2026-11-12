// stale_recover.go — the heal action of coredns-stale-watchdog:
// cooldown/storm-gate/watch-cache-wedge/maintenance-mutex/rollout
// gates, then either a
// Deployment rollout-restart (whole fleet stale) or surgical deletes
// of only the stale pods, plus stamping the cooldown annotation.
package corednswatchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// recover applies cooldown/storm-gate/watch-cache-wedge/
// maintenance-mutex/rollout gates, then either rollout-restarts the
// Deployment (whole fleet stale) or deletes only the stale pods, and
// stamps the cooldown annotation. podUID maps pod name → the UID
// the sweep's pod list saw — the deletes carry it as a UID
// precondition. Hard API failures are returned so the wrapper
// counts them.
func (w *coreDNSWatchdog) recover(ctx context.Context, suspects []string,
	podUID map[string]types.UID, nPods int) error {
	log := logf.FromContext(ctx)
	deploy, err := w.cs.AppsV1().Deployments(corednsNS).Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get deployment %s/coredns: %w", corednsNS, err)
	}
	// Cooldown lives on Deployment metadata — patching it does not
	// roll the pods (unlike a pod-template annotation). AnnoTime
	// accepts the new RFC3339 stamps AND the legacy unix ones still
	// live on older objects.
	if last, ok := kube.AnnoTime(deploy, corednsTSAnno); ok {
		if ago := w.now.Now().Sub(last); ago < corednsCooldownS*time.Second {
			// Legitimate skip — the cooldown IS the pacing doing its
			// job, not a failure; no IncError (a 30m cooldown wrongly
			// counted as a run error would page on every recovery).
			log.Info("SKIP recovery: inside cooldown",
				"pods", suspects, "agoS", int64(ago.Seconds()), "cooldownS", corednsCooldownS)
			return nil
		}
	}
	// Storm-gate: never evict while nodes are NotReady — eviction
	// only slows recovery during a cluster storm.
	notReady, err := kube.CountNotReadyNodesCached(ctx, w.nodeReader, w.cs)
	if err != nil {
		return fmt.Errorf("count not-ready nodes (storm gate): %w", err)
	}
	if notReady > 0 {
		// Legitimate skip — the storm gate holding is the guard
		// working as designed.
		log.Info("SKIP recovery: nodes NotReady — cluster storm",
			"pods", suspects, "notReady", notReady)
		return nil
	}
	// Watch-cache wedge gate (watch-cache-wedge-gate): a fresh
	// ApiserverWatchCacheWedged=True on any node means the apiserver
	// is serving stale watch-cache data — deleting coredns pods or
	// restarting the Deployment would strip the last DNS answers
	// while the control plane is already degraded. Defer the whole
	// recovery (pod deletes AND rollout restart) until the wedge
	// clears; the heartbeat-freshness check keeps a dead reporter's
	// zombie True from suppressing recovery forever.
	wedged, err := w.watchCacheWedgedNode(ctx)
	if err != nil {
		return fmt.Errorf("check apiserver watch-cache wedge: %w", err)
	}
	if wedged != "" {
		// Legitimate skip — same class as the storm gate: the
		// cluster is degraded and churn makes it worse.
		log.Info("SKIP recovery: apiserver watch-cache wedged — deferring DNS pod churn",
			"pods", suspects, "node", wedged)
		return nil
	}
	// Fleet not fully ready = a rollout is already recreating pods —
	// check BEFORE the maintenance mutex/budget so a mid-rollout
	// sweep never spends a heal token on a skip it already knows.
	if deploy.Status.ReadyReplicas < deploy.Status.Replicas {
		// Legitimate skip — recovery would stack on the in-flight
		// rollout it is waiting for.
		log.Info("SKIP recovery: coredns not fully ready",
			"pods", suspects,
			"ready", deploy.Status.ReadyReplicas, "replicas", deploy.Status.Replicas)
		return nil
	}
	// Maintenance mutex — a SECOND, different storm signal alongside
	// the NotReady gate above: cordon/kured/autopilot mean a drain
	// or k0s upgrade is in flight and pod deletes must not race it.
	// heal.AllowedV runs with a nil heals ledger — the cooldown
	// above is annotation-persisted on the Deployment, not a
	// CooldownSet — and shares w.verdict so the run pays one
	// evaluation. A held mutex defers with no error (the defer log
	// with the why comes from AllowedV); only UNVERIFIABLE fails
	// closed as an error and IncErrors the queue below.
	// gateNow is captured ONCE: the budget grant AllowedV consumes is
	// stamped with this instant, and RefundGrant's un-consume matches
	// on time.Equal — a second w.now.Now() call would miss the stamp
	// by nanoseconds and silently keep the grant.
	gateNow := w.now.Now()
	proceed, unverifiable := heal.AllowedV(ctx, log, &w.verdict,
		w.cs, w.dyn, nil, "coredns", 0, gateNow)
	if unverifiable {
		metrics.IncError(w.queue)
		return nil
	}
	if !proceed {
		return nil
	}

	// New stamps are always RFC3339 — the unix branch of
	// ParseAnnoTime is read-compat only.
	stamp := w.now.Now().UTC().Format(time.RFC3339)
	if nPods == 0 || len(suspects) >= nPods {
		// Whole fleet stale (or empty pod list) — restart the
		// Deployment once; a short outage beats stale answers. Both
		// stamps land in ONE merge doc on the same object: the
		// pod-template restartedAt triggers the rollout while the
		// Deployment-level cooldown stays metadata-only (it does
		// not roll pods).
		log.Info("ACTION: rollout restart deploy/coredns",
			"suspects", len(suspects), "total", nPods)
		// The pod-template restartedAt half comes from the shared
		// kube.RestartTemplatePatch builder (the same doc fluentbit
		// roller patches with); the Deployment-level cooldown stamp
		// merges into the SAME doc so both stamps land in one write
		// (metadata-only — it does not roll pods).
		var doc map[string]any
		if err := json.Unmarshal(kube.RestartTemplatePatch(w.now.Now()), &doc); err != nil {
			return fmt.Errorf("render restart patch: %w", err)
		}
		doc["metadata"] = map[string]any{
			"annotations": map[string]string{corednsTSAnno: stamp},
		}
		patch, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		if _, err := w.cs.AppsV1().Deployments(corednsNS).Patch(ctx, "coredns",
			types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("rollout-restart patch deployment %s/coredns: %w", corednsNS, err)
		}
	} else {
		// Evict only the stale pods through the PDB-respecting
		// Eviction API — a raw Delete would bypass every
		// PodDisruptionBudget and could strip the last Ready DNS
		// replica mid-outage (the same contract heal.EvictPodV
		// enforces elsewhere; here the maintenance/budget preamble
		// already ran once above, so the plain EvictPod half is the
		// right pairing — one grant covers the batch). The UID
		// precondition closes the TOCTOU between the sweep's pod
		// list and the eviction: a same-named pod recreated since
		// is a fresh replica, not ours to kill. Every suspect name
		// has a podUID entry (same list); an absent entry yields an
		// empty-UID precondition that can never match a live pod —
		// fail closed, evict nothing.
		log.Info("ACTION: evict stale pods", "pods", suspects)
		// Per-pass eviction cap: max(1, ready/4). The batch shares
		// ONE AllowedV grant, but the pods it evicts do NOT all sit
		// under a PDB on clusters that never installed one — an
		// uncapped loop could take N-1 of N CoreDNS replicas down
		// in a single pass and blackhole DNS exactly while the
		// cluster needs it most. Quarter-of-ready keeps a floor of
		// surviving replicas; the remainder is picked up next
		// sweep.
		evictCap := max(1, int(deploy.Status.ReadyReplicas)/4)
		deleted := 0
		for _, name := range suspects {
			if deleted >= evictCap {
				log.Info("DEFER: per-pass CoreDNS eviction cap reached — rest next sweep",
					"cap", evictCap, "deleted", deleted, "remaining", len(suspects)-deleted)
				break
			}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: corednsNS, UID: podUID[name],
			}}
			evicted, refused, err := heal.EvictPod(ctx, w.cs, nil, "",
				pod, w.now.Now())
			switch {
			case refused:
				// PDB at its floor — a deferral, not a failure:
				// the replica budget is spoken for, the pod stays,
				// and nothing is metered (same contract as
				// heal.EvictPodV's refund path).
				log.Info("DEFER: PDB refused stale pod eviction — keeping pod alive",
					"pod", corednsNS+"/"+name)
				continue
			case apierrors.IsNotFound(err):
				// Already gone — a previous cycle's eviction (or the
				// Deployment controller) got there first. Not a
				// failure; the fleet is exactly where we wanted it.
				log.Info("stale pod already gone", "pod", corednsNS+"/"+name)
				continue
			case err != nil:
				return fmt.Errorf("evict stale pod %s/%s: %w", corednsNS, name, err)
			case !evicted:
				continue
			}
			deleted++
		}
		// The cooldown annotation is stamped only for recovery we
		// DELIVERED — zero deletes means nothing happened this cycle,
		// and stamping anyway would suppress a needed recovery for a
		// full cooldown window. The batch's single AllowedV grant
		// bought no heal either, so it goes back — same contract
		// heal.EvictPodV applies per PDB refusal.
		if deleted == 0 {
			heal.RefundGrant(gateNow)
			log.Info("sweep done: no stale pod deleted (all already gone)", "pods", suspects)
			return nil
		}
		patch, err := kube.MergePatchAnnos(map[string]any{corednsTSAnno: stamp})
		if err != nil {
			return err
		}
		if _, err := w.cs.AppsV1().Deployments(corednsNS).Patch(ctx, "coredns",
			types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("stamp cooldown annotation on deployment %s/coredns: %w", corednsNS, err)
		}
	}
	log.Info("sweep done: stale coredns recovery issued", "pods", suspects)
	return nil
}

// watchCacheWedgedHeartbeatMax bounds the LastHeartbeatTime age that
// still counts as live evidence for the watch-cache-wedge gate — the
// same 10m freshness window the other heartbeat-gated condition
// consumers use (mesh watchdog's ciliumIPAMCondHeartbeatMax).
const watchCacheWedgedHeartbeatMax = 10 * time.Minute

// watchCacheWedgedNode returns the name of the first node holding a
// FRESH ApiserverWatchCacheWedged=True, or "" when none does — the
// coredns-stale-watchdog's defer signal while the apiserver serves
// stale watch-cache reads. A frozen heartbeat means the reporter
// that owned the True is dead (a zombie the node-condition-sweeper
// clears), so it does not count.
func (w *coreDNSWatchdog) watchCacheWedgedNode(ctx context.Context) (string, error) {
	// Direct apiserver read, NOT the informer cache: this gate only
	// runs when CoreDNS is already proven stale, which is exactly
	// when an ApiserverWatchCacheWedged=True condition is live — and
	// a wedged watch cache freezes the informer cache too, so the
	// cached read would never see the condition it exists to check.
	nodes, err := kube.ListNodes(ctx, w.cs)
	if err != nil {
		return "", err
	}
	now := w.now.Now()
	for i := range nodes {
		c := kube.NodeCondition(&nodes[i], nodecond.ApiserverWatchCacheWedged)
		if c != nil && c.Status == corev1.ConditionTrue &&
			kube.CondHeartbeatLive(c, watchCacheWedgedHeartbeatMax, now) {
			return nodes[i].Name, nil
		}
	}
	return "", nil
}

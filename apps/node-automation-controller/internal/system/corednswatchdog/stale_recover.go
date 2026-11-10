// stale_recover.go — the heal action of coredns-stale-watchdog:
// cooldown/storm-gate/maintenance-mutex/rollout gates, then either a
// Deployment rollout-restart (whole fleet stale) or surgical deletes
// of only the stale pods, plus stamping the cooldown annotation.
package corednswatchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// recover applies cooldown/storm-gate/maintenance-mutex/rollout
// gates, then either rollout-restarts the Deployment (whole fleet
// stale) or deletes only the stale pods, and stamps the cooldown
// annotation. podUID maps pod name → the UID the sweep's pod list
// saw — the deletes carry it as a UID precondition. Hard API
// failures are returned so the wrapper counts them.
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
	proceed, unverifiable := heal.AllowedV(ctx, log, &w.verdict,
		w.cs, w.dyn, nil, "coredns", 0, w.now.Now())
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
		// Delete only the stale pods — healthy replicas keep serving.
		// The UID precondition closes the TOCTOU between the sweep's
		// pod list and the delete: a same-named pod recreated since
		// is a fresh replica, not ours to kill. Every suspect name
		// has a podUID entry (same list); an absent entry yields an
		// empty-UID precondition that can never match a live pod —
		// fail closed, delete nothing.
		log.Info("ACTION: delete stale pods", "pods", suspects)
		deleted := 0
		for _, name := range suspects {
			if err := w.cs.CoreV1().Pods(corednsNS).Delete(ctx, name,
				kube.UIDDeleteOptions(podUID[name], "")); err != nil {
				if apierrors.IsNotFound(err) {
					// Already gone — a previous cycle's delete (or the
					// Deployment controller) got there first. Not a
					// failure; the fleet is exactly where we wanted it.
					log.Info("stale pod already gone", "pod", corednsNS+"/"+name)
					continue
				}
				return fmt.Errorf("delete stale pod %s/%s: %w", corednsNS, name, err)
			}
			deleted++
		}
		// The cooldown annotation is stamped only for recovery we
		// DELIVERED — zero deletes means nothing happened this cycle,
		// and stamping anyway would suppress a needed recovery for a
		// full cooldown window.
		if deleted == 0 {
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

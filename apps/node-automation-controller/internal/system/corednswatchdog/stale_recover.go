// stale_recover.go — the heal action of coredns-stale-watchdog:
// cooldown/storm-gate/rollout gates, then either a Deployment
// rollout-restart (whole fleet stale) or surgical deletes of only the
// stale pods, plus stamping the cooldown annotation.
package corednswatchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// recover applies cooldown/storm-gate/rollout gates, then either
// rollout-restarts the Deployment (whole fleet stale) or deletes only
// the stale pods, and stamps the cooldown annotation. Hard API
// failures are returned so the wrapper counts them.
func (w *coreDNSWatchdog) recover(ctx context.Context, suspects []string, nPods int) error {
	log := logf.FromContext(ctx)
	deploy, err := w.cs.AppsV1().Deployments(corednsNS).Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get deployment %s/coredns: %w", corednsNS, err)
	}
	// Cooldown lives on Deployment metadata — patching it does not
	// roll the pods (unlike a pod-template annotation).
	if last, ok := deploy.Annotations[corednsTSAnno]; ok {
		if ts, err := strconv.ParseInt(last, 10, 64); err == nil {
			if ago := time.Now().Unix() - ts; ago < corednsCooldownS {
				metrics.IncError(w.queue)
				log.Info("SKIP recovery: inside cooldown",
					"pods", suspects, "agoS", ago, "cooldownS", corednsCooldownS)
				return nil
			}
		}
	}
	// Storm-gate: never evict while nodes are NotReady — eviction
	// only slows recovery during a cluster storm.
	notReady, err := shared.CountNotReadyNodes(ctx, w.cs)
	if err != nil {
		return fmt.Errorf("count not-ready nodes (storm gate): %w", err)
	}
	if notReady > 0 {
		metrics.IncError(w.queue)
		log.Info("SKIP recovery: nodes NotReady — cluster storm",
			"pods", suspects, "notReady", notReady)
		return nil
	}
	// Fleet not fully ready = a rollout is already recreating pods.
	if deploy.Status.ReadyReplicas < deploy.Status.Replicas {
		metrics.IncError(w.queue)
		log.Info("SKIP recovery: coredns not fully ready",
			"pods", suspects,
			"ready", deploy.Status.ReadyReplicas, "replicas", deploy.Status.Replicas)
		return nil
	}

	if nPods == 0 || len(suspects) >= nPods {
		// Whole fleet stale (or empty pod list) — restart the
		// Deployment once; a short outage beats stale answers.
		log.Info("ACTION: rollout restart deploy/coredns",
			"suspects", len(suspects), "total", nPods)
		patch, err := json.Marshal(map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"metadata": map[string]any{
						"annotations": map[string]string{
							"kubectl.kubernetes.io/restartedAt": time.Now().UTC().Format(time.RFC3339),
						},
					},
				},
			},
		})
		if err != nil {
			return err
		}
		if _, err := w.cs.AppsV1().Deployments(corednsNS).Patch(ctx, "coredns",
			types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("rollout-restart patch deployment %s/coredns: %w", corednsNS, err)
		}
	} else {
		// Delete only the stale pods — healthy replicas keep serving.
		log.Info("ACTION: delete stale pods", "pods", suspects)
		for _, name := range suspects {
			if err := w.cs.CoreV1().Pods(corednsNS).Delete(ctx, name,
				metav1.DeleteOptions{}); err != nil {
				return fmt.Errorf("delete stale pod %s/%s: %w", corednsNS, name, err)
			}
		}
	}
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				corednsTSAnno: strconv.FormatInt(time.Now().Unix(), 10),
			},
		},
	})
	if err != nil {
		return err
	}
	_, err = w.cs.AppsV1().Deployments(corednsNS).Patch(ctx, "coredns",
		types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("stamp cooldown annotation on deployment %s/coredns: %w", corednsNS, err)
	}
	log.Info("sweep done: stale coredns recovery issued", "pods", suspects)
	return nil
}

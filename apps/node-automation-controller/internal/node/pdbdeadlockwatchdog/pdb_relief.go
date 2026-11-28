// pdb_relief.go — cordoned-node PDB block relief (P2-#10): patches
// unhealthyPodEvictionPolicy=AlwaysAllow when safe or falls back to
// deleting a long-wedged, non-quorum pod on the cordoned node.
// Split from pdb_deadlock_watchdog.go.
package pdbdeadlockwatchdog

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

var pdbReliefErrReasons = map[string]bool{
	"CrashLoopBackOff":           true,
	"ImagePullBackOff":           true,
	"ErrImagePull":               true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"InvalidImageName":           true,
}

var pdbDBQuorumLabels = []string{
	"cnpg.io/cluster",
	"postgres-operator.crunchydata.com/cluster",
	"pgv2.percona.com/cluster",
	"everest.percona.com/cluster",
	"pxc.percona.com/cluster",
	"psmdb.percona.com/cluster",
	"scylla.scylladb.com/cluster",
	"apps.rabbitmq.com/cluster",
}

func (w *pdbDeadlockWatchdog) relieveCordonedBlock(ctx context.Context,
	log logr.Logger, now time.Time, pdb *policyv1.PodDisruptionBudget,
	cordoned map[string]bool) {
	w.relieveCordonedBlockWithPods(ctx, log, now, pdb, cordoned, nil, false)
}

func (w *pdbDeadlockWatchdog) relieveCordonedBlockWithPods(ctx context.Context,
	log logr.Logger, now time.Time, pdb *policyv1.PodDisruptionBudget,
	cordoned map[string]bool, pods []corev1.Pod, podsFetched bool) {

	if !w.cfg.cordonedUnhealthyRelief {
		return
	}
	pod := w.failingPodOnCordonedNodeWithPods(ctx, now, pdb, cordoned, pods, podsFetched)
	if pod == nil {
		return
	}

	policy := pdb.Spec.UnhealthyPodEvictionPolicy
	if w.cfg.unhealthyEvictionPolicyPatch &&
		(policy == nil || *policy == policyv1.IfHealthyBudget) {

		key := pdb.Namespace + "/" + pdb.Name
		if w.heals.CooledDown(key, pdbReliefCooldown, now) {
			return
		}
		proceed, unverifiable := heal.AllowedUpgradeOnly(ctx, log, w.maintenance,
			w.cs, w.dyn, "pdb/"+key, now)
		switch {
		case unverifiable:
			metrics.IncError(w.queue)
			return
		case proceed:
			if heal.FluxPatchGate("pdb", pdb, "pdb/"+key, now) {
				if w.patchUnhealthyEvictionPolicy(ctx, log, now, pdb, key) {
					return
				}
			}
		default:
			return
		}
	}

	if unreadyFor, ok := kube.PodUnreadyFor(pod, now); !ok ||
		unreadyFor < pdbReliefDeleteMinAge {
		return
	}
	if podHasDBQuorumLabel(pod) {
		log.Info("PDB relief: skipping pod delete — DB quorum member",
			"pdb", pdb.Namespace+"/"+pdb.Name,
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	key := pdb.Namespace + "/" + pdb.Name + "/" + pod.Name
	proceed, unverifiable := heal.AllowedClusterWideOnly(ctx, log, w.maintenance,
		w.cs, w.dyn, &w.heals, key, pdbReliefCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(w.queue)
		return
	case !proceed:
		return
	}
	deleted, err := heal.DeletePod(ctx, w.cs, &w.heals, key, pod, now)
	if err != nil {
		metrics.IncError(w.queue)
		log.Error(err, "PDB relief pod delete failed",
			"pdb", pdb.Namespace+"/"+pdb.Name,
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	if !deleted {
		heal.RefundGrant(now)
		return
	}
	log.Info("ACTION: deleted wedged pod to unblock cordoned drain",
		"pdb", pdb.Namespace+"/"+pdb.Name,
		"pod", pod.Namespace+"/"+pod.Name)
}

func (w *pdbDeadlockWatchdog) failingPodOnCordonedNodeWithPods(ctx context.Context,
	now time.Time, pdb *policyv1.PodDisruptionBudget,
	cordoned map[string]bool, pods []corev1.Pod, podsFetched bool) *corev1.Pod {

	if !podsFetched {
		if pdb.Spec.Selector == nil {
			return nil
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			return nil
		}
		var listErr error
		pods, listErr = kube.ListAll(ctx, metav1.ListOptions{
			FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
			Limit:         kube.DefaultListPageSize,
			LabelSelector: sel.String(),
		}, kube.Pods(w.cs, pdb.Namespace))
		if listErr != nil {
			metrics.IncError(w.queue)
			logf.FromContext(ctx).Error(listErr, "PDB relief pod list failed",
				"pdb", pdb.Namespace+"/"+pdb.Name)
			return nil
		}
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == "" || !cordoned[pod.Spec.NodeName] {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		unreadyFor, ok := kube.PodUnreadyFor(pod, now)
		if !ok || unreadyFor < pdbReliefPodMinAge {
			continue
		}
		if !podInReliefErrorState(pod) {
			continue
		}
		return pod
	}
	return nil
}

func podInReliefErrorState(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Waiting != nil && pdbReliefErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && pdbReliefErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	for _, cs := range pod.Status.EphemeralContainerStatuses {
		if cs.State.Waiting != nil && pdbReliefErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	return false
}

func podHasDBQuorumLabel(pod *corev1.Pod) bool {
	for _, k := range pdbDBQuorumLabels {
		if pod.Labels[k] != "" {
			return true
		}
	}
	return false
}

func (w *pdbDeadlockWatchdog) patchUnhealthyEvictionPolicy(ctx context.Context,
	log logr.Logger, now time.Time, pdb *policyv1.PodDisruptionBudget,
	key string) bool {

	patch := []byte(`{"spec":{"unhealthyPodEvictionPolicy":"AlwaysAllow"}}`)
	_, err := w.cs.PolicyV1().PodDisruptionBudgets(pdb.Namespace).Patch(
		ctx, pdb.Name, types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.Info("WARN: PDB unhealthyPodEvictionPolicy patch forbidden (RBAC) — falling back to pod delete",
				"pdb", pdb.Namespace+"/"+pdb.Name)
			return false
		}
		metrics.IncError(w.queue)
		log.Error(err, "PDB unhealthyPodEvictionPolicy patch failed",
			"pdb", pdb.Namespace+"/"+pdb.Name)
		return true
	}
	w.heals.Stamp(key, now)
	pdbUnhealthyPolicyPatchedTotal.Inc()
	log.Info("ACTION: patched PDB unhealthyPodEvictionPolicy=AlwaysAllow",
		"pdb", pdb.Namespace+"/"+pdb.Name)
	return true
}

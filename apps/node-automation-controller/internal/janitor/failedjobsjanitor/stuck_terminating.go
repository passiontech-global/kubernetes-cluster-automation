// stuck_terminating.go — duty 3 of failed-jobs-janitor: the C3b
// stuck-Terminating auditor (detect-only) plus the W4
// pvc-protection unstick.
//
// Namespaces, PVCs and VolumeAttachments can wedge in Terminating
// forever when the controller that owns a finalizer is gone or itself
// deadlocked (namespace-controller cannot finish an ns whose remaining
// resources need a deleted API service; kubernetes.io/pvc-protection
// waits on a pod that will never exit; a VA's external-attacher
// finalizer never drains once its node is gone). Nothing in-tree
// alerts on it — the object just sits there for days.
//
// The audit marks each resource Terminating >2h on
// node_automation_stuck_terminating_resources and logs its finalizer
// list — the finalizer names the controller that stopped draining, so
// it is the debugging payload. Detection only: finalizers are never
// stripped automatically (a stripped finalizer on a still-mounted
// volume is a data-loss vector) — the sole exception is the W4
// pvc-protection unstick, which fires only when a per-namespace pod
// scan proves nothing references the claim.
package failedjobsjanitor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// stuckTerminatingMaxAge: a DeletionTimestamp older than this is
	// genuinely stuck — every legitimate finalizer drain (pod exit,
	// PVC unprotect, resourcequota reconcile) finishes in seconds to
	// a couple of minutes.
	stuckTerminatingMaxAge = 2 * time.Hour

	// pvcProtectionFinalizer is the in-tree claim-protection finalizer —
	// it drains only after the pvc-protection-controller verifies no pod
	// references the claim; a wedged controller (or a deleted pod whose
	// reference the controller missed) leaves it forever (W4).
	pvcProtectionFinalizer = "kubernetes.io/pvc-protection"
)

// auditStuckTerminating marks every namespace/PVC/VolumeAttachment
// stuck in Terminating past stuckTerminatingMaxAge on
// metrics.StuckTerminatingResources and logs its finalizers — the
// finalizer list is the debugging payload: it names the controller
// that stopped draining (kubernetes.io/pvc-protection, a wedged
// external-attacher finalizer on a VA whose node is gone, a deleted
// operator's custom finalizer, ...). Detect-only — finalizers are
// never stripped automatically.
//
// Label convention: kind is "Namespace", "PersistentVolumeClaim" or
// "VolumeAttachment". For the cluster-scoped kinds (Namespace,
// VolumeAttachment) the "namespace" label is the empty string —
// there is no containing namespace, and repeating the object name
// would only make the two labels redundant.
func (j *failedJobsJanitor) auditStuckTerminating(ctx context.Context) error {
	log := logf.FromContext(ctx)
	now := j.now.Now()

	// All lists land before any series is emitted — a failed later
	// list must not leave the gauge half-populated for an hour.
	nss, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Namespaces(j.cs))
	if err != nil {
		return fmt.Errorf("list namespaces: %w", err)
	}
	pvcs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PersistentVolumeClaims(j.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list persistentvolumeclaims: %w", err)
	}
	vas, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(j.cs))
	if err != nil {
		return fmt.Errorf("list volumeattachments: %w", err)
	}

	stuck := 0 // tuples re-asserted this sweep (for the done log)
	mark := func(kind, ns, name string, terminatingSince *metav1.Time, finalizers []string) {
		if terminatingSince == nil ||
			now.Sub(terminatingSince.Time) <= stuckTerminatingMaxAge {
			return // not terminating, or still inside the grace window
		}
		j.stuckEmitted.Set(metrics.StuckTerminatingResources, 1,
			stuckTerminatingKey{kind: kind, ns: ns, name: name}, kind, ns, name)
		stuck++
		log.Info("STUCK: still Terminating past threshold — inspect finalizers",
			"kind", kind, "namespace", ns, "name", name,
			"terminatingFor", now.Sub(terminatingSince.Time).Truncate(time.Minute),
			"finalizers", finalizers)
	}
	for i := range nss {
		n := &nss[i]
		// spec.finalizers is the list the namespace controller drains
		// (metadata.finalizers is not what wedges a Terminating ns).
		mark("Namespace", "", n.Name, n.DeletionTimestamp, nsFinalizerNames(n))
	}
	nss = nil
	// W4: a PVC wedged past the threshold whose ONLY finalizer is
	// kubernetes.io/pvc-protection is stuck waiting on the protection
	// controller to prove no pod uses it — when zero pods in the
	// namespace still reference it, the finalizer is stripped. The
	// per-namespace reference scan is cached per audit pass.
	nsClaims := map[string]pvcUseProbe{}
	for i := range pvcs {
		p := &pvcs[i]
		mark("PersistentVolumeClaim", p.Namespace, p.Name, p.DeletionTimestamp, p.Finalizers)
		if p.DeletionTimestamp != nil &&
			now.Sub(p.DeletionTimestamp.Time) > stuckTerminatingMaxAge &&
			len(p.Finalizers) == 1 && p.Finalizers[0] == pvcProtectionFinalizer {
			j.unstickPVCProtection(ctx, p, nsClaims)
		}
	}
	pvcs = nil
	// VolumeAttachments: the volumeattachment-cleaner refuses to
	// touch a VA already Terminating — the wedged attacher finalizer
	// is exactly what this audit exists to surface.
	for i := range vas {
		v := &vas[i]
		mark("VolumeAttachment", "", v.Name, v.DeletionTimestamp, v.Finalizers)
	}
	vas = nil

	// Hygiene: series for resources that finished terminating are
	// deleted, not zeroed — a Set(0) leaves the label triple in
	// /metrics forever, which Prometheus still treats as a live
	// series. Same convention as metrics.ForgetAPIBackend.
	j.stuckEmitted.Prune(metrics.StuckTerminatingResources.DeleteLabelValues)

	log.Info("stuck-terminating audit done", "stuck", stuck)
	return nil
}

// pvcUseProbe caches one namespace's "who still claims what" verdict
// per audit pass — a shared failure must not be re-listed per PVC.
type pvcUseProbe struct {
	claims map[string]bool // claim names still referenced by a live pod
	err    error
}

// unstickPVCProtection strips the pvc-protection finalizer from a
// stuck Terminating claim once a namespace pod scan proves nothing
// references it. Any list failure fails closed — the claim stays
// protected rather than risk an early unbind.
func (j *failedJobsJanitor) unstickPVCProtection(ctx context.Context,
	pvc *corev1.PersistentVolumeClaim, cache map[string]pvcUseProbe) {
	log := logf.FromContext(ctx)
	pr, ok := cache[pvc.Namespace]
	if !ok {
		pr = pvcUseProbe{claims: map[string]bool{}}
		pods, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.Pods(j.cs, pvc.Namespace))
		if err != nil {
			pr.err = err
		} else {
			for i := range pods {
				p := &pods[i]
				if p.Status.Phase == corev1.PodSucceeded ||
					p.Status.Phase == corev1.PodFailed {
					continue
				}
				for _, v := range p.Spec.Volumes {
					if v.PersistentVolumeClaim != nil {
						pr.claims[v.PersistentVolumeClaim.ClaimName] = true
					}
				}
			}
		}
		cache[pvc.Namespace] = pr
	}
	if pr.err != nil {
		metrics.IncError(j.queue)
		log.Error(pr.err, "pod list failed — keeping pvc-protection finalizer (fail closed)",
			"pvc", pvc.Namespace+"/"+pvc.Name)
		return
	}
	if pr.claims[pvc.Name] {
		return // still referenced — the finalizer is doing its job
	}
	log.Info("PATCH-FINALIZER: stuck PVC unreferenced by every live pod — removing pvc-protection",
		"pvc", pvc.Namespace+"/"+pvc.Name,
		"terminatingFor", j.now.Now().Sub(pvc.DeletionTimestamp.Time).Truncate(time.Minute))
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": pvc.ResourceVersion,
			"finalizers":      nil,
		},
	})
	if err != nil {
		metrics.IncError(j.queue)
		return
	}
	if _, err := j.cs.CoreV1().PersistentVolumeClaims(pvc.Namespace).Patch(ctx,
		pvc.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(j.queue)
		log.Error(err, "pvc-protection finalizer strip failed",
			"pvc", pvc.Namespace+"/"+pvc.Name)
	}
}

// nsFinalizerNames renders .spec.finalizers — the list that actually
// blocks a Terminating namespace — as plain strings for logging.
func nsFinalizerNames(n *corev1.Namespace) []string {
	out := make([]string, 0, len(n.Spec.Finalizers))
	for _, f := range n.Spec.Finalizers {
		out = append(out, string(f))
	}
	return out
}

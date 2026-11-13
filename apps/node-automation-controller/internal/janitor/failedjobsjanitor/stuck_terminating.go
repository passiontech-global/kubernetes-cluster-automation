// stuck_terminating.go — duty 3 of failed-jobs-janitor: the C3b
// stuck-Terminating auditor (detect-only) plus the va-stuck-terminating
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
// volume is a data-loss vector) — the sole exception is the va-stuck-terminating
// pvc-protection unstick, which fires only when a per-namespace pod
// scan proves nothing references the claim.
package failedjobsjanitor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
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
	// reference the controller missed) leaves it forever (va-stuck-terminating).
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
func (j *failedJobsJanitor) auditStuckTerminating(ctx context.Context,
	census *pvcCensus) error {
	if census == nil {
		census = &pvcCensus{}
	}
	j.stuckEmitted.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)
	now := j.now.Now()

	// All lists land before any series is emitted — a failed later
	// list must not leave the gauge half-populated for an hour, so
	// every census materializes before mark() runs (the PVC read is
	// the shared per-run census — see pvcCensus). Namespaces list
	// TYPED and stay full objects: the audit reads .spec.finalizers
	// — the list the namespace controller actually drains — which
	// metadata lists do not carry.
	nss, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Namespaces(j.cs))
	if err != nil {
		return fmt.Errorf("list namespaces: %w", err)
	}
	pvcs, err := census.listPVCs(ctx, j)
	if err != nil {
		return fmt.Errorf("list persistentvolumeclaims: %w", err)
	}
	// VolumeAttachments read metadata-only: name, DeletionTimestamp
	// and finalizers are the audit's entire field set.
	vas, err := kube.ListPartialOrFallback(ctx, j.meta, j.cs, j.dyn,
		storagev1.SchemeGroupVersion.WithResource("volumeattachments"),
		metav1.NamespaceAll,
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
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
	// va-stuck-terminating: a PVC wedged past the threshold whose ONLY finalizer is
	// kubernetes.io/pvc-protection is stuck waiting on the protection
	// controller to prove no pod uses it — when zero pods in the
	// namespace still reference it, the finalizer is stripped. The
	// per-namespace reference scan rides the run-shared census — the
	// orphan-PVC pass runs the identical pod scan in the same run.
	nsClaims := census.claims()
	for i := range pvcs {
		p := &pvcs[i]
		// va-stuck-terminating: a PVC wedged past the threshold whose ONLY finalizer is
		// kubernetes.io/pvc-protection is stuck waiting on the protection
		// controller to prove no pod uses it — when zero pods in the
		// namespace still reference it, the finalizer is stripped. The
		// per-namespace reference scan rides the run-shared census — the
		// orphan-PVC pass runs the identical pod scan in the same run.
		// The unstick runs BEFORE mark: a PVC whose finalizer just came
		// off is draining normally — emitting StuckTerminatingResources=1
		// for it would hold a false warning for the rest of the hour.
		if p.DeletionTimestamp != nil &&
			now.Sub(p.DeletionTimestamp.Time) > stuckTerminatingMaxAge &&
			len(p.Finalizers) == 1 && p.Finalizers[0] == pvcProtectionFinalizer &&
			j.unstickPVCProtection(ctx, p, nsClaims) {
			continue
		}
		mark("PersistentVolumeClaim", p.Namespace, p.Name, p.DeletionTimestamp, p.Finalizers)
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

// pvcCensus is the per-run read-share between sweepOrphanWorkspacePVCs
// and auditStuckTerminating: both duties walk the SAME cluster-wide
// PVC list and both run the same per-namespace "which claims do live
// pods still reference" pod scan (claimedPVCNames and the
// unstickPVCProtection probe are identical reads) — the census pays
// the PVC list once per run and hands both duties one claims map.
// The PVC read is metadata-only (ListPartialOrFallback): every field
// both duties touch — labels, ownerRefs, finalizers, timestamps,
// UID, and the ResourceVersion the unstick patch carries — is
// ObjectMeta, so the census pays PartialObjectMetadata bytes instead
// of full claim bodies. A nil census (a test driving a single duty)
// builds a private one — same reads, just unshared.
type pvcCensus struct {
	pvcs     []metav1.PartialObjectMetadata
	pvcsErr  error
	pvcsSet  bool
	nsClaims map[string]pvcUseProbe
}

// listPVCs returns the shared cluster-wide PVC metadata census,
// listing on first call only.
func (c *pvcCensus) listPVCs(ctx context.Context,
	j *failedJobsJanitor) ([]metav1.PartialObjectMetadata, error) {
	if !c.pvcsSet {
		c.pvcsSet = true
		c.pvcs, c.pvcsErr = kube.ListPartialOrFallback(ctx, j.meta, j.cs, j.dyn,
			corev1.SchemeGroupVersion.WithResource("persistentvolumeclaims"),
			metav1.NamespaceAll,
			metav1.ListOptions{Limit: kube.DefaultListPageSize})
	}
	return c.pvcs, c.pvcsErr
}

// claims returns the shared per-namespace claims-probe cache.
func (c *pvcCensus) claims() map[string]pvcUseProbe {
	if c.nsClaims == nil {
		c.nsClaims = map[string]pvcUseProbe{}
	}
	return c.nsClaims
}

// unstickPVCProtection strips the pvc-protection finalizer from a
// stuck Terminating claim once a namespace pod scan proves nothing
// references it. Any list failure fails closed — the claim stays
// protected rather than risk an early unbind. The first (cached) scan
// gates the strip; right before the patch a FRESH re-query of the
// namespace's pods re-proves the claim unreferenced — the census
// snapshot predates this run's deletes and the minutes the audit
// waited, and stripping protection from a freshly-mounted claim is
// the data-loss vector this whole duty exists to avoid.
//
// Metering: a namespace's failed pod scan is IncError'd ONCE, by
// whoever fills the census cache — later cache hits (and the audit's
// other PVCs in that namespace) log the fail-closed verdict without
// re-counting the same broken list.
//
// Returns true only when the finalizer patch landed — the caller
// uses it to skip the stuck gauge for a PVC that is now draining.
func (j *failedJobsJanitor) unstickPVCProtection(ctx context.Context,
	pvc *metav1.PartialObjectMetadata, cache map[string]pvcUseProbe) bool {
	log := logf.FromContext(ctx)
	pr, ok := cache[pvc.Namespace]
	if !ok {
		pr = pvcUseProbe{}
		pr.claims, pr.err = j.claimedPVCNames(ctx, pvc.Namespace)
		if pr.err != nil {
			metrics.IncError(j.queue)
		}
		cache[pvc.Namespace] = pr
	}
	if pr.err != nil {
		log.Error(pr.err, "pod list failed — keeping pvc-protection finalizer (fail closed)",
			"pvc", pvc.Namespace+"/"+pvc.Name, "cached", ok)
		return false
	}
	if pr.claims[pvc.Name] {
		return false // still referenced — the finalizer is doing its job
	}
	// Fresh re-proof right before the destructive patch.
	freshClaims, err := j.claimedPVCNames(ctx, pvc.Namespace)
	if err != nil {
		metrics.IncError(j.queue)
		log.Error(err, "fresh pod re-query failed — keeping pvc-protection finalizer (fail closed)",
			"pvc", pvc.Namespace+"/"+pvc.Name)
		return false
	}
	if freshClaims[pvc.Name] {
		log.Info("SKIP: claim mounted since the audit scan — finalizer stays",
			"pvc", pvc.Namespace+"/"+pvc.Name)
		return false
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
		return false
	}
	if _, err := j.cs.CoreV1().PersistentVolumeClaims(pvc.Namespace).Patch(ctx,
		pvc.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(j.queue)
		log.Error(err, "pvc-protection finalizer strip failed",
			"pvc", pvc.Namespace+"/"+pvc.Name)
		return false
	}
	return true
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

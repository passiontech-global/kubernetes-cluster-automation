// stuck_terminating_storage.go — #11 Orphan pv-protection & CSI
// VolumeSnapshot / VolumeSnapshotContent bound-protection unsticker.
//
// All paths fail CLOSED on any API error or unresolved attachment:
//   - pv-protection: 5 gates: (1) Terminating > 2h, (2) ONLY finalizer is
//     kubernetes.io/pv-protection, (3) spec.claimRef (if set) confirmed
//     IsNotFound via live Get, (4) no attached VolumeAttachment references PV,
//     (5) cluster-wide Pod scan confirms no live pod (nor Failed pod on a
//     dead/unknown node) references the claim; patch includes resourceVersion.
//   - VolumeSnapshot / VolumeSnapshotContent: Terminating > 2h, removes ONLY
//     snapshot.storage.kubernetes.io/volumesnapshot-bound-protection or
//     volumesnapshotcontent-bound-protection when the counterpart object is
//     confirmed IsNotFound via live Get, preserving all other finalizers and
//     passing resourceVersion. Skips cleanly via kube.IsCRDAbsent if CSI
//     Snapshot CRDs are not installed.
package failedjobsjanitor

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	pvProtectionFinalizer       = "kubernetes.io/pv-protection"
	vsBoundProtectionFinalizer  = "snapshot.storage.kubernetes.io/volumesnapshot-bound-protection"
	vscBoundProtectionFinalizer = "snapshot.storage.kubernetes.io/volumesnapshotcontent-bound-protection"
)

type stuckStorageLists struct {
	pvs  []corev1.PersistentVolume
	vss  []unstructured.Unstructured
	vscs []unstructured.Unstructured
}

func (j *failedJobsJanitor) listStuckStorageCandidates(ctx context.Context) (stuckStorageLists, error) {
	opts := metav1.ListOptions{Limit: kube.DefaultListPageSize}
	log := logf.FromContext(ctx)
	pvs, err := kube.ListAll(ctx, opts, kube.PersistentVolumes(j.cs))
	if err != nil {
		if !apierrors.IsForbidden(err) {
			return stuckStorageLists{}, fmt.Errorf("list persistentvolumes: %w", err)
		}
		// Missing PV list RBAC is a tolerated sub-failure: skip ONLY this
		// half of the audit and keep going to VolumeSnapshot/VSC — an
		// empty PV list must not drop the snapshot half with it. Do NOT
		// IncError: the periodic wrapper counts only the error the run
		// returns. V(1) avoids a per-sweep warn flood.
		log.V(1).Info("skip persistentvolumes: RBAC forbidden", "error", err)
		pvs = nil
	}
	out := stuckStorageLists{pvs: pvs}
	if j.dyn == nil {
		return out, nil
	}
	vss, err := kube.ListAllUnstructured(ctx, j.dyn.Resource(kube.GVRVolumeSnapshot).Namespace(metav1.NamespaceAll), opts)
	switch {
	case err == nil && vss != nil:
		out.vss = vss.Items
	case err != nil && apierrors.IsForbidden(err):
		// RBAC varies per cluster — a missing snapshot CRD permission
		// must NOT abort the whole stuck-terminating audit (the PVC/PV
		// half still runs). V(1) keeps the warn from spamming /metrics.
		log.V(1).Info("skip volumesnapshots: RBAC forbidden", "error", err)
	case err != nil && !kube.IsCRDAbsent(err):
		return stuckStorageLists{}, fmt.Errorf("list volumesnapshots: %w", err)
	}
	vscs, err := kube.ListAllUnstructured(ctx, j.dyn.Resource(kube.GVRVolumeSnapshotContent), opts)
	switch {
	case err == nil && vscs != nil:
		out.vscs = vscs.Items
	case err != nil && apierrors.IsForbidden(err):
		log.V(1).Info("skip volumesnapshotcontents: RBAC forbidden", "error", err)
	case err != nil && !kube.IsCRDAbsent(err):
		return stuckStorageLists{}, fmt.Errorf("list volumesnapshotcontents: %w", err)
	}
	return out, nil
}

func (j *failedJobsJanitor) processStuckStorage(
	ctx context.Context,
	lists stuckStorageLists,
	now time.Time,
	census *pvcCensus,
	mark func(kind, ns, name string, terminatingSince *metav1.Time, finalizers []string),
) {
	if census == nil {
		census = &pvcCensus{}
	}
	for i := range lists.pvs {
		pv := &lists.pvs[i]
		if pv.DeletionTimestamp != nil &&
			now.Sub(pv.DeletionTimestamp.Time) > stuckTerminatingMaxAge &&
			len(pv.Finalizers) == 1 && pv.Finalizers[0] == pvProtectionFinalizer &&
			j.unstickPVProtectionWithCensus(ctx, pv, census) {
			continue
		}
		mark("PersistentVolume", "", pv.Name, pv.DeletionTimestamp, pv.Finalizers)
	}
	for i := range lists.vss {
		vs := &lists.vss[i]
		ts := vs.GetDeletionTimestamp()
		finalizers := vs.GetFinalizers()
		if ts != nil && now.Sub(ts.Time) > stuckTerminatingMaxAge &&
			slices.Contains(finalizers, vsBoundProtectionFinalizer) {
			if fullyUnblocked, remaining := j.unstickVolumeSnapshot(ctx, vs, finalizers); fullyUnblocked {
				continue
			} else {
				finalizers = remaining
			}
		}
		mark("VolumeSnapshot", vs.GetNamespace(), vs.GetName(), ts, finalizers)
	}
	for i := range lists.vscs {
		vsc := &lists.vscs[i]
		ts := vsc.GetDeletionTimestamp()
		finalizers := vsc.GetFinalizers()
		if ts != nil && now.Sub(ts.Time) > stuckTerminatingMaxAge &&
			slices.Contains(finalizers, vscBoundProtectionFinalizer) {
			if fullyUnblocked, remaining := j.unstickVolumeSnapshotContent(ctx, vsc, finalizers); fullyUnblocked {
				continue
			} else {
				finalizers = remaining
			}
		}
		mark("VolumeSnapshotContent", "", vsc.GetName(), ts, finalizers)
	}
}

func (j *failedJobsJanitor) unstickPVProtection(ctx context.Context, pv *corev1.PersistentVolume) bool {
	return j.unstickPVProtectionWithCensus(ctx, pv, nil)
}

func (j *failedJobsJanitor) unstickPVProtectionWithCensus(ctx context.Context, pv *corev1.PersistentVolume, census *pvcCensus) bool {
	if census == nil {
		census = &pvcCensus{}
	}
	log := logf.FromContext(ctx)

	// Gate 3: a PV WITHOUT a fully populated ClaimRef is not an orphan —
	// it is unbound/released storage that some other controller still
	// owns. Stripping pv-protection there is a data-loss vector, so
	// fail closed. A BOUND PV likewise still has a live consumer by
	// definition; only Released/Failed (or an empty phase with a
	// confirmed-gone claim) is eligible.
	ref := pv.Spec.ClaimRef
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return false
	}
	if pv.Status.Phase == corev1.VolumeBound {
		return false
	}
	_, err := j.cs.CoreV1().PersistentVolumeClaims(ref.Namespace).
		Get(ctx, ref.Name, metav1.GetOptions{})
	if err == nil {
		return false // bound PVC still exists — protection finalizer valid
	}
	if !apierrors.IsNotFound(err) {
		metrics.IncError(j.queue)
		log.Error(err, "claimRef PVC lookup failed — keeping pv-protection (fail closed)", "pv", pv.Name)
		return false
	}

	// Gate 4: no VolumeAttachment attached (or unconfirmed detach) for this PV.
	attached, err, cached := j.vaAttachedToPVWithCensus(ctx, census, pv.Name)
	if err != nil {
		if !cached {
			metrics.IncError(j.queue)
		}
		log.Error(err, "volumeattachment check failed — keeping pv-protection (fail closed)",
			"pv", pv.Name, "cached", cached)
		return false
	}
	if attached {
		log.Info("SKIP: VolumeAttachment still references PV — pv-protection stays", "pv", pv.Name)
		return false
	}

	// Gate 5: cluster-wide Pod scan confirms no live pod or dead-node failed pod uses the PVC.
	inUse, err, cached := j.clusterPodUsesClaimRefWithCensus(ctx, pv.Spec.ClaimRef, census)
	if err != nil {
		if !cached {
			metrics.IncError(j.queue)
		}
		log.Error(err, "cluster pod scan failed — keeping pv-protection (fail closed)",
			"pv", pv.Name, "cached", cached)
		return false
	}
	if inUse {
		log.Info("SKIP: pod still references PV claim — pv-protection stays", "pv", pv.Name)
		return false
	}

	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": pv.ResourceVersion,
			"finalizers":      nil,
		},
	})
	if err != nil {
		metrics.IncError(j.queue)
		return false
	}
	if _, err := j.cs.CoreV1().PersistentVolumes().Patch(ctx, pv.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return true
		}
		if apierrors.IsConflict(err) {
			log.Info("SKIP: pv-protection target resourceVersion conflicted — retry next sweep", "pv", pv.Name)
			return false
		}
		if apierrors.IsForbidden(err) {
			// This is a tolerated sub-failure: the audit keeps running
			// and the periodic wrapper only counts errors it returns.
			log.V(1).Info("SKIP: persistentvolume patch forbidden — keeping pv-protection", "pv", pv.Name, "error", err)
			return false
		}
		metrics.IncError(j.queue)
		log.Error(err, "pv-protection finalizer strip failed", "pv", pv.Name)
		return false
	}
	log.Info("ACTION: removed orphan pv-protection finalizer", "pv", pv.Name)
	return true
}

func (j *failedJobsJanitor) clusterPodUsesClaimRef(ctx context.Context, ref *corev1.ObjectReference) (bool, error) {
	inUse, err, _ := j.clusterPodUsesClaimRefWithCensus(ctx, ref, nil)
	return inUse, err
}

func (j *failedJobsJanitor) clusterPodUsesClaimRefWithCensus(ctx context.Context, ref *corev1.ObjectReference, census *pvcCensus) (bool, error, bool) {
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return false, nil, false
	}
	if census == nil {
		census = &pvcCensus{}
	}
	pr, err, cached := census.probeNamespacePodClaims(ctx, j, ref.Namespace)
	if err != nil {
		return true, err, cached
	}
	return pr.inUseClaims[ref.Name], nil, cached
}

func (j *failedJobsJanitor) unstickVolumeSnapshot(ctx context.Context, vs *unstructured.Unstructured, finalizers []string) (bool, []string) {
	if j.dyn == nil {
		return false, finalizers
	}
	log := logf.FromContext(ctx)
	vscName, _ := kube.NestedString(vs.Object, "status", "boundVolumeSnapshotContentName")
	if vscName == "" {
		vscName, _ = kube.NestedString(vs.Object, "spec", "source", "volumeSnapshotContentName")
	}
	if vscName == "" {
		return false, finalizers
	}
	_, err := j.dyn.Resource(kube.GVRVolumeSnapshotContent).Get(ctx, vscName, metav1.GetOptions{})
	switch {
	case err == nil:
		return false, finalizers // counterpart still exists
	case apierrors.IsNotFound(err):
		// counterpart gone — safe to strip this finalizer below
	case apierrors.IsForbidden(err):
		// Tolerated RBAC sub-failure: fail closed (keep the finalizer),
		// but do NOT IncError — the run absorbs it and only the errors
		// it returns are counted by the periodic wrapper. V(1) keeps
		// the log from spamming every sweep.
		log.V(1).Info("SKIP: counterpart VolumeSnapshotContent lookup forbidden — keeping bound-protection",
			"volumesnapshot", vs.GetNamespace()+"/"+vs.GetName(), "vsc", vscName, "error", err)
		return false, finalizers
	default:
		metrics.IncError(j.queue)
		log.Error(err, "counterpart VolumeSnapshotContent lookup failed — fail closed",
			"volumesnapshot", vs.GetNamespace()+"/"+vs.GetName(), "vsc", vscName)
		return false, finalizers
	}

	remaining := withoutFinalizer(finalizers, vsBoundProtectionFinalizer)
	payload, err := finalizersPatchPayload(vs.GetResourceVersion(), remaining)
	if err != nil {
		metrics.IncError(j.queue)
		return false, finalizers
	}
	if _, err := j.dyn.Resource(kube.GVRVolumeSnapshot).Namespace(vs.GetNamespace()).
		Patch(ctx, vs.GetName(), types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if apierrors.IsConflict(err) {
			return false, finalizers
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("SKIP: volumesnapshot patch forbidden — keeping bound-protection",
				"volumesnapshot", vs.GetNamespace()+"/"+vs.GetName(), "error", err)
			return false, finalizers
		}
		metrics.IncError(j.queue)
		log.Error(err, "volumesnapshot bound-protection finalizer strip failed",
			"volumesnapshot", vs.GetNamespace()+"/"+vs.GetName())
		return false, finalizers
	}
	log.Info("ACTION: removed orphan volumesnapshot-bound-protection finalizer",
		"volumesnapshot", vs.GetNamespace()+"/"+vs.GetName(), "remaining", len(remaining))
	return len(remaining) == 0, remaining
}

func (j *failedJobsJanitor) unstickVolumeSnapshotContent(ctx context.Context, vsc *unstructured.Unstructured, finalizers []string) (bool, []string) {
	if j.dyn == nil {
		return false, finalizers
	}
	log := logf.FromContext(ctx)
	vsNS, _ := kube.NestedString(vsc.Object, "spec", "volumeSnapshotRef", "namespace")
	vsName, _ := kube.NestedString(vsc.Object, "spec", "volumeSnapshotRef", "name")
	if vsNS == "" || vsName == "" {
		return false, finalizers
	}
	_, err := j.dyn.Resource(kube.GVRVolumeSnapshot).Namespace(vsNS).Get(ctx, vsName, metav1.GetOptions{})
	switch {
	case err == nil:
		return false, finalizers // counterpart still exists
	case apierrors.IsNotFound(err):
		// counterpart gone — safe to strip this finalizer below
	case apierrors.IsForbidden(err):
		// Tolerated RBAC sub-failure: fail closed (keep the finalizer),
		// but do NOT IncError — the run absorbs it and only the errors
		// it returns are counted by the periodic wrapper. V(1) keeps
		// the log from spamming every sweep.
		log.V(1).Info("SKIP: counterpart VolumeSnapshot lookup forbidden — keeping bound-protection",
			"volumesnapshotcontent", vsc.GetName(), "vs", vsNS+"/"+vsName, "error", err)
		return false, finalizers
	default:
		metrics.IncError(j.queue)
		log.Error(err, "counterpart VolumeSnapshot lookup failed — fail closed",
			"volumesnapshotcontent", vsc.GetName(), "vs", vsNS+"/"+vsName)
		return false, finalizers
	}

	remaining := withoutFinalizer(finalizers, vscBoundProtectionFinalizer)
	payload, err := finalizersPatchPayload(vsc.GetResourceVersion(), remaining)
	if err != nil {
		metrics.IncError(j.queue)
		return false, finalizers
	}
	if _, err := j.dyn.Resource(kube.GVRVolumeSnapshotContent).
		Patch(ctx, vsc.GetName(), types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if apierrors.IsConflict(err) {
			return false, finalizers
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("SKIP: volumesnapshotcontent patch forbidden — keeping bound-protection",
				"volumesnapshotcontent", vsc.GetName(), "error", err)
			return false, finalizers
		}
		metrics.IncError(j.queue)
		log.Error(err, "volumesnapshotcontent bound-protection finalizer strip failed",
			"volumesnapshotcontent", vsc.GetName())
		return false, finalizers
	}
	log.Info("ACTION: removed orphan volumesnapshotcontent-bound-protection finalizer",
		"volumesnapshotcontent", vsc.GetName(), "remaining", len(remaining))
	return len(remaining) == 0, remaining
}

func withoutFinalizer(in []string, target string) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		if f != target {
			out = append(out, f)
		}
	}
	return out
}

func finalizersPatchPayload(rv string, remaining []string) ([]byte, error) {
	var finVal any
	if len(remaining) == 0 {
		finVal = nil
	} else {
		finVal = remaining
	}
	return json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": rv,
			"finalizers":      finVal,
		},
	})
}

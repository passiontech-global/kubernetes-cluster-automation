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
	"encoding/json"
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
	pvs, err := kube.ListAll(ctx, opts, kube.PersistentVolumes(j.cs))
	if err != nil {
		return stuckStorageLists{}, fmt.Errorf("list persistentvolumes: %w", err)
	}
	out := stuckStorageLists{pvs: pvs}
	if j.dyn == nil {
		return out, nil
	}
	vss, err := kube.ListAllUnstructured(ctx, j.dyn.Resource(kube.GVRVolumeSnapshot).Namespace(metav1.NamespaceAll), opts)
	if err != nil && !kube.IsCRDAbsent(err) {
		return stuckStorageLists{}, fmt.Errorf("list volumesnapshots: %w", err)
	}
	if err == nil && vss != nil {
		out.vss = vss.Items
	}
	vscs, err := kube.ListAllUnstructured(ctx, j.dyn.Resource(kube.GVRVolumeSnapshotContent), opts)
	if err != nil && !kube.IsCRDAbsent(err) {
		return stuckStorageLists{}, fmt.Errorf("list volumesnapshotcontents: %w", err)
	}
	if err == nil && vscs != nil {
		out.vscs = vscs.Items
	}
	return out, nil
}

func (j *failedJobsJanitor) processStuckStorage(
	ctx context.Context,
	lists stuckStorageLists,
	now time.Time,
	mark func(kind, ns, name string, terminatingSince *metav1.Time, finalizers []string),
) {
	for i := range lists.pvs {
		pv := &lists.pvs[i]
		if pv.DeletionTimestamp != nil &&
			now.Sub(pv.DeletionTimestamp.Time) > stuckTerminatingMaxAge &&
			len(pv.Finalizers) == 1 && pv.Finalizers[0] == pvProtectionFinalizer &&
			j.unstickPVProtection(ctx, pv) {
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
	log := logf.FromContext(ctx)

	// Gate 3: if ClaimRef points to a PVC, namespace and name must be populated
	// and live Get MUST confirm IsNotFound (fail closed on partial/empty ref).
	if pv.Spec.ClaimRef != nil {
		if pv.Spec.ClaimRef.Namespace == "" || pv.Spec.ClaimRef.Name == "" {
			return false
		}
		_, err := j.cs.CoreV1().PersistentVolumeClaims(pv.Spec.ClaimRef.Namespace).
			Get(ctx, pv.Spec.ClaimRef.Name, metav1.GetOptions{})
		if err == nil {
			return false // bound PVC still exists — protection finalizer valid
		}
		if !apierrors.IsNotFound(err) {
			metrics.IncError(j.queue)
			log.Error(err, "claimRef PVC lookup failed — keeping pv-protection (fail closed)", "pv", pv.Name)
			return false
		}
	}

	// Gate 4: no VolumeAttachment attached (or unconfirmed detach) for this PV.
	attached, err := j.vaAttachedToPV(ctx, pv.Name)
	if err != nil {
		metrics.IncError(j.queue)
		log.Error(err, "volumeattachment check failed — keeping pv-protection (fail closed)", "pv", pv.Name)
		return false
	}
	if attached {
		log.Info("SKIP: VolumeAttachment still references PV — pv-protection stays", "pv", pv.Name)
		return false
	}

	// Gate 5: cluster-wide Pod scan confirms no live pod or dead-node failed pod uses the PVC.
	inUse, err := j.clusterPodUsesClaimRef(ctx, pv.Spec.ClaimRef)
	if err != nil {
		metrics.IncError(j.queue)
		log.Error(err, "cluster pod scan failed — keeping pv-protection (fail closed)", "pv", pv.Name)
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
		metrics.IncError(j.queue)
		log.Error(err, "pv-protection finalizer strip failed", "pv", pv.Name)
		return false
	}
	log.Info("ACTION: removed orphan pv-protection finalizer", "pv", pv.Name)
	return true
}

func (j *failedJobsJanitor) clusterPodUsesClaimRef(ctx context.Context, ref *corev1.ObjectReference) (bool, error) {
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return false, nil
	}
	nodes, err := kube.ListNodes(ctx, j.cs)
	if err != nil {
		return true, err
	}
	ready := make(map[string]bool, len(nodes))
	for i := range nodes {
		ready[nodes[i].Name] = kube.NodeReady(&nodes[i])
	}

	inUse := false
	err = kube.ListEach(ctx, metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(j.cs, metav1.NamespaceAll), func(page []corev1.Pod) error {
			for i := range page {
				p := &page[i]
				if p.Namespace != ref.Namespace {
					continue
				}
				if p.Status.Phase == corev1.PodSucceeded {
					continue
				}
				if p.Status.Phase == corev1.PodFailed {
					if p.Spec.NodeName == "" || ready[p.Spec.NodeName] {
						continue
					}
				}
				if slices.Contains(kube.PodClaimedPVCs(p), ref.Name) {
					inUse = true
					return nil
				}
			}
			return nil
		})
	return inUse, err
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
	if err == nil {
		return false, finalizers // counterpart still exists
	}
	if !apierrors.IsNotFound(err) {
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
	if err == nil {
		return false, finalizers // counterpart still exists
	}
	if !apierrors.IsNotFound(err) {
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

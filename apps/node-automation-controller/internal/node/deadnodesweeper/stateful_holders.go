// stateful_holders.go — the stateful split-brain gate: the holder
// checks that decide whether force-detaching a dead node's volumes is
// dangerous (RWO VolumeAttachments, StatefulSet pods) plus the
// signal-only VolumeAttachment forensics log. Pure extraction from
// dead_node_sweeper.go — the safety story lives in doc.go.
package deadnodesweeper

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// nodeHasStatefulHolders reports whether the node holds
// anything that makes force-detaching its volumes dangerous: a
// VolumeAttachment whose volume carries a ReadWriteOnce access mode
// (RWO is the single-writer contract a not-really-dead node breaks
// loudly), or a Pod owned by a StatefulSet (its identity is
// volume-bound even when the current spec lost the claim). A list
// failure is an error — the caller fails closed.
func (s *deadNodeSweeper) nodeHasStatefulHolders(ctx context.Context, nodeName string) (bool, error) {
	// One PV census for the whole check: PV-referenced attachments
	// carry only the volume NAME — the access modes live on the PV
	// object itself (inline CSI specs carry their own). PVs are
	// cluster-scoped and number in the dozens, so one paged list is
	// the cheap shape.
	pvModes := map[string][]corev1.PersistentVolumeAccessMode{}
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PersistentVolumes(s.cs),
		func(items []corev1.PersistentVolume) error {
			for i := range items {
				pvModes[items[i].Name] = items[i].Spec.AccessModes
			}
			return nil
		})
	if err != nil {
		return false, fmt.Errorf("list persistentvolumes: %w", err)
	}
	hasRWO := false
	err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(s.cs),
		func(items []storagev1.VolumeAttachment) error {
			for i := range items {
				if items[i].Spec.NodeName == nodeName && volumeAttachmentRWO(&items[i], pvModes) {
					hasRWO = true
				}
			}
			return nil
		})
	if err != nil {
		return false, fmt.Errorf("list volumeattachments: %w", err)
	}
	if hasRWO {
		return true, nil
	}

	// Server-side node filter with the in-code check kept — fake
	// clientsets ignore field selectors (the belt every paged pod
	// list in this codebase wears).
	stsPod := false
	err = kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(s.cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Spec.NodeName != nodeName {
					continue
				}
				for _, ref := range p.OwnerReferences {
					if ref.Kind == "StatefulSet" {
						stsPod = true
					}
				}
			}
			return nil
		})
	if err != nil {
		return false, fmt.Errorf("list pods: %w", err)
	}
	return stsPod, nil
}

// volumeAttachmentRWO reports whether the attachment's volume carries
// a ReadWriteOnce access mode: inline CSI specs resolve off their own
// spec, PV-referenced ones off the pvModes census. A volume with no
// modes anywhere (attachment still in flight, PV since deleted)
// cannot prove multi-writer safety either way and reads as NOT RWO —
// logVolumeAttachments still names it for forensics.
func volumeAttachmentRWO(va *storagev1.VolumeAttachment,
	pvModes map[string][]corev1.PersistentVolumeAccessMode) bool {
	if va.Spec.Source.InlineVolumeSpec != nil {
		for _, mode := range va.Spec.Source.InlineVolumeSpec.AccessModes {
			if mode == corev1.ReadWriteOnce {
				return true
			}
		}
	}
	if name := va.Spec.Source.PersistentVolumeName; name != nil {
		for _, mode := range pvModes[*name] {
			if mode == corev1.ReadWriteOnce {
				return true
			}
		}
	}
	return false
}

// logVolumeAttachments lists VolumeAttachments bound to the node as a
// forensics signal (these are what the taint will force-detach).
// Never fatal, never vetoes a decision.
func (s *deadNodeSweeper) logVolumeAttachments(ctx context.Context, nodeName string) {
	log := logf.FromContext(ctx)
	// Paged like the pod list above — VolumeAttachments are
	// cluster-scoped and unbounded, and this read is signal-only.
	var names []string
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(s.cs),
		func(items []storagev1.VolumeAttachment) error {
			for i := range items {
				if items[i].Spec.NodeName == nodeName {
					names = append(names, items[i].Name)
				}
			}
			return nil
		})
	if err != nil {
		log.Error(err, "volumeattachment list failed — signal only", "node", nodeName)
		metrics.IncError(s.queue)
		return
	}
	if len(names) > 0 {
		log.Info("node holds volumeattachments — taint will force-detach",
			"node", nodeName, "attachments", names)
	}
}

// fenceNode applies the out-of-service taint to a confirmed-dead node
// and books the split-brain accounting: the signal-only attachment log,
// the TaintNode patch (a failure is logged + IncError'd here and
// returns so the caller skips the node — fail closed, not failed
// sweep), the without-SNR fence counter with its has_volumes label,
// and the stale skip-flag clear (the fence resolves the hold). A
// fence without a SNR CR is a judgment call even with the override,
// so alerting sees every fence the sweeper decided on its own
// evidence.
func (s *deadNodeSweeper) fenceNode(ctx context.Context, nodeName string,
	count int, viaSNR, hasVolumes bool, reason string) error {
	log := logf.FromContext(ctx)

	// Signal only: which volumes will the taint force-detach.
	// Failure here must not veto the taint decision.
	s.logVolumeAttachments(ctx, nodeName)

	if err := kube.TaintNode(ctx, s.cs, nodeName, outOfServiceTaintKey,
		outOfServiceTaintValue, corev1.TaintEffectNoExecute); err != nil {
		log.Error(err, "out-of-service taint failed", "node", nodeName,
			"stuckPods", count)
		metrics.IncError(s.queue)
		return err
	}
	if !viaSNR {
		metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues(
			nodeName, strconv.FormatBool(hasVolumes)).Inc()
		metrics.DeadNodeUnfencedStatefulSkipped.DeleteLabelValues(nodeName)
	}
	log.Info("TAINT: node confirmed dead -> out-of-service=nodeshutdown:NoExecute "+
		"(pods force-deleted, volumes detached by node controller)",
		"node", nodeName, "stuckPods", count,
		"evidence", reason, "viaSNR", viaSNR)
	return nil
}

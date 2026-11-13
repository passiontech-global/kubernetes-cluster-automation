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

// volumeAttachmentCache memoizes the once-per-sweep VolumeAttachment
// listing — nodeHasStatefulHolders and logVolumeAttachments consume
// the same census (previously two full cluster lists per fence). The
// list error is cached too, and each consumer applies its own policy
// to it: the holder check fails closed, the forensics log is
// signal-only — both stay consistent across the sweep instead of
// re-hammering a flapping API per node (same shape as
// verdict.go's remediationCache).
type volumeAttachmentCache struct {
	fetched bool
	items   []storagev1.VolumeAttachment
	err     error
}

// volumeAttachments returns the cluster's VolumeAttachments, listing
// at most once per cache instance.
func (s *deadNodeSweeper) volumeAttachments(ctx context.Context,
	vac *volumeAttachmentCache) ([]storagev1.VolumeAttachment, error) {
	if vac.fetched {
		return vac.items, vac.err
	}
	vac.fetched = true
	vac.err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(s.cs),
		func(items []storagev1.VolumeAttachment) error {
			vac.items = append(vac.items, items...)
			return nil
		})
	return vac.items, vac.err
}

// pvCache memoizes the once-per-sweep PersistentVolume census —
// PV-referenced VolumeAttachments carry only the volume NAME, so
// nodeHasStatefulHolders resolves access modes off the PV object
// itself. PVs are cluster-scoped and number in the dozens; without
// the cache every suspect node re-paged the whole list.
type pvCache struct {
	fetched bool
	modes   map[string][]corev1.PersistentVolumeAccessMode // pv name -> accessModes
	err     error
}

// pvAccessModes returns PV name → access modes, listing at most
// once per cache.
func (s *deadNodeSweeper) pvAccessModes(ctx context.Context,
	pc *pvCache) (map[string][]corev1.PersistentVolumeAccessMode, error) {
	if pc.fetched {
		return pc.modes, pc.err
	}
	pc.fetched = true
	pc.modes = map[string][]corev1.PersistentVolumeAccessMode{}
	pc.err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PersistentVolumes(s.cs),
		func(items []corev1.PersistentVolume) error {
			for i := range items {
				pc.modes[items[i].Name] = items[i].Spec.AccessModes
			}
			return nil
		})
	return pc.modes, pc.err
}

// pvcCache memoizes the once-per-sweep PVC census — the same
// listing serves every suspect node (previously each node would
// re-list all claims). Keyed "namespace/name" → bound PV name.
type pvcCache struct {
	fetched bool
	pvOf    map[string]string // claim "ns/name" -> spec.volumeName
	err     error
}

// pvClaims returns claim→PV bindings, listing at most once per cache.
func (s *deadNodeSweeper) pvClaims(ctx context.Context,
	pc *pvcCache) (map[string]string, error) {
	if pc.fetched {
		return pc.pvOf, pc.err
	}
	pc.fetched = true
	pc.pvOf = map[string]string{}
	pc.err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PersistentVolumeClaims(s.cs, metav1.NamespaceAll),
		func(items []corev1.PersistentVolumeClaim) error {
			for i := range items {
				c := &items[i]
				if c.Spec.VolumeName != "" {
					pc.pvOf[c.Namespace+"/"+c.Name] = c.Spec.VolumeName
				}
			}
			return nil
		})
	return pc.pvOf, pc.err
}

// nodeHasStatefulHolders reports whether the node holds
// anything that makes force-detaching its volumes dangerous: a
// VolumeAttachment whose volume carries a ReadWriteOnce or
// ReadWriteOncePod access mode (RWO/RWOP are the single-writer
// contracts a not-really-dead node breaks loudly), a Pod owned by
// a StatefulSet (its identity is volume-bound even when the current
// spec lost the claim), or ANY pod — whatever its controller —
// bound to a PVC whose volume is RWO/RWOP (CloudNativePG Cluster
// pods, bare DB pods, Jobs with claims: none are StatefulSet-owned
// yet all hold single-writer disks). A list failure is an error —
// the caller fails closed.
func (s *deadNodeSweeper) nodeHasStatefulHolders(ctx context.Context, nodeName string,
	vac *volumeAttachmentCache, pc *pvcCache, pvC *pvCache) (bool, error) {
	// One PV census for the whole sweep (pvCache): PV-referenced
	// attachments carry only the volume NAME — the access modes
	// live on the PV object itself (inline CSI specs carry their
	// own). PVs are cluster-scoped and number in the dozens, so
	// one paged list per sweep is the cheap shape.
	pvModes, err := s.pvAccessModes(ctx, pvC)
	if err != nil {
		return false, fmt.Errorf("list persistentvolumes: %w", err)
	}
	hasRWO := false
	attachments, err := s.volumeAttachments(ctx, vac)
	if err != nil {
		return false, fmt.Errorf("list volumeattachments: %w", err)
	}
	for i := range attachments {
		if attachments[i].Spec.NodeName == nodeName && volumeAttachmentRWO(&attachments[i], pvModes) {
			hasRWO = true
		}
	}
	if hasRWO {
		return true, nil
	}

	// Server-side node filter with the in-code check kept — fake
	// clientsets ignore field selectors (the belt every paged pod
	// list in this codebase wears). One pass decides BOTH holder
	// classes: StatefulSet-owned pods AND any pod bound to an
	// RWO/RWOP claim. The claim→PV census is one cached list per
	// sweep, paid here because the pod scan needs it to resolve
	// claim names to volumes.
	claims, claimsErr := s.pvClaims(ctx, pc)
	if claimsErr != nil {
		return false, fmt.Errorf("list persistentvolumeclaims: %w", claimsErr)
	}
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
				if stsPod {
					continue
				}
				for _, vol := range p.Spec.Volumes {
					claim := vol.PersistentVolumeClaim
					if claim == nil {
						continue
					}
					pvName, ok := claims[p.Namespace+"/"+claim.ClaimName]
					if !ok {
						continue // unbound claim — no volume to split yet
					}
					for _, mode := range pvModes[pvName] {
						if mode == corev1.ReadWriteOnce ||
							mode == corev1.ReadWriteOncePod {
							stsPod = true
						}
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
// a single-writer access mode (ReadWriteOnce or ReadWriteOncePod —
// RWOP landed in the access-mode enum after the original RWO-only
// check and a not-really-dead node breaks it just as loudly):
// inline CSI specs resolve off their own spec, PV-referenced ones
// off the pvModes census. A volume with no modes anywhere
// (attachment still in flight, PV since deleted) cannot prove
// multi-writer safety either way and reads as NOT single-writer —
// logVolumeAttachments still names it for forensics.
func volumeAttachmentRWO(va *storagev1.VolumeAttachment,
	pvModes map[string][]corev1.PersistentVolumeAccessMode) bool {
	if va.Spec.Source.InlineVolumeSpec != nil {
		for _, mode := range va.Spec.Source.InlineVolumeSpec.AccessModes {
			if mode == corev1.ReadWriteOnce || mode == corev1.ReadWriteOncePod {
				return true
			}
		}
	}
	if name := va.Spec.Source.PersistentVolumeName; name != nil {
		for _, mode := range pvModes[*name] {
			if mode == corev1.ReadWriteOnce || mode == corev1.ReadWriteOncePod {
				return true
			}
		}
	}
	return false
}

// logVolumeAttachments reads the sweep's VolumeAttachment census (the
// cache nodeHasStatefulHolders already filled — never a second list)
// and logs the attachments bound to the node as a forensics signal
// (these are what the taint will force-detach). Never fatal, never
// vetoes a decision.
func (s *deadNodeSweeper) logVolumeAttachments(ctx context.Context, nodeName string,
	vac *volumeAttachmentCache) {
	log := logf.FromContext(ctx)
	attachments, err := s.volumeAttachments(ctx, vac)
	if err != nil {
		log.Error(err, "volumeattachment list failed — signal only", "node", nodeName)
		metrics.IncError(s.queue)
		return
	}
	var names []string
	for i := range attachments {
		if attachments[i].Spec.NodeName == nodeName {
			names = append(names, attachments[i].Name)
		}
	}
	if len(names) > 0 {
		log.Info("node holds volumeattachments — taint will force-detach",
			"node", nodeName, "attachments", names)
	}
}

// fenceNode applies the out-of-service taint to a confirmed-dead node
// and books the split-brain accounting: the signal-only attachment log
// (fed from the sweep's shared VolumeAttachment census), the
// TaintNode patch (a failure is logged + IncError'd here and returns
// so the caller skips the node — fail closed, not failed sweep), the
// without-SNR fence counter with its has_volumes label, and the stale
// skip-flag clear (the fence resolves the hold). A fence without a
// SNR CR is a judgment call even with the override, so alerting sees
// every fence the sweeper decided on its own evidence.
func (s *deadNodeSweeper) fenceNode(ctx context.Context, nodeName string,
	count int, viaSNR, hasVolumes bool, reason string, vac *volumeAttachmentCache) error {
	log := logf.FromContext(ctx)

	// Signal only: which volumes will the taint force-detach.
	// Failure here must not veto the taint decision.
	s.logVolumeAttachments(ctx, nodeName, vac)

	if err := kube.TaintNode(ctx, s.cs, nodeName, kube.TaintNodeOutOfService,
		outOfServiceTaintValue, corev1.TaintEffectNoExecute); err != nil {
		log.Error(err, "out-of-service taint failed", "node", nodeName,
			"stuckPods", count)
		metrics.IncError(s.queue)
		return err
	}
	if !viaSNR {
		hv := strconv.FormatBool(hasVolumes)
		metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues(nodeName, hv).Inc()
		// Same series hygiene as the gauge sibling: book the tuple so
		// the sweep prunes the series once the node leaves the census
		// (key node\x00has_volumes — a counter series can otherwise
		// only accumulate on node-pool rotation).
		s.fencedWithoutSNREmitted.Emit(nodeName+"\x00"+hv, nodeName, hv)
		metrics.DeadNodeUnfencedStatefulSkipped.DeleteLabelValues(nodeName)
	}
	log.Info("TAINT: node confirmed dead -> out-of-service=nodeshutdown:NoExecute "+
		"(pods force-deleted, volumes detached by node controller)",
		"node", nodeName, "stuckPods", count,
		"evidence", reason, "viaSNR", viaSNR)
	return nil
}

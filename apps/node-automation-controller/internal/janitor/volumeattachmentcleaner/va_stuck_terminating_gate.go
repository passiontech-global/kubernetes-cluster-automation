// va_stuck_terminating_gate.go — gate 3 of the volumeattachment-cleaner:
// the stuck-Terminating finalizer strip (va-stuck-terminating). A VA already carrying a
// DeletionTimestamp past vaStuckTerminatingAge whose attacher-side
// cleanup is dead can never drain its own finalizer, so the cleaner
// strips it to free the PV. Two proof shapes survive the plain-delete
// gates: the node gone outright, or fenced with zero live pods (a
// DaemonSet pod holding a claim mount counts as live — see
// livePodCount — stuckTerminatingNodeDead); and the fast-reboot leak —
// the node came back Ready before the fencing taint ever landed, the
// volume is provably unused, and the sighting held for >= 2
// consecutive cycles (stuckReadyUnused and the Ready-node
// unused-volume gate below). Split out of volumeattachment_cleaner.go
// — see that file for the sweep that consumes these verdicts.
package volumeattachmentcleaner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// stuckTerminatingNodeDead is the va-stuck-terminating wedged-detach gate: the VA's
// node is gone outright, or carries the out-of-service taint while a
// live pod List proves zero live pods remain (a DaemonSet pod holding
// a claim mount counts — the same census the out-of-service gate
// runs) — in both shapes the external-attacher has no live node to
// report the detach to, so the finalizer can never drain. Any
// pod-list failure fails closed (the mount may still be real).
func (c *volumeAttachmentCleaner) stuckTerminatingNodeDead(ctx context.Context,
	va *storagev1.VolumeAttachment, nodeByName map[string]*corev1.Node,
	livePods map[string]podListProbe, stuckReadyPrior map[string]bool,
	now time.Time) bool {
	log := logf.FromContext(ctx)
	node, ok := nodeByName[va.Spec.NodeName]
	if !ok {
		return true // node object gone — nothing left to detach from
	}
	if !kube.HasTaint(node.Spec.Taints, vaOutOfServiceTaint) {
		// Ready-node unused-volume branch: the node rebooted back
		// to Ready before attach-detach finished the detach, so the
		// fencing taint never landed and the fenced gate below can
		// never see it. The unused-volume gate itself was evaluated
		// in the pre-pass — strip only after it held for >=2
		// consecutive cycles (stuckReadyPrior), never on first
		// sight.
		if kube.NodeReady(node) && stuckReadyPrior[va.Name] {
			return true
		}
		return false
	}
	if kube.NodeReady(node) {
		// Fenced but alive — the taint is stale and the attacher is
		// live to drain its own finalizer; stripping it here could
		// detach a mounted volume (same guard nodeFencedDead runs).
		return false
	}
	notReadyFor, ok := c.nodeNotReadySince.Seen(node.Name, now)
	if !ok || notReadyFor < vaOutOfServiceDownFor {
		// The node has not been not-Ready long enough — the node
		// controller's own force-detach may still be in flight; we
		// only take over a wedged cleanup, never a working one.
		log.Info("KEEP: fenced node inside not-Ready window — finalizers stay",
			"node", node.Name,
			"notReadyFor", notReadyFor.Truncate(time.Minute),
			"required", vaOutOfServiceDownFor)
		return false
	}
	live, err := c.livePodCount(ctx, livePods, node.Name)
	if err != nil {
		if pr := livePods[node.Name]; !pr.reported {
			pr.reported = true
			livePods[node.Name] = pr
			metrics.IncError(c.queue)
		}
		log.Error(err, "pod list failed — keeping stuck VA finalizers (fail closed)",
			"node", node.Name)
		return false
	}
	return live == 0
}

// stripFinalizers merge-patches metadata.finalizers on a wedged
// VolumeAttachment — the last resort that frees the PV when the
// attacher-side cleanup is dead. Only external-attacher finalizers
// are stripped: a third-party finalizer somebody parked on the
// object survives — the gate's proofs establish the attacher is
// dead, not that every holder may go. The patch pins
// resourceVersion so a concurrent attacher write makes this a
// conflict (retried next sweep) rather than a blind overwrite.
func (c *volumeAttachmentCleaner) stripFinalizers(ctx context.Context,
	va *storagev1.VolumeAttachment) error {
	log := logf.FromContext(ctx)
	kept := make([]string, 0, len(va.Finalizers))
	for _, f := range va.Finalizers {
		if !strings.HasPrefix(f, "external-attacher/") {
			kept = append(kept, f)
		}
	}
	log.Info("PATCH-FINALIZERS: stuck VolumeAttachment on a dead node — stripping attacher finalizers to free the volume",
		"va", va.Name, "node", va.Spec.NodeName,
		"pv", ptr.Deref(va.Spec.Source.PersistentVolumeName, "?"),
		"terminatingFor", c.now.Now().Sub(va.DeletionTimestamp.Time).Truncate(time.Minute),
		"finalizers", va.Finalizers, "keeping", kept)
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": va.ResourceVersion,
			"finalizers":      kept,
		},
	})
	if err != nil {
		return err
	}
	if _, err := c.cs.StorageV1().VolumeAttachments().Patch(ctx, va.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "stuck volumeattachment finalizer strip failed",
			"va", va.Name, "node", va.Spec.NodeName)
		return err
	}
	metrics.VolumeAttachmentFinalizersRemovedTotal.
		WithLabelValues(va.Spec.NodeName).Inc()
	// The counter is never decremented by its own code path — the
	// ledger tracks the tuple so the sweep's end-of-sweep Prune can
	// retire the series once the node is gone (each sweep re-arms it
	// via the carry-forward while the census still lists the node).
	c.finalizersRemovedEmitted.Emit(va.Spec.NodeName, va.Spec.NodeName)
	return nil
}

// sightStuckReadyUnused is the pre-pass collector for the
// Ready-node unused-volume branch: records this cycle's sighting for
// every stuck VA (including capped ones) so the two-cycle window
// measures consecutive CYCLES, not consecutive confirmations.
func (c *volumeAttachmentCleaner) sightStuckReadyUnused(ctx context.Context,
	va *storagev1.VolumeAttachment, nodeByName map[string]*corev1.Node,
	nodePods map[string]podListProbe, pvcPVs map[string]pvcProbe,
	pvNames map[string]pvProbe, stuckReadyNow, stuckReadyPrior map[string]bool,
	now time.Time, log logr.Logger) {
	if c.stuckReadyUnused(ctx, va, nodeByName, nodePods, pvcPVs, pvNames, log) {
		stuckReadyNow[va.Name] = true
		_, stuckReadyPrior[va.Name] =
			c.stuckReadyFirstSeen.Observe(vaFirstSeenKey(va), now)
	}
}

// forgetSettledStuckReady re-arms the Ready-node window when the
// gate stopped holding (pod rebound, volume re-attached, node
// unReady or the VA resolved) — resetting the two-cycle count.
func (c *volumeAttachmentCleaner) forgetSettledStuckReady(
	stuckReadyNow map[string]bool) {
	c.stuckReadyFirstSeen.Prune(func(key string) bool {
		return stuckReadyNow[vaLedgerName(key)]
	})
}

// ---------------------------------------------------------------------------
// Ready-node unused-volume gate (dangling VA after a fast reboot)
// ---------------------------------------------------------------------------
//
// The stuck-terminating shapes above cover a node that is gone or
// fenced; a THIRD shape survives both: the node force-rebooted and
// came back Ready before attach-detach finished the detach — no
// out-of-service taint ever landed, the VA still carries its
// DeletionTimestamp, and the external-attacher's finalizer never
// drains because the volume is already unmounted. Strip it only
// when EVERY proof holds: the node is Ready and taint-free, no
// non-terminal pod on the node mounts the PV (through any of its
// claim volumes), and the volume is absent from BOTH
// node.Status.VolumesInUse and node.Status.VolumesAttached — the
// kubelet's own ledger saying the mount is gone. Every unverifiable
// read fails closed.

// podListProbe caches one node's full pod LIST for the cycle —
// several VAs share a node, the ready-node gate inspects pod
// volumes rather than just counts, and the fenced gate's live count
// reads the same slice. reported marks an already-metered err.
type podListProbe struct {
	pods     []corev1.Pod
	err      error
	reported bool
}

// nodePodList is the single per-cycle pod list every gate reads —
// one apiserver ListAll per node per sweep, however many gates
// (fenced live-count, stuck-Terminating mounted-claim scan) consume
// it. Error is cached with the probe: a failed list fails every
// consumer closed for the cycle without re-hitting the apiserver.
func (c *volumeAttachmentCleaner) nodePodList(ctx context.Context,
	cache map[string]podListProbe, node string) (podListProbe, error) {
	if pr, ok := cache[node]; ok {
		return pr, pr.err
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(c.cs, metav1.NamespaceAll))
	if err != nil {
		err = fmt.Errorf("list pods on %s: %w", node, err)
	}
	pr := podListProbe{pods: pods, err: err}
	cache[node] = pr
	return pr, err
}

// pvcProbe caches one PVC's bound spec.volumeName for the cycle —
// err is the GET failure (a NotFound caches volume="" — a claim
// that does not exist cannot hold a mount).
type pvcProbe struct {
	volume   string
	err      error
	reported bool
}

// pvProbe caches one PV's resolved kubelet unique volume name for
// the cycle: ok=false means the PV shape cannot be resolved to a
// VolumesInUse entry (fail closed); unique=="" with ok=true means
// the PV object itself is gone — provably unattached.
type pvProbe struct {
	unique   string
	ok       bool
	err      error
	reported bool
}

// stuckReadyUnused reports whether a stuck-Terminating VA on a Ready
// node provably holds a volume nothing uses — the fast-reboot leak
// the fenced gate cannot see. True only when ALL hold: the node is
// Ready and unfenced, no non-terminal pod on the node mounts the PV,
// and the volume is absent from VolumesInUse AND VolumesAttached.
func (c *volumeAttachmentCleaner) stuckReadyUnused(ctx context.Context,
	va *storagev1.VolumeAttachment, nodeByName map[string]*corev1.Node,
	nodePods map[string]podListProbe, pvcPVs map[string]pvcProbe,
	pvNames map[string]pvProbe, log logr.Logger) bool {

	node, ok := nodeByName[va.Spec.NodeName]
	if !ok || !kube.NodeReady(node) ||
		kube.HasTaint(node.Spec.Taints, vaOutOfServiceTaint) {
		return false
	}
	pvName := ptr.Deref(va.Spec.Source.PersistentVolumeName, "")
	if pvName == "" {
		return false // inline volume source — unresolvable, keep
	}
	using, err := c.podsUsingVolume(ctx, nodePods, pvcPVs,
		node.Name, pvName, log)
	if err != nil || using > 0 {
		return false
	}
	inUse, verifiable := c.volumeOnNode(ctx, pvNames, node, pvName, log)
	return verifiable && !inUse
}

// podsUsingVolume counts the non-terminal pods on node that mount a
// volume bound to pvName — via a PVC claim or a generic ephemeral
// volume's generated claim; those are the only pod volume shapes
// that can bind a PV (a pod-level `csi` volume is a standalone CSI
// mount with no PV object behind it — corev1.CSIVolumeSource carries
// no volumeHandle — so it can never be using pvName). Any lookup
// failure fails closed.
func (c *volumeAttachmentCleaner) podsUsingVolume(ctx context.Context,
	nodePods map[string]podListProbe, pvcPVs map[string]pvcProbe,
	node, pvName string, log logr.Logger) (int, error) {

	pr, err := c.nodePodList(ctx, nodePods, node)
	if err != nil {
		if !pr.reported {
			pr.reported = true
			nodePods[node] = pr
			metrics.IncError(c.queue)
		}
		log.Error(pr.err, "pod list failed — keeping stuck VA finalizers (fail closed)",
			"node", node)
		return 0, pr.err
	}
	using := 0
	for i := range pr.pods {
		p := &pr.pods[i]
		if p.Spec.NodeName != node {
			continue // fake clientsets ignore field selectors
		}
		if p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue // terminal — nobody is writing through it
		}
		for _, v := range p.Spec.Volumes {
			claim := ""
			switch {
			case v.PersistentVolumeClaim != nil:
				claim = v.PersistentVolumeClaim.ClaimName
			case v.Ephemeral != nil:
				// Generic ephemeral volumes materialize a PVC named
				// <pod>-<volume> owned by the pod.
				claim = p.Name + "-" + v.Name
			}
			if claim == "" {
				continue
			}
			vol, err := c.pvcBoundVolume(ctx, pvcPVs,
				p.Namespace, claim, log)
			if err != nil {
				return 0, err
			}
			if vol == pvName {
				using++
			}
		}
	}
	return using, nil
}

// pvcBoundVolume resolves a PVC's spec.volumeName, memoized per
// cycle. A NotFound reads as "" — the claim cannot hold a mount it
// does not have; any other failure is fail-closed.
func (c *volumeAttachmentCleaner) pvcBoundVolume(ctx context.Context,
	pvcPVs map[string]pvcProbe, ns, name string,
	log logr.Logger) (string, error) {

	key := ns + "/" + name
	pr, ok := pvcPVs[key]
	if !ok {
		pvc, err := c.cs.CoreV1().PersistentVolumeClaims(ns).
			Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			pr = pvcProbe{}
		case err != nil:
			pr = pvcProbe{err: fmt.Errorf("get pvc %s: %w", key, err)}
		default:
			pr = pvcProbe{volume: pvc.Spec.VolumeName}
		}
		pvcPVs[key] = pr
	}
	if pr.err != nil {
		if !pr.reported {
			pr.reported = true
			pvcPVs[key] = pr
			metrics.IncError(c.queue)
		}
		log.Error(pr.err, "pvc lookup failed — keeping stuck VA finalizers (fail closed)",
			"pvc", key)
		return "", pr.err
	}
	return pr.volume, nil
}

// volumeOnNode reports whether the PV's kubelet unique volume name
// still appears in node.Status.VolumesInUse or VolumesAttached —
// the kubelet's own confirmation the mount is gone. verifiable=false
// means the PV cannot be resolved to a unique name (fail closed).
func (c *volumeAttachmentCleaner) volumeOnNode(ctx context.Context,
	pvNames map[string]pvProbe, node *corev1.Node, pvName string,
	log logr.Logger) (inUse, verifiable bool) {

	pr, ok := pvNames[pvName]
	if !ok {
		pv, err := c.cs.CoreV1().PersistentVolumes().
			Get(ctx, pvName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			pr = pvProbe{ok: true} // PV gone — nothing can mount it
		case err != nil:
			pr = pvProbe{err: fmt.Errorf("get pv %s: %w", pvName, err)}
		default:
			unique, resolved := uniqueVolumeName(pv)
			pr = pvProbe{unique: unique, ok: resolved}
		}
		pvNames[pvName] = pr
	}
	switch {
	case pr.err != nil:
		if !pr.reported {
			pr.reported = true
			pvNames[pvName] = pr
			metrics.IncError(c.queue)
		}
		log.Error(pr.err, "pv lookup failed — keeping stuck VA finalizers (fail closed)",
			"pv", pvName)
		return false, false
	case !pr.ok:
		return false, false // unresolvable shape — cannot prove unused
	case pr.unique == "":
		return false, true // PV object gone — provably absent
	}
	for _, v := range node.Status.VolumesInUse {
		if string(v) == pr.unique {
			return true, true
		}
	}
	for _, v := range node.Status.VolumesAttached {
		if string(v.Name) == pr.unique {
			return true, true
		}
	}
	return false, true
}

// uniqueVolumeName computes the kubelet unique volume name attach-
// detach records in node.Status.VolumesInUse / VolumesAttached: CSI
// volumes are "kubernetes.io/csi/<driver>^<volumeHandle>", local
// volumes "kubernetes.io/local-volume/<pv name>". ok=false means the
// PV is a shape whose name cannot be computed here — the caller
// fails closed rather than guess at a mount it cannot see.
func uniqueVolumeName(pv *corev1.PersistentVolume) (string, bool) {
	if csi := pv.Spec.PersistentVolumeSource.CSI; csi != nil {
		return "kubernetes.io/csi/" + csi.Driver + "^" +
			csi.VolumeHandle, true
	}
	if pv.Spec.PersistentVolumeSource.Local != nil {
		return "kubernetes.io/local-volume/" + pv.Name, true
	}
	return "", false
}

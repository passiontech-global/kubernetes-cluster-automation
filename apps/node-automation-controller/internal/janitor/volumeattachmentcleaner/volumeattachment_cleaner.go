// volumeattachment-cleaner — C4, the orphaned VolumeAttachment reaper.
//
// A VolumeAttachment (VA) is the cluster-scoped record that a CSI
// driver holds a volume attached to a node. It is also THE detach
// switch: deleting the VA object is what tells attach-detach the
// volume is detached and the PV may be mounted elsewhere — which is
// exactly why this module exists AND exactly why it must fail closed.
// Deleting a VA whose node is actually alive-and-mounted produces the
// classic split-brain: the PV becomes attachable on a second node
// while still attached to the first → two writers, filesystem
// corruption (the same foot-gun dead-node-sweeper documents for pod
// force-delete). Every gate below exists to prove the node cannot be
// a live writer before a delete is issued.
//
// Two leak shapes are reaped:
//
//	missing_node — spec.nodeName has no Node object (node removed
//	without drain: dead host replaced, `kubectl delete node` on a
//	lost worker). Nothing in-tree ever cleans that VA — the
//	external-attacher keeps "detaching" from a node that does not
//	exist, its finalizer never drains, the PV stays attached
//	forever and the rescheduled workload hits Multi-Attach on the
//	new node. Gates: VA age ≥ 5m (brand-new VAs legitimately race
//	ahead of a node create during provisioning) AND the orphan seen
//	in ≥2 consecutive cycles — a node missing from ONE List
//	(watch-cache gap, apiserver blip) must never detach a volume.
//
//	out_of_service_node — the node carries
//	node.kubernetes.io/out-of-service, the fencing signal CSI
//	respects (dead-node-sweeper and medik8s SNR set it once a node
//	is confirmed dead). On that taint attach-detach force-detaches
//	by deleting the VAs itself, so a VA still pointing at a fenced
//	node is a straggler — created after the taint, or its
//	force-delete wedged. Gates: node continuously not-Ready ≥ 15m
//	(first-seen ledger — a Ready node re-arms the window) AND a
//	live pod List confirms 0 non-terminal pods on it: a pod still
//	in Pending/Running on that node may still hold the mount, and
//	only the node controller — never us — force-deletes those.
//
// Hard bounds: the node list must be non-empty (an empty list means
// the apiserver or RBAC lied — every VA would look orphaned, so
// refuse to evaluate anything) and at most vaDeleteCap deletions per
// cycle bound the blast radius of a wrong verdict. Deletion is a
// plain Delete — the VA's own attacher finalizer still gates the
// real detach, but for the two shapes above removing the object is
// the unstick the PV needs.
package volumeattachmentcleaner

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	volumeAttachmentCleanerQueue = "volumeattachment-cleaner"
	vaCleanerInterval            = 5 * time.Minute

	// vaMissingNodeMinAge: a VA must exist at least this long before
	// "its node is gone" counts against it — a VA can legitimately
	// be created seconds before its Node object registers.
	vaMissingNodeMinAge = 5 * time.Minute
	// vaOutOfServiceDownFor: an out-of-service node must stay
	// not-Ready this long before its VAs are reaped — covers the
	// node controller's own force-detach grace so we only ever take
	// over a wedged cleanup, never a working one.
	vaOutOfServiceDownFor = 15 * time.Minute
	// vaDeleteCap bounds detach calls per cycle — a wrong verdict
	// must never detach more than a handful of volumes at once.
	vaDeleteCap = 10
	// vaListPageSize bounds each cluster-wide VA/pod List page —
	// continue-token pagination keeps a large fleet from arriving
	// as one giant response body.
	vaListPageSize = 500
	// vaOutOfServiceTaint is the Kubernetes-native "node is fenced"
	// signal — the same key dead-node-sweeper sets.
	vaOutOfServiceTaint = "node.kubernetes.io/out-of-service"
	// vaStuckTerminatingAge: a VA already carrying a DeletionTimestamp
	// this long whose node is gone or fenced-and-empty is a wedged
	// attach-detach cleanup — the external-attacher finalizer never
	// drains because the node it reports to no longer exists. Past
	// this age the cleaner strips the finalizers itself (W4).
	vaStuckTerminatingAge = 15 * time.Minute
)

type volumeAttachmentCleaner struct {
	cs kubernetes.Interface
	// nowFn is the clock seam — tests pin and advance it freely.
	nowFn func() time.Time

	mu sync.Mutex
	// orphanFirstSeen: va name → first cycle the VA pointed at a
	// node that does not exist. Two consecutive sightings are
	// required to delete — an operator restart re-arms the window,
	// biasing conservative (same convention as helmrelease-unlocker).
	orphanFirstSeen shared.FirstSeenLedger
	// nodeNotReadySince: node name → first cycle the node was seen
	// not-Ready. Only consumed for out-of-service candidates, but
	// tracking every not-Ready node (not just tainted ones) means a
	// node that gets fenced after a long outage does not start a
	// fresh 15m window — its death clock was already running.
	nodeNotReadySince shared.FirstSeenLedger
}

// Setup registers the 5-minute sweep. The
// VOLUMEATTACHMENT_CLEANER_ENABLED gate (default on) is resolved by
// setupModules into Deps.Disabled — disabled skips registration
// entirely, matching the certmanager-reaper / cilium-taint-reaper
// contract.
func Setup(d shared.Deps) error {
	if d.Disabled {
		return nil
	}
	c := &volumeAttachmentCleaner{
		cs:    d.CS,
		nowFn: time.Now,
	}
	return shared.AddPeriodic(d.Mgr, volumeAttachmentCleanerQueue, vaCleanerInterval, c.run)
}

func (c *volumeAttachmentCleaner) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowFn()

	// Gate 1: the node list is the single source of truth for
	// "should this attachment exist". Abort on error — a partial or
	// blippy list would brand healthy attachments orphaned.
	nodes, err := shared.ListNodes(ctx, c.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err) // periodic wrapper IncErrors volumeattachment-cleaner
	}
	if len(nodes) == 0 {
		// An empty list is not "every VA is orphaned" — the operator
		// always runs against a cluster with nodes, so zero nodes
		// means the apiserver or RBAC broke. Refuse to evaluate, but
		// meter it: a persistently-empty node list is invisible
		// otherwise (the run deliberately still returns nil).
		metrics.IncError(volumeAttachmentCleanerQueue)
		log.Info("SKIP: node list empty — refusing to evaluate attachments")
		return nil
	}
	nodeByName := make(map[string]*corev1.Node, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		nodeByName[n.Name] = n
		// The not-Ready ledger feeds the out-of-service gate.
		// Recovery (or a vanished node, below) re-arms the window —
		// a node that flapped back to life must prove another full
		// 15m of death before its VAs are touched again.
		if !shared.NodeReady(n) {
			c.nodeNotReadySince.Observe(n.Name, now)
		} else {
			c.nodeNotReadySince.Forget(n.Name)
		}
	}
	// A node that vanished between cycles re-arms too — its
	// not-Ready clock was measuring a node that no longer exists.
	c.nodeNotReadySince.Prune(func(name string) bool {
		_, ok := nodeByName[name]
		return ok
	})
	nodes = nil

	vas, err := shared.ListAll(ctx,
		metav1.ListOptions{Limit: vaListPageSize},
		shared.VolumeAttachments(c.cs))
	if err != nil {
		return fmt.Errorf("list volumeattachments: %w", err)
	}
	// Deterministic order — the per-cycle cap must always pick the
	// same victims, not whichever ordering the apiserver returned.
	sort.Slice(vas, func(i, j int) bool {
		return vas[i].Name < vas[j].Name
	})

	// orphanNow tracks which VAs still look missing-node orphaned
	// this cycle — a VA whose node reappeared, or that was deleted,
	// must re-arm the two-sighting rule.
	orphanNow := map[string]bool{}
	// livePods caches the per-node non-terminal pod verdict for the
	// cycle — several VAs typically share a node, and the List is
	// the expensive part of the out-of-service gate. Errors are
	// cached too (nil pods + err): without it every VA on one
	// fenced node would re-issue the same failing List and each
	// bump IncError.
	livePods := map[string]podProbe{}

	// seenPrior records which of this cycle's missing-node sightings
	// were already tracked BEFORE the pre-pass stamped them —
	// "seen in >= 2 consecutive cycles" must compare against the
	// previous cycle, not the stamp the pre-pass just wrote
	// (Observe's 'seen' return is exactly that distinction).
	seenPrior := map[string]bool{}

	// Pre-pass: record this cycle's missing-node sightings for EVERY
	// listed VA before any delete runs — a VA past the delete cap
	// keeps its firstSeen ledger instead of re-arming the
	// two-sighting window every capped cycle.
	for i := range vas {
		va := &vas[i]
		if va.DeletionTimestamp != nil {
			continue
		}
		if _, ok := nodeByName[va.Spec.NodeName]; !ok {
			orphanNow[va.Name] = true
			_, seenPrior[va.Name] = c.orphanFirstSeen.Observe(va.Name, now)
			if !seenPrior[va.Name] {
				log.Info("orphaned VA sighted — tracking for next cycle",
					"va", va.Name, "node", va.Spec.NodeName)
			}
		}
	}

	deleted, failed := 0, 0
	capped := false
	for i := range vas {
		va := &vas[i]
		if va.DeletionTimestamp != nil {
			// W4: already terminating past the stuck age on a node
			// that is gone (or fenced with zero non-DaemonSet pods)
			// — the attacher finalizer can never drain, so the
			// finalizers are stripped to free the volume. Inside
			// the grace window it stays the stuck-terminating
			// audit's surface (C3b), untouched here.
			if now.Sub(va.DeletionTimestamp.Time) < vaStuckTerminatingAge {
				continue
			}
			if !c.stuckTerminatingNodeDead(ctx, va, nodeByName, livePods) {
				continue
			}
			if deleted+failed >= vaDeleteCap {
				capped = true
				break
			}
			if err := c.stripFinalizers(ctx, va); err != nil {
				failed++
				continue
			}
			deleted++
			continue
		}

		reason := ""
		if node, ok := nodeByName[va.Spec.NodeName]; !ok {
			// missing_node: the node object is gone — the VA can
			// only be garbage. Still requires the VA to be old
			// enough AND a sighting in a PRIOR cycle (seenPrior),
			// so a one-off node List gap never detaches anything.
			if seenPrior[va.Name] &&
				now.Sub(va.CreationTimestamp.Time) >= vaMissingNodeMinAge {
				reason = "missing_node"
			}
		} else if c.nodeFencedDead(ctx, node, livePods, now) {
			reason = "out_of_service_node"
		}
		if reason == "" {
			continue
		}
		if deleted >= vaDeleteCap {
			capped = true
			break
		}

		log.Info(fmt.Sprintf("DELETE volumeattachment %s: reason=%s node=%s pv=%s",
			va.Name, reason, va.Spec.NodeName,
			ptr.Deref(va.Spec.Source.PersistentVolumeName, "?")))
		// UID precondition: VA names are deterministic csi-hash
		// names — a volume re-attachment between list and delete
		// recreates the SAME name, so only the object we vetted may
		// be removed.
		uid := va.UID
		if err := c.cs.StorageV1().VolumeAttachments().Delete(ctx, va.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(volumeAttachmentCleanerQueue)
			log.Error(err, "volumeattachment delete failed",
				"va", va.Name, "node", va.Spec.NodeName,
				"pv", ptr.Deref(va.Spec.Source.PersistentVolumeName, "?"))
			failed++
			continue
		}
		metrics.VolumeAttachmentsCleanedTotal.WithLabelValues(reason).Inc()
		c.orphanFirstSeen.Forget(va.Name)
		deleted++
	}
	// Re-arm the grace window for every VA that stopped looking
	// orphaned (node reappeared, or the VA vanished between cycles).
	c.orphanFirstSeen.Prune(func(name string) bool {
		if orphanNow[name] {
			return true
		}
		log.Info("orphan sighting cleared — node reappeared or VA gone", "va", name)
		return false
	})
	if capped {
		log.Info(fmt.Sprintf("SKIP rest: cap=%d reached", vaDeleteCap))
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)
	return nil
}

// stuckTerminatingNodeDead is the W4 wedged-detach gate: the VA's
// node is gone outright, or carries the out-of-service taint while a
// live pod List proves zero non-DaemonSet pods remain — in both
// shapes the external-attacher has no live node to report the detach
// to, so the finalizer can never drain. Any pod-list failure fails
// closed (the mount may still be real).
func (c *volumeAttachmentCleaner) stuckTerminatingNodeDead(ctx context.Context,
	va *storagev1.VolumeAttachment, nodeByName map[string]*corev1.Node,
	livePods map[string]podProbe) bool {
	log := logf.FromContext(ctx)
	node, ok := nodeByName[va.Spec.NodeName]
	if !ok {
		return true // node object gone — nothing left to detach from
	}
	if !shared.HasTaint(node.Spec.Taints, vaOutOfServiceTaint) {
		return false
	}
	live, err := c.livePodCount(ctx, livePods, node.Name)
	if err != nil {
		if pr := livePods[node.Name]; !pr.reported {
			pr.reported = true
			livePods[node.Name] = pr
			metrics.IncError(volumeAttachmentCleanerQueue)
		}
		log.Error(err, "pod list failed — keeping stuck VA finalizers (fail closed)",
			"node", node.Name)
		return false
	}
	return live == 0
}

// stripFinalizers merge-patches metadata.finalizers away on a wedged
// VolumeAttachment — the last resort that frees the PV when the
// attacher-side cleanup is dead. The patch pins resourceVersion so a
// concurrent attacher write makes this a conflict (retried next
// sweep) rather than a blind overwrite.
func (c *volumeAttachmentCleaner) stripFinalizers(ctx context.Context,
	va *storagev1.VolumeAttachment) error {
	log := logf.FromContext(ctx)
	log.Info("PATCH-FINALIZERS: stuck VolumeAttachment on a dead node — stripping finalizers to free the volume",
		"va", va.Name, "node", va.Spec.NodeName,
		"pv", ptr.Deref(va.Spec.Source.PersistentVolumeName, "?"),
		"terminatingFor", c.nowFn().Sub(va.DeletionTimestamp.Time).Truncate(time.Minute),
		"finalizers", va.Finalizers)
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": va.ResourceVersion,
			"finalizers":      nil,
		},
	})
	if err != nil {
		return err
	}
	if _, err := c.cs.StorageV1().VolumeAttachments().Patch(ctx, va.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(volumeAttachmentCleanerQueue)
		log.Error(err, "stuck volumeattachment finalizer strip failed",
			"va", va.Name, "node", va.Spec.NodeName)
		return err
	}
	metrics.VolumeAttachmentFinalizersRemovedTotal.
		WithLabelValues(va.Spec.NodeName).Inc()
	return nil
}

// nodeFencedDead is the out-of-service gate: true only when the node
// carries the fencing taint AND has been not-Ready past the window
// AND provably hosts zero non-terminal pods. Any failed check keeps
// the VA — the volume may still be mounted by something real.
// podProbe caches one node's live-pod verdict for the cycle: a
// successful count, or the list error (fail closed either way on
// retry within the same sweep). reported marks that err already
// bumped IncError — N VAs sharing one fenced node must not fire N
// error bumps off the single cached failure.
type podProbe struct {
	count    int
	err      error
	reported bool
}

func (c *volumeAttachmentCleaner) nodeFencedDead(ctx context.Context,
	node *corev1.Node, livePods map[string]podProbe, now time.Time) bool {
	log := logf.FromContext(ctx)
	if !shared.HasTaint(node.Spec.Taints, vaOutOfServiceTaint) {
		return false // not fenced — NotReady alone is never a verdict
	}
	if shared.NodeReady(node) {
		return false // fenced but alive — the taint is stale, VAs stay
	}
	notReadyFor, ok := c.nodeNotReadySince.Seen(node.Name, now)
	if !ok {
		return false // node not in the not-Ready ledger — no verdict
	}
	if notReadyFor < vaOutOfServiceDownFor {
		log.Info("KEEP: fenced node still inside not-Ready window",
			"node", node.Name,
			"notReadyFor", notReadyFor.Truncate(time.Minute),
			"required", vaOutOfServiceDownFor)
		return false // not-Ready window still running
	}
	live, err := c.livePodCount(ctx, livePods, node.Name)
	if err != nil {
		// Cannot prove the node is empty → cannot prove the mount
		// is dead. Fail closed: keep the VA, flag the API failure —
		// once per node, not once per VA: every VA on this node
		// re-reads the same cached error, so the once-flag rides on
		// the probe itself.
		if pr := livePods[node.Name]; !pr.reported {
			pr.reported = true
			livePods[node.Name] = pr
			metrics.IncError(volumeAttachmentCleanerQueue)
		}
		log.Error(err, "pod list failed — keeping node VAs (fail closed)",
			"node", node.Name)
		return false
	}
	if live > 0 {
		log.Info("KEEP: fenced node still hosts non-terminal pods",
			"node", node.Name, "pods", live)
		return false
	}
	return true
}

// livePodCount lists pods bound to node and returns how many
// WORKLOAD pods are non-terminal (not Succeeded/Failed) — the "is
// anyone still potentially writing" check. DaemonSet and static
// mirror pods don't count: they run on every node, hold no PVC
// mounts, and on a fenced node are force-deleted + recreated as
// Pending by the controller — counting them would keep this gate
// permanently closed and the feature dead. Terminating workload
// pods count as live: a pod wedged in Terminating on a fenced node
// is the node controller's force-delete problem, and until it
// finishes the mount may still exist. Counts are cached per cycle.
func (c *volumeAttachmentCleaner) livePodCount(ctx context.Context,
	cache map[string]podProbe, node string) (int, error) {
	if pr, ok := cache[node]; ok {
		return pr.count, pr.err
	}
	pods, err := shared.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
		Limit:         vaListPageSize,
	}, shared.Pods(c.cs, metav1.NamespaceAll))
	if err != nil {
		err = fmt.Errorf("list pods on %s: %w", node, err)
		cache[node] = podProbe{err: err}
		return 0, err
	}
	live := 0
	for i := range pods {
		p := &pods[i]
		// Fake clientsets ignore field selectors — the spec.nodeName
		// filter is applied in code too, same convention as the
		// phase filters elsewhere in this codebase.
		if p.Spec.NodeName != node {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue // terminal — nobody is writing through it
		}
		if _, mirror := p.Annotations["kubernetes.io/config.mirror"]; mirror {
			continue // static pod mirror — the kubelet owns the real pod
		}
		ds := false
		for _, o := range p.OwnerReferences {
			if o.Kind == "DaemonSet" {
				ds = true
				break
			}
		}
		if ds {
			continue // infra agent — never holds a workload mount
		}
		live++
	}
	cache[node] = podProbe{count: live}
	return live, nil
}

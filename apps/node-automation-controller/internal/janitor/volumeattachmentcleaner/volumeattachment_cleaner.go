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
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	vaCleanerInterval = 5 * time.Minute

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
	// nodeReader backs ListNodesCached — the informer-backed node
	// census; destructive gates still confirm on the direct
	// clientset. Nil (test fixtures) falls back to ListNodes.
	nodeReader kube.CachedNodeReader
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin and advance it freely.
	now shared.Clock

	// orphanFirstSeen: va name → first cycle the VA pointed at a
	// node that does not exist. Two consecutive sightings are
	// required to delete — an operator restart re-arms the window,
	// biasing conservative (same convention as helmrelease-unlocker).
	orphanFirstSeen state.FirstSeenLedger
	// nodeNotReadySince: node name → first cycle the node was seen
	// not-Ready. Only consumed for out-of-service candidates, but
	// tracking every not-Ready node (not just tainted ones) means a
	// node that gets fenced after a long outage does not start a
	// fresh 15m window — its death clock was already running.
	nodeNotReadySince state.FirstSeenLedger
	// stuckReadyFirstSeen: va name → first cycle the VA sat stuck
	// Terminating on a Ready node with the volume provably unused
	// (the fast-reboot leak — the node came back before the fencing
	// taint ever landed). Two consecutive sightings are required to
	// strip — same conservative convention as orphanFirstSeen.
	stuckReadyFirstSeen state.FirstSeenLedger
}

// Setup registers the 5-minute sweep. The
// VOLUMEATTACHMENT_CLEANER_ENABLED gate (default on) is resolved by
// setupModules into Deps.Disabled — disabled skips registration
// entirely, matching the certmanager-reaper / cilium-taint-reaper
// contract.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		c := &volumeAttachmentCleaner{
			cs:         d.CS,
			nodeReader: d.Mgr.GetClient(),
			queue:      d.Name,
			now:        shared.SystemClock,
		}
		return shared.AddPeriodic(d.Mgr, c.queue, vaCleanerInterval, c.run)
	})
}

func (c *volumeAttachmentCleaner) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	now := c.now.Now()

	// Gate 1: the node list is the single source of truth for
	// "should this attachment exist". Abort on error — a partial or
	// blippy list would brand healthy attachments orphaned.
	nodes, err := kube.ListNodesCached(ctx, c.nodeReader, c.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err) // periodic wrapper IncErrors volumeattachment-cleaner
	}
	if len(nodes) == 0 {
		// An empty list is not "every VA is orphaned" — the operator
		// always runs against a cluster with nodes, so zero nodes
		// means the apiserver or RBAC broke. Refuse to evaluate, but
		// meter it: a persistently-empty node list is invisible
		// otherwise (the run deliberately still returns nil).
		metrics.IncError(c.queue)
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
		if !kube.NodeReady(n) {
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

	vas, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(c.cs))
	if err != nil {
		return fmt.Errorf("list volumeattachments: %w", err)
	}

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
	// nodePods caches the full per-node pod LIST for the Ready-node
	// unused-volume gate (a pod's volumes — not just its count —
	// must be inspected). pvcPVs/pvNames memoize the per-cycle PVC
	// bound-volume and PV unique-name resolutions the gate's lookups
	// make; every cache carries its error (fail closed) and meters
	// it at most once.
	nodePods := map[string]podListProbe{}
	pvcPVs := map[string]pvcProbe{}
	pvNames := map[string]pvProbe{}

	// seenPrior records which of this cycle's missing-node sightings
	// were already tracked BEFORE the pre-pass stamped them —
	// "seen in >= 2 consecutive cycles" must compare against the
	// previous cycle, not the stamp the pre-pass just wrote
	// (Observe's 'seen' return is exactly that distinction).
	seenPrior := map[string]bool{}

	// stuckReadyNow/stuckReadyPrior mirror orphanNow/seenPrior for
	// the Ready-node unused-volume gate: the sightings must be
	// recorded BEFORE the sweep runs so a VA past the delete cap
	// keeps its two-cycle window instead of re-arming every capped
	// cycle.
	stuckReadyNow := map[string]bool{}
	stuckReadyPrior := map[string]bool{}

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

	// vaTarget is one listed VA carried into the sweep — strip tags
	// the W4 finalizer-strip action, reason the metric label of the
	// plain delete (decided inside Confirm, so a capped-out VA costs
	// no gate evaluation at all). Items are pointers so Confirm's
	// reason reaches LogTarget/Delete.
	type vaTarget struct {
		va     *storagev1.VolumeAttachment
		strip  bool
		reason string
	}
	var targets []*vaTarget
	for i := range vas {
		va := &vas[i]
		if va.DeletionTimestamp != nil {
			// W4: already terminating past the stuck age on a node
			// that is gone (or fenced with zero non-DaemonSet pods)
			// — the attacher finalizer can never drain, so the
			// finalizers are stripped to free the volume. Inside
			// the grace window it stays the stuck-terminating
			// audit's surface (C3b), untouched here.
			if now.Sub(va.DeletionTimestamp.Time) >= vaStuckTerminatingAge {
				targets = append(targets, &vaTarget{va: va, strip: true})
				// Ready-node unused-volume sighting — recorded for
				// every stuck VA (including capped ones) so the
				// two-cycle window measures consecutive CYCLES, not
				// consecutive confirmations.
				if c.stuckReadyUnused(ctx, va, nodeByName, nodePods,
					pvcPVs, pvNames, log) {
					stuckReadyNow[va.Name] = true
					_, stuckReadyPrior[va.Name] =
						c.stuckReadyFirstSeen.Observe(va.Name, now)
				}
			}
			continue
		}
		targets = append(targets, &vaTarget{va: va})
	}
	vas = nil

	deleted, failed, capped := reap.Sweep(ctx, log, targets, reap.Options[*vaTarget]{
		// The cap bounds delete ATTEMPTS — a wrong verdict must
		// never detach more than a handful of volumes at once, and
		// a rejected write churns the apiserver the same way.
		Cap: vaDeleteCap,
		// Deterministic victims — the cap must always pick the same
		// names, not whichever ordering the apiserver returned.
		Less: func(a, b *vaTarget) bool { return a.va.Name < b.va.Name },
		Confirm: func(ctx context.Context, t *vaTarget) (bool, error) {
			if t.strip {
				// The W4 wedged-detach gate — fails closed inside
				// (a pod-list failure keeps the finalizers).
				return c.stuckTerminatingNodeDead(ctx, t.va, nodeByName,
					livePods, stuckReadyPrior, now), nil
			}
			if node, ok := nodeByName[t.va.Spec.NodeName]; !ok {
				// missing_node: the node object is gone — the VA can
				// only be garbage. Still requires the VA to be old
				// enough AND a sighting in a PRIOR cycle (seenPrior),
				// so a one-off node List gap never detaches anything.
				if seenPrior[t.va.Name] &&
					now.Sub(t.va.CreationTimestamp.Time) >= vaMissingNodeMinAge {
					t.reason = "missing_node"
				}
			} else if c.nodeFencedDead(ctx, node, livePods, now) {
				t.reason = "out_of_service_node"
			}
			return t.reason != "", nil
		},
		LogTarget: func(log logr.Logger, t *vaTarget) {
			if t.strip {
				return // stripFinalizers emits its own PATCH-FINALIZERS line
			}
			log.Info("DELETE volumeattachment",
				"va", t.va.Name, "reason", t.reason, "node", t.va.Spec.NodeName,
				"pv", ptr.Deref(t.va.Spec.Source.PersistentVolumeName, "?"))
		},
		Delete: func(ctx context.Context, t *vaTarget) error {
			if t.strip {
				return c.stripFinalizers(ctx, t.va)
			}
			// UID precondition: VA names are deterministic csi-hash
			// names — a volume re-attachment between list and delete
			// recreates the SAME name, so only the object we vetted may
			// be removed.
			if err := c.cs.StorageV1().VolumeAttachments().Delete(ctx, t.va.Name,
				kube.UIDDeleteOptions(t.va.UID, "")); err != nil {
				return err
			}
			metrics.VolumeAttachmentsCleanedTotal.WithLabelValues(t.reason).Inc()
			c.orphanFirstSeen.Forget(t.va.Name)
			return nil
		},
		OnError: func(log logr.Logger, t *vaTarget, err error) {
			if t.strip {
				return // stripFinalizers already metered + logged the failure
			}
			metrics.IncError(c.queue)
			log.Error(err, "volumeattachment delete failed",
				"va", t.va.Name, "node", t.va.Spec.NodeName,
				"pv", ptr.Deref(t.va.Spec.Source.PersistentVolumeName, "?"))
		},
	})
	// Re-arm the grace window for every VA that stopped looking
	// orphaned (node reappeared, or the VA vanished between cycles).
	c.orphanFirstSeen.Prune(func(name string) bool {
		if orphanNow[name] {
			return true
		}
		log.Info("orphan sighting cleared — node reappeared or VA gone", "va", name)
		return false
	})
	// Same re-arm for the Ready-node window — the gate stopped
	// holding (pod rebound, volume re-attached, node unReady or the
	// VA resolved) resets the two-cycle count.
	c.stuckReadyFirstSeen.Prune(func(name string) bool {
		return stuckReadyNow[name]
	})
	if capped {
		log.Info("SKIP rest: cap reached", "cap", vaDeleteCap)
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
	livePods map[string]podProbe, stuckReadyPrior map[string]bool,
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
		"terminatingFor", c.now.Now().Sub(va.DeletionTimestamp.Time).Truncate(time.Minute),
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
		metrics.IncError(c.queue)
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
	if !kube.HasTaint(node.Spec.Taints, vaOutOfServiceTaint) {
		return false // not fenced — NotReady alone is never a verdict
	}
	if kube.NodeReady(node) {
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
			metrics.IncError(c.queue)
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
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(c.cs, metav1.NamespaceAll))
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
// several VAs share a node and the ready-node gate inspects pod
// volumes, not just counts. reported marks an already-metered err.
type podListProbe struct {
	pods     []corev1.Pod
	err      error
	reported bool
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
// volume bound to pvName — via a PVC claim, a generic ephemeral
// volume's generated claim, or a direct CSI volume whose driver and
// volumeHandle match the PV's. Any lookup failure fails closed.
func (c *volumeAttachmentCleaner) podsUsingVolume(ctx context.Context,
	nodePods map[string]podListProbe, pvcPVs map[string]pvcProbe,
	node, pvName string, log logr.Logger) (int, error) {

	pr, ok := nodePods[node]
	if !ok {
		pods, err := kube.ListAll(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + node,
			Limit:         kube.DefaultListPageSize,
		}, kube.Pods(c.cs, metav1.NamespaceAll))
		if err != nil {
			err = fmt.Errorf("list pods on %s: %w", node, err)
		}
		pr = podListProbe{pods: pods, err: err}
		nodePods[node] = pr
	}
	if pr.err != nil {
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

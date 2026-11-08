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
// force-delete). Every gate exists to prove the node cannot be
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
//
// The gate proofs live in sibling files: va_missing_node_gate.go
// (gate 1 — the orphan sighting pre-pass and age proof),
// va_out_of_service_gate.go (gate 2 — the fenced-node proof) and
// va_stuck_terminating_gate.go (gate 3 — the W4 stuck-Terminating
// finalizer strip); this file keeps Setup and the sweep
// orchestration that consumes their verdicts.
package volumeattachmentcleaner

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		c.trackNodeNotReady(n, now)
	}
	// A node that vanished between cycles re-arms too — its
	// not-Ready clock was measuring a node that no longer exists.
	c.pruneVanishedNodes(nodeByName)
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
	c.sightMissingNodeOrphans(vas, nodeByName, orphanNow, seenPrior, now, log)

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
				c.sightStuckReadyUnused(ctx, va, nodeByName, nodePods,
					pvcPVs, pvNames, stuckReadyNow, stuckReadyPrior, now, log)
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
				// missing_node — the node object is gone; the
				// age + prior-sighting proof is the gate's.
				t.reason = c.missingNodeReason(t.va, seenPrior, now)
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
	c.forgetReattachedOrphans(orphanNow, log)
	// Same re-arm for the Ready-node window — the gate stopped
	// holding (pod rebound, volume re-attached, node unReady or the
	// VA resolved) resets the two-cycle count.
	c.forgetSettledStuckReady(stuckReadyNow)
	if capped {
		log.Info("SKIP rest: cap reached", "cap", vaDeleteCap)
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)
	return nil
}

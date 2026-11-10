// va_sweep.go — the sweep phase run() orchestrates after the node
// census: the per-cycle probe caches and sighting ledgers (vaCycle),
// the target build (the missing-node sighting pre-pass plus the
// stuck-Terminating classification) and the reap.Sweep wiring whose
// Confirm re-runs every destructive verdict through the live-node
// confirm. The gate proofs the verdicts defer to live in
// va_missing_node_gate.go, va_out_of_service_gate.go and
// va_stuck_terminating_gate.go.
package volumeattachmentcleaner

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

// vaCycle is the per-cycle working set: the probe caches every gate
// memoizes against (a VA's verdict may cost a pod List per node —
// several VAs share a node, so the List runs once) and the sighting
// ledgers the two-cycle proofs read and write. All maps are
// cycle-scoped — nothing in here outlives one run.
type vaCycle struct {
	// livePods caches the per-node non-terminal pod verdict for the
	// cycle — several VAs typically share a node, and the List is
	// the expensive part of the out-of-service gate. Errors are
	// cached too (nil pods + err): without it every VA on one
	// fenced node would re-issue the same failing List and each
	// bump IncError.
	livePods map[string]podListProbe
	// nodePods caches the full per-node pod LIST for the Ready-node
	// unused-volume gate (a pod's volumes — not just its count —
	// must be inspected). pvcPVs/pvNames memoize the per-cycle PVC
	// bound-volume and PV unique-name resolutions the gate's lookups
	// make; every cache carries its error (fail closed) and meters
	// it at most once.
	nodePods map[string]podListProbe
	pvcPVs   map[string]pvcProbe
	pvNames  map[string]pvProbe

	// orphanNow tracks which VAs still look missing-node orphaned
	// this cycle — a VA whose node reappeared, or that was deleted,
	// must re-arm the two-sighting rule.
	orphanNow map[string]bool
	// seenPrior records which of this cycle's missing-node sightings
	// were already tracked BEFORE the pre-pass stamped them —
	// "seen in >= 2 consecutive cycles" must compare against the
	// previous cycle, not the stamp the pre-pass just wrote
	// (Observe's 'seen' return is exactly that distinction).
	seenPrior map[string]bool

	// stuckReadyNow/stuckReadyPrior mirror orphanNow/seenPrior for
	// the Ready-node unused-volume gate: the sightings must be
	// recorded BEFORE the sweep runs so a VA past the delete cap
	// keeps its two-cycle window instead of re-arming every capped
	// cycle.
	stuckReadyNow   map[string]bool
	stuckReadyPrior map[string]bool
}

func newVaCycle() *vaCycle {
	return &vaCycle{
		livePods:        map[string]podListProbe{},
		nodePods:        map[string]podListProbe{},
		pvcPVs:          map[string]pvcProbe{},
		pvNames:         map[string]pvProbe{},
		orphanNow:       map[string]bool{},
		seenPrior:       map[string]bool{},
		stuckReadyNow:   map[string]bool{},
		stuckReadyPrior: map[string]bool{},
	}
}

// vaTarget is one listed VA carried into the sweep — strip tags
// the va-stuck-terminating finalizer-strip action, reason the metric label of the
// plain delete (decided inside Confirm, so a capped-out VA costs
// no gate evaluation at all). Items are pointers so Confirm's
// reason reaches LogTarget/Delete.
type vaTarget struct {
	va     *storagev1.VolumeAttachment
	strip  bool
	reason string
}

// buildTargets lists the cluster's VolumeAttachments and runs the
// sighting pre-pass, classifying every listed VA into a sweep
// target. The missing-node sightings are recorded for EVERY VA
// before any delete runs — a VA past the delete cap keeps its
// firstSeen ledger instead of re-arming the two-sighting window
// every capped cycle. A Terminating VA past the stuck age becomes a
// strip target and gets its Ready-node unused-volume sighting
// stamped (recorded for every stuck VA including capped ones — the
// window measures consecutive CYCLES, not consecutive
// confirmations). The paged list is local to this function so it is
// released before the sweep runs.
func (c *volumeAttachmentCleaner) buildTargets(ctx context.Context,
	nodeByName map[string]*corev1.Node, cyc *vaCycle,
	now time.Time, log logr.Logger) ([]*vaTarget, error) {
	vas, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(c.cs))
	if err != nil {
		return nil, fmt.Errorf("list volumeattachments: %w", err)
	}
	c.sightMissingNodeOrphans(vas, nodeByName, cyc.orphanNow, cyc.seenPrior, now, log)
	var targets []*vaTarget
	for i := range vas {
		va := &vas[i]
		if va.DeletionTimestamp != nil {
			// va-stuck-terminating: already terminating past the stuck age on a node
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
				c.sightStuckReadyUnused(ctx, va, nodeByName, cyc.nodePods,
					cyc.pvcPVs, cyc.pvNames, cyc.stuckReadyNow, cyc.stuckReadyPrior, now, log)
			}
			continue
		}
		targets = append(targets, &vaTarget{va: va})
	}
	return targets, nil
}

// sweep runs the targets through reap.Sweep — cap-bounded,
// deterministic victims, and a single Confirm point that re-proves
// every destructive verdict on the live apiserver (the census is
// informer-backed and can lag a Get). The gates the census half of
// Confirm consults live in the va_*_gate.go files.
func (c *volumeAttachmentCleaner) sweep(ctx context.Context, log logr.Logger,
	nodeByName map[string]*corev1.Node, targets []*vaTarget,
	cyc *vaCycle, now time.Time) (deleted, failed int, capped bool) {
	return reap.Sweep(ctx, log, targets, reap.Options[*vaTarget]{
		// The cap bounds delete ATTEMPTS — a wrong verdict must
		// never detach more than a handful of volumes at once, and
		// a rejected write churns the apiserver the same way.
		Cap: vaDeleteCap,
		// Deterministic victims — the cap must always pick the same
		// names, not whichever ordering the apiserver returned.
		Less: func(a, b *vaTarget) bool { return a.va.Name < b.va.Name },
		Confirm: func(ctx context.Context, t *vaTarget) (bool, error) {
			return c.confirmTarget(ctx, t, nodeByName, cyc, now, log)
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
			switch {
			case apierrors.IsNotFound(err):
				// The VA was deleted under us — raced with an
				// external cleanup; nothing failed.
				log.Info("SKIP: volumeattachment already gone — raced with an external delete",
					"va", t.va.Name)
			case apierrors.IsConflict(err):
				// The UID precondition fired — the VA was recreated
				// (same csi-hash name, new volume) since the list.
				log.Info("SKIP: volumeattachment recreated since the list — UID precondition fired",
					"va", t.va.Name, "node", t.va.Spec.NodeName)
			default:
				metrics.IncError(c.queue)
				log.Error(err, "volumeattachment delete failed",
					"va", t.va.Name, "node", t.va.Spec.NodeName,
					"pv", ptr.Deref(t.va.Spec.Source.PersistentVolumeName, "?"))
			}
		},
	})
}

// confirmTarget is the sweep's single Confirm: the census verdict
// off the informer-backed node map (cheap, cached) gates whether the
// direct live-node confirm runs at all — and only a destructive
// verdict pays for it. A failed or refuted confirm keeps the VA
// fail-closed; a live node contradicting the census re-runs the
// destructive branch against the LIVE object.
func (c *volumeAttachmentCleaner) confirmTarget(ctx context.Context,
	t *vaTarget, nodeByName map[string]*corev1.Node,
	cyc *vaCycle, now time.Time, log logr.Logger) (bool, error) {
	censusVerdict := ""
	if t.strip {
		// The va-stuck-terminating wedged-detach gate — fails closed inside
		// (a pod-list failure keeps the finalizers).
		if c.stuckTerminatingNodeDead(ctx, t.va, nodeByName,
			cyc.livePods, cyc.stuckReadyPrior, now) {
			censusVerdict = "stuck_terminating"
		}
	} else if node, ok := nodeByName[t.va.Spec.NodeName]; !ok {
		// missing_node — the node object is gone; the
		// age + prior-sighting proof is the gate's.
		censusVerdict = c.missingNodeReason(t.va, cyc.seenPrior, now)
	} else if c.nodeFencedDead(ctx, node, cyc.livePods, now) {
		censusVerdict = "out_of_service_node"
	}
	if censusVerdict == "" {
		return false, nil
	}
	if !t.strip {
		t.reason = censusVerdict
	}
	// The destructive verdict came off the informer cache,
	// which can lag the apiserver — confirm the node on the
	// DIRECT clientset before any write (the doc promise).
	// Fail closed: an unverifiable confirm never detaches a
	// volume.
	live, gone, err := c.confirmLiveNode(ctx, t.va.Spec.NodeName)
	if err != nil {
		metrics.IncError(c.queue)
		log.Error(err, "live node confirm failed — keeping VA (fail closed)",
			"va", t.va.Name, "node", t.va.Spec.NodeName)
		return false, nil
	}
	if gone {
		// The apiserver itself answers NotFound — the
		// strongest shape of every destructive verdict; the
		// census verdict stands.
		return true, nil
	}
	// The live Get found the node — the census snapshot may
	// have been stale. The LIVE node wins: re-run the
	// destructive branch against it.
	if t.strip {
		liveNodes := map[string]*corev1.Node{t.va.Spec.NodeName: live}
		if !c.stuckTerminatingNodeDead(ctx, t.va, liveNodes,
			cyc.livePods, cyc.stuckReadyPrior, now) {
			return false, nil
		}
		// Ready-node branch: the two-cycle unused-volume sighting ran
		// against the informer snapshot — a pod may have mounted the
		// volume since. Re-run the proof against the LIVE node so its
		// Status.VolumesInUse/VolumesAttached (and the pod census)
		// decide, never the stale copy.
		if kube.NodeReady(live) &&
			!kube.HasTaint(live.Spec.Taints, vaOutOfServiceTaint) {
			return c.stuckReadyUnused(ctx, t.va, liveNodes,
				cyc.nodePods, cyc.pvcPVs, cyc.pvNames, log), nil
		}
		return true, nil
	}
	if t.reason == "missing_node" {
		// The node object exists on the live apiserver —
		// the orphan sighting came off a stale snapshot.
		// Clear it so the two-sighting window re-arms (same
		// convention as the orphanendpointslicecleaner's
		// stale-snapshot reset).
		c.orphanFirstSeen.Forget(t.va.Name)
		log.Info("KEEP: live node confirm found the node — census snapshot stale",
			"va", t.va.Name, "node", t.va.Spec.NodeName)
		return false, nil
	}
	// out_of_service_node — re-run the gate on the LIVE
	// node: Ready again or the taint dropped keeps the VA;
	// still fenced-and-dead holds the verdict (the pod
	// census re-reads the cycle's cache).
	return c.nodeFencedDead(ctx, live, cyc.livePods, now), nil
}

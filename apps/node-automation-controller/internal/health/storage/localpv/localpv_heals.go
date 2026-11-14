// localpv_heals.go — the maintenance-gated auto-heals of the
// localpv-stranded-pods check (localpv-stranded-pods): the ephemeral PVC+pod rescue
// for workloads stranded on a confirmed-dead node, and the wedged
// openebs-localpv-provisioner bounce for stalled hostpath claims.
// Split out of localpv_stranded_pods.go — see that file for the
// check, its per-sweep collectors and its gauges.
package localpv

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// healStrandedEphemeral runs the queued ephemeral-volume rescues.
// HealAllowed folds the per-target cooldown plus the maintenance
// mutex (memoized on the shared Deps verdict — one evaluation per
// sweep) — pod/PVC kills during a drain are exactly what it exists
// to prevent; "cannot verify" fails closed. PVC first, then the
// pod — the claim release flips the PV to Released so the
// node-host-agent sweeps it, and the pod delete lets the
// StatefulSet rebind onto a live node. UID preconditions close the
// list→delete TOCTOU on both.
func (p *localPVStrandedCheck) healStrandedEphemeral(ctx context.Context,
	log logr.Logger, heals []strandedHeal, now time.Time) {
	for i := range heals {
		h := &heals[i]
		pvcKey := h.pvc.Namespace + "/" + h.pvc.Name
		// Free in-RAM cooldown before the mutex/budget preamble.
		if p.localPVHealed.CooledDown(pvcKey, localPVEphemeralHealCooldown, now) {
			continue
		}
		proceed, unverifiable := p.HealAllowed(ctx, log,
			&p.localPVHealed, pvcKey,
			localPVEphemeralHealCooldown, now)
		if unverifiable {
			metrics.IncError(p.Name)
			continue
		}
		if !proceed {
			continue
		}
		pvcUID := h.pvc.UID
		pvcErr := p.CS.CoreV1().PersistentVolumeClaims(h.pvc.Namespace).
			Delete(ctx, h.pvc.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &pvcUID},
			})
		switch {
		case pvcErr == nil || apierrors.IsNotFound(pvcErr):
			kube.MarkPVCDeleted(ctx, pvcUID)
			// NotFound: the claim vanished between list and heal —
			// the release half is already done, still free the pod.
		case apierrors.IsForbidden(pvcErr):
			// RBAC-denied is permanent (PVC delete is only granted
			// via the concourse Role — an ephemeral-localpv opt-in
			// elsewhere can never succeed). Stamp the cooldown so
			// the check doesn't error-loop every sweep, keep the
			// pod, and surface once.
			metrics.IncError(p.Name)
			log.Error(pvcErr, "ephemeral localpv pvc delete forbidden — RBAC scope blocks the heal; stamping cooldown",
				"pvc", pvcKey)
			p.localPVHealed.Stamp(pvcKey, now)
			continue
		default:
			metrics.IncError(p.Name)
			log.Error(pvcErr, "ephemeral localpv pvc delete failed", "pvc", pvcKey)
			continue
		}
		// A pod already gone (NotFound) still counts the heal — the
		// claim release landed and the pod slot is free either way —
		// so the stamp stays manual rather than riding
		// heal.DeletePod's delivered-delete stamp.
		didDelete, err := heal.DeletePod(ctx, p.CS, nil, "", h.pod, now)
		if err != nil && !apierrors.IsNotFound(err) {
			metrics.IncError(p.Name)
			log.Error(err, "stranded pod delete failed",
				"pod", h.pod.Namespace+"/"+h.pod.Name)
			continue
		}
		if err == nil && !didDelete {
			// Quorum reservation denied — a sibling check already
			// spent this workload's one-disruption slot this sweep.
			// The PVC release already landed; the stranded pod is
			// dead weight either way, so next sweep's re-detection
			// finishes the job. (A NotFound err still falls through
			// to the bookkeeping below — pod already gone counts.)
			continue
		}
		kube.MarkPodDeleted(ctx, h.pod.UID) // O(1) tombstone — no census reset
		p.localPVHealed.Stamp(pvcKey, now)
		localPVEphemeralHealsTotal.
			WithLabelValues(h.pvc.Namespace, h.pvc.Name, h.node).Inc()
		log.Info("DELETE: ephemeral localpv pvc+pod stranded on a confirmed-dead node — StatefulSet rebinds on a live node",
			"pvc", pvcKey, "pod", h.pod.Namespace+"/"+h.pod.Name,
			"node", h.node, "reason", h.reason)
	}
}

// healLocalPVProvisioner deletes the openebs-localpv-provisioner
// pod(s) — the same re-sync nudge every operator heal here applies.
// Pending hostpath claims while Ready workers exist mean the
// provisioner missed a watch event; a restart makes it re-list and
// provision. The cooldown is the wider of the in-RAM ledger and the
// passiontech.dev/last-localpv-provisioner-heal stamp persisted on
// the provisioner Deployment (survives operator restarts) — a
// Deployment read failure defers fail-closed, an absent Deployment
// degrades to the ledger-only gate — then the shared HealAllowed
// maintenance gate. 1h cooldown, maintenance-gated.
func (p *localPVStrandedCheck) healLocalPVProvisioner(ctx context.Context,
	log logr.Logger, now time.Time) {

	// The durable cooldown half rides the provisioner's own
	// Deployment — the one object whose lifetime spans the heal
	// window. Resolved from the sweep's shared Deployment census
	// (cluster-wide read, client-side name filter); absent degrades
	// to the ledger-only gate, an unreadable census defers
	// fail-closed.
	var obj metav1.Object
	deps, err := p.AllDeployments(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: read localpv provisioner deployment failed — heal deferred",
			"error", err)
		return
	}
	for i := range deps {
		if deps[i].Namespace == openebsProvisionerNS &&
			deps[i].Name == openebsProvisionerName {
			obj = &deps[i]
			break
		}
	}
	// Confirm a provisioner pod exists BEFORE the persisted-cooldown
	// + mutex + budget preamble — an empty/absent pod set must not
	// spend a global heal token. BounceOperatorPod runs that same
	// confirm on its own fresh list (pick → empty ⇒ return before
	// the gate), so the persisted half is all that remains here.
	if obj != nil && heal.PersistedCooledDown(ctx, &p.pvcProvHealed, obj,
		pvcProvHealAnno, openebsProvisionerName, pvcProvisionerHealCooldown, now) {
		return
	}
	// BounceOperatorPod: in-RAM cooldown → fresh pod list → pick →
	// HealAllowed (memoized mutex + budget) → UID deletes. The pick
	// caps the bounce at ONE controller-owned pod — the old loop
	// deleted every prefix match, including stray pods no
	// controller would recreate.
	deleted := p.BounceOperatorPod(ctx, log, CheckNameLocalPVStranded,
		openebsProvisionerNS,
		func(pods []corev1.Pod) []*corev1.Pod {
			for i := range pods {
				pod := &pods[i]
				if !strings.HasPrefix(pod.Name, openebsProvisionerPrefix) ||
					pod.DeletionTimestamp != nil ||
					metav1.GetControllerOf(pod) == nil {
					continue
				}
				return []*corev1.Pod{pod}
			}
			return nil
		},
		&p.pvcProvHealed, openebsProvisionerName,
		pvcProvisionerHealCooldown, now)
	if deleted == 0 {
		return
	}
	pvcProvisionerHealsTotal.
		WithLabelValues(openebsProvisionerName).Inc()
	// Persist the stamp on the Deployment — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half (the delivered
	// delete already stamped pvcProvHealed) holding; nil ledger
	// because the in-RAM key is shared with DeletePod's own stamps.
	if err := heal.StampPersisted(ctx, nil,
		func(ctx context.Context, data []byte) error {
			_, err := p.CS.AppsV1().Deployments(openebsProvisionerNS).
				Patch(ctx, openebsProvisionerName, types.MergePatchType, data,
					metav1.PatchOptions{})
			return err
		},
		pvcProvHealAnno, nil, "", now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist localpv provisioner heal stamp failed",
			"deployment", openebsProvisionerNS+"/"+openebsProvisionerName)
	}
}

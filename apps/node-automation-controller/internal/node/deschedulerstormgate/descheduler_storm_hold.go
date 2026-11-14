// descheduler_storm_hold.go — the maintenance-hold-stale half of the
// descheduler-storm-gate reconcile: forgotten storm-gate holds and
// NodeHealthCheck pauseRequests each fire ONE MaintenanceHoldStale
// Warning per hold episode, with the first-seen window tracked on
// the object (annotation half) and in the reconciler (ledger half).
// Split from descheduler_storm_gate.go (see its header for the
// module contract).
package deschedulerstormgate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// maintenance-hold-stale — a maintenance hold (storm-gate-hold annotation or a
// NodeHealthCheck spec.pauseRequests) kept continuously past
// this age is a forgotten one: the Warning
// MaintenanceHoldStale event asks the operator to confirm it is
// still wanted. One warning per episode — re-armed only when
// the hold releases.
const (
	maintenanceHoldStaleAfter  = 2 * time.Hour
	maintenanceHoldStaleReason = "MaintenanceHoldStale"
	// stormHoldLedgerKey is the single ledger key the descheduler
	// Deployment's hold first-seen stamp rides.
	stormHoldLedgerKey = "kube-system/descheduler"
)

// ---------------------------------------------------------------------------
// maintenance-hold-stale — forgotten maintenance holds (MaintenanceHoldStale).
// ---------------------------------------------------------------------------

// checkHoldStale fires the one-per-episode MaintenanceHoldStale
// Warning for a storm-gate-hold="true" annotation held continuously
// past maintenanceHoldStaleAfter. The hold annotation carries no
// timestamp, so the window lives under
// kube.AnnoFirstSeenStormGateHold on the Deployment (the annotation
// half of heal.FirstSeenPersisted — a restart resumes the window
// instead of re-arming it) with r.holdSeen as the in-RAM half. The
// Warning rides the manager's event recorder; a nil recorder
// (StubManager tests) drops it rather than panicking.
func (r *deschedulerStormGate) checkHoldStale(ctx context.Context,
	deploy *appsv1.Deployment, now time.Time, log logr.Logger) {
	if !heal.FirstSeenPersisted(ctx, log, &r.holdSeen, deploy,
		kube.AnnoFirstSeenStormGateHold, stormHoldLedgerKey,
		maintenanceHoldStaleAfter, now, r.deployAnnoPatch(deploy)) {
		return // window not yet held out — nothing to warn about
	}
	if !r.holdWarned.Add(stormHoldLedgerKey) {
		return // this episode already warned — no spam on re-reconciles
	}
	if r.recorder != nil {
		r.recorder.Eventf(deploy, nil, corev1.EventTypeWarning,
			maintenanceHoldStaleReason, "StormGateHoldStale",
			"storm-gate hold annotation %s has been \"true\" for more than %s — "+
				"confirm the maintenance hold is still wanted",
			stormGateHoldAnno, maintenanceHoldStaleAfter)
	}
	log.Info("WARN: storm-gate hold is stale",
		"deployment", stormHoldLedgerKey,
		"annotation", stormGateHoldAnno,
		"heldForMoreThan", maintenanceHoldStaleAfter)
}

// deployAnnoPatch delivers the hold's first-seen stamp merge patch
// onto the descheduler Deployment — the same merge-patch-only
// contract the scale path runs (no full-object Update that would
// race a concurrent spec edit) — and refreshes deploy.ResourceVersion
// so a subsequent RV-pinned scale patch in the same reconcile sees the
// post-patch RV instead of self-conflicting with 409.
func (r *deschedulerStormGate) deployAnnoPatch(deploy *appsv1.Deployment) func(context.Context, []byte) error {
	return func(ctx context.Context, data []byte) error {
		updated, err := r.cs.AppsV1().Deployments("kube-system").Patch(ctx,
			"descheduler", types.MergePatchType, data, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf(
				"patch first-seen annotation on deployment kube-system/descheduler: %w", err)
		}
		if updated != nil && updated.ResourceVersion != "" && deploy != nil {
			deploy.ResourceVersion = updated.ResourceVersion
		}
		return nil
	}
}

// checkNHCPauseStale is the NHC half of maintenance-hold-stale: every NodeHealthCheck
// whose spec.pauseRequests has been non-empty past
// maintenanceHoldStaleAfter gets the same one-per-episode
// MaintenanceHoldStale Warning on the NHC object itself, window
// tracked under kube.AnnoFirstSeenNHCPause. A released pause clears
// the stamp (re-arms the full window for the next pause) and resets
// the emitted-once marker; objects that vanish take their ledger
// entries with them via the live prune. NHC is cluster-scoped, so
// keys are bare names. One stamp key per object and one visit per
// sweep — the patch closure needs no read-back mirror into the
// listed object (olmCRPatch mirrors because several live reasons
// share ONE CSV's map; here nothing re-reads the annotation after
// the patch).
func (r *deschedulerStormGate) checkNHCPauseStale(ctx context.Context,
	now time.Time, log logr.Logger) error {
	if r.dyn == nil {
		return errors.New(
			"no dynamic client — NodeHealthCheck pause-staleness probe unverifiable")
	}
	list, err := kube.ListAllUnstructured(ctx,
		r.dyn.Resource(kube.GVRNodeHealthCheck),
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
	switch {
	case kube.IsCRDAbsent(err):
		return nil // CRD absent on this cluster — nothing to probe
	case err != nil:
		return fmt.Errorf("list nodehealthchecks (pause staleness): %w", err)
	}
	live := make(map[string]bool, len(list.Items))
	for i := range list.Items {
		obj := &list.Items[i]
		key := obj.GetName()
		live[key] = true
		pauseRequests, _ := kube.NestedStringSlice(
			obj.Object, "spec", "pauseRequests")
		if len(pauseRequests) == 0 {
			// Pause released — the episode ended: drop the stamp and
			// the emitted-once marker so a later pause warns fresh.
			if err := heal.ClearPersistedFirstSeen(ctx, log, &r.nhcSeen,
				obj, kube.AnnoFirstSeenNHCPause, key, r.nhcAnnoPatch(obj)); err != nil {
				log.Info("WARN: NHC pause first-seen clear failed — "+
					"a stale stamp could fast-trip a recurrence",
					"nodehealthcheck", key, "error", err)
			}
			r.nhcWarned.Forget(key)
			continue
		}
		if !heal.FirstSeenPersisted(ctx, log, &r.nhcSeen, obj,
			kube.AnnoFirstSeenNHCPause, key,
			maintenanceHoldStaleAfter, now, r.nhcAnnoPatch(obj)) {
			continue // window not yet held out
		}
		if !r.nhcWarned.Add(key) {
			continue // this pause episode already warned — no spam
		}
		if r.recorder != nil {
			r.recorder.Eventf(obj, nil, corev1.EventTypeWarning,
				maintenanceHoldStaleReason, "NodeHealthCheckPauseStale",
				"spec.pauseRequests has been non-empty for more than %s — "+
					"confirm the pause is still wanted",
				maintenanceHoldStaleAfter)
		}
		log.Info("WARN: NodeHealthCheck pause is stale",
			"nodehealthcheck", key,
			"pauseRequests", len(pauseRequests))
	}
	r.nhcWarned.Prune(func(key string) bool { return live[key] })
	r.nhcSeen.Prune(func(key string) bool { return live[key] })
	return nil
}

// nhcAnnoPatch delivers the NHC's first-seen stamp merge patch via
// the dynamic client (cluster-scoped resource — no namespace).
func (r *deschedulerStormGate) nhcAnnoPatch(
	obj *unstructured.Unstructured) func(context.Context, []byte) error {
	return func(ctx context.Context, data []byte) error {
		_, err := r.dyn.Resource(kube.GVRNodeHealthCheck).Patch(ctx,
			obj.GetName(), types.MergePatchType, data, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch %s on nodehealthcheck %s: %w",
				kube.AnnoFirstSeenNHCPause, obj.GetName(), err)
		}
		return nil
	}
}

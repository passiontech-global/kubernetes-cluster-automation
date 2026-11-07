// linkerd_endpoint_sync_heal.go — the desync heal of the
// linkerd-endpoint-sync check (W10-FIX7): delete the provably-stale
// endpointslice-controller-owned slices, then bounce the oldest
// linkerd-destination pod so its endpoint table rebuilds — 1h
// per-service cooldown, maintenance-gated, UID-preconditioned.
package nethealth

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// healLinkerdDestination repairs a desynced Service on two
// fronts (W10-FIX7):
//
//  1. DELETE the provably-stale endpointslice-controller-owned
//     EndpointSlices staleLinkerdSlices flagged — a bounce only
//     re-reads the slices, so without this the destination pod would
//     resync from the same stale data. KCM's endpointslice-controller
//     recreates them from current pod state (UID-preconditioned,
//     same delete shape as the orphan-slice cleaner).
//  2. delete the OLDEST linkerd-destination pod — the component that
//     turns EndpointSlices into proxy endpoint state, so restarting
//     it forces a full resync from the (now corrected) slices.
//
// Gates: the 1h in-RAM cooldown keyed on the desynced service (the
// heal targets are the slices + pod — nothing else can carry the
// stamp; one stamp covers BOTH actions so a 5m sweep cannot churn
// slice deletes inside the pod-bounce cooldown) and the maintenance
// mutex, same shape as every pod-delete heal in this sweep. The
// cooldown stamps when ANY heal action succeeded — a failed delete
// retries next sweep instead of burning the hour.
func (p *linkerdEndpointSyncCheck) healLinkerdDestination(ctx context.Context,
	log logr.Logger, svcKey string, now time.Time, stale []linkerdSliceRef) {

	// linkerdDesyncHealed keys "ns/svc" — Services can be
	// decommissioned, so bound the map so their stamps cannot
	// accumulate.
	p.linkerdDesyncHealed.PruneExpired(now, linkerdDestHealCooldown)

	proceed, unverifiable := p.HealAllowed(ctx, log,
		&p.linkerdDesyncHealed, svcKey, linkerdDestHealCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}

	healed := false
	for _, sl := range stale {
		err := p.CS.DiscoveryV1().EndpointSlices(sl.ns).Delete(ctx, sl.name,
			kube.UIDDeleteOptions(sl.uid, ""))
		switch {
		case err == nil:
			healed = true
			p.InvalidateSweep(ctx) // slice census changed — drop the snapshot
			log.Info("DELETE: stale EndpointSlice for endpoint desync — endpointslice-controller rebuild forced",
				"endpointslice", sl.ns+"/"+sl.name, "service", svcKey)
		case apierrors.IsNotFound(err):
			// Already gone — another actor or the controller beat
			// us to it; nothing to heal.
		default:
			metrics.IncError(p.Name)
			log.Error(err, "stale endpointslice delete failed",
				"endpointslice", sl.ns+"/"+sl.name, "service", svcKey)
		}
	}

	pods, err := p.PodsIn(ctx, probefw.LinkerdNS)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list linkerd pods failed — heal deferred",
			"error", err)
		if healed {
			// Slice deletes already landed — stamp them now or an
			// unstamped sweep re-deletes the slices the
			// endpointslice-controller just rebuilt.
			p.linkerdDesyncHealed.Stamp(svcKey, now)
		}
		return
	}
	// The pod pick stays bespoke — the component matcher is not a
	// plain name-prefix list (exact name + Deployment prefix +
	// control-plane-component label, any phase), which
	// heal.OldestRunningPod's Running-only prefix scan cannot express.
	var target *corev1.Pod
	for i := range pods {
		pod := pods[i]
		if pod.DeletionTimestamp != nil ||
			!probefw.LinkerdPodMatchesComponent(pod, probefw.LinkerdDestinationName) {
			continue
		}
		if target == nil ||
			pod.CreationTimestamp.Before(&target.CreationTimestamp) {
			target = pod
		}
	}
	if target != nil {
		// The stamp is NOT the ledger's here — svcKey stamps once at
		// the end when ANY heal action (slice or pod delete) landed.
		if _, err := heal.DeletePod(ctx, p.CS, nil, "", target, now); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "linkerd-destination delete failed",
				"pod", target.Namespace+"/"+target.Name)
		} else {
			healed = true
			p.InvalidatePods(ctx) // pod gone — drop the census
			metrics.ControlPlanePodHealsTotal.WithLabelValues(probefw.LinkerdDestinationName).Inc()
			log.Info("DELETE: linkerd-destination bounce for endpoint desync — forcing endpoint-table resync",
				"pod", target.Namespace+"/"+target.Name, "service", svcKey)
		}
	}
	if healed {
		p.linkerdDesyncHealed.Stamp(svcKey, now)
	}
}

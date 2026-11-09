// linkerd_endpoint_sync_heal.go — the desync heal of the
// linkerd-endpoint-sync check (W10-FIX7): delete the provably-stale
// endpointslice-controller-owned slices, then bounce the oldest
// linkerd-destination pod so its endpoint table rebuilds — 1h
// per-service cooldown, maintenance-gated, UID-preconditioned.
package linkerd

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
// Gates: the escalating per-service cooldown (linkerdDestHealEscalation
// — the wider of the in-RAM linkerdDesyncHealed ledger and the
// passiontech.dev/last-linkerd-endpoint-sync-heal stamp persisted on
// the Service, so it survives operator restarts) and the maintenance
// mutex, same shape as every pod-delete heal in this sweep. The
// ladder counts CONSECUTIVE INEFFECTIVE bounces: each delivered heal
// lands a streak hit, the prune in Run resets it wherever a sweep
// sees the desync converge, and a third failed bounce in a row stops
// the bouncing (the divergence may be caused by a slice the
// managed-by delete never reaps — bouncing forever fixes nothing).
// One stamp covers BOTH actions so a 5m sweep cannot churn slice
// deletes inside the pod-bounce cooldown; the cooldown stamps when
// ANY heal action succeeded — a failed delete retries next sweep
// instead of burning the hour.
func (p *linkerdEndpointSyncCheck) healLinkerdDestination(ctx context.Context,
	log logr.Logger, svc *corev1.Service, svcKey string,
	now time.Time, stale []linkerdSliceRef) {

	// linkerdDesyncHealed keys "ns/svc" — Services can be
	// decommissioned, so bound the map so their stamps cannot
	// accumulate. The bound is the LONGEST cooldown the escalation
	// ladder serves (24h), not the base 1h.
	p.linkerdDesyncHealed.PruneExpired(now, linkerdDestHealCooldownMax)

	// Escalation — the current streak sizes this attempt's cooldown;
	// at the ladder's end the bouncing stops and the gauge + FAIL
	// series carry the alert. The streak counts DELIVERED bounces
	// (Hit after a landed heal), so a failed delete never advances
	// the ladder.
	fails := p.linkerdDesyncBounceFails.Count(svcKey)
	if fails >= len(linkerdDestHealEscalation) {
		log.Info("skip heal: linkerd endpoint desync survived three consecutive "+
			"bounces — escalation exhausted, leaving the alert to converge it",
			"service", svcKey, "bounces", fails)
		return
	}

	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.linkerdDesyncHealed, svc, linkerdDestHealAnno, svcKey,
		linkerdDestHealEscalation[fails], now)
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
			p.InvalidateEndpointSlices(ctx) // slice census changed — drop the snapshot
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

	pods, err := p.PodsIn(ctx, kube.LinkerdNS)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list linkerd pods failed — heal deferred",
			"error", err)
		if healed {
			// Slice deletes already landed — stamp them now or an
			// unstamped sweep re-deletes the slices the
			// endpointslice-controller just rebuilt.
			p.stampLinkerdDestinationHeal(ctx, log, svc, svcKey, now)
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
			!probefw.LinkerdPodMatchesComponent(pod, kube.LinkerdDestinationName) {
			continue
		}
		if target == nil ||
			pod.CreationTimestamp.Before(&target.CreationTimestamp) {
			target = pod
		}
	}
	if target != nil {
		// A bounce that outlives the workload is a blackhole, not a
		// heal — the destination must keep a genuinely Ready sibling
		// (ReadySiblings discounts the target itself when it still
		// reports Ready).
		readyByOwner := probefw.ReadyByOwner(ptrDerefPods(pods))
		if probefw.ReadySiblings(readyByOwner, target) < 1 {
			log.Info("skip linkerd-destination bounce: no Ready sibling replica — bounce would blackhole the endpoint table",
				"service", svcKey)
			if healed {
				// Slice deletes already landed — stamp them now or an
				// unstamped sweep re-deletes the slices the
				// endpointslice-controller just rebuilt.
				p.stampLinkerdDestinationHeal(ctx, log, svc, svcKey, now)
			}
			return
		}
		// The shared bounce cooldown keys the DESTINATION component,
		// not the service: two desynced services must not bounce the
		// same singleton linkerd-destination Deployment back-to-back
		// inside one sweep (the ladder tier scales it with the
		// per-service cooldown). Cooldown-ONLY — the budget token for
		// this heal was granted up front by HealAllowedPersisted
		// above, so a second HealAllowed here would double-spend for
		// one delete (and a fresh mutex evaluation is pointless: the
		// preamble already cleared it moments ago).
		ck := "linkerd/linkerd-destination"
		if p.Heals.CooledDown(ck, linkerdDestHealEscalation[fails], now) {
			log.Info("skip linkerd-destination bounce: inside bounce cooldown",
				"service", svcKey)
			if healed {
				p.stampLinkerdDestinationHeal(ctx, log, svc, svcKey, now)
			}
			return
		}
		// The svcKey stamp is NOT this ledger's — svcKey stamps once at
		// the end when ANY heal action (slice or pod delete) landed;
		// the shared key stamps here so the NEXT service's heal sees
		// the destination bounce even though this sweep's stamp
		// landed first.
		if _, err := heal.DeletePod(ctx, p.CS, &p.Heals, ck, target, now); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "linkerd-destination delete failed",
				"pod", target.Namespace+"/"+target.Name)
		} else {
			healed = true
			p.InvalidatePods(ctx) // pod gone — drop the census
			metrics.ControlPlanePodHealsTotal.WithLabelValues(kube.LinkerdDestinationName).Inc()
			log.Info("DELETE: linkerd-destination bounce for endpoint desync — forcing endpoint-table resync",
				"pod", target.Namespace+"/"+target.Name, "service", svcKey)
		}
	}
	if healed {
		p.stampLinkerdDestinationHeal(ctx, log, svc, svcKey, now)
	}
}

// stampLinkerdDestinationHeal lands the cooldown halves after a
// delivered heal: the in-RAM ledger stamp, the
// passiontech.dev/last-linkerd-endpoint-sync-heal annotation on the
// desynced Service (the durable half — a patch failure leaves the
// in-RAM half holding), and the ineffective-bounce streak hit whose
// next-sweep convergence check decides whether this bounce advances
// the escalation ladder.
func (p *linkerdEndpointSyncCheck) stampLinkerdDestinationHeal(
	ctx context.Context, log logr.Logger, svc *corev1.Service,
	svcKey string, now time.Time) {

	p.linkerdDesyncHealed.Stamp(svcKey, now)
	p.linkerdDesyncBounceFails.Hit(svcKey)
	// The Service already carries the first-seen stamp through the
	// same patch closure — reuse it for the heal stamp.
	if err := heal.StampPersisted(ctx, p.linkerdSvcPatch(svc),
		linkerdDestHealAnno, nil, "", now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist linkerd endpoint heal stamp failed",
			"service", svcKey)
	}
}

// ptrDerefPods copies a []*corev1.Pod census into a []corev1.Pod —
// the shape probefw.ReadyByOwner consumes (elements alias the
// snapshot's pod structs; read-only).
func ptrDerefPods(pods []*corev1.Pod) []corev1.Pod {
	out := make([]corev1.Pod, len(pods))
	for i := range pods {
		out[i] = *pods[i]
	}
	return out
}

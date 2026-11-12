// dragonfly_heals.go — the dragonfly auto-heals of the
// stateful-masterless-services check (stateful-masterless-services step 1 + dual-replica-deadlock step 2):
// the dragonfly-operator leader delete forcing master re-election,
// and the dual-replica deadlock heal deleting the lowest-ordinal
// STS pod once the operator bounce demonstrably failed to re-elect.
// Split out of stateful_masterless_services.go — see that file for
// the check and its knobs.
package datastore

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

var (
	// dual-replica-deadlock — dragonfly STS ordinal-0 pods deleted to force master
	// re-election after a dual-replica deadlock. Counts delivered
	// heals only.
	dragonflyMasterlessPodHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_dragonfly_masterless_pod_heals_total",
		Help: "Dragonfly STS ordinal-0 pods deleted to force master re-election after a dual-replica deadlock.",
	}, []string{"namespace", "statefulset"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		dragonflyMasterlessPodHealsTotal)
}

// healDragonflyOperator deletes at most ONE dragonfly-operator
// controller pod per cycle — the same re-election nudge the operator
// watchdog applies, keyed on its own 30m cooldown so the leader is
// never churned. Mid-rollout the operator runs two ReplicaSet
// generations side by side and the per-controller cooldown only
// dedups pods of the SAME RS, so deleting every prefix match in one
// sweep would take out the whole operator (leader election included)
// in a single pass; the 1-per-cycle cap with the deterministic
// oldest-pod pick mirrors healOLMOperator. The cooldown is the wider
// of the in-RAM ledger and the
// passiontech.dev/last-dragonfly-operator-heal stamp persisted on the STS
// that triggered it (survives operator restarts).
func (p *statefulMasterlessCheck) healDragonflyOperator(ctx context.Context, log logr.Logger,
	sig masterSvc, now time.Time) {
	// drHealed keys on controller names that die with their
	// Deployments — bound the map so stale stamps cannot accumulate.
	p.drHealed.PruneExpired(now, dragonflyHealCooldown)
	// drOpHealed keys on StatefulSets that may be decommissioned —
	// bound the map so their stamps cannot accumulate. It mirrors
	// the drHealed stamps, so it prunes on the same cooldown.
	p.drOpHealed.PruneExpired(now, dragonflyHealCooldown)
	// Pick ONE candidate from the sweep's pod snapshot BEFORE the
	// gate (mirrors healOLMOperator): mid-rollout the operator runs
	// two ReplicaSet generations side by side and the per-controller
	// cooldown only dedups pods of the SAME RS — deleting every
	// prefix match in one sweep would take out the whole operator
	// (leader election included) in a single pass. The cap is one
	// pod per cycle, picked deterministically as the OLDEST
	// candidate (name as the tie-break) so WHICH leader goes first
	// never depends on map order; with no candidate at all the
	// annotation read and the mutex verdict slot stay unspent. A
	// terminating, not-yet-Running or controller-less pod is not a
	// leader to bounce: deleting a failed/terminating remnant locks
	// the shared 30m cooldown while the actually running leader
	// survives untouched, and a controller-less pod would be deleted
	// PERMANENTLY (nothing recreates it).
	pods, err := p.AllPods(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list dragonfly-operator pods failed — heal deferred",
			"error", err)
		return
	}
	var target *corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != kube.DragonflyOperatorNS ||
			!strings.HasPrefix(pod.Name, dragonflyOperatorPodPrefix) ||
			pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			metav1.GetControllerOf(pod) == nil {
			continue
		}
		if target == nil ||
			pod.CreationTimestamp.Before(&target.CreationTimestamp) ||
			(pod.CreationTimestamp.Equal(&target.CreationTimestamp) &&
				pod.Name < target.Name) {
			target = pod // oldest — the deterministic 1-per-cycle pick
		}
	}
	if target == nil {
		return
	}
	// Gate: per-controller cooldown + persisted STS stamp +
	// maintenance mutex in ONE call (Deps.HealAllowedPersisted →
	// heal.AllowedVPersisted), fail closed on unverifiable. The
	// in-RAM half keys on the pod's CONTROLLER, not its name — a
	// deleted operator pod is recreated by its ReplicaSet under a
	// fresh suffix, so a pod-name stamp never suppressed the re-heal
	// and the leader was deleted every sweep. Never kill an operator
	// mid-drain/upgrade — "cannot verify" fails closed like
	// healOperatorLeader (operator-workqueue-watchdog).
	stsKey := sig.sts.Namespace + "/" + sig.sts.Name
	key := kube.PodControllerKey(target)
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.drHealed, sig.sts, dragonflyHealAnno, key,
		dragonflyHealCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	didDelete, err := heal.DeletePod(ctx, p.CS, &p.drHealed, key, target,
		now)
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "dragonfly operator delete failed",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
	if !didDelete {
		// Quorum reservation denied — a sibling check already spent
		// this workload's one-disruption slot this sweep.
		log.Info("DEFER: workload disruption already reserved this sweep",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
	kube.MarkPodDeleted(ctx, target.UID) // O(1) tombstone — no census reset
	p.drOpHealed.Stamp(stsKey, now)
	log.Info("DELETE: dragonfly operator pod — masterless service, forcing re-election",
		"pod", target.Namespace+"/"+target.Name, "service", sig.ns+"/"+sig.svc,
		"statefulset", sig.sts.Name)
	// Persist the stamp on the STS — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half (the delivered
	// delete already stamped drHealed under the controller key)
	// holding; nil ledger because the in-RAM key is the
	// per-controller cooldown stamped above.
	if err := heal.StampPersisted(ctx,
		sig.sts,
		func(ctx context.Context, data []byte) error {
			if _, err := p.CS.AppsV1().StatefulSets(sig.sts.Namespace).
				Patch(ctx, sig.sts.Name, types.MergePatchType, data,
					metav1.PatchOptions{}); err != nil {
				return err
			}
			// Mirror the landed stamp onto the LISTED STS — several
			// master Services can share one StatefulSet, and the
			// serial sweep sees no apiserver echo: without the mirror
			// a second heal-due candidate reads the pre-patch
			// annotations and double-heals the same operator.
			probefw.MergeAnnoPatchLocally(ctx, sig.sts, data)
			return nil
		},
		dragonflyHealAnno, nil, "", now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist dragonfly heal stamp failed",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name)
	}
}

// dragonflyOperatorHealedAt returns the most recent moment a
// dragonfly-operator leader pod was deleted by step 1 — the wider
// of the persisted passiontech.dev/last-dragonfly-operator-heal stamp on
// this STS and the in-RAM drOpHealed stamp (which survives an STS
// patch failure; CooldownSet.Last reports the stamp back, which a
// plain CooledDown gate cannot). ok=false means no heal has landed
// yet: the dual-replica heal must not skip ahead of step 1.
func (p *statefulMasterlessCheck) dragonflyOperatorHealedAt(sig masterSvc) (time.Time, bool) {
	latest, _ := p.drOpHealed.Last(sig.sts.Namespace + "/" + sig.sts.Name)
	if t, ok := kube.AnnoTime(sig.sts, dragonflyHealAnno); ok && t.After(latest) {
		latest = t
	}
	return latest, !latest.IsZero()
}

// smallestOrdinalPod returns the pod with the lowest StatefulSet
// ordinal — "<sts>-0" in the common case — or nil when none of the
// pods match the "<sts>-<n>" naming. StatefulSet pod names are the
// only source of truth for the ordinal (there is no field for it).
func smallestOrdinalPod(pods []*corev1.Pod, stsName string) *corev1.Pod {
	var best *corev1.Pod
	bestOrd := -1
	for i := range pods {
		name := pods[i].Name
		if !strings.HasPrefix(name, stsName+"-") {
			continue
		}
		ord, err := strconv.Atoi(name[len(stsName)+1:])
		if err != nil {
			continue
		}
		if bestOrd < 0 || ord < bestOrd {
			bestOrd = ord
			best = pods[i]
		}
	}
	return best
}

// healDragonflyReplicaDeadlock is the dual-replica-deadlock step-2 heal: the
// dragonfly-operator leader was already bounced (step 1, stateful-masterless-services) but
// the masterless streak outlived it — the dual-replica deadlock
// where every pod holds role=replica (each still executing
// REPLICAOF <old-dead-ip>) and an operator restart alone cannot
// re-elect. Deleting the lowest-ordinal pod forces the election
// from scratch.
//
// Gates, in order:
//  1. the operator heal must have actually landed >=
//     dragonflyOperatorSettleMin ago — deleting a pod before the new
//     leader had time to relabel reaps it pointlessly, and no heal
//     record at all means step 1 never ran: keep waiting rather
//     than skipping to pod kills;
//  2. the deadlock itself: every STS pod Ready AND zero pods
//     carrying a master-role label — an unready pod or an existing
//     master means the wedge sits elsewhere and a pod kill helps
//     nothing;
//  3. the 30m cooldown (wider of in-RAM ledger and persisted STS
//     stamp) and the maintenance mutex — the same shape every
//     pod-delete heal in this sweep carries.
func (p *statefulMasterlessCheck) healDragonflyReplicaDeadlock(ctx context.Context, log logr.Logger,
	sig masterSvc, now time.Time) {

	stsKey := sig.sts.Namespace + "/" + sig.sts.Name

	// drPodHealed keys on StatefulSets that may be decommissioned —
	// bound the map so their stamps cannot accumulate.
	p.drPodHealed.PruneExpired(now, dragonflyPodHealCooldown)

	// Gate 1 — the operator heal must have settled first.
	opHealedAt, healed := p.dragonflyOperatorHealedAt(sig)
	switch {
	case !healed:
		log.Info("dual-replica deadlock: no operator heal recorded — waiting for step 1",
			"statefulset", stsKey)
		return
	case now.Sub(opHealedAt) < dragonflyOperatorSettleMin:
		log.Info("dual-replica deadlock: operator heal still settling — waiting",
			"statefulset", stsKey,
			"ago", now.Sub(opHealedAt).Truncate(time.Minute))
		return
	}

	sel, err := metav1.LabelSelectorAsSelector(sig.sts.Spec.Selector)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: statefulset selector unparseable — deadlock heal deferred",
			"statefulset", stsKey, "error", err)
		return
	}
	allPods, err := p.AllPods(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list statefulset pods failed — deadlock heal deferred",
			"statefulset", stsKey, "error", err)
		return
	}
	// Client-side ns+selector filter over the shared pod census —
	// the same shape PodsMatching serves, but sel is the STS's
	// structured selector, not a string.
	var pods []*corev1.Pod
	for i := range allPods {
		pod := &allPods[i]
		if pod.Namespace == sig.sts.Namespace &&
			sel.Matches(labels.Set(pod.Labels)) {
			pods = append(pods, pod)
		}
	}

	// Gate 2 — confirm the deadlock shape: all replicas Ready but
	// nobody holds the master role.
	if len(pods) == 0 {
		return // no pods — nothing safe to delete
	}
	allReady := true
	hasMaster := false
	for i := range pods {
		pod := pods[i]
		if !kube.PodReadyCond(pod) {
			allReady = false
		}
		if podMasterRole(pod) {
			hasMaster = true
		}
	}
	switch {
	case !allReady:
		log.Info("dual-replica deadlock not confirmed: unready pod — heal deferred",
			"statefulset", stsKey)
		return
	case hasMaster:
		// A pod already carries the master role — endpoints will
		// follow; a pod kill now would fight a live re-election.
		return
	}

	// Confirm the delete target exists BEFORE the persisted-cooldown
	// + mutex + budget preamble — a StatefulSet with no matching pod
	// must not spend a global heal token on a guaranteed no-op.
	target := smallestOrdinalPod(pods, sig.sts.Name)
	if target == nil {
		return // no STS-named pod found — nothing safe to delete
	}
	// Gate 3 — persisted stamp → maintenance mutex in ONE call
	// (Deps.HealAllowedPersisted folds the 30m wider-of in-RAM+
	// persisted cooldown with the mutex, on the Deps-wide memoized
	// verdict): never kill a stateful pod mid-drain/upgrade; "cannot
	// verify" fails closed like every other caller.
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.drPodHealed, sig.sts, dragonflyPodHealAnno,
		stsKey, dragonflyPodHealCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}

	// UID precondition (inside heal.DeletePod) closes the list→delete
	// TOCTOU: a same-named replacement pod is not ours to reap.
	didDelete, err := heal.DeletePod(ctx, p.CS, &p.drPodHealed, stsKey, target, now)
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "dragonfly dual-replica pod delete failed",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
	if !didDelete {
		// Quorum reservation denied — a sibling check already spent
		// this workload's one-disruption slot this sweep.
		log.Info("DEFER: workload disruption already reserved this sweep",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
	kube.MarkPodDeleted(ctx, target.UID) // O(1) tombstone — no census reset
	dragonflyMasterlessPodHealsTotal.
		WithLabelValues(sig.sts.Namespace, sig.sts.Name).Inc()
	log.Info("DELETE: dragonfly dual-replica deadlock — lowest-ordinal pod deleted to force master re-election",
		"pod", target.Namespace+"/"+target.Name,
		"statefulset", stsKey, "service", sig.ns+"/"+sig.svc)

	// Persist the stamp on the STS — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half holding:
	// drPodHealed was already stamped by the delivered DeletePod, so
	// the stamp lands nil-ledger here (delivered-only belongs to the
	// delete, not the annotation write).
	if err := heal.StampPersisted(ctx,
		sig.sts,
		func(ctx context.Context, data []byte) error {
			if _, err := p.CS.AppsV1().StatefulSets(sig.sts.Namespace).
				Patch(ctx, sig.sts.Name, types.MergePatchType, data,
					metav1.PatchOptions{}); err != nil {
				return err
			}
			// Same listed-copy mirror as the operator heal above —
			// a shared StatefulSet must not be re-healed by a
			// sibling Service's candidate later this sweep.
			probefw.MergeAnnoPatchLocally(ctx, sig.sts, data)
			return nil
		},
		dragonflyPodHealAnno, nil, "", now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist dragonfly pod heal stamp failed",
			"statefulset", stsKey)
	}
}

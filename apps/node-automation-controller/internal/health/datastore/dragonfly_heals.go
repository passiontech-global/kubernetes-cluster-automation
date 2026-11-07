// dragonfly_heals.go — the dragonfly auto-heals of the
// stateful-masterless-services check (W6.2 step 1 + W7-C3 step 2):
// the dragonfly-operator leader delete forcing master re-election,
// and the dual-replica deadlock heal deleting the lowest-ordinal
// STS pod once the operator bounce demonstrably failed to re-elect.
// Split out of stateful_masterless_services.go — see that file for
// the check and its knobs.
package datastore

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

var (
	// W7-C3 — dragonfly STS ordinal-0 pods deleted to force master
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

// healDragonflyOperator deletes the dragonfly-operator controller
// pod(s) — the same re-election nudge the operator watchdog applies,
// keyed on its own 30m cooldown so the leader is never churned. The
// cooldown is the wider of the in-RAM ledger and the
// passiontech.dev/last-dragonfly-operator-heal stamp persisted on the STS
// that triggered it (survives operator restarts).
func (p *statefulMasterlessCheck) healDragonflyOperator(ctx context.Context, log logr.Logger,
	sig masterSvc, now time.Time) {
	// drHealed keys on controller names that die with their
	// Deployments — bound the map so stale stamps cannot accumulate.
	p.drHealed.PruneExpired(now, dragonflyHealCooldown)
	// The cheap persisted-stamp cooldown runs BEFORE the mutex —
	// same ordering healDragonflyReplicaDeadlock carries: a stamp
	// inside the window skips the three-signal API reads entirely.
	// Nil ledger — this heal's per-pod drHealed keys are checked
	// inside the delete loop, not here, so the annotation half is
	// all the preamble reads.
	if heal.PersistedCooledDown(nil, sig.sts, dragonflyHealAnno, "",
		dragonflyHealCooldown, now) {
		log.Info("skip heal: persisted stamp inside cooldown",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name)
		return
	}
	// Maintenance mutex — never kill an operator mid-drain/upgrade;
	// "cannot verify" fails closed like healOperatorLeader (W5.8).
	// heal.AllowedV gets a nil ledger here: this heal's cooldown is the
	// wider of the persisted STS stamp and the per-pod drHealed
	// entries, not a single CooldownSet key, so only its mutex gate
	// applies — shared via the check's verdict so the whole sweep
	// pays one evaluation.
	stsKey := sig.sts.Namespace + "/" + sig.sts.Name
	proceed, unverifiable := heal.AllowedV(ctx, log, &p.verdict,
		p.CS, p.Dyn, nil, stsKey, 0, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	pods, err := p.CS.CoreV1().Pods(probefw.DragonflyOperatorNS).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list dragonfly-operator pods failed — heal deferred",
			"error", err)
		return
	}
	deleted := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.HasPrefix(pod.Name, dragonflyOperatorPodPrefix) {
			continue
		}
		// The cooldown keys on the pod's CONTROLLER, not its name —
		// a deleted operator pod is recreated by its ReplicaSet under
		// a fresh suffix, so a pod-name stamp never suppressed the
		// re-heal and the leader was deleted every sweep.
		key := kube.PodControllerKey(pod)
		if p.drHealed.CooledDown(key, dragonflyHealCooldown, now) {
			log.Info("skip heal: dragonfly operator inside cooldown",
				"controller", key, "pod", pod.Name)
			continue
		}
		if _, err := heal.DeletePod(ctx, p.CS, &p.drHealed, key, pod, now); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "dragonfly operator delete failed",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		if now.After(p.drOpHealAt[stsKey]) {
			if p.drOpHealAt == nil {
				p.drOpHealAt = map[string]time.Time{}
			}
			p.drOpHealAt[stsKey] = now
		}
		deleted = true
		log.Info("DELETE: dragonfly operator pod — masterless service, forcing re-election",
			"pod", pod.Namespace+"/"+pod.Name, "service", sig.ns+"/"+sig.svc,
			"statefulset", sig.sts.Name)
	}
	if !deleted {
		return
	}
	// Persist the stamp on the STS — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half (the per-pod
	// drHealed stamps inside DeletePod) holding; nil ledger because
	// there is no per-STS ledger key for this heal.
	if err := heal.StampPersisted(ctx,
		func(ctx context.Context, data []byte) error {
			_, err := p.CS.AppsV1().StatefulSets(sig.sts.Namespace).
				Patch(ctx, sig.sts.Name, types.MergePatchType, data,
					metav1.PatchOptions{})
			return err
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
// this STS and the in-RAM drOpHealAt stamp (which survives an STS
// patch failure). ok=false means no heal has landed yet: the
// dual-replica heal must not skip ahead of step 1.
func (p *statefulMasterlessCheck) dragonflyOperatorHealedAt(sig masterSvc) (time.Time, bool) {
	latest := p.drOpHealAt[sig.sts.Namespace+"/"+sig.sts.Name]
	if t, ok := kube.AnnoTime(sig.sts, dragonflyHealAnno); ok && t.After(latest) {
		latest = t
	}
	return latest, !latest.IsZero()
}

// healDragonflyReplicaDeadlock is the W7-C3 step-2 heal: the
// dragonfly-operator leader was already bounced (step 1, W6.2) but
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
	pods, err := p.CS.CoreV1().Pods(sig.sts.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list statefulset pods failed — deadlock heal deferred",
			"statefulset", stsKey, "error", err)
		return
	}

	// Gate 2 — confirm the deadlock shape: all replicas Ready but
	// nobody holds the master role.
	if len(pods.Items) == 0 {
		return // no pods — nothing safe to delete
	}
	allReady := true
	hasMaster := false
	for i := range pods.Items {
		pod := &pods.Items[i]
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

	// Gate 3 — the 30m cooldown (wider of in-RAM + persisted via
	// PersistedCooledDown), then the maintenance mutex: heal.AllowedV
	// runs with a nil ledger as the mutex-only gate (shared verdict):
	// never kill a stateful pod mid-drain/upgrade; "cannot verify"
	// fails closed like every other caller.
	if heal.PersistedCooledDown(&p.drPodHealed, sig.sts,
		dragonflyPodHealAnno, stsKey, dragonflyPodHealCooldown, now) {
		log.Info("skip heal: dragonfly pod inside cooldown",
			"statefulset", stsKey)
		return
	}
	proceed, unverifiable := heal.AllowedV(ctx, log, &p.verdict,
		p.CS, p.Dyn, nil, stsKey, 0, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}

	target := smallestOrdinalPod(pods.Items, sig.sts.Name)
	if target == nil {
		return // no STS-named pod found — nothing safe to delete
	}
	// UID precondition (inside heal.DeletePod) closes the list→delete
	// TOCTOU: a same-named replacement pod is not ours to reap.
	if _, err := heal.DeletePod(ctx, p.CS, &p.drPodHealed, stsKey, target, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "dragonfly dual-replica pod delete failed",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
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
		func(ctx context.Context, data []byte) error {
			_, err := p.CS.AppsV1().StatefulSets(sig.sts.Namespace).
				Patch(ctx, sig.sts.Name, types.MergePatchType, data,
					metav1.PatchOptions{})
			return err
		},
		dragonflyPodHealAnno, nil, "", now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist dragonfly pod heal stamp failed",
			"statefulset", stsKey)
	}
}

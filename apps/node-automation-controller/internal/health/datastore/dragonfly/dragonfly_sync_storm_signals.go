// dragonfly_sync_storm_signals.go — the dragonfly-replica-sync-storm
// check's evidence + verdict phases: the Prometheus storm-evidence
// collection (the link-down and sync-full queries and their
// namespace/pod scoping), the per-series verdict loop (persistence
// window → gauge emit → gated replica heal), and the quiet-stamp
// cleanup tail. Run() in dragonfly_replica_sync_storm.go
// orchestrates the phases; the downscaler helpers live in
// downscaler.go.
package dragonfly

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// dragonflyStormEvidence is the collected storm proof the per-pod
// verdicts need: the link-down series themselves plus the sync-storm
// corroboration, scoped per namespace/pod — a sync storm in ns A
// must not authorize restarts of desynced replicas in ns B.
type dragonflyStormEvidence struct {
	linkSeries  []promq.Sample
	stormActive bool
	stormNS     map[string]bool
	stormPods   map[string]bool
}

// collectStormEvidence runs the two Prometheus queries. The
// master-link series is the check's PRIMARY signal — its failure is
// returned as the error (the sweep saw nothing, and a Pass would
// read a sustained Prometheus outage as a healthy fleet: the
// sibling checks' posture — primary-signal failure is Infra, not a
// pass). The sync-storm series is corroboration only: its failure
// just leaves the storm unconfirmed (warned, tolerated).
func (p *dragonflyReplicaSyncStormCheck) collectStormEvidence(
	ctx context.Context, log logr.Logger) (dragonflyStormEvidence, error) {
	var ev dragonflyStormEvidence
	linkSeries, err := p.PromQuery(ctx,
		`(dragonfly_master_link_status == 0) or (redis_master_link_status == 0)`)
	if err != nil {
		log.Info("WARN: dragonfly master-link query failed — check inconclusive",
			"error", err)
		return ev, err
	}
	ev.linkSeries = linkSeries

	stormSeries, err := p.PromQuery(ctx,
		`(increase(dragonfly_sync_full[15m]) >= 3) or (changes(redis_connected_slaves[15m]) >= 3)`)
	ev.stormNS = map[string]bool{}
	ev.stormPods = map[string]bool{}
	if err != nil {
		log.Info("WARN: dragonfly sync-storm query failed — storm unconfirmed",
			"error", err)
		return ev, nil
	}
	ev.stormActive = len(stormSeries) > 0
	for _, s := range stormSeries {
		ns := s.Label("namespace")
		if ns == "" {
			// Series WITHOUT a namespace label are DROPPED
			// (fail-closed): treating them as cluster-wide evidence
			// would let one unscoped series restart replicas in
			// every namespace.
			continue
		}
		ev.stormNS[ns] = true
		if pn := s.Label("pod", "pod_name"); pn != "" {
			ev.stormPods[ns+"/"+pn] = true
		}
	}
	return ev, nil
}

// evalLinkSeries walks the link-down series: every sustained
// (persisted-window) sighting emits its gauge tuple, and a sighting
// that is also storm-corroborated in its own namespace, on a
// non-master, dragonfly-owned, controller-backed pod earns the
// cooled-down replica restart. Returns the report accumulator and
// the seenKeep set the tail phases reconcile against.
func (p *dragonflyReplicaSyncStormCheck) evalLinkSeries(
	ctx context.Context, log logr.Logger, ev dragonflyStormEvidence,
	podByKey map[string]*corev1.Pod, downscaled map[string]bool,
	now time.Time) (probefw.SweepReport, map[string]bool) {
	var rep probefw.SweepReport
	seenKeep := map[string]bool{}
	for _, s := range ev.linkSeries {
		ns := s.Label("namespace")
		name := s.Label("pod", "pod_name")
		if ns == "" || name == "" {
			continue
		}
		if downscaledMemberPod(ns, name, downscaled) {
			continue // parked cluster — not storm evidence
		}
		key := ns + "/" + name
		sig := "link/" + key
		seenKeep[sig] = true
		pod := podByKey[key]
		// The link-storm window gates a pod restart, so it runs the
		// persisted (annotation-backed) variant whenever a pod exists
		// to carry the stamp — the annotation survives an operator
		// restart that would otherwise re-arm the full 5m mid-storm.
		// A series whose pod is already gone from the census has no
		// annotation carrier (FirstSeenPersisted needs a real object):
		// keep the pure in-RAM window — the heal cannot target a
		// missing pod anyway.
		persisted := false
		if pod != nil {
			persisted = heal.FirstSeenPersisted(ctx, log, &p.seen, pod,
				kube.AnnoFirstSeenDragonflyLinkStorm, sig,
				dragonflyLinkMinAge, now, kube.PodMergePatcher(p.CS, pod))
		} else {
			persisted = probefw.Persisted(&p.seen, sig, now,
				dragonflyLinkMinAge, log)
		}
		if !persisted {
			continue // link down must persist the window
		}
		rep.Emit(dragonflyReplicaSyncStormGauge, key, []string{ns, name}, key)

		if pod == nil || pod.DeletionTimestamp != nil {
			continue
		}
		if podMasterRole(pod) {
			log.Info("skip heal: pod holds master role — never restart the master",
				"pod", key)
			continue
		}
		if !isDragonflyPod(pod) {
			log.Info("skip heal: pod not dragonfly-owned",
				"pod", key)
			continue
		}
		if !ev.stormActive ||
			(!ev.stormNS[ns] && !ev.stormPods[key]) {
			continue // link-down alone, or storm unproven in THIS ns, doesn't restart
		}
		// A controller-less pod would be deleted PERMANENTLY — no
		// owner recreates it — and the cooldown keys on that very
		// controller, so without one there is no heal to deliver.
		if metav1.GetControllerOf(pod) == nil {
			log.Info("skip heal: pod has no controller owner — delete would not be recreated",
				"pod", key)
			continue
		}
		// The cooldown keys on the pod's CONTROLLER — the deleted
		// replica is recreated under a fresh suffix, so a pod-name
		// key never suppressed the re-heal of the same desync.
		p.DeletePodHeal(ctx, log, CheckNameDragonflySyncStorm,
			kube.PodControllerKey(pod), pod, dragonflySyncHealCool, now)
	}
	return rep, seenKeep
}

// clearQuietLinkStamps drops the persisted first-seen stamp of every
// pod whose link signature went quiet, so the next drop re-arms the
// full window — a stale stamp would fast-trip the restart.
// Terminating pods are skipped (the stamp dies with them); a clear
// failure is a tolerated sub-failure — the ledger Forget already
// landed, the annotation retry is Warn-only.
func (p *dragonflyReplicaSyncStormCheck) clearQuietLinkStamps(
	ctx context.Context, log logr.Logger,
	podByKey map[string]*corev1.Pod, seenKeep map[string]bool) {
	for key, pod := range podByKey {
		if seenKeep["link/"+key] || pod.DeletionTimestamp != nil {
			continue
		}
		if err := heal.ClearPersistedFirstSeen(ctx, log, &p.seen, pod,
			kube.AnnoFirstSeenDragonflyLinkStorm, "link/"+key,
			kube.PodMergePatcher(p.CS, pod)); err != nil {
			log.Info("WARN: dragonfly link-storm first-seen clear failed",
				"pod", key, "error", err)
		}
	}
}

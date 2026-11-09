// dragonfly_replica_sync_storm.go — the
// dragonfly-replica-sync-storm check (W10-ST4): sustained
// master-link-down + sync-full storm — restart ONLY the desynced
// replica pod, never the master.
package datastore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// dragonflyReplicaSyncStormCheck is the dragonfly replica sync-storm
// watchdog.
type dragonflyReplicaSyncStormCheck struct {
	*probefw.Deps

	// seen tracks each link-down pod's first-seen sweep — the 5m
	// persistence window the storm signature requires; pruned when
	// the link recovers so a later drop re-arms.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted state.GaugeLedger[string]
}

// newDragonflyReplicaSyncStormCheck builds the W10-ST4 check — its
// state is the seen/emitted ledgers (zero value usable); heal
// cooldowns ride the shared Deps.Heals set via deletePodHeal.
func NewDragonflyReplicaSyncStormCheck(d *probefw.Deps) probefw.Check {
	return &dragonflyReplicaSyncStormCheck{Deps: d}
}

const (
	CheckNameDragonflySyncStorm = "dragonfly-replica-sync-storm"

	// W10-ST4 — dragonfly-replica-sync-storm knobs.
	dragonflyLinkMinAge   = 5 * time.Minute
	dragonflySyncHealCool = 30 * time.Minute
)

var (
	// W10-ST4 — Dragonfly/Valkey replica sync storm.
	dragonflyReplicaSyncStormGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_dragonfly_replica_sync_storm",
		Help: "1 while the replica pod shows sustained master-link-down during a sync storm — W10-ST4.",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		dragonflyReplicaSyncStormGauge)
}

// isDragonflyPod reports whether the pod belongs to a
// Dragonfly/Valkey workload — app.kubernetes.io/name=dragonfly per
// the fluxcd shared-spec, with part-of/created-by fallbacks.
func isDragonflyPod(pod *corev1.Pod) bool {
	if pod.Labels["app.kubernetes.io/name"] == "dragonfly" ||
		pod.Labels["app.kubernetes.io/part-of"] == "dragonfly" ||
		pod.Labels["app.kubernetes.io/created-by"] == "dragonfly-operator" {
		return true
	}
	for _, v := range pod.Labels {
		if strings.Contains(v, "dragonfly") {
			return true
		}
	}
	return false
}

// checkDragonflyReplicaSyncStorm detects the replica full-sync
// storm: a replica's master link stays down (link_status==0 for the
// whole 5m window via first-seen persistence) while sync-full
// counters climb (>=3 per 15m) or connected-slaves oscillates.
// Only the DESYNCED REPLICA pod is restarted — never the master
// (podMasterRole on role/redis-role/app.kubernetes.io/role labels)
// — 30m cooldown.
func (p *dragonflyReplicaSyncStormCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	// emptySweepClose is the ledger-hygiene tail for the early
	// returns: with no series (or no pod census to judge them) the
	// first-seen entries drop so the next real signal re-arms the
	// FULL window, and the emitted ledger reconciles against an
	// empty set so stale gauge series DeleteLabelValues instead of
	// leaking a 1 past the incident.
	emptySweepClose := func() probefw.Result {
		p.seen.Prune(func(string) bool { return false })
		var empty probefw.SweepReport
		return empty.Result(&p.emitted,
			dragonflyReplicaSyncStormGauge.DeleteLabelValues, "", ", ")
	}

	linkSeries, errL := p.PromQuery(ctx,
		`(dragonfly_master_link_status == 0) or (redis_master_link_status == 0)`)
	if errL != nil {
		log.Info("WARN: dragonfly master-link query failed — check inconclusive",
			"error", errL)
		res := emptySweepClose()
		res.Pass = true
		return res
	}
	stormSeries, errS := p.PromQuery(ctx,
		`(increase(dragonfly_sync_full[15m]) >= 3) or (changes(redis_connected_slaves[15m]) >= 3)`)
	// Storm evidence is scoped per namespace when the series carry
	// one — a sync storm in ns A must not authorize restarts of
	// desynced replicas in ns B. Series WITHOUT a namespace label
	// are cluster-wide evidence (can't disprove locality).
	stormNS := map[string]bool{}
	stormPods := map[string]bool{}
	stormGlobal := false
	stormActive := false
	if errS != nil {
		log.Info("WARN: dragonfly sync-storm query failed — storm unconfirmed",
			"error", errS)
	} else {
		stormActive = len(stormSeries) > 0
		for _, s := range stormSeries {
			if ns := s.Label("namespace"); ns != "" {
				stormNS[ns] = true
			}
			if pn := s.Label("pod", "pod_name"); pn != "" {
				if ns := s.Label("namespace"); ns != "" {
					stormPods[ns+"/"+pn] = true
				} else {
					stormGlobal = true // pod label w/o ns — can't scope
				}
			} else if s.Label("namespace") == "" {
				stormGlobal = true
			}
		}
	}

	// A Dragonfly CR the go-kube-downscaler parked at
	// spec.replicas:0 is asleep on purpose — stale link-down series
	// for its removed member pods are intent, never storm evidence.
	// A list failure fails open: the signatures keep their normal
	// posture.
	crs, err := p.AllUnstructured(ctx, kube.GVRDragonfly)
	downscaled, err := downscaledClusterCRs(crs, err)
	if err != nil {
		log.Info("WARN: list dragonflies failed — downscaler awareness off",
			"error", err)
	}

	// Pod census for master-role + ownership checks.
	pods, err := p.AllPods(ctx)
	if err != nil {
		// The link findings this far stay unjudged — but the ledger
		// hygiene still runs so a stale gauge series does not
		// outlive the sweep that could not verify it.
		res := emptySweepClose()
		res.Infra = fmt.Errorf("list pods: %w", err)
		return res
	}
	podByKey := map[string]*corev1.Pod{}
	for i := range pods {
		podByKey[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}

	seenKeep := map[string]bool{}
	var rep probefw.SweepReport
	for _, s := range linkSeries {
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
		if !stormActive ||
			(!stormGlobal && !stormNS[ns] && !stormPods[key]) {
			continue // sustained link-down alone FAILs but doesn't restart
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
	// A pod whose link signature went quiet drops its persisted stamp
	// so the next drop re-arms the full window — a stale stamp would
	// fast-trip the restart. Terminating pods are skipped (the stamp
	// dies with them); a clear failure is a tolerated sub-failure —
	// the ledger Forget already landed, the annotation retry is
	// Warn-only.
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
	p.seen.Prune(func(k string) bool { return seenKeep[k] })
	stormNote := "storm=confirmed"
	if !stormActive {
		stormNote = "storm=unconfirmed"
	}
	return rep.Result(&p.emitted, dragonflyReplicaSyncStormGauge.DeleteLabelValues,
		fmt.Sprintf("dragonfly/valkey replicas with master-link down >%s (%s): ",
			dragonflyLinkMinAge, stormNote), ", ")
}

// dragonfly_replica_sync_storm.go — the
// dragonfly-replica-sync-storm check (W10-ST4): sustained
// master-link-down + sync-full storm — restart ONLY the desynced
// replica pod, never the master.
package datastore

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// dragonflyReplicaSyncStormCheck is the dragonfly replica sync-storm
// watchdog.
type dragonflyReplicaSyncStormCheck struct {
	*probefw.Deps

	// seen tracks each link-down pod's first-seen sweep — the 5m
	// persistence window the storm signature requires; pruned when
	// the link recovers so a later drop re-arms.
	seen shared.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted shared.GaugeLedger[string]
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

	linkSeries, errL := p.PromQuery(ctx,
		`(dragonfly_master_link_status == 0) or (redis_master_link_status == 0)`)
	if errL != nil {
		log.Info("WARN: dragonfly master-link query failed — check inconclusive",
			"error", errL)
		return probefw.Result{Pass: true}
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

	// Pod census for master-role + ownership checks.
	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	podByKey := map[string]*corev1.Pod{}
	for i := range pods.Items {
		podByKey[pods.Items[i].Namespace+"/"+pods.Items[i].Name] = &pods.Items[i]
	}

	current := map[string][]string{}
	seenKeep := map[string]bool{}
	var desynced []string
	for _, s := range linkSeries {
		ns := s.Label("namespace")
		name := s.Label("pod", "pod_name")
		if ns == "" || name == "" {
			continue
		}
		key := ns + "/" + name
		sig := "link/" + key
		seenKeep[sig] = true
		first, _ := p.seen.Observe(sig, now)
		if now.Sub(first) < dragonflyLinkMinAge {
			continue // link down must persist the window
		}
		lv := []string{ns, name}
		current[key] = lv
		dragonflyReplicaSyncStormGauge.WithLabelValues(lv...).Set(1)
		desynced = append(desynced, key)

		pod := podByKey[key]
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
		p.DeletePodHeal(ctx, log, CheckNameDragonflySyncStorm,
			key, pod, dragonflySyncHealCool, now)
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })
	sort.Strings(desynced)
	p.emitted.Reconcile(current, dragonflyReplicaSyncStormGauge.DeleteLabelValues)
	if len(desynced) == 0 {
		return probefw.Result{Pass: true}
	}
	stormNote := "storm=confirmed"
	if !stormActive {
		stormNote = "storm=unconfirmed"
	}
	return probefw.Result{Why: fmt.Sprintf(
		"dragonfly/valkey replicas with master-link down >%s (%s): %s",
		dragonflyLinkMinAge, stormNote, strings.Join(desynced, ", "))}
}

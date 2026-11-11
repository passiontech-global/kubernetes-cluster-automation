// dragonfly_replica_sync_storm.go — the
// dragonfly-replica-sync-storm check (dragonfly-replica-sync-storm): sustained
// master-link-down + sync-full storm — restart ONLY the desynced
// replica pod, never the master. The check splits by phase: this
// file keeps the identity/registration plumbing and the Run
// orchestration; the Prometheus evidence collection, the per-series
// verdict loop and the quiet-stamp tail live in
// dragonfly_sync_storm_signals.go.
package dragonfly

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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

// newDragonflyReplicaSyncStormCheck builds the dragonfly-replica-sync-storm check — its
// state is the seen/emitted ledgers (zero value usable); heal
// cooldowns ride the shared Deps.Heals set via deletePodHeal.
func NewDragonflyReplicaSyncStormCheck(d *probefw.Deps) probefw.Check {
	return &dragonflyReplicaSyncStormCheck{Deps: d}
}

const (
	CheckNameDragonflySyncStorm = "dragonfly-replica-sync-storm"

	// dragonfly-replica-sync-storm — dragonfly-replica-sync-storm knobs.
	dragonflyLinkMinAge   = 5 * time.Minute
	dragonflySyncHealCool = 30 * time.Minute
)

var (
	// dragonfly-replica-sync-storm — Dragonfly/Valkey replica sync storm.
	dragonflyReplicaSyncStormGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_dragonfly_replica_sync_storm",
		Help: "1 while the replica pod shows sustained master-link-down during a sync storm — dragonfly-replica-sync-storm.",
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

	// Evidence phase (dragonfly_sync_storm_signals.go): the primary
	// link-down query + the corroborating sync-storm query. A
	// primary-signal failure is Infra — a Pass here would read a
	// sustained Prometheus outage as a healthy fleet.
	ev, err := p.collectStormEvidence(ctx, log)
	if err != nil {
		res := emptySweepClose()
		res.Infra = fmt.Errorf("dragonfly master-link query: %w", err)
		return res
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

	// Verdict phase: persisted-window sightings emit the gauge and
	// earn the gated replica restart.
	rep, seenKeep := p.evalLinkSeries(ctx, log, ev, podByKey, downscaled, now)
	p.clearQuietLinkStamps(ctx, log, podByKey, seenKeep)
	p.seen.Prune(func(k string) bool { return seenKeep[k] })
	stormNote := "storm=confirmed"
	if !ev.stormActive {
		stormNote = "storm=unconfirmed"
	}
	return rep.Result(&p.emitted, dragonflyReplicaSyncStormGauge.DeleteLabelValues,
		fmt.Sprintf("dragonfly/valkey replicas with master-link down >%s (%s): ",
			dragonflyLinkMinAge, stormNote), ", ")
}

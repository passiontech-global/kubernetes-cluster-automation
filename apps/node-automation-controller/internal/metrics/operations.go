// operations.go — series emitted by the periodic sweep / janitor /
// node-ops modules outside internal/{apiserver,health,integration}:
// pdb-deadlock-watchdog, failed-jobs-janitor, volumeattachment-
// cleaner, zombie-sidecar-reaper, orphan-endpointslice-cleaner,
// cronjob-catchup, statefulset-ondelete-roller (system),
// cf-tunnel-proxy-watchdog (system) and the volume-attachment
// finalizer sweep. Var order and comments follow the original
// metrics.go layout.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// ---------------------------------------------------------------------------
// Self-healing / gray-failure defense metrics (Quick-Wins + C1-C6).
// Exported so the module packages under internal/<domain>/ drive the
// vectors directly.
// ---------------------------------------------------------------------------

// PDBDrainBlocked marks (1) PodDisruptionBudgets blocking drains
// (C2). reason is impossible_policy | cordoned_node_blocked |
// prolonged_zero_disruptions.
var PDBDrainBlocked = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_pdb_drain_blocked",
	Help: "1 while the PDB reports expectedPods>0 and disruptionsAllowed==0 past its reason threshold.",
}, []string{"namespace", "pdb", "reason"})

// StuckTerminatingResources marks (1) Namespaces / PVCs stuck
// Terminating past the audit threshold (C3).
var StuckTerminatingResources = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_stuck_terminating_resources",
	Help: "1 while the resource has had a DeletionTimestamp past the stuck threshold.",
}, []string{"kind", "namespace", "name"})

// VolumeAttachmentsCleanedTotal counts orphaned VolumeAttachments
// deleted by the volumeattachment-cleaner (C4). reason is
// missing_node | out_of_service_node.
var VolumeAttachmentsCleanedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_volumeattachments_cleaned_total",
	Help: "Orphaned VolumeAttachments reaped, by detection reason.",
}, []string{"reason"})

// ---------------------------------------------------------------------------
// Operations metrics — cluster-health check series.
// ---------------------------------------------------------------------------

// ZombieSidecarPodsReapedTotal counts Job Pods reaped because the
// linkerd sidecar kept them Running after the app exited (B2).
var ZombieSidecarPodsReapedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_zombie_sidecar_pods_reaped_total",
	Help: "Job Pods reaped while a lingering sidecar kept them Running after the app terminated.",
}, []string{"namespace"})

// OrphanEndpointSlicesCleanedTotal counts EndpointSlices deleted after
// their parent Service disappeared (orphan-endpointslice-cleaner, C4).
var OrphanEndpointSlicesCleanedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_orphan_endpointslices_cleaned_total",
	Help: "Orphaned EndpointSlices reaped after their Service no longer exists.",
}, []string{"namespace"})

// StatefulSetOnDeletePodsRolledTotal counts Pods deleted by the opt-in
// OnDelete rolling helper (statefulset-ondelete-roller, C2).
var StatefulSetOnDeletePodsRolledTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_statefulset_ondelete_pods_rolled_total",
	Help: "StatefulSet Pods deleted one-at-a-time to complete an OnDelete update.",
}, []string{"namespace", "statefulset"})

// ---------------------------------------------------------------------------
// Self-healing metrics (operator-workqueue-watchdog/cronjob-catchup/stateful-masterless-services/rabbitmq-suspended-listener).
// ---------------------------------------------------------------------------

// CronJobTooManyMissedStarts marks (1) CronJobs that accumulated
// more than 100 missed start times — the point where the controller
// permanently stops scheduling them until startingDeadlineSeconds is
// set (cronjob-catchup auto-unfreezer, cronjob-catchup).
var CronJobTooManyMissedStarts = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_cronjob_too_many_missed_starts",
	Help: "1 while the CronJob has more than 100 missed start times (controller stops scheduling it).",
}, []string{"namespace", "cronjob"})

// ---------------------------------------------------------------------------
// Health metrics (cp-freeze-heal/velero-bsl-audit/node-hang-precordon/issuer-serial-watch/mesh-net-guards/va-stuck-terminating).
// ---------------------------------------------------------------------------

// VolumeAttachmentFinalizersRemovedTotal counts wedged VolumeAttachment
// finalizers stripped after the attach-detach cleanup provably died
// (node gone, or out-of-service with zero non-DaemonSet pods) — va-stuck-terminating.
var VolumeAttachmentFinalizersRemovedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_volumeattachment_finalizers_removed_total",
	Help: "Stuck VolumeAttachment finalizers stripped to free the volume, by node. A series is deleted once its node leaves the sweep census — the counter restarts from 0 if the node returns.",
}, []string{"node"})

// ---------------------------------------------------------------------------
// Later self-healing metrics grouped by owning module (kine-bloat-guard/backup-posture-audit/
// externalsecret-storm-guard/cloudflared-wedge-heal/velero-inflight-audit/namespace-terminating-wedged).
// ---------------------------------------------------------------------------

// CFTunnelWedgePodsDeletedTotal counts cloudflared connector pods
// deleted by the cf-tunnel proxy watchdog wedge healer (cloudflared-wedge-heal).
// reason is fatal_logs (wedged log signature) or all_unready_oldest
// (readyCount==0 deadlock — oldest stale-unready pod deleted once per
// cooldown). Labels: pod namespace + reason.
var CFTunnelWedgePodsDeletedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_cftunnel_wedge_pods_deleted_total",
	Help: "Wedged cloudflared connector pods deleted, by namespace and reason.",
}, []string{"namespace", "reason"})

// HealBudgetExhaustedTotal counts heal grants denied by the global
// heal budget (internal/platform/heal — consulted inside
// heal.AllowedV so every heal-gated module shares the aggregate
// ceiling). A sustained rate means a fleet-wide signature is
// churning heals faster than the budget allows.
var HealBudgetExhaustedTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "node_automation_heal_budget_exhausted_total",
	Help: "Heal grants denied by the global heal budget (aggregate blast-radius cap).",
})

// HealTargetCircuitBrokenTotal counts per-target heal circuit-breaker
// open transitions (internal/platform/heal — consulted by the node
// cordon/taint patch actions of kubelet-liveness-reaper,
// partition-pod-evictor and cpu-steal-taint-sync). An open means the
// same (module,node) was already remediated 3 times inside the 3h
// window without converging; further remediation defers until the
// window expires or the target reports healthy. A sustained rate is
// a node stuck in a remediation loop — look at the module+node pair.
//
// Series hygiene: a target's series is DELETED when the breaker drops
// the target's history (window expiry or RecordTargetHealthy) — the
// counter restarts from 0 on the target's next episode. rate()/
// increase() see the reset natively; presence-based or absolute
// threshold alerts must not assume process-lifetime monotonicity.
var HealTargetCircuitBrokenTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_heal_target_circuit_broken_total",
	Help: "Per-target heal circuit-breaker open transitions (non-convergent remediation), by module and target. A series is deleted when the breaker drops the target's history (window expiry or recovery) — the counter restarts from 0 on the next episode.",
}, []string{"module", "target"})

// ---------------------------------------------------------------------------
// Dead-node-sweeper operations metrics (the branch-(b) split-brain
// gate).
// ---------------------------------------------------------------------------

// DeadNodeUnfencedStatefulSkipped marks (1) a confirmed-dead node the
// sweeper REFUSED to fence: branch (b) — no medik8s SNR CR —
// while the node still holds an RWO VolumeAttachment or a StatefulSet
// pod, so the out-of-service taint would risk a split-brain on its
// volumes. Cleared when the node is eventually fenced or recovers.
var DeadNodeUnfencedStatefulSkipped = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_dead_node_unfenced_stateful_skipped",
	Help: "1 while the dead node holds stateful volumes/pods without a medik8s SNR CR — fencing skipped (fail closed against split-brain).",
}, []string{"node"})

// DeadNodeFencedWithoutSNRTotal counts out-of-service fences the
// sweeper applied WITHOUT a medik8s SNR CR backing them (branch (b):
// Ready=Unknown>30m + dead kubelet) — has_volumes records
// whether the node held RWO volumes/StatefulSet pods at decision time
// (those fences carried the DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL
// override). A sustained rate means the sweeper is deciding node death
// on its own evidence — watch it against the SNR controller.
var DeadNodeFencedWithoutSNRTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_dead_node_fenced_without_snr_total",
	Help: "Out-of-service fences applied without a medik8s SNR CR, by node and whether it held stateful volumes/pods.",
}, []string{"node", "has_volumes"})

// LeaderLeasePreemptionsTotal counts fast dead-leader lease
// preemptions (internal/platform/leaderelect — the
// NeedLeaderElection=false sweep that shortens the controller's own
// leader-election LeaseDuration to 1s when the holder pod is
// deleted/terminating or its node is NotReady/tainted-dead). The
// reason label carries which dead-holder evidence fired
// (pod_missing / pod_terminating / node_not_ready /
// node_unreachable). A sustained rate means the active/passive HA
// pair is failing over on dead-node evidence repeatedly — check
// whether the leader's node is flapping rather than truly dead.
var LeaderLeasePreemptionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_leader_lease_preemptions_total",
	Help: "Leader-election LeaseDuration shortenings applied after the holder proved dead, by holder-dead evidence.",
}, []string{"reason"})

// operationsCollectors lists every vector declared in this file, in
// declaration order; the single init() below registers the table, so
// registration order stays byte-stable and adding a metric touches
// only this file.
var operationsCollectors = []prometheus.Collector{
	PDBDrainBlocked, StuckTerminatingResources,
	VolumeAttachmentsCleanedTotal,
	ZombieSidecarPodsReapedTotal, OrphanEndpointSlicesCleanedTotal,
	StatefulSetOnDeletePodsRolledTotal,
	CronJobTooManyMissedStarts,
	VolumeAttachmentFinalizersRemovedTotal,
	CFTunnelWedgePodsDeletedTotal, HealBudgetExhaustedTotal,
	HealTargetCircuitBrokenTotal,
	DeadNodeUnfencedStatefulSkipped, DeadNodeFencedWithoutSNRTotal,
	LeaderLeasePreemptionsTotal,
}

func init() {
	for _, c := range operationsCollectors {
		ctrlmetrics.Registry.MustRegister(c)
	}
}

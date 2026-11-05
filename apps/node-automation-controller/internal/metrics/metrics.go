// Package metrics exposes Prometheus counters for the operator.
//
// hookRunErrors keeps the exact metric/label contract that
// shell-operator exposed (shell_operator_hook_run_errors_total{queue})
// so the existing PrometheusRule alerts
// (CoreDnsStaleWatchdogRunFailed, CiliumTaintReaperStale) keep working
// unchanged. reconcileErrors is the new native counterpart.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var hookRunErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "shell_operator_hook_run_errors_total",
	Help: "Module run errors (shell-operator compatible counter).",
}, []string{"queue"})

var reconcileErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_reconcile_errors_total",
	Help: "Module run errors (node-automation-controller native counter).",
}, []string{"controller"})

// apiserver-endpoint-guard per-backend gauges — the wedge signal
// itself, so alerting can fire on rv_gap growth BEFORE a quarantine
// happens. Label is the backend IP; -1 marks a failed probe cycle.
var apiBackendRVGap = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_apiserver_rv_gap",
	Help: "Per-apiserver-backend live_rv - cache_rv (watch-cache wedge signal; -1 on probe failure).",
}, []string{"backend"})

var apiBackendQuarantined = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_apiserver_quarantined",
	Help: "1 while the backend IP is quarantined out of default/Endpoints and EndpointSlice kubernetes.",
}, []string{"backend"})

// cluster-health-probes gauges — the EXACT series kuberhealthy
// exported for the five ported HealthChecks, so the
// KuberhealthyCheckFailed / KuberhealthyCheckStale PrometheusRule
// alerts (and any dashboard keyed on check=<HealthCheck name>) keep
// firing with no PromQL change. The namespace label stays the literal
// "kuberhealthy" — the ns the HealthCheck CRs lived in — because the
// alert annotations render {{ $labels.namespace }}.
const healthCheckMetricNamespace = "kuberhealthy"

var healthCheckStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "kuberhealthy_check",
	Help: "Kuberhealthy-compatible check result (status=OK|FAIL) emitted by the in-process prober.",
}, []string{"check", "namespace", "status"})

var healthCheckSecondsSinceSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "kuberhealthy_check_seconds_since_success",
	Help: "Seconds since the check last reported OK (kuberhealthy-compatible).",
}, []string{"check", "namespace"})

// ---------------------------------------------------------------------------
// Self-healing / gray-failure defense metrics (Quick-Wins + C1-C6).
// Exported so the module packages under internal/<domain>/ drive the
// vectors directly.
// ---------------------------------------------------------------------------

// CiliumIdentitiesCollectedTotal counts CiliumIdentity objects reaped
// by the cilium-identity-auditor two-pass safe GC.
var CiliumIdentitiesCollectedTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "node_automation_cilium_identities_collected_total",
	Help: "CiliumIdentity objects reaped by the two-pass safe GC.",
})

// WebhookCircuitBroken marks (1) each sub-webhook currently patched to
// failurePolicy=Ignore by the admission-webhook circuit breaker (C1).
// Labels: webhook config kind, config name, sub-webhook name.
var WebhookCircuitBroken = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_webhook_circuit_broken",
	Help: "1 while the named sub-webhook is circuit-broken (failurePolicy patched to Ignore).",
}, []string{"kind", "name", "webhook"})

// WebhookCircuitBreakerTripsTotal counts how many times the circuit
// breaker tripped per webhook config.
var WebhookCircuitBreakerTripsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_webhook_circuit_breaker_trips_total",
	Help: "Circuit-breaker trips per webhook config.",
}, []string{"kind", "name"})

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

// HelmHookJobsCleanedTotal counts failed helm-hook Jobs reaped when
// the helmrelease-unlocker frees a stuck HelmRelease (C3).
var HelmHookJobsCleanedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_helm_hook_jobs_cleaned_total",
	Help: "Failed helm.sh/hook Jobs deleted in the HelmRelease target namespace.",
}, []string{"namespace"})

// VolumeAttachmentsCleanedTotal counts orphaned VolumeAttachments
// deleted by the volumeattachment-cleaner (C4). reason is
// missing_node | out_of_service_node.
var VolumeAttachmentsCleanedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_volumeattachments_cleaned_total",
	Help: "Orphaned VolumeAttachments reaped, by detection reason.",
}, []string{"reason"})

// WebhookCABundleMismatch marks (1) webhook configs whose caBundle
// drifted from the cert-manager injection source (C5).
var WebhookCABundleMismatch = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_webhook_ca_bundle_mismatch",
	Help: "1 while the named sub-webhook caBundle differs from its injection source.",
}, []string{"kind", "name", "webhook"})

// TLSSecretDaysToExpiry exposes days until the tls.crt in each
// kubernetes.io/tls Secret expires (C5).
var TLSSecretDaysToExpiry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_tls_secret_days_to_expiry",
	Help: "Days until the tls.crt certificate in the Secret expires.",
}, []string{"namespace", "secret"})

// KCMWorkqueueFrozen marks (1) a kube-controller-manager workqueue
// freeze: the leader Lease still renews but objects stop being
// reconciled (C6). reason identifies the stall signature.
var KCMWorkqueueFrozen = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_kcm_workqueue_frozen",
	Help: "1 while KCM renews its Lease but stops reconciling objects.",
}, []string{"reason"})

// ---------------------------------------------------------------------------
// Waves 1-3 operations metrics (2.1-2.7 + A/B/C groups).
// ---------------------------------------------------------------------------

// APIServiceUnavailable marks (1) aggregated APIServices whose
// Available=False condition persisted past the guard threshold
// (apiservice-guard, 2.3).
var APIServiceUnavailable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_apiservice_unavailable",
	Help: "1 while the aggregated APIService reports Available=False past the audit threshold.",
}, []string{"name", "service_namespace", "service_name"})

// WebhookCABundleDaysToExpiry exposes days until each webhook
// clientConfig.caBundle certificate expires (cert-drift-auditor, 2.4).
var WebhookCABundleDaysToExpiry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_webhook_ca_bundle_days_to_expiry",
	Help: "Days until the clientConfig.caBundle certificate of the named sub-webhook expires.",
}, []string{"kind", "name", "webhook"})

// TrustBundleDaysToExpiry exposes days until the earliest certificate
// in a trust-bundle ConfigMap/Secret expires (cert-drift-auditor, 2.4).
var TrustBundleDaysToExpiry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_trust_bundle_days_to_expiry",
	Help: "Days until the earliest certificate in the trust bundle expires.",
}, []string{"namespace", "name"})

// UnmeshedPods marks (1) Running Pods that should carry a linkerd-proxy
// sidecar but do not (unmeshed-pod-auditor, 2.2).
var UnmeshedPods = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_unmeshed_pods",
	Help: "1 while the Pod runs without the injected linkerd-proxy sidecar despite injection being enabled.",
}, []string{"namespace", "pod"})

// UnmeshedPodsRecreatedTotal counts unmeshed Pods deleted for
// re-creation once the injector webhook is healthy again.
var UnmeshedPodsRecreatedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_unmeshed_pods_recreated_total",
	Help: "Unmeshed Pods deleted so their controller recreates them with the sidecar.",
}, []string{"namespace"})

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

// FluxSourceReconcilesTriggeredTotal counts reconcile requests patched
// onto Flux source objects when a consumer reported a stale/missing
// artifact (Flux source healer, C1).
var FluxSourceReconcilesTriggeredTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_flux_source_reconciles_triggered_total",
	Help: "reconcile.fluxcd.io/requestedAt nudges applied to Flux source objects.",
}, []string{"kind", "namespace", "name"})

// HelmStallUnwedgesTotal counts old-ReplicaSet scale-downs applied to
// open a scheduling window behind a Stalled/RetriesExceeded
// HelmRelease (helmrelease-unlocker stalled-rollout signature).
// Labels: workload namespace + Deployment name.
var HelmStallUnwedgesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_helm_stall_unwedges_total",
	Help: "Old-ReplicaSet scale-downs that unwedged an anti-affinity surge deadlock behind a stalled HelmRelease.",
}, []string{"namespace", "deployment"})

// StatefulSetOnDeletePodsRolledTotal counts Pods deleted by the opt-in
// OnDelete rolling helper (statefulset-ondelete-roller, C2).
var StatefulSetOnDeletePodsRolledTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_statefulset_ondelete_pods_rolled_total",
	Help: "StatefulSet Pods deleted one-at-a-time to complete an OnDelete update.",
}, []string{"namespace", "statefulset"})

// VeleroSchedulePaused marks (1) velero.io Schedules left paused past
// the audit threshold (velero-backup-auditor, C3).
var VeleroSchedulePaused = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_schedule_paused",
	Help: "1 while the Velero Schedule has spec.paused=true past the audit threshold.",
}, []string{"namespace", "schedule"})

// VeleroBackupEmptyOrErrored marks (1) Schedules whose latest Backup
// completed with zero items/bytes or non-zero errors/warnings (C3).
var VeleroBackupEmptyOrErrored = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_backup_empty_or_errored",
	Help: "1 while the Schedule's latest Backup completed empty/errored/warned.",
}, []string{"namespace", "schedule", "reason"})

// ---------------------------------------------------------------------------
// Wave 5/6 self-healing metrics (W5.8/W5.9b/W6.2/W6.4).
// ---------------------------------------------------------------------------

// OperatorWorkqueueFrozen marks (1) an operator whose leader Lease
// still renews while its target CRs sit unreconciled past the stuck
// threshold — the same gray-failure shape as the C6 KCM watchdog
// (operator-workqueue-watchdog, W5.8). reason identifies the stall
// signature.
var OperatorWorkqueueFrozen = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_operator_workqueue_frozen",
	Help: "1 while the operator renews its Lease but its CRs stay unreconciled past the stuck threshold.",
}, []string{"operator", "reason"})

// OperatorWorkqueueHealsTotal counts stuck-operator leader pods
// deleted by the W5.8 auto-healer to force re-election.
var OperatorWorkqueueHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_operator_workqueue_heals_total",
	Help: "Stuck operator leader pods deleted to force re-election, by detected stall reason.",
}, []string{"operator", "reason"})

// CronJobTooManyMissedStarts marks (1) CronJobs that accumulated
// more than 100 missed start times — the point where the controller
// permanently stops scheduling them until startingDeadlineSeconds is
// set (cronjob-catchup auto-unfreezer, W5.9b).
var CronJobTooManyMissedStarts = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_cronjob_too_many_missed_starts",
	Help: "1 while the CronJob has more than 100 missed start times (controller stops scheduling it).",
}, []string{"namespace", "cronjob"})

// StatefulServiceZeroEndpoints marks (1) a master-role Service
// (role/redis-role/app.kubernetes.io/role in {master,primary,leader})
// backed by a ready StatefulSet whose EndpointSlices report 0 Ready
// endpoints — a masterless stateful service (W6.2).
var StatefulServiceZeroEndpoints = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_stateful_service_zero_endpoints",
	Help: "1 while the master-role Service of a ready StatefulSet reports 0 Ready endpoints.",
}, []string{"namespace", "service", "statefulset"})

// RabbitMQSuspendedHealsTotal counts RabbitMQ pods deleted because
// they ran suspended (all containers started but Ready=false — the
// ranch:suspended listener wedge) while every peer replica was
// Ready (W6.4).
var RabbitMQSuspendedHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_rabbitmq_suspended_heals_total",
	Help: "RabbitMQ pods deleted while running with a suspended listener (started but never Ready).",
}, []string{"namespace", "pod"})

// ---------------------------------------------------------------------------
// Wave 7 self-healing metrics (W7-C3/W7-C4/W7-C5/W7-C6).
// ---------------------------------------------------------------------------

// DragonflyMasterlessPodHealsTotal counts dragonfly StatefulSet
// ordinal-0 pods deleted to force a master re-election after the
// operator-heal (W6.2) left both replicas stuck role=replica — the
// dual-replica deadlock (W7-C3).
var DragonflyMasterlessPodHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_dragonfly_masterless_pod_heals_total",
	Help: "Dragonfly STS ordinal-0 pods deleted to force master re-election after a dual-replica deadlock.",
}, []string{"namespace", "statefulset"})

// LocalPVStrandedPods marks (1) pods stuck Pending because their bound
// local PV's nodeAffinity pins them to a node that is missing,
// out-of-service, NotReady or cordoned — the volume can never follow
// the pod to a new node (W7-C4). reason is missing_node |
// out_of_service | not_ready | cordoned.
var LocalPVStrandedPods = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_localpv_stranded_pods",
	Help: "1 while the Pod pends on a local PV node-affinity-pinned to an unavailable node.",
}, []string{"namespace", "pod", "pvc", "node", "reason"})

// LocalPVEphemeralHealsTotal counts dead PVC+pod pairs reaped for
// workloads whose local volume is disposable — concourse-worker or
// anything annotated node.ops/ephemeral-localpv — once the bound
// node is confirmed gone (missing or out-of-service). Deleting the
// PVC lets the StatefulSet rebind the pod onto a live node; the
// Released PV is swept by the node-host-agent (W7-C4).
var LocalPVEphemeralHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_localpv_ephemeral_heals_total",
	Help: "Ephemeral localpv PVC+pod pairs reaped after their bound node was confirmed gone.",
}, []string{"namespace", "pvc", "node"})

// PVCProvisioningStalled marks (1) PVCs Pending on a local
// provisioner storage class while Ready+schedulable worker nodes
// exist — the provisioner pod wedged, not the cluster (W7-C4).
var PVCProvisioningStalled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_pvc_provisioning_stalled",
	Help: "1 while the PVC pends on a local provisioner despite Ready schedulable workers existing.",
}, []string{"namespace", "pvc", "storageclass"})

// PVCProvisionerHealsTotal counts local provisioner pods deleted to
// unstick Pending claims, by provisioner (W7-C4).
var PVCProvisionerHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_pvc_provisioner_heals_total",
	Help: "Local provisioner pods deleted to unstick Pending claims, by provisioner.",
}, []string{"provisioner"})

// OLMUnhealthyResources marks (1) OLM ClusterServiceVersions stuck
// off Succeeded or overdue on cert rotation, and Subscriptions
// reporting CatalogSourcesUnhealthy / ResolutionFailed, past the
// audit threshold (W7-C5). kind is ClusterServiceVersion |
// Subscription.
var OLMUnhealthyResources = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_olm_unhealthy_resources",
	Help: "1 while the OLM resource reports an unhealthy phase/condition past the audit threshold.",
}, []string{"kind", "namespace", "name", "reason"})

// OLMOperatorHealsTotal counts olm-operator pods deleted to unstick
// wedged CSV reconciliation or webhook cert rotation (W7-C5).
var OLMOperatorHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_olm_operator_heals_total",
	Help: "olm-operator pods deleted to unstick wedged CSV/cert-rotation reconciliation, by detected reason.",
}, []string{"reason"})

// ReplicatedSecretDrift marks (1) kubernetes-replicator copies
// (replicator.v1.mittwald.de/replicated-from) whose tls.crt diverged
// from the source Secret across consecutive scans — the replicator
// missed a watch event or the copy was hand-edited (W7-C6).
var ReplicatedSecretDrift = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_replicated_secret_drift",
	Help: "1 while the replicated Secret's tls.crt differs from its source across consecutive scans.",
}, []string{"namespace", "name", "source"})

// ---------------------------------------------------------------------------
// Wave 8 metrics (W8-CP3/W8-ST1/W8-ST2/W8-NM2-3/W4).
// ---------------------------------------------------------------------------

// SchedulerFrozen marks (1) pods Pending >=5m with no nodeName and no
// PodScheduled condition while Ready uncordoned workers exist — the
// kube-scheduler stopped scheduling (W8-CP3).
var SchedulerFrozen = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "node_automation_scheduler_frozen",
	Help: "1 while unscheduled Pending pods accumulate past 5m despite Ready uncordoned workers.",
})

// VeleroBSLUnavailable marks (1) each velero.io BackupStorageLocation
// whose status.phase is not Available (W8-ST1).
var VeleroBSLUnavailable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_bsl_unavailable",
	Help: "1 while the BackupStorageLocation reports a phase other than Available.",
}, []string{"namespace", "name"})

// ControlPlanePodHealsTotal counts control-plane/operator pods deleted
// by the cluster-health mesh watchdogs — cilium-operator on
// CiliumIPAMExhausted (W8-NM2), linkerd-destination/identity on the
// wedged-watch signature (W8-NM3), and db operator pods deleted to
// force master re-election for a masterless StatefulSet (W4
// stateful-masterless extension).
var ControlPlanePodHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_controlplane_pod_heals_total",
	Help: "Control-plane/operator pods deleted to force re-election or resync, by component.",
}, []string{"component"})

// NodeHangCordonsTotal counts nodes preemptively cordoned by the W8-ST2
// hang guard (FilesystemReadOnly / KernelHungTasks / ClockUnsynchronized)
// before NHC/SNR reboots them.
var NodeHangCordonsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_node_hang_cordons_total",
	Help: "Worker nodes patched spec.unschedulable after a sustained hang condition.",
}, []string{"node"})

// NodeHangUncordonsTotal counts nodes the W8-ST2 pre-cordon guard put
// back into the scheduling pool after every hang latch cleared —
// transient recovery or a post-SNR reboot that kept
// spec.unschedulable.
var NodeHangUncordonsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_node_hang_uncordons_total",
	Help: "Worker nodes patched schedulable after the pre-cordon hang latch cleared.",
}, []string{"node"})

// VolumeAttachmentFinalizersRemovedTotal counts wedged VolumeAttachment
// finalizers stripped after the attach-detach cleanup provably died
// (node gone, or out-of-service with zero non-DaemonSet pods) — W4.
var VolumeAttachmentFinalizersRemovedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_volumeattachment_finalizers_removed_total",
	Help: "Stuck VolumeAttachment finalizers stripped to free the volume, by node.",
}, []string{"node"})

// ---------------------------------------------------------------------------
// Wave 9 metrics (W9-CP3/W9-NM2/W9-ST1).
// ---------------------------------------------------------------------------

// LinkerdEndpointDesync marks (1) a headless Service in a
// linkerd-injected namespace whose EndpointSlice stayed desynced from
// its Ready pod IPs — missing a Ready pod IP or holding a deleted
// pod's address — past the persistence window (W9-NM2). Past the
// window the check also rolling-bounces the oldest
// linkerd-destination pod (1h per-service cooldown) to force a
// resync.
var LinkerdEndpointDesync = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_linkerd_endpoint_desync",
	Help: "1 while the headless Service's EndpointSlice misses a Ready pod IP or holds a deleted pod's address.",
}, []string{"namespace", "service"})

// ScyllaClusterUnhealthy marks (1) a ScyllaCluster or one of its
// member services/pods reporting a sustained unhealthy signature past
// its persistence window (W9-ST1). reason is degraded_condition |
// member_service_desync | gossip_or_raft_stall.
var ScyllaClusterUnhealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_scylla_unhealthy",
	Help: "1 while the ScyllaCluster/member shows a sustained unhealthy signature.",
}, []string{"namespace", "cluster", "reason"})

// ---------------------------------------------------------------------------
// Later self-healing metrics grouped by owning module (W9-CP2/W9-ST3/
// W9-GO1/W10-NM2/W10-ST6/W10-CP1).
// ---------------------------------------------------------------------------

// HelmSecretsPrunedTotal counts superseded helm release secrets
// deleted by the helmrelease-unlocker Kine bloat guard (W9-CP2) —
// helm keeps every revision forever and each secret embeds the full
// compressed chart, so unbounded superseded history bloats Kine.
// Label: the namespace the release secrets live in.
var HelmSecretsPrunedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_helm_secrets_pruned_total",
	Help: "Superseded helm release secrets pruned per release, by namespace.",
}, []string{"namespace"})

// DBBackupUnhealthy marks (1) each Everest DatabaseCluster whose
// backup posture is unhealthy (W9-ST3). reason is failed (latest
// backup Failed), stuck (a Running/Starting backup older than 6h)
// or stale (newest Succeeded backup older than 36h). Labels:
// DatabaseCluster namespace + name + reason.
var DBBackupUnhealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_db_backup_unhealthy",
	Help: "1 while the DatabaseCluster's backups are failed, stuck or stale.",
}, []string{"namespace", "cluster", "reason"})

// ExternalSecretStormSuppressed marks (1) while the
// externalsecret-nudge storm guard is active (W9-GO1): >=5
// ExternalSecrets Ready=False AND >=50% of all ExternalSecrets
// failing simultaneously — the signature of a 1Password
// Connect/429/store outage where force-sync stamps would only
// amplify the failure.
var ExternalSecretStormSuppressed = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "node_automation_externalsecret_storm_suppressed",
	Help: "1 while the ExternalSecret storm guard suppresses force-sync stamps.",
})

// CFTunnelWedgePodsDeletedTotal counts cloudflared connector pods
// deleted by the cf-tunnel proxy watchdog wedge healer (W10-NM2).
// reason is fatal_logs (wedged log signature) or all_unready_oldest
// (readyCount==0 deadlock — oldest stale-unready pod deleted once per
// cooldown). Labels: pod namespace + reason.
var CFTunnelWedgePodsDeletedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_cftunnel_wedge_pods_deleted_total",
	Help: "Wedged cloudflared connector pods deleted, by namespace and reason.",
}, []string{"namespace", "reason"})

// VeleroBackupStuck marks (1) each velero.io Backup wedged
// InProgress or Deleting for over 6h (W10-ST6). Labels: namespace +
// backup name.
var VeleroBackupStuck = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_backup_stuck",
	Help: "1 while a velero.io Backup is InProgress or Deleting for over 6h.",
}, []string{"namespace", "backup"})

// VeleroPodVolumeBackupWedged marks (1) each velero.io
// PodVolumeBackup stuck InProgress for over 6h whose node-agent
// restarted or has no active Kopia process (W10-ST6). Labels:
// namespace + pvb name.
var VeleroPodVolumeBackupWedged = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_podvolumebackup_wedged",
	Help: "1 while a PodVolumeBackup is wedged InProgress past the Kopia criteria.",
}, []string{"namespace", "pvb"})

// VeleroWedgedObjectsCleanedTotal counts wedged velero objects
// cleaned by the backup auditor (W10-ST6). action is pvb_deleted or
// pod_restarted. Labels: namespace + action.
var VeleroWedgedObjectsCleanedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_velero_wedged_objects_cleaned_total",
	Help: "Wedged velero PodVolumeBackups deleted and pods bounced, by namespace and action.",
}, []string{"namespace", "action"})

// APIServiceUnblockHealsTotal counts dead APIService heals forced
// through the namespace-skip gate by the apiservice guard (W10-CP1):
// an APIService in a normally-skipped namespace that stayed
// Available=False >=15m while a namespace sat Terminating >=15m with
// references to its API group.
var APIServiceUnblockHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_apiservice_unblock_heals_total",
	Help: "APIService heals forced past the skip-namespace gate, by namespace and reason.",
}, []string{"namespace", "reason"})

// queues are the legacy shell-operator queue names — pre-instantiated
// at 0 so /metrics always exposes every series (an empty CounterVec
// emits nothing, and shell-operator emitted its counters eagerly).
var queues = []string{
	"konnectivity-patcher", "cilium-taint-reaper", "descheduler-storm-gate",
	"node-labeler", "fluent-bit-config-roller", "coredns-stale-watchdog",
	"kubelet-liveness-reaper", "admission-webhook-guard",
	"partition-pod-evictor", "failed-jobs-janitor",
	"concourse-workdir-janitor",
	// remediation modules (v0.2.0)
	"dead-node-sweeper", "helmrelease-unlocker", "externalsecret-nudge",
	"evicted-pod-janitor", "cronjob-catchup", "certmanager-reaper",
	"cilium-identity-auditor", "csr-watcher",
	// watch-cache wedge guard
	"apiserver-endpoint-guard",
	// ported kubectl CronJobs (v0.8.0)
	"coredns-patcher", "metrics-server-patcher", "cf-tunnel-proxy-watchdog",
	// ported kuberhealthy HealthChecks
	"cluster-health-probes",
	// self-healing / gray-failure defense modules
	"pdb-deadlock-watchdog", "volumeattachment-cleaner",
	"cert-drift-auditor",
	// waves 1-3 operations modules
	"apiservice-guard", "zombie-sidecar-reaper",
	"orphan-endpointslice-cleaner", "statefulset-ondelete-roller",
	"velero-backup-auditor",
}

func init() {
	ctrlmetrics.Registry.MustRegister(hookRunErrors, reconcileErrors,
		apiBackendRVGap, apiBackendQuarantined,
		healthCheckStatus, healthCheckSecondsSinceSuccess,
		CiliumIdentitiesCollectedTotal,
		WebhookCircuitBroken, WebhookCircuitBreakerTripsTotal,
		PDBDrainBlocked, StuckTerminatingResources,
		HelmHookJobsCleanedTotal, VolumeAttachmentsCleanedTotal,
		WebhookCABundleMismatch, TLSSecretDaysToExpiry,
		KCMWorkqueueFrozen,
		APIServiceUnavailable, WebhookCABundleDaysToExpiry,
		TrustBundleDaysToExpiry, UnmeshedPods,
		UnmeshedPodsRecreatedTotal, ZombieSidecarPodsReapedTotal,
		OrphanEndpointSlicesCleanedTotal,
		FluxSourceReconcilesTriggeredTotal, HelmStallUnwedgesTotal,
		StatefulSetOnDeletePodsRolledTotal, VeleroSchedulePaused,
		VeleroBackupEmptyOrErrored,
		OperatorWorkqueueFrozen, OperatorWorkqueueHealsTotal,
		CronJobTooManyMissedStarts, StatefulServiceZeroEndpoints,
		RabbitMQSuspendedHealsTotal,
		DragonflyMasterlessPodHealsTotal, LocalPVStrandedPods,
		LocalPVEphemeralHealsTotal, PVCProvisioningStalled,
		PVCProvisionerHealsTotal, OLMUnhealthyResources,
		OLMOperatorHealsTotal, ReplicatedSecretDrift,
		SchedulerFrozen, VeleroBSLUnavailable,
		ControlPlanePodHealsTotal, NodeHangCordonsTotal,
		NodeHangUncordonsTotal,
		VolumeAttachmentFinalizersRemovedTotal,
		LinkerdEndpointDesync, ScyllaClusterUnhealthy,
		HelmSecretsPrunedTotal, DBBackupUnhealthy,
		ExternalSecretStormSuppressed, CFTunnelWedgePodsDeletedTotal,
		VeleroBackupStuck, VeleroPodVolumeBackupWedged,
		VeleroWedgedObjectsCleanedTotal, APIServiceUnblockHealsTotal)
	for _, q := range queues {
		hookRunErrors.WithLabelValues(q)
		reconcileErrors.WithLabelValues(q)
	}
}

// IncError increments both counters for module `name`. `name` must be
// the legacy shell-operator queue name (e.g. "coredns-stale-watchdog")
// so alert queries keep matching.
func IncError(name string) {
	hookRunErrors.WithLabelValues(name).Inc()
	reconcileErrors.WithLabelValues(name).Inc()
}

// ObserveAPIBackend records one probe cycle of the
// apiserver-endpoint-guard for backend `ip`: rvGap is live_rv-cache_rv
// (-1 on probe failure) and quarantined marks whether the IP is
// currently pulled out of default/kubernetes.
func ObserveAPIBackend(ip string, rvGap float64, quarantined bool) {
	apiBackendRVGap.WithLabelValues(ip).Set(rvGap)
	v := 0.0
	if quarantined {
		v = 1
	}
	apiBackendQuarantined.WithLabelValues(ip).Set(v)
}

// ForgetAPIBackend prunes the per-backend series when an IP leaves the
// controller set (controller decommissioned) so /metrics does not leak
// stale label values.
func ForgetAPIBackend(ip string) {
	apiBackendRVGap.DeleteLabelValues(ip)
	apiBackendQuarantined.DeleteLabelValues(ip)
}

// ObserveHealthCheck records one result of a ported kuberhealthy check
// under its original HealthCheck name: the status=OK|FAIL gauges
// mirror kuberhealthy's output exactly (a pass sets OK=1/FAIL=0, a
// fail flips them) and secondsSinceSuccess feeds the stale-check
// alert — the caller tracks lastSuccess and passes now-lastSuccess
// (0 on a pass, growing while the check keeps failing).
func ObserveHealthCheck(check string, ok bool, secondsSinceSuccess float64) {
	okV, failV := 0.0, 1.0
	if ok {
		okV, failV = 1.0, 0.0
	}
	healthCheckStatus.WithLabelValues(check, healthCheckMetricNamespace, "OK").Set(okV)
	healthCheckStatus.WithLabelValues(check, healthCheckMetricNamespace, "FAIL").Set(failV)
	healthCheckSecondsSinceSuccess.
		WithLabelValues(check, healthCheckMetricNamespace).Set(secondsSinceSuccess)
}

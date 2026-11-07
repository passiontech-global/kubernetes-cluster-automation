// integration.go — series emitted by the internal/integration
// modules: cilium-identity-auditor, helmrelease-unlocker (incl. the
// flux source healer), externalsecret-nudge, cert-drift-auditor,
// certmanager-reaper and velerobackupauditor (Velero + Percona
// Everest). Var order and comments follow the original metrics.go
// layout.
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

// CiliumIdentitiesCollectedTotal counts CiliumIdentity objects reaped
// by the cilium-identity-auditor two-pass safe GC.
var CiliumIdentitiesCollectedTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "node_automation_cilium_identities_collected_total",
	Help: "CiliumIdentity objects reaped by the two-pass safe GC.",
})

// HelmHookJobsCleanedTotal counts failed helm-hook Jobs reaped when
// the helmrelease-unlocker frees a stuck HelmRelease (C3).
var HelmHookJobsCleanedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_helm_hook_jobs_cleaned_total",
	Help: "Failed helm.sh/hook Jobs deleted in the HelmRelease target namespace.",
}, []string{"namespace"})

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

// ---------------------------------------------------------------------------
// Waves 1-3 operations metrics (2.1-2.7 + A/B/C groups).
// ---------------------------------------------------------------------------

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
// Wave 7 self-healing metrics (W7-C3/W7-C4/W7-C5/W7-C6).
// ---------------------------------------------------------------------------

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

// VeleroBSLUnavailable marks (1) each velero.io BackupStorageLocation
// whose status.phase is not Available (W8-ST1).
var VeleroBSLUnavailable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_bsl_unavailable",
	Help: "1 while the BackupStorageLocation reports a phase other than Available.",
}, []string{"namespace", "name"})

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

// ExternalSecretEmptyKey marks (1) each key in a Ready=True
// ExternalSecret's target Secret that synced missing, empty or
// whitespace-only — ESO reports SecretSynced while the app reads a
// blank credential (W12-GO3). Labels: ES namespace + ES name + the
// offending secret key.
var ExternalSecretEmptyKey = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_externalsecret_empty_key",
	Help: "1 while the named key of the ExternalSecret's target Secret is missing/empty/whitespace-only.",
}, []string{"namespace", "name", "key"})

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

// VeleroRepoUnhealthy marks (1) each velero.io BackupRepository
// reporting a status.phase other than Ready, or a
// status.lastMaintenanceTime older than 7 days (backup-health) — the
// restic/kopia maintenance loop stopped, so restores degrade or the
// repo cannot be opened at all. reason is phase_not_ready or
// maintenance_stale. Labels: namespace + name + reason.
var VeleroRepoUnhealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_repo_unhealthy",
	Help: "1 while a velero.io BackupRepository is not Ready or its maintenance is >7d stale.",
}, []string{"namespace", "name", "reason"})

// init registers exactly the vectors declared in this file — the
// per-domain init() split means adding an integration-domain metric
// touches only this file, not a central registry list. Order
// follows declaration order.
func init() {
	ctrlmetrics.Registry.MustRegister(
		CiliumIdentitiesCollectedTotal,
		HelmHookJobsCleanedTotal,
		WebhookCABundleMismatch, TLSSecretDaysToExpiry,
		WebhookCABundleDaysToExpiry, TrustBundleDaysToExpiry,
		FluxSourceReconcilesTriggeredTotal, HelmStallUnwedgesTotal,
		VeleroSchedulePaused, VeleroBackupEmptyOrErrored,
		ReplicatedSecretDrift,
		VeleroBSLUnavailable,
		HelmSecretsPrunedTotal, DBBackupUnhealthy,
		ExternalSecretStormSuppressed, ExternalSecretEmptyKey,
		VeleroBackupStuck, VeleroPodVolumeBackupWedged,
		VeleroWedgedObjectsCleanedTotal, VeleroRepoUnhealthy)
}

// Package metrics exposes Prometheus counters for the operator.
//
// hookRunErrors keeps the exact metric/label contract that
// shell-operator exposed (shell_operator_hook_run_errors_total{queue})
// so the existing PrometheusRule alerts
// (CoreDnsStaleWatchdogRunFailed, CiliumTaintReaperStale) keep working
// unchanged. reconcileErrors is the new native counterpart.
//
// The package is split by emitting domain: core.go (this file) holds
// the run-error counters, the queue list, init() and IncError;
// apiserver.go / health.go / integration.go / operations.go hold the
// per-domain vectors. Registration order and label values are
// unchanged from the original single-file layout.
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

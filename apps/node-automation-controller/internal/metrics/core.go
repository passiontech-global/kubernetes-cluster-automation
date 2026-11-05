// Package metrics exposes Prometheus counters for the operator.
//
// hookRunErrors keeps the exact metric/label contract that
// shell-operator exposed (shell_operator_hook_run_errors_total{queue})
// so the existing PrometheusRule alerts
// (CoreDnsStaleWatchdogRunFailed, CiliumTaintReaperStale) keep working
// unchanged. reconcileErrors is the new native counterpart.
//
// The package is split by emitting domain: core.go (this file) holds
// the run-error counters, init(), PredeclareQueue and IncError;
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

// The queue label values are NOT listed here — cmd/manager's module
// registry is the single source of truth for the fleet's ops names,
// and setupModules calls PredeclareQueue for every row (gated or
// not) at boot. IncError below auto-creates a series on demand
// anyway; predeclaration exists only so /metrics exposes every
// module's 0-valued series before the first scrape, matching the
// eager emission shell-operator had.

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
}

// PredeclareQueue instantiates both error counters for module `name`
// at 0 — an empty CounterVec emits nothing on /metrics, and
// shell-operator emitted its counters eagerly, so every registered
// module's series must exist before the first scrape. setupModules
// calls this for every registry row (a gated-off module still gets
// its series — alert queries must not go absent when a module is
// disabled). `name` is the module's ops name from the registry, which
// is the legacy shell-operator queue name.
func PredeclareQueue(name string) {
	hookRunErrors.WithLabelValues(name)
	reconcileErrors.WithLabelValues(name)
}

// IncError increments both counters for module `name`. `name` must be
// the legacy shell-operator queue name (e.g. "coredns-stale-watchdog")
// so alert queries keep matching.
func IncError(name string) {
	hookRunErrors.WithLabelValues(name).Inc()
	reconcileErrors.WithLabelValues(name).Inc()
}

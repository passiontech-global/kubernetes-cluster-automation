package metrics

import (
	"testing"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestGatherFindsCounters(t *testing.T) {
	IncError("q")
	ObserveHealthCheck("q", true, 0)
	ObserveAPIBackend("10.0.0.1", 5, true)
	// Empty vecs emit no family — instantiate one series each so the
	// gather asserts the registration, not just the label plumbing.
	CiliumIdentitiesCollectedTotal.Inc()
	WebhookCircuitBroken.WithLabelValues("k", "n", "w").Set(1)
	WebhookCircuitBreakerTripsTotal.WithLabelValues("k", "n").Inc()
	PDBDrainBlocked.WithLabelValues("ns", "pdb", "r").Set(1)
	StuckTerminatingResources.WithLabelValues("k", "ns", "n").Set(1)
	HelmHookJobsCleanedTotal.WithLabelValues("ns").Inc()
	VolumeAttachmentsCleanedTotal.WithLabelValues("r").Inc()
	WebhookCABundleMismatch.WithLabelValues("k", "n", "w").Set(1)
	TLSSecretDaysToExpiry.WithLabelValues("ns", "s").Set(1)
	KCMWorkqueueFrozen.WithLabelValues("r").Set(1)
	APIServiceUnavailable.WithLabelValues("n", "ns", "s").Set(1)
	WebhookCABundleDaysToExpiry.WithLabelValues("k", "n", "w").Set(1)
	TrustBundleDaysToExpiry.WithLabelValues("ns", "n").Set(1)
	UnmeshedPods.WithLabelValues("ns", "p").Set(1)
	UnmeshedPodsRecreatedTotal.WithLabelValues("ns").Inc()
	ZombieSidecarPodsReapedTotal.WithLabelValues("ns").Inc()
	OrphanEndpointSlicesCleanedTotal.WithLabelValues("ns").Inc()
	FluxSourceReconcilesTriggeredTotal.WithLabelValues("k", "ns", "n").Inc()
	StatefulSetOnDeletePodsRolledTotal.WithLabelValues("ns", "s").Inc()
	VeleroSchedulePaused.WithLabelValues("ns", "s").Set(1)
	VeleroBackupEmptyOrErrored.WithLabelValues("ns", "s", "r").Set(1)
	fams, _ := ctrlmetrics.Registry.Gather()
	names := map[string]bool{}
	for _, f := range fams {
		names[f.GetName()] = true
	}
	for _, want := range []string{
		"shell_operator_hook_run_errors_total",
		"node_automation_reconcile_errors_total",
		"kuberhealthy_check",
		"kuberhealthy_check_seconds_since_success",
		"node_automation_apiserver_rv_gap",
		"node_automation_apiserver_quarantined",
		"node_automation_cilium_identities_collected_total",
		"node_automation_webhook_circuit_broken",
		"node_automation_webhook_circuit_breaker_trips_total",
		"node_automation_pdb_drain_blocked",
		"node_automation_stuck_terminating_resources",
		"node_automation_helm_hook_jobs_cleaned_total",
		"node_automation_volumeattachments_cleaned_total",
		"node_automation_webhook_ca_bundle_mismatch",
		"node_automation_tls_secret_days_to_expiry",
		"node_automation_kcm_workqueue_frozen",
		"node_automation_apiservice_unavailable",
		"node_automation_webhook_ca_bundle_days_to_expiry",
		"node_automation_trust_bundle_days_to_expiry",
		"node_automation_unmeshed_pods",
		"node_automation_unmeshed_pods_recreated_total",
		"node_automation_zombie_sidecar_pods_reaped_total",
		"node_automation_orphan_endpointslices_cleaned_total",
		"node_automation_flux_source_reconciles_triggered_total",
		"node_automation_statefulset_ondelete_pods_rolled_total",
		"node_automation_velero_schedule_paused",
		"node_automation_velero_backup_empty_or_errored",
	} {
		if !names[want] {
			t.Fatalf("family %s not in registry", want)
		}
	}
}

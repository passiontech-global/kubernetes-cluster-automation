package metrics

import (
	"testing"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestGatherFindsCounters(t *testing.T) {
	IncError("q")
	ObserveHealthCheck("q", true, 0)
	ObserveAPIBackend("10.0.0.1", 5, true)
	ObserveAPIBackendJWKSSkew("10.0.0.1", true)
	ControlPlanePodHealsTotal.WithLabelValues("q").Inc()
	// Empty vecs emit no family — instantiate one series each so the
	// gather asserts the registration, not just the label plumbing.
	CiliumIdentitiesCollectedTotal.Inc()
	CiliumActiveIdentities.Set(1)
	WebhookCircuitBroken.WithLabelValues("k", "n", "w").Set(1)
	WebhookCircuitBreakerTripsTotal.WithLabelValues("k", "n").Inc()
	BootWebhookFailOpenTotal.WithLabelValues("n", "w").Inc()
	WebhookMissingCriticalNSExclusion.WithLabelValues("k", "n", "w").Set(1)
	WebhookHeartbeatResourceExposed.WithLabelValues("k", "n", "w", "r").Set(1)
	CRDConversionWebhookUnhealthy.WithLabelValues("c", "s", "r").Set(1)
	PDBDrainBlocked.WithLabelValues("ns", "pdb", "r").Set(1)
	StuckTerminatingResources.WithLabelValues("k", "ns", "n").Set(1)
	HelmHookJobsCleanedTotal.WithLabelValues("ns").Inc()
	VolumeAttachmentsCleanedTotal.WithLabelValues("r").Inc()
	VolumeAttachmentFinalizersRemovedTotal.WithLabelValues("node").Inc()
	CronJobTooManyMissedStarts.WithLabelValues("ns", "cj").Set(1)
	CFTunnelWedgePodsDeletedTotal.WithLabelValues("ns", "r").Inc()
	CFTunnelGatewaySyncError.WithLabelValues("ns").Set(1)
	HealBudgetExhaustedTotal.Inc()
	HealGitOpsConflictTotal.WithLabelValues("m").Inc()
	HealTargetCircuitBrokenTotal.WithLabelValues("mod", "tgt").Inc()
	DeadNodeUnfencedStatefulSkipped.WithLabelValues("node").Set(1)
	DeadNodeFencedWithoutSNRTotal.WithLabelValues("node", "false").Inc()
	LeaderLeasePreemptionsTotal.WithLabelValues("r").Inc()
	WebhookCABundleMismatch.WithLabelValues("k", "n", "w").Set(1)
	TLSSecretDaysToExpiry.WithLabelValues("ns", "s").Set(1)
	APIServiceUnavailable.WithLabelValues("n", "ns", "s").Set(1)
	APIServiceUnblockHealsTotal.WithLabelValues("ns", "r").Inc()
	WebhookCABundleDaysToExpiry.WithLabelValues("k", "n", "w").Set(1)
	TrustBundleDaysToExpiry.WithLabelValues("ns", "n").Set(1)
	LinkerdTrustAnchorSkew.Set(0)
	UnmeshedPods.WithLabelValues("ns", "p").Set(1)
	UnmeshedPodsRecreatedTotal.WithLabelValues("ns").Inc()
	ZombieSidecarPodsReapedTotal.WithLabelValues("ns").Inc()
	OrphanEndpointSlicesCleanedTotal.WithLabelValues("ns").Inc()
	FluxSourceReconcilesTriggeredTotal.WithLabelValues("k", "ns", "n").Inc()
	HelmStallUnwedgesTotal.WithLabelValues("ns", "dep").Inc()
	StatefulSetOnDeletePodsRolledTotal.WithLabelValues("ns", "s").Inc()
	StatefulSetOnDeleteDragonflyUnsyncedSkipped.WithLabelValues("ns", "s").Inc()
	VeleroSchedulePaused.WithLabelValues("ns", "s").Set(1)
	VeleroBackupEmptyOrErrored.WithLabelValues("ns", "s", "r").Set(1)
	ReplicatedSecretDrift.WithLabelValues("ns", "n", "src").Set(1)
	VeleroBSLUnavailable.WithLabelValues("ns", "n").Set(1)
	HelmSecretsPrunedTotal.WithLabelValues("ns").Inc()
	DBBackupUnhealthy.WithLabelValues("ns", "c", "r").Set(1)
	ExternalSecretStormSuppressed.Set(0)
	ExternalSecretEmptyKey.WithLabelValues("ns", "n", "k").Set(1)
	OnePasswordConnectSyncUnhealthy.WithLabelValues("ns", "p").Set(1)
	VeleroBackupStuck.WithLabelValues("ns", "b").Set(1)
	VeleroPodVolumeBackupWedged.WithLabelValues("ns", "pvb").Set(1)
	VeleroPodVolumeRestoreWedged.WithLabelValues("ns", "pvr").Set(1)
	VeleroWedgedObjectsCleanedTotal.WithLabelValues("ns", "a").Inc()
	VeleroRepoUnhealthy.WithLabelValues("ns", "n", "r").Set(1)
	VeleroDataMovementWedged.WithLabelValues("ns", "n", "k").Set(1)
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
		"node_automation_controlplane_pod_heals_total",
		"node_automation_apiserver_rv_gap",
		"node_automation_apiserver_quarantined",
		"node_automation_apiserver_jwks_kid_skew",
		"node_automation_cilium_identities_collected_total",
		"node_automation_cilium_active_identities",
		"node_automation_webhook_circuit_broken",
		"node_automation_webhook_circuit_breaker_trips_total",
		"node_automation_boot_webhook_failopen_total",
		"node_automation_webhook_missing_critical_ns_exclusion",
		"node_automation_webhook_heartbeat_resource_exposed",
		"node_automation_crd_conversion_webhook_unhealthy",
		"node_automation_pdb_drain_blocked",
		"node_automation_stuck_terminating_resources",
		"node_automation_helm_hook_jobs_cleaned_total",
		"node_automation_volumeattachments_cleaned_total",
		"node_automation_volumeattachment_finalizers_removed_total",
		"node_automation_cronjob_too_many_missed_starts",
		"node_automation_cftunnel_wedge_pods_deleted_total",
		"node_automation_cftunnel_gateway_sync_error",
		"node_automation_heal_budget_exhausted_total",
		"node_automation_heal_gitops_conflict_total",
		"node_automation_heal_target_circuit_broken_total",
		"node_automation_dead_node_unfenced_stateful_skipped",
		"node_automation_dead_node_fenced_without_snr_total",
		"node_automation_leader_lease_preemptions_total",
		"node_automation_webhook_ca_bundle_mismatch",
		"node_automation_tls_secret_days_to_expiry",
		"node_automation_apiservice_unavailable",
		"node_automation_apiservice_unblock_heals_total",
		"node_automation_webhook_ca_bundle_days_to_expiry",
		"node_automation_trust_bundle_days_to_expiry",
		"node_automation_linkerd_trust_anchor_skew",
		"node_automation_unmeshed_pods",
		"node_automation_unmeshed_pods_recreated_total",
		"node_automation_zombie_sidecar_pods_reaped_total",
		"node_automation_orphan_endpointslices_cleaned_total",
		"node_automation_flux_source_reconciles_triggered_total",
		"node_automation_helm_stall_unwedges_total",
		"node_automation_statefulset_ondelete_pods_rolled_total",
		"node_automation_statefulset_ondelete_dragonfly_unsynced_skipped_total",
		"node_automation_velero_schedule_paused",
		"node_automation_velero_backup_empty_or_errored",
		"node_automation_replicated_secret_drift",
		"node_automation_velero_bsl_unavailable",
		"node_automation_helm_secrets_pruned_total",
		"node_automation_db_backup_unhealthy",
		"node_automation_externalsecret_storm_suppressed",
		"node_automation_externalsecret_empty_key",
		"node_automation_onepassword_connect_sync_unhealthy",
		"node_automation_velero_backup_stuck",
		"node_automation_velero_podvolumebackup_wedged",
		"node_automation_velero_podvolumerestore_wedged",
		"node_automation_velero_wedged_objects_cleaned_total",
		"node_automation_velero_repo_unhealthy",
		"node_automation_velero_data_movement_wedged",
	} {
		if !names[want] {
			t.Fatalf("family %s not in registry", want)
		}
	}
}

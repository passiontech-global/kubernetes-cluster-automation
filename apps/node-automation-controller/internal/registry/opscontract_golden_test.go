// opscontract_golden_test.go — golden pins for the byte-stable ops
// contract: the module registry table (Name/Group in table order —
// row order IS the boot order and the health-sweep order), the
// Prometheus metric family names (metric names are scraped by live
// PrometheusRules; a rename silently breaks alerts), and the
// annotation/label/taint key consts (annos.go). Any drift — a
// renamed row, a re-grouped module, an inserted/reordered row, a
// renamed metric, a changed key value — fails here and may only
// ship with a conscious golden update in this file.
package registry

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// goldenRegistryRows is a frozen copy of the registry table in
// registry.go, in order. Row order is contract twice over: it is the
// boot order AND, inside the health section, the cluster-health
// sweep order (the historical kuberhealthy sequence). Group is the
// blast-radius set the -modules @-entries select on.
var goldenRegistryRows = []struct{ Name, Group string }{
	{"konnectivity-patcher", "system"},
	{"fluent-bit-config-roller", "system"},
	{"coredns-stale-watchdog", "system"},
	{"coredns-patcher", "system"},
	{"metrics-server-patcher", "system"},
	{"cf-tunnel-proxy-watchdog", "system"},
	{"statefulset-ondelete-roller", "system"},
	{"cilium-taint-reaper", "node"},
	{"descheduler-storm-gate", "node"},
	{"node-labeler", "node"},
	{"kubelet-liveness-reaper", "node"},
	{"partition-pod-evictor", "node"},
	{"dead-node-sweeper", "node"},
	{"csr-watcher", "node"},
	{"pdb-deadlock-watchdog", "node"},
	{"admission-webhook-guard", "apiserver"},
	{"apiserver-endpoint-guard", "apiserver"},
	{"apiservice-guard", "apiserver"},
	{"failed-jobs-janitor", "janitors"},
	{"evicted-pod-janitor", "janitors"},
	{"cronjob-catchup", "janitors"},
	{"concourse-workdir-janitor", "janitors"},
	{"volumeattachment-cleaner", "janitors"},
	{"zombie-sidecar-reaper", "janitors"},
	{"orphan-endpointslice-cleaner", "janitors"},
	{"helmrelease-unlocker", "integration"},
	{"externalsecret-nudge", "integration"},
	{"certmanager-reaper", "integration"},
	{"cilium-identity-auditor", "integration"},
	{"cert-drift-auditor", "integration"},
	{"velero-backup-auditor", "integration"},
	{"dns-status-internal", "health"},
	{"http-content-check", "health"},
	{"pod-restarts", "health"},
	{"pod-status-check", "health"},
	{"resource-quota-check", "health"},
	{"kcm-workqueue-watchdog", "health"},
	{"operator-workqueue-watchdog", "health"},
	{"stateful-masterless-services", "health"},
	{"rabbitmq-suspended-listener", "health"},
	{"localpv-stranded-pods", "health"},
	{"olm-subscription-health", "health"},
	{"scheduler-watchdog", "health"},
	{"mesh-controlplane-watchdog", "health"},
	{"node-hang-precordon", "health"},
	{"linkerd-endpoint-sync", "health"},
	{"scylla-cluster-health", "health"},
	{"flux-helmrelease-retries", "health"},
	{"percona-cluster-quorum", "health"},
	{"cilium-bpf-map-pressure", "health"},
	{"linkerd-protocol-detection-stall", "health"},
	{"coredns-upstream", "health"},
	{"cilium-node-ipam-exhaustion", "health"},
	{"namespace-terminating-wedged", "health"},
	{"argocd-app-stuck", "health"},
	{"kargo-promotion-health", "health"},
	{"rabbitmq-quorum-health", "health"},
	{"dragonfly-replica-sync-storm", "health"},
	{"image-pull-storm", "health"},
	{"api-object-sprawl-report-gc", "health"},
	{"cpu-steal-taint-sync", "health"},
	{"cilium-missing-endpoint", "health"},
	{"linkerd-h2-stream-guard", "health"},
	{"cloudflared-tunnel-health", "health"},
	{"liqo-tunnel-health", "health"},
	{"konnectivity-tunnel-health", "health"},
	{"postgres-wal-archive-guard", "health"},
	{"scylla-compaction-schema-guard", "health"},
	{"nats-jetstream-health", "health"},
	{"keda-scaledobject-guard", "health"},
	{"gateway-route-health", "health"},
	{"controller-lease-guard", "health"},
	{"pvc-resize-stall-guard", "health"},
	{"endpointslice-zone-starvation", "health"},
	{"linkerd-outlier-guard", "health"},
	{"node-condition-sweeper", "health"},
	{"onepassword-connect-sync-probe", "health"},
	{"linkerd-sidecar-oom-guard", "health"},
	{"cilium-datapath-map-guard", "health"},
	{"cilium-l2-lease-guard", "health"},
	{"observability-pipeline-guard", "health"},
	{"apiserver-relist-storm-breaker", "health"},
	{"flux-kustomization-health", "health"},
	{"workload-scale-flapping", "health"},
	{"imagepull-secret-auditor", "health"},
	{"cluster-health-probes", "health"},
	// argocd-agent-spin — argocd-agent spin healer, last row (see registry.go).
	{"argocd-agent-spin", "health"},
}

// goldenMetricFamilies is the frozen set of metric family names the
// fleet exposes on :9115/metrics — every vector declared in
// internal/metrics plus the per-check private gauges registered in
// check files' init() calls (see internal/metrics/core.go). Compiled
// statically (sourced from the literal metric Name: opts across
// internal/) because a Vec family only appears in a Gather() once it
// holds at least one series, so a live gather is incomplete by
// construction; the live check below still guards against surprise
// runtime families and against registration nondeterminism.
var goldenMetricFamilies = []string{
	"node_automation_analysisrun_stuck",
	"node_automation_api_object_count",
	"node_automation_apiserver_jwks_kid_skew",
	"node_automation_apiserver_quarantined",
	"node_automation_apiserver_relist_storm",
	"node_automation_apiserver_rv_gap",
	"node_automation_apiservice_unavailable",
	"node_automation_apiservice_unblock_heals_total",
	"node_automation_argocd_app_stuck",
	"node_automation_cftunnel_gateway_sync_error",
	"node_automation_cftunnel_wedge_pods_deleted_total",
	"node_automation_cilium_active_identities",
	"node_automation_cilium_bpf_map_pressure",
	"node_automation_cilium_datapath_degraded",
	"node_automation_cilium_identities_collected_total",
	"node_automation_cilium_ipam_free_ratio",
	"node_automation_cilium_l2_stale_lease",
	"node_automation_cilium_linkerd_socklb_conflict",
	"node_automation_cilium_missing_cep_pods",
	"node_automation_cloudflared_tunnel_degraded",
	"node_automation_cnpg_cluster_unhealthy",
	"node_automation_controller_lease_thrashing",
	"node_automation_controller_lease_unhealthy",
	"node_automation_controlplane_pod_heals_total",
	"node_automation_coredns_upstream_failing",
	"node_automation_crd_conversion_webhook_unhealthy",
	"node_automation_cronjob_too_many_missed_starts",
	"node_automation_db_backup_unhealthy",
	"node_automation_dead_node_fenced_without_snr_total",
	"node_automation_dead_node_unfenced_stateful_skipped",
	"node_automation_dragonfly_masterless_pod_heals_total",
	"node_automation_dragonfly_replica_sync_storm",
	"node_automation_ephemeral_reports_deleted_total",
	"node_automation_ephemeral_reports_orphaned",
	"node_automation_externalsecret_empty_key",
	"node_automation_externalsecret_storm_suppressed",
	"node_automation_flux_kustomization_stuck",
	"node_automation_flux_source_reconciles_triggered_total",
	"node_automation_gateway_route_unhealthy",
	"node_automation_gateway_route_zero_endpoints",
	"node_automation_heal_budget_exhausted_total",
	"node_automation_heal_target_circuit_broken_total",
	"node_automation_helm_hook_jobs_cleaned_total",
	"node_automation_helm_release_secrets_excess",
	"node_automation_helm_release_secrets_pruned_total",
	"node_automation_helm_secrets_pruned_total",
	"node_automation_helm_stall_unwedges_total",
	"node_automation_image_pull_backoff",
	"node_automation_imagepull_secret_unhealthy",
	"node_automation_kargo_promotion_stuck",
	"node_automation_kargo_warehouse_unhealthy",
	"node_automation_kcm_workqueue_frozen",
	"node_automation_keda_scaledobject_unhealthy",
	"node_automation_kine_large_object_bytes",
	"node_automation_konnectivity_agent_half_open",
	"node_automation_leader_lease_preemptions_total",
	"node_automation_linkerd_endpoint_desync",
	"node_automation_linkerd_gitops_opaque_drift",
	"node_automation_linkerd_h2_stream_stalled",
	"node_automation_linkerd_init_deadlock_pods",
	"node_automation_linkerd_opaque_port_missing",
	"node_automation_linkerd_outbound_balancer_wedged",
	"node_automation_linkerd_outlier_pods",
	"node_automation_linkerd_proxy_identity_stalled",
	"node_automation_linkerd_proxy_oomkilled",
	"node_automation_linkerd_sidecar_oom",
	"node_automation_linkerd_trust_anchor_skew",
	"node_automation_liqo_peer_unhealthy",
	"node_automation_localpv_ephemeral_heals_total",
	"node_automation_localpv_stranded_pods",
	"node_automation_localpv_stranded_stateful_pod",
	"node_automation_namespace_terminating_wedged",
	"node_automation_nats_jetstream_unhealthy",
	"node_automation_node_condition_sweeps_total",
	"node_automation_node_cpu_steal_tainted",
	"node_automation_node_hang_cordons_total",
	"node_automation_node_hang_uncordons_total",
	"node_automation_observability_pipeline_degraded",
	"node_automation_olm_operator_heals_total",
	"node_automation_olm_unhealthy_resources",
	"node_automation_onepassword_connect_sync_unhealthy",
	"node_automation_operator_workqueue_frozen",
	"node_automation_operator_workqueue_heals_total",
	"node_automation_orphan_endpointslices_cleaned_total",
	"node_automation_pdb_drain_blocked",
	"node_automation_percona_cluster_degraded",
	"node_automation_postgres_inactive_slot_wal_bloat",
	"node_automation_postgres_wal_archive_unhealthy",
	"node_automation_pvc_provisioner_heals_total",
	"node_automation_pvc_provisioning_stalled",
	"node_automation_pvc_resize_stalled",
	"node_automation_rabbitmq_quorum_unhealthy",
	"node_automation_rabbitmq_suspended_heals_total",
	"node_automation_reconcile_errors_total",
	"node_automation_registry_pull_outage",
	"node_automation_replicated_secret_drift",
	"node_automation_scheduler_frozen",
	"node_automation_scheduler_preemption_storm",
	"node_automation_scylla_compaction_backlog",
	"node_automation_scylla_overload_stall",
	"node_automation_scylla_schema_split",
	"node_automation_scylla_shard_imbalance",
	"node_automation_scylla_unhealthy",
	"node_automation_service_topology_zone_starved",
	"node_automation_stateful_master_site_skew",
	"node_automation_stateful_service_multiple_masters",
	"node_automation_stateful_service_zero_endpoints",
	"node_automation_statefulset_ondelete_pods_rolled_total",
	"node_automation_stuck_terminating_resources",
	"node_automation_tls_secret_days_to_expiry",
	"node_automation_trust_bundle_days_to_expiry",
	"node_automation_unmeshed_pods",
	"node_automation_unmeshed_pods_recreated_total",
	"node_automation_velero_backup_empty_or_errored",
	"node_automation_velero_backup_stuck",
	"node_automation_velero_bsl_unavailable",
	"node_automation_velero_data_movement_wedged",
	"node_automation_velero_podvolumebackup_wedged",
	"node_automation_velero_podvolumerestore_wedged",
	"node_automation_velero_repo_unhealthy",
	"node_automation_velero_schedule_paused",
	"node_automation_velero_wedged_objects_cleaned_total",
	"node_automation_volumeattachment_finalizers_removed_total",
	"node_automation_volumeattachments_cleaned_total",
	"node_automation_webhook_ca_bundle_days_to_expiry",
	"node_automation_webhook_ca_bundle_mismatch",
	"node_automation_webhook_circuit_breaker_trips_total",
	// bootwebhooks — medik8s boot fail-open enforcement (not alphabetical, new row).
	"node_automation_boot_webhook_failopen_total",
	"node_automation_webhook_circuit_broken",
	"node_automation_webhook_heartbeat_resource_exposed",
	"node_automation_webhook_missing_critical_ns_exclusion",
	"node_automation_workload_scale_flapping",
	"node_automation_zombie_sidecar_pods_reaped_total",
	// argocd-agent-spin — argocd-agent spin gauge (not alphabetical, new row).
	"node_automation_argocd_agent_spin",
	"shell_operator_hook_run_errors_total",
}

// goldenAnnoKeys freezes every exported annotation/label/taint key
// const in internal/platform/kube/annos.go. Values are the ops
// contract — external-owned keys (fluent-bit, kured, flux, kargo)
// must never change at all; internal-owned renames read as "never
// stamped" to persistence.
var goldenAnnoKeys = []struct{ Key, Value string }{
	{"AnnoLastHelmUnlock", "passiontech.dev/last-helm-unlock"},
	{"AnnoLastHelmStallUnwedge", "passiontech.dev/last-helm-stall-unwedge"},
	{"AnnoLastImmutableJobHeal", "passiontech.dev/last-immutable-job-heal"},
	{"AnnoLastSourceNudge", "passiontech.dev/last-source-nudge"},
	{"AnnoLastESNudge", "passiontech.dev/last-es-nudge"},
	{"AnnoLastOperatorHeal", "passiontech.dev/last-operator-heal"},
	{"AnnoLastDragonflyOperatorHeal", "passiontech.dev/last-dragonfly-operator-heal"},
	{"AnnoLastDragonflyPodHeal", "passiontech.dev/last-dragonfly-pod-heal"},
	{"AnnoACMEOrderResets", "passiontech.dev/acme-order-resets"},
	{"AnnoStartingDeadlinePatched", "passiontech.dev/starting-deadline-patched"},
	{"AnnoEphemeralLocalPV", "passiontech.dev/ephemeral-localpv"},
	{"AnnoPreCordonedBy", "passiontech.dev/precordoned-by"},
	{"AnnoAutoRollOnDelete", "passiontech.dev/auto-roll-ondelete"},
	{"AnnoEvictOnPartition", "passiontech.dev/evict-on-partition"},
	{"AnnoQuarantinedEndpoints", "passiontech.dev/quarantined-endpoints"},
	{"AnnoCircuitBrokenWebhooks", "passiontech.dev/circuit-broken-webhooks"},
	{"AnnoLastCoreDNSRestart", "passiontech.dev/last-coredns-restart"},
	{"AnnoCatchup", "passiontech.dev/catchup"},
	{"LabelMissedCatchup", "passiontech.dev/missed-catchup"},
	{"AnnoConcourseBaselineNodeFSGiB", "passiontech.dev/baseline-nodefs-gib"},
	{"AnnoWatchdogForceResync", "passiontech.dev/force-resync"},
	{"AnnoStormGateHold", "passiontech.dev/storm-gate-hold"},
	{"AnnoStormGateDecision", "passiontech.dev/storm-gate-decision"},
	{"AnnoFirstSeenKSMWedge", "passiontech.dev/first-seen-ksm-wedge"},
	{"AnnoFirstSeenCPUStealClear", "passiontech.dev/first-seen-cpu-steal-clear"},
	{"AnnoFirstSeenKedaScaledObject", "passiontech.dev/first-seen-keda-scaledobject"},
	{"AnnoFirstSeenRabbitQuorum", "passiontech.dev/first-seen-rabbitmq-quorum"},
	{"AnnoFirstSeenRabbitSuspended", "passiontech.dev/first-seen-rabbitmq-suspended"},
	{"AnnoFirstSeenDragonflyLinkStorm", "passiontech.dev/first-seen-dragonfly-linkstorm"},
	{"AnnoFirstSeenOLMUnhealthy", "passiontech.dev/first-seen-olm-unhealthy"},
	{"AnnoFirstSeenStatefulMasterless", "passiontech.dev/first-seen-stateful-masterless"},
	{"AnnoFirstSeenOperatorWorkqueue", "passiontech.dev/first-seen-operator-workqueue"},
	{"AnnoFirstSeenLinkerdEndpointSync", "passiontech.dev/first-seen-linkerd-endpoint-sync"},
	{"AnnoFirstSeenArgoCDAppStuck", "passiontech.dev/first-seen-argocd-app-stuck"},
	{"AnnoFirstSeenStormGateHold", "passiontech.dev/first-seen-storm-gate-hold"},
	{"AnnoFirstSeenNHCPause", "passiontech.dev/first-seen-nhc-pause"},
	{"AnnoLastLinkerdOpaquePatch", "passiontech.dev/last-linkerd-opaque-patch"},
	{"AnnoLastKargoRefresh", "passiontech.dev/last-kargo-refresh"},
	{"AnnoAllowEmptySecretKey", "passiontech.dev/allow-empty-secret-key"},
	{"AnnoRolledConfigHash", "passiontech.dev/rolled-config-hash"},
	{"TaintKubeletUnresponsive", "passiontech.dev/kubelet-unresponsive"},
	{"TaintNetworkPartitioned", "passiontech.dev/network-partitioned"},
	{"TaintCPUSteal", "passiontech.dev/cpu-steal"},
	{"AnnoFluentConfigHash", "fluent.io/config-hash"},
	{"TaintKuredNodeReboot", "weave.works/kured-node-reboot"},
	{"AnnoFluxRequestedAt", "reconcile.fluxcd.io/requestedAt"},
	{"AnnoFluxResetAt", "reconcile.fluxcd.io/resetAt"},
	{"AnnoFluxForceAt", "reconcile.fluxcd.io/forceAt"},
	{"AnnoKargoRefresh", "kargo.akuity.io/refresh"},
}

func TestGoldenRegistryRows(t *testing.T) {
	if len(Modules) != len(goldenRegistryRows) {
		t.Fatalf("registry row count drifted: live=%d golden=%d (add/remove/reorder needs a conscious golden update)", len(Modules), len(goldenRegistryRows))
	}
	for i, want := range goldenRegistryRows {
		got := Modules[i]
		if got.Name != want.Name || got.Group != want.Group {
			t.Errorf("registry row %d drifted: live={%s %s} golden={%s %s} — row order IS the boot/sweep contract", i, got.Name, got.Group, want.Name, want.Group)
		}
	}
}

func gatherFamilies(t *testing.T) []string {
	t.Helper()
	mfs, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics registry: %v", err)
	}
	out := make([]string, 0, len(mfs))
	for _, mf := range mfs {
		out = append(out, mf.GetName())
	}
	sort.Strings(out)
	return out
}

func TestGoldenMetricFamilies(t *testing.T) {
	// Stability: two consecutive gathers of the live registry must
	// agree — init()-time registration is deterministic, so a
	// mismatch means nondeterministic registration crept in.
	first := gatherFamilies(t)
	second := gatherFamilies(t)
	if len(first) != len(second) {
		t.Fatalf("metric registry unstable across consecutive gathers: first=%d second=%d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("metric registry unstable across consecutive gathers: first[%d]=%s second[%d]=%s", i, first[i], i, second[i])
		}
	}
	// Every fleet family visible at runtime must be a pinned golden
	// name — a live family absent from the golden is undeclared drift
	// (a new metric shipped without a conscious golden update). The
	// registry also carries controller-runtime's own go/process/
	// certwatcher families; those are not part of this ops contract
	// and are skipped here.
	golden := map[string]bool{}
	for _, n := range goldenMetricFamilies {
		golden[n] = true
	}
	for _, n := range first {
		if !strings.HasPrefix(n, "node_automation_") && !strings.HasPrefix(n, "shell_operator_") {
			continue
		}
		if !golden[n] {
			t.Errorf("live metric family %q is not pinned in goldenMetricFamilies (empty-vec families are invisible to Gather, so the golden is the full static list)", n)
		}
	}
	// The golden list must match the source declarations exactly —
	// both directions — even for Vecs that hold no series in this
	// binary and are invisible to Gather: without the source walk a
	// renamed or deleted Name: opt would leave the stale golden
	// green forever (mirrors internal/envdoc's source coverage).
	declared := goldenMetricNamesFromSource(t)
	for name, path := range declared {
		if !golden[name] {
			t.Errorf("%s declares metric %q not pinned in goldenMetricFamilies — update the golden consciously", path, name)
		}
	}
	for _, n := range goldenMetricFamilies {
		if _, ok := declared[n]; !ok {
			t.Errorf("goldenMetricFamilies pins %q but no source declares it (renamed or deleted metric — update the golden consciously)", n)
		}
	}
	// A total registration regression must not pass vacuously.
	if len(first) == 0 {
		t.Fatal("live metric registry gathered zero families after importing internal/registry")
	}
}

// goldenMetricNamesFromSource collects every metric Name literal the
// non-test sources declare, keyed by declaring file, so the golden
// covers families that hold no series at gather time. Walks the
// package parent (internal/) — the only tree that declares metrics.
func goldenMetricNamesFromSource(t *testing.T) map[string]string {
	t.Helper()
	re := regexp.MustCompile(`Name:\s+"((?:node_automation|shell_operator)_[^"]+)"`)
	found := map[string]string{}
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllSubmatch(src, -1) {
			name := string(m[1])
			if _, dup := found[name]; !dup {
				found[name] = path
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("metric source walk failed: %v", err)
	}
	return found
}

func TestGoldenAnnoKeys(t *testing.T) {
	for _, want := range goldenAnnoKeys {
		if got := annoKeyFor(t, want.Key); got != want.Value {
			t.Errorf("anno key %s drifted: live=%q golden=%q — external-contract values must never change", want.Key, got, want.Value)
		}
	}
}

// annoKeyFor resolves a golden key name against the real consts via
// a generated switch, so a renamed or deleted const fails the test
// loudly instead of compiling to an empty string.
func annoKeyFor(t *testing.T, name string) string {
	t.Helper()
	switch name {
	case "AnnoLastHelmUnlock":
		return kube.AnnoLastHelmUnlock
	case "AnnoLastHelmStallUnwedge":
		return kube.AnnoLastHelmStallUnwedge
	case "AnnoLastImmutableJobHeal":
		return kube.AnnoLastImmutableJobHeal
	case "AnnoLastSourceNudge":
		return kube.AnnoLastSourceNudge
	case "AnnoLastESNudge":
		return kube.AnnoLastESNudge
	case "AnnoLastOperatorHeal":
		return kube.AnnoLastOperatorHeal
	case "AnnoLastDragonflyOperatorHeal":
		return kube.AnnoLastDragonflyOperatorHeal
	case "AnnoLastDragonflyPodHeal":
		return kube.AnnoLastDragonflyPodHeal
	case "AnnoACMEOrderResets":
		return kube.AnnoACMEOrderResets
	case "AnnoStartingDeadlinePatched":
		return kube.AnnoStartingDeadlinePatched
	case "AnnoEphemeralLocalPV":
		return kube.AnnoEphemeralLocalPV
	case "AnnoPreCordonedBy":
		return kube.AnnoPreCordonedBy
	case "AnnoAutoRollOnDelete":
		return kube.AnnoAutoRollOnDelete
	case "AnnoEvictOnPartition":
		return kube.AnnoEvictOnPartition
	case "AnnoQuarantinedEndpoints":
		return kube.AnnoQuarantinedEndpoints
	case "AnnoCircuitBrokenWebhooks":
		return kube.AnnoCircuitBrokenWebhooks
	case "AnnoLastCoreDNSRestart":
		return kube.AnnoLastCoreDNSRestart
	case "AnnoCatchup":
		return kube.AnnoCatchup
	case "LabelMissedCatchup":
		return kube.LabelMissedCatchup
	case "AnnoConcourseBaselineNodeFSGiB":
		return kube.AnnoConcourseBaselineNodeFSGiB
	case "AnnoWatchdogForceResync":
		return kube.AnnoWatchdogForceResync
	case "AnnoStormGateHold":
		return kube.AnnoStormGateHold
	case "AnnoStormGateDecision":
		return kube.AnnoStormGateDecision
	case "AnnoFirstSeenKSMWedge":
		return kube.AnnoFirstSeenKSMWedge
	case "AnnoFirstSeenCPUStealClear":
		return kube.AnnoFirstSeenCPUStealClear
	case "AnnoFirstSeenKedaScaledObject":
		return kube.AnnoFirstSeenKedaScaledObject
	case "AnnoFirstSeenRabbitQuorum":
		return kube.AnnoFirstSeenRabbitQuorum
	case "AnnoFirstSeenRabbitSuspended":
		return kube.AnnoFirstSeenRabbitSuspended
	case "AnnoFirstSeenDragonflyLinkStorm":
		return kube.AnnoFirstSeenDragonflyLinkStorm
	case "AnnoFirstSeenOLMUnhealthy":
		return kube.AnnoFirstSeenOLMUnhealthy
	case "AnnoFirstSeenStatefulMasterless":
		return kube.AnnoFirstSeenStatefulMasterless
	case "AnnoFirstSeenOperatorWorkqueue":
		return kube.AnnoFirstSeenOperatorWorkqueue
	case "AnnoFirstSeenLinkerdEndpointSync":
		return kube.AnnoFirstSeenLinkerdEndpointSync
	case "AnnoFirstSeenArgoCDAppStuck":
		return kube.AnnoFirstSeenArgoCDAppStuck
	case "AnnoFirstSeenStormGateHold":
		return kube.AnnoFirstSeenStormGateHold
	case "AnnoFirstSeenNHCPause":
		return kube.AnnoFirstSeenNHCPause
	case "AnnoLastLinkerdOpaquePatch":
		return kube.AnnoLastLinkerdOpaquePatch
	case "AnnoLastKargoRefresh":
		return kube.AnnoLastKargoRefresh
	case "AnnoAllowEmptySecretKey":
		return kube.AnnoAllowEmptySecretKey
	case "AnnoRolledConfigHash":
		return kube.AnnoRolledConfigHash
	case "TaintKubeletUnresponsive":
		return kube.TaintKubeletUnresponsive
	case "TaintNetworkPartitioned":
		return kube.TaintNetworkPartitioned
	case "TaintCPUSteal":
		return kube.TaintCPUSteal
	case "AnnoFluentConfigHash":
		return kube.AnnoFluentConfigHash
	case "TaintKuredNodeReboot":
		return kube.TaintKuredNodeReboot
	case "AnnoFluxRequestedAt":
		return kube.AnnoFluxRequestedAt
	case "AnnoFluxResetAt":
		return kube.AnnoFluxResetAt
	case "AnnoFluxForceAt":
		return kube.AnnoFluxForceAt
	case "AnnoKargoRefresh":
		return kube.AnnoKargoRefresh
	default:
		t.Fatalf("golden key %s no longer exists as an exported const in internal/platform/kube/annos.go — update the golden consciously", name)
		return ""
	}
}

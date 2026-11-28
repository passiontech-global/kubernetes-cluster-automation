// registry_health.go — the health section of the module registry:
// one CheckReg row per check the cluster-health-probes sweep runs,
// then the sweep row itself (the section's only Setup). Concatenated
// after moduleRows into Modules — see registry.go for the table's
// ops-contract documentation.
package registry

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/clusterhealthprobes"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/dragonfly"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/nats"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/percona"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/postgres"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/rabbitmq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/scylla"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops/olm"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/cloudflared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/connectionskew"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/gateway"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/linkerd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/liqo"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nodehealth"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/ported"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/storage/localpv"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/storage/pvc"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/watchdogs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/watchdogs/leases"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/watchdogs/sprawl"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// healthRows is the CheckReg half of the registry — one row per
// check the cluster-health-probes sweep runs, then the sweep row
// itself (the section's only Setup). A check row carries CheckReg
// instead of Setup: it contributes a {check-name, ctor} pair into
// the sweep roster — SetupModules collects the enabled, selected
// rows' registrations into Deps.CheckRegs in registry order (see
// internal/health/clusterhealthprobes/check_modules.go) — rather
// than registering runnables, so THE ROW ORDER BELOW IS THE SWEEP
// ORDER: the historical kuberhealthy sequence is an ops contract and
// must not be reordered. Each row's module Name is the check's
// kuberhealthy_check label value, so a check is also selectable by
// name via -modules — but it still requires the
// cluster-health-probes module to actually run the sweep (a check
// row selected alone contributes to a roster nothing consumes;
// cluster-health-probes selected alone sweeps an empty roster).
//
// The first block is the always-on checks — no GateEnv: the ported
// kuberhealthy checks and their successor checks ran unconditionally
// and keep doing so.
var healthRows = []shared.Module{
	{Name: "dns-status-internal", Group: groupHealth, CheckReg: &shared.CheckReg{Name: ported.CheckNameDNS, New: ported.NewDNSStatusCheck}},
	{Name: "http-content-check", Group: groupHealth, CheckReg: &shared.CheckReg{Name: ported.CheckNameHTTPContent, New: ported.NewHTTPContentCheck}},
	{Name: "pod-restarts", Group: groupHealth, CheckReg: &shared.CheckReg{Name: ported.CheckNamePodRestarts, New: ported.NewPodRestartsCheck}},
	{Name: "pod-status-check", Group: groupHealth, CheckReg: &shared.CheckReg{Name: ported.CheckNamePodStatus, New: ported.NewPodStatusCheck}},
	{Name: "resource-quota-check", Group: groupHealth, CheckReg: &shared.CheckReg{Name: ported.CheckNameResourceQuota, New: ported.NewResourceQuotaCheck}},
	{Name: "kcm-workqueue-watchdog", Group: groupHealth, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameKCMWorkqueue, New: watchdogs.NewKcmWorkqueueCheck}},
	{Name: "operator-workqueue-watchdog", Group: groupHealth, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameOperatorWorkqueue, New: watchdogs.NewOperatorWorkqueueCheck}},
	{Name: "stateful-masterless-services", Group: groupHealth, CheckReg: &shared.CheckReg{Name: datastore.CheckNameStatefulMasterless, New: datastore.NewStatefulMasterlessCheck}},
	{Name: "rabbitmq-suspended-listener", Group: groupHealth, CheckReg: &shared.CheckReg{Name: rabbitmq.CheckNameRabbitMQSuspended, New: rabbitmq.NewRabbitMQSuspendedCheck}},
	{Name: "localpv-stranded-pods", Group: groupHealth, CheckReg: &shared.CheckReg{Name: localpv.CheckNameLocalPVStranded, New: localpv.NewLocalPVStrandedCheck}},
	{Name: "olm-subscription-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: olm.CheckNameOLMHealth, New: olm.NewOlmHealthCheck}},
	{Name: "scheduler-watchdog", Group: groupHealth, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameSchedulerWatchdog, New: watchdogs.NewSchedulerWatchdogCheck}},
	{Name: "mesh-controlplane-watchdog", Group: groupHealth, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameMeshWatchdog, New: watchdogs.NewMeshControlPlaneCheck}},
	{Name: "node-hang-precordon", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameNodeHang, New: nodehealth.NewNodeHangCheck}},
	{Name: "linkerd-endpoint-sync", Group: groupHealth, CheckReg: &shared.CheckReg{Name: linkerd.CheckNameLinkerdEndpointSync, New: linkerd.NewLinkerdEndpointSyncCheck}},
	{Name: "scylla-cluster-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: scylla.CheckNameScyllaHealth, New: scylla.NewScyllaHealthCheck}},
	{Name: "flux-helmrelease-retries", Group: groupHealth, CheckReg: &shared.CheckReg{Name: gitops.CheckNameFluxHRRetries, New: gitops.NewFluxHRRetriesCheck}},
	{Name: "percona-cluster-quorum", Group: groupHealth, CheckReg: &shared.CheckReg{Name: percona.CheckNamePerconaQuorum, New: percona.NewPerconaQuorumCheck}},
	{Name: "cilium-bpf-map-pressure", Group: groupHealth, CheckReg: &shared.CheckReg{Name: cilium.CheckNameCiliumBPFMapPressure, New: cilium.NewCiliumBPFMapPressureCheck}},
	{Name: "linkerd-protocol-detection-stall", Group: groupHealth, CheckReg: &shared.CheckReg{Name: linkerd.CheckNameLinkerdOpaqueStall, New: linkerd.NewLinkerdProtocolDetectionStallCheck}},
	{Name: "coredns-upstream", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameCoreDNSUpstream, New: nethealth.NewCoreDNSUpstreamCheck}},
	{Name: "cilium-node-ipam-exhaustion", Group: groupHealth, CheckReg: &shared.CheckReg{Name: cilium.CheckNameCiliumNodeIPAM, New: cilium.NewCiliumNodeIPAMExhaustionCheck}},
	{Name: "namespace-terminating-wedged", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameNamespaceWedged, New: nodehealth.NewNamespaceTerminatingWedgedCheck}},
	{Name: "argocd-app-stuck", Group: groupHealth, CheckReg: &shared.CheckReg{Name: gitops.CheckNameArgoCDAppStuck, New: gitops.NewArgoCDAppStuckCheck}},
	{Name: "kargo-promotion-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: gitops.CheckNameKargoPromotionHealth, New: gitops.NewKargoPromotionHealthCheck}},
	{Name: "rabbitmq-quorum-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: rabbitmq.CheckNameRabbitMQQuorum, New: rabbitmq.NewRabbitMQQuorumHealthCheck}},
	{Name: "dragonfly-replica-sync-storm", Group: groupHealth, CheckReg: &shared.CheckReg{Name: dragonfly.CheckNameDragonflySyncStorm, New: dragonfly.NewDragonflyReplicaSyncStormCheck}},
	{Name: "image-pull-storm", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameImagePullStorm, New: nodehealth.NewImagePullStormCheck}},
	{Name: "api-object-sprawl-report-gc", Group: groupHealth, CheckReg: &shared.CheckReg{Name: sprawl.CheckNameAPIObjectSprawlReportGC, New: sprawl.NewAPIObjectSprawlReportGCCheck}},
	{Name: "cpu-steal-taint-sync", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameCPUStealTaintSync, New: nodehealth.NewCPUStealTaintSyncCheck}},
	{Name: "cilium-missing-endpoint", Group: groupHealth, CheckReg: &shared.CheckReg{Name: cilium.CheckNameCiliumMissingEndpoints, New: cilium.NewCiliumMissingEndpointsCheck}},
	{Name: "linkerd-h2-stream-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: linkerd.CheckNameLinkerdH2StreamGuard, New: linkerd.NewLinkerdH2StreamGuardCheck}},
	{Name: "cloudflared-tunnel-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: cloudflared.CheckNameCloudflaredTunnelHealth, New: cloudflared.NewCloudflaredTunnelHealthCheck}},
	{Name: "liqo-tunnel-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: liqo.CheckNameLiqoTunnelHealth, New: liqo.NewLiqoTunnelHealthCheck}},
	{Name: "konnectivity-tunnel-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameKonnectivityTunnelHealth, New: nethealth.NewKonnectivityTunnelHealthCheck}},
	{Name: "postgres-wal-archive-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: postgres.CheckNamePostgresWALArchiveGuard, New: postgres.NewPostgresWALArchiveGuardCheck}},
	{Name: "scylla-compaction-schema-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: scylla.CheckNameScyllaCompactionSchemaGuard, New: scylla.NewScyllaCompactionSchemaGuardCheck}},
	{Name: "nats-jetstream-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nats.CheckNameNatsJetstreamHealth, New: nats.NewNatsJetstreamHealthCheck}},
	{Name: "keda-scaledobject-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: gitops.CheckNameKedaScaledObjectGuard, New: gitops.NewKedaScaledObjectGuardCheck}},
	{Name: "gateway-route-health", Group: groupHealth, CheckReg: &shared.CheckReg{Name: gateway.CheckNameGatewayRouteHealth, New: gateway.NewGatewayRouteHealthCheck}},
	{Name: "controller-lease-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: leases.CheckNameControllerLeaseGuard, New: leases.NewControllerLeaseGuardCheck}},
	{Name: "pvc-resize-stall-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: pvc.CheckNamePVCResizeStallGuard, New: pvc.NewPVCResizeStallGuardCheck}},
	{Name: "endpointslice-zone-starvation", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameEndpointSliceZoneStarvation, New: nethealth.NewEndpointSliceZoneStarvationCheck}},
	{Name: "linkerd-outlier-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: linkerd.CheckNameLinkerdOutlierGuard, New: linkerd.NewLinkerdOutlierGuardCheck}},
	{Name: "node-condition-sweeper", Group: groupHealth, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameNodeCondSweeper, New: nodehealth.NewNodeConditionSweeperCheck}},
	{Name: "onepassword-connect-sync-probe", Group: groupHealth, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameOnePasswordConnectSync, New: watchdogs.NewOnePasswordConnectSyncCheck}},
	{Name: "linkerd-sidecar-oom-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: linkerd.CheckNameLinkerdSidecarOOMGuard, New: linkerd.NewLinkerdSidecarOOMGuardCheck}},
	{Name: "cilium-datapath-map-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: cilium.CheckNameCiliumDatapathMapGuard, New: cilium.NewCiliumDatapathMapGuardCheck}},
	{Name: "cilium-l2-lease-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: cilium.CheckNameCiliumL2LeaseGuard, New: cilium.NewCiliumL2LeaseGuardCheck}},
	{Name: "observability-pipeline-guard", Group: groupHealth, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameObservabilityPipelineGuard, New: watchdogs.NewObservabilityPipelineGuardCheck}},
	{Name: "apiserver-relist-storm-breaker", Group: groupHealth, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameAPIServerRelistStorm, New: watchdogs.NewAPIServerRelistStormCheck}},
	// The gated gitops check rows carry the section's only per-check
	// registration gates; they close out the roster — the sweep
	// order contract puts them after the always-on block.
	{Name: "flux-kustomization-health", Group: groupHealth, GateEnv: "NODE_AUTOMATION_FLUX_KUSTOMIZATION_HEALTH_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: gitops.CheckNameFluxKustomizationHealth, New: gitops.NewFluxKustomizationHealthCheck}},
	{Name: "workload-scale-flapping", Group: groupHealth, GateEnv: "NODE_AUTOMATION_WORKLOAD_SCALE_FLAPPING_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: gitops.CheckNameWorkloadScaleFlapping, New: gitops.NewWorkloadScaleFlappingCheck}},
	{Name: "imagepull-secret-auditor", Group: groupHealth, GateEnv: "NODE_AUTOMATION_IMAGEPULL_SECRET_AUDITOR_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: gitops.CheckNameImagePullSecretAuditor, New: gitops.NewImagePullSecretAuditorCheck}},
	{Name: "cluster-health-probes", Group: groupHealth, GateEnv: "CLUSTER_HEALTH_PROBES_ENABLED", DefaultOn: true, ConsumesCheckRegs: true, ProbeClients: true, Setup: clusterhealthprobes.Setup},
	// argocd-agent-spin — the argocd-agent reconnect hot-loop auto-healer closes
	// the roster after the gated block.
	{Name: "argocd-agent-spin", Group: groupHealth, CheckReg: &shared.CheckReg{Name: gitops.CheckNameArgoCDAgentSpin, New: gitops.NewArgoCDAgentSpinCheck}},
	// apiserver-node-reachability — the apiserver-dark node detector +
	// webhook-backend evacuee (2026-11-12 lanit-04 webhook EOF incident).
	{Name: "apiserver-node-reachability", Group: groupHealth, GateEnv: "NODE_AUTOMATION_APISERVER_NODE_REACHABILITY_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameApiserverNodeReachability, New: nethealth.NewApiserverNodeReachabilityCheck}},
	// apf-selfheal-shield — keeps the APF PriorityLevelConfiguration/
	// FlowSchema shield for self-heal traffic converged (appended per
	// the self-healing wave's roster order).
	{Name: "apf-selfheal-shield", Group: groupHealth, GateEnv: "NODE_AUTOMATION_APF_SHIELD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameAPFSelfHealShield, New: watchdogs.NewAPFSelfHealShieldCheck}},
	// The three L3 workload/drain unstickers — appended after the APF
	// row per the self-healing wave's roster order.
	{Name: "statefulset-rollout-unstick", Group: groupHealth, GateEnv: "NODE_AUTOMATION_STATEFULSET_ROLLOUT_UNSTICK_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameStatefulSetRolloutUnstick, New: watchdogs.NewStatefulSetRolloutUnstickCheck}},
	{Name: "daemonset-rollout-wedge", Group: groupHealth, GateEnv: "NODE_AUTOMATION_DAEMONSET_ROLLOUT_WEDGE_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameDaemonSetRolloutWedge, New: watchdogs.NewDaemonSetRolloutWedgeCheck}},
	{Name: "cronjob-forbid-zombie", Group: groupHealth, GateEnv: "NODE_AUTOMATION_CRONJOB_FORBID_ZOMBIE_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameCronJobForbidZombie, New: watchdogs.NewCronJobForbidZombieCheck}},
	// The six self-healing wave-2 checks — appended after the
	// existing roster per the plan; each carries its own
	// NODE_AUTOMATION_*_ENABLED registration gate.
	{Name: "apiserver-write-storm-breaker", Group: groupHealth, GateEnv: "NODE_AUTOMATION_WRITE_STORM_BREAKER_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameAPIServerWriteStorm, New: watchdogs.NewAPIServerWriteStormCheck}},
	{Name: "critical-daemonset-starvation", Group: groupHealth, GateEnv: "NODE_AUTOMATION_CRITICAL_DS_STARVATION_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameCriticalDSStarvation, New: watchdogs.NewCriticalDaemonSetStarvationCheck}},
	{Name: "coredns-forward-saturation", Group: groupHealth, GateEnv: "NODE_AUTOMATION_COREDNS_FORWARD_SATURATION_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameCoreDNSForwardSaturation, New: nethealth.NewCoreDNSForwardSaturationCheck}},
	{Name: "hpa-scaling-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_HPA_SCALING_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: gitops.CheckNameHPAScalingGuard, New: gitops.NewHPAScalingGuardCheck}},
	{Name: "deployment-rollout-wedge", Group: groupHealth, GateEnv: "NODE_AUTOMATION_DEPLOYMENT_ROLLOUT_WEDGE_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameDeploymentRolloutWedge, New: watchdogs.NewDeploymentRolloutWedgeCheck}},
	{Name: "subpath-config-drift", Group: groupHealth, GateEnv: "NODE_AUTOMATION_SUBPATH_CONFIG_DRIFT_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameSubPathConfigDrift, New: watchdogs.NewSubPathConfigDriftCheck}},
	// Self-healing wave-3 checks — appended at end of healthRows.
	{Name: "service-selector-blackhole", Group: groupHealth, GateEnv: "NODE_AUTOMATION_SERVICE_BLACKHOLE_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameServiceSelectorBlackhole, New: nethealth.NewServiceSelectorBlackholeCheck}},
	{Name: "topology-spread-zone-deadlock", Group: groupHealth, GateEnv: "NODE_AUTOMATION_TOPOLOGY_ZONE_DEADLOCK_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameTopologyZoneDeadlock, New: watchdogs.NewTopologySpreadZoneDeadlockCheck}},
	// Wave 4A checks — appended at end of healthRows.
	{Name: "admission-security-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_ADMISSION_SECURITY_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameAdmissionSecurityGuard, New: watchdogs.NewAdmissionSecurityGuardCheck}},
	// Wave 4B checks — appended at end of healthRows.
	{Name: "cilium-policy-bgp-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_CILIUM_POLICY_BGP_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: cilium.CheckNameCiliumPolicyBGPGuard, New: cilium.NewCiliumPolicyBGPGuardCheck}},
	{Name: "service-traffic-policy-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_SERVICE_TRAFFIC_POLICY_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameServiceTrafficPolicyGuard, New: nethealth.NewServiceTrafficPolicyGuardCheck}},
	{Name: "pvc-lifecycle-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_PVC_LIFECYCLE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: pvc.CheckNamePVCLifecycleGuard, New: pvc.NewPVCLifecycleGuardCheck}},
	{Name: "workload-admission-block-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_WORKLOAD_ADMISSION_BLOCK_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameWorkloadAdmissionBlockGuard, New: watchdogs.NewWorkloadAdmissionBlockGuardCheck}},
	// Wave 4C checks — appended at end of healthRows.
	{Name: "gitops-mass-prune-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_GITOPS_MASS_PRUNE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: gitops.CheckNameGitOpsMassPruneGuard, New: gitops.NewGitOpsMassPruneGuardCheck}},
	{Name: "image-resilience-auditor", Group: groupHealth, GateEnv: "NODE_AUTOMATION_IMAGE_RESILIENCE_AUDITOR_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameImageResilienceAuditor, New: nodehealth.NewImageResilienceAuditorCheck}},
	// Wave 5 checks — appended at end of healthRows.
	{Name: "volumesnapshot-lifecycle-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_VOLUMESNAPSHOT_LIFECYCLE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: pvc.CheckNameVolumeSnapshotLifecycleGuard, New: pvc.NewVolumeSnapshotLifecycleGuardCheck}},
	{Name: "dra-claim-wedge-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_DRA_CLAIM_WEDGE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameDRAClaimWedgeGuard, New: nodehealth.NewDRAClaimWedgeGuardCheck}},
	{Name: "pod-resize-wedge-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_POD_RESIZE_WEDGE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNamePodResizeWedgeGuard, New: watchdogs.NewPodResizeWedgeGuardCheck}},
	{Name: "ingress-nginx-retirement-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_INGRESS_NGINX_RETIREMENT_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameIngressNginxRetirementGuard, New: watchdogs.NewIngressNginxRetirementGuardCheck}},
	{Name: "workload-connection-skew-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_WORKLOAD_CONNECTION_SKEW_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: connectionskew.CheckNameWorkloadConnectionSkewGuard, New: connectionskew.NewWorkloadConnectionSkewGuardCheck}},
	// Wave 6 checks — appended at end of healthRows.
	{Name: "pvc-auto-expand", Group: groupHealth, GateEnv: "NODE_AUTOMATION_PVC_AUTO_EXPAND_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: pvc.CheckNamePVCAutoExpand, New: pvc.NewPVCAutoExpandCheck}},
	{Name: "oom-inplace-resize-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_OOM_INPLACE_RESIZE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameOOMInplaceResizeGuard, New: watchdogs.NewOOMInplaceResizeGuardCheck}},
	{Name: "netpol-egress-lockout-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_NETPOL_EGRESS_LOCKOUT_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameNetpolEgressLockoutGuard, New: nethealth.NewNetpolEgressLockoutGuardCheck}},
	{Name: "service-cidr-exhaustion-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_SERVICE_CIDR_EXHAUSTION_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameServiceCIDRExhaustionGuard, New: nethealth.NewServiceCIDRExhaustionGuardCheck}},
	{Name: "root-ca-drift-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_ROOT_CA_DRIFT_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameRootCADriftGuard, New: watchdogs.NewRootCADriftGuardCheck}},
	{Name: "kms-secret-canary-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_KMS_CANARY_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameKMSCanaryGuard, New: watchdogs.NewKMSCanaryGuardCheck}},
	{Name: "crd-stored-versions-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_CRD_STORED_VERSIONS_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameCRDStoredVersionsGuard, New: watchdogs.NewCRDStoredVersionsGuardCheck}},
	{Name: "autoscaler-quota-posture-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_AUTOSCALER_QUOTA_POSTURE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameAutoscalerQuotaPostureGuard, New: watchdogs.NewAutoscalerQuotaPostureGuardCheck}},
	{Name: "zone-gray-failure-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_ZONE_GRAY_FAILURE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameZoneGrayFailureGuard, New: nodehealth.NewZoneGrayFailureGuardCheck}},
	{Name: "init-container-wedge-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_INIT_CONTAINER_WEDGE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameInitContainerWedgeGuard, New: watchdogs.NewInitContainerWedgeGuardCheck}},
	// Wave 7 standalone checks — appended at end of healthRows.
	{Name: "readiness-gate-wedge-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_READINESS_GATE_WEDGE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameReadinessGateWedgeGuard, New: watchdogs.NewReadinessGateWedgeGuardCheck}},
	{Name: "scheduling-gate-wedge-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_SCHEDULING_GATE_WEDGE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameSchedulingGateWedgeGuard, New: watchdogs.NewSchedulingGateWedgeGuardCheck}},
	{Name: "workload-dangling-refs-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_WORKLOAD_DANGLING_REFS_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameWorkloadDanglingRefsGuard, New: watchdogs.NewWorkloadDanglingRefsGuardCheck}},
	{Name: "service-lb-lifecycle-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_SERVICE_LB_LIFECYCLE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nethealth.CheckNameServiceLBLifecycleGuard, New: nethealth.NewServiceLBLifecycleGuardCheck}},
	{Name: "apiserver-admission-token-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_APISERVER_ADMISSION_TOKEN_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameAPIServerAdmissionTokenGuard, New: watchdogs.NewAPIServerAdmissionTokenGuardCheck}},
	{Name: "k8s-upgrade-gang-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_K8S_UPGRADE_GANG_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: watchdogs.CheckNameK8sUpgradeGangGuard, New: watchdogs.NewK8sUpgradeGangGuardCheck}},
	{Name: "cluster-hygiene-guard", Group: groupHealth, GateEnv: "NODE_AUTOMATION_CLUSTER_HYGIENE_GUARD_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: nodehealth.CheckNameClusterHygieneGuard, New: nodehealth.NewClusterHygieneGuardCheck}},
}

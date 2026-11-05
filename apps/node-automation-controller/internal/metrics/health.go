// health.go — the kuberhealthy-compatible check gauges plus every
// series emitted by internal/health/clusterhealthprobes (the
// ported HealthChecks and the W5-W10 self-healing watchdogs). Var
// order and comments follow the original metrics.go layout.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

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

// KCMWorkqueueFrozen marks (1) a kube-controller-manager workqueue
// freeze: the leader Lease still renews but objects stop being
// reconciled (C6). reason identifies the stall signature.
var KCMWorkqueueFrozen = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_kcm_workqueue_frozen",
	Help: "1 while KCM renews its Lease but stops reconciling objects.",
}, []string{"reason"})

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

// init registers exactly the vectors declared in this file — the
// per-domain init() split means adding a health-domain metric
// touches only this file, not a central registry list. Order
// follows declaration order.
func init() {
	ctrlmetrics.Registry.MustRegister(
		healthCheckStatus, healthCheckSecondsSinceSuccess,
		KCMWorkqueueFrozen,
		OperatorWorkqueueFrozen, OperatorWorkqueueHealsTotal,
		StatefulServiceZeroEndpoints, RabbitMQSuspendedHealsTotal,
		DragonflyMasterlessPodHealsTotal,
		LocalPVStrandedPods, LocalPVEphemeralHealsTotal,
		PVCProvisioningStalled, PVCProvisionerHealsTotal,
		OLMUnhealthyResources, OLMOperatorHealsTotal,
		SchedulerFrozen, ControlPlanePodHealsTotal,
		NodeHangCordonsTotal, NodeHangUncordonsTotal,
		LinkerdEndpointDesync, ScyllaClusterUnhealthy)
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

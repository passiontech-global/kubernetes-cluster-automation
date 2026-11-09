// annos.go — the central registry of annotation/label/taint KEYS the
// controller reads or stamps. This file is the single place the
// values are spelled out; call sites adopt the consts.
//
// Two ownership classes matter:
//
//   - EXTERNAL contract keys (marked per const) are written or read
//     by tooling outside this controller — the fluent-bit config
//     hash annotations, the kured reboot keys. Their VALUES MUST
//     NEVER CHANGE: renaming one silently breaks the integration.
//   - Internal-owned keys — the whole passiontech.dev/* family —
//     answer only to this codebase. Renames are still
//     persistence-visible (a renamed stamp reads as "never stamped"
//     until re-written), but nothing off-cluster depends on them.
//
// Naming: AnnoXxx for annotations, LabelXxx for labels, TaintXxx for
// taint keys — the same domain literal is used as a taint key by the
// node-side modules (a taint named "Anno" would invite misuse).
package kube

// ---------------------------------------------------------------------------
// passiontech.dev/* — internal-owned annotations (the operator's own
// stamps). The last-* family are durable cooldown stamps read via
// AnnoTime; see annotools.go for the two accepted timestamp formats.
// ---------------------------------------------------------------------------
const (
	// AnnoLastHelmUnlock is helmrelease-unlocker's durable
	// pending-secret unlock stamp on the HelmRelease.
	AnnoLastHelmUnlock = "passiontech.dev/last-helm-unlock"
	// AnnoLastHelmStallUnwedge is helmrelease-unlocker's stall-unwedge
	// stamp (suspended-too-long unwedge cooldown).
	AnnoLastHelmStallUnwedge = "passiontech.dev/last-helm-stall-unwedge"
	// AnnoLastImmutableJobHeal is helmrelease-unlocker's
	// immutable-Job recreate stamp.
	AnnoLastImmutableJobHeal = "passiontech.dev/last-immutable-job-heal"
	// AnnoLastSourceNudge is helmrelease-unlocker's flux source
	// reconcile-nudge stamp.
	AnnoLastSourceNudge = "passiontech.dev/last-source-nudge"
	// AnnoLastESNudge is externalsecret-nudge's per-ES nudge stamp —
	// persisted alongside the legacy unix force-sync annotation.
	AnnoLastESNudge = "passiontech.dev/last-es-nudge"
	// AnnoLastOperatorHeal is the watchdogs' operator-leader-heal
	// stamp on the healed operator.
	AnnoLastOperatorHeal = "passiontech.dev/last-operator-heal"
	// AnnoLastDragonflyOperatorHeal / AnnoLastDragonflyPodHeal are
	// the datastore stateful-masterless check's two dragonfly heal
	// stamps (operator bounce vs direct pod bounce).
	AnnoLastDragonflyOperatorHeal = "passiontech.dev/last-dragonfly-operator-heal"
	AnnoLastDragonflyPodHeal      = "passiontech.dev/last-dragonfly-pod-heal"
	// AnnoACMEOrderResets is cert-manager-reaper's count of ACME
	// order resets stamped on the order.
	AnnoACMEOrderResets = "passiontech.dev/acme-order-resets"
	// AnnoStartingDeadlinePatched is cronjob-catchup's marker that a
	// CronJob's startingDeadlineSeconds was already patched once.
	AnnoStartingDeadlinePatched = "passiontech.dev/starting-deadline-patched"
	// AnnoEphemeralLocalPV marks a nodehealth-stranded pod as localPV
	// ephemeral — safe to reap with its node.
	AnnoEphemeralLocalPV = "passiontech.dev/ephemeral-localpv"
	// AnnoPreCordonedBy records which controller pre-cordoned a
	// hanging node (nodehealth node-hang path).
	AnnoPreCordonedBy = "passiontech.dev/precordoned-by"
	// AnnoAutoRollOnDelete opts a StatefulSet into
	// statefulset-roller's roll-on-delete.
	AnnoAutoRollOnDelete = "passiontech.dev/auto-roll-ondelete"
	// AnnoEvictOnPartition opts an individual POD (in any namespace)
	// into partition-evictor's partitioned-node eviction — pod-level
	// opt-in only: the sweep reads p.Annotations, never the
	// namespace's, so annotating the namespace object opts nothing in.
	AnnoEvictOnPartition = "passiontech.dev/evict-on-partition"
	// AnnoQuarantinedEndpoints is apiserver-endpoint-guard's record
	// of endpoints it removed from the apiserver Service.
	AnnoQuarantinedEndpoints = "passiontech.dev/quarantined-endpoints"
	// AnnoCircuitBrokenWebhooks is webhook-guard's open-circuit
	// record — the webhooks currently being skipped.
	AnnoCircuitBrokenWebhooks = "passiontech.dev/circuit-broken-webhooks"
	// AnnoLastCoreDNSRestart is coredns-watchdog's restart stamp.
	AnnoLastCoreDNSRestart = "passiontech.dev/last-coredns-restart"
	// AnnoCatchup is cronjob-catchup's annotation marker on a CronJob
	// it already caught up.
	AnnoCatchup = "passiontech.dev/catchup"
	// LabelMissedCatchup is cronjob-catchup's LABEL marking a Job it
	// spawned for a missed CronJob schedule.
	LabelMissedCatchup = "passiontech.dev/missed-catchup"
	// AnnoConcourseBaselineNodeFSGiB is concourse-janitor's recorded
	// baseline node filesystem size on the node.
	AnnoConcourseBaselineNodeFSGiB = "passiontech.dev/baseline-nodefs-gib"
	// AnnoWatchdogForceResync is cftunnel-proxy-watchdog's annotation
	// an operator sets to force a tunnel proxy resync.
	AnnoWatchdogForceResync = "passiontech.dev/force-resync"
	// AnnoStormGateHold / AnnoStormGateDecision are
	// descheduler-storm-gate's node annotations recording an active
	// hold and the last verdict — internal-owned.
	AnnoStormGateHold     = "passiontech.dev/storm-gate-hold"
	AnnoStormGateDecision = "passiontech.dev/storm-gate-decision"

	// AnnoFirstSeen* are the persisted first-seen window stamps —
	// the durable half of "signature must hold >= N before the
	// remediation fires" tracking (heal.FirstSeenPersisted). Each is
	// a JSON object {"<ledger-key>": "<rfc3339>", ...} stamped on the
	// object the signature is evaluated against, one anno per check
	// so concurrent modules never share a map (a lost update on a
	// shared key would corrupt a sibling check's window). The stamp
	// dies with the object — a bounced pod or deleted CR needs no
	// sweep-side cleanup; live-but-resolved objects are cleared by
	// heal.ClearPersistedFirstSeen on the healthy path.
	AnnoFirstSeenKSMWedge            = "passiontech.dev/first-seen-ksm-wedge"
	AnnoFirstSeenCPUStealClear       = "passiontech.dev/first-seen-cpu-steal-clear"
	AnnoFirstSeenKedaScaledObject    = "passiontech.dev/first-seen-keda-scaledobject"
	AnnoFirstSeenRabbitQuorum        = "passiontech.dev/first-seen-rabbitmq-quorum"
	AnnoFirstSeenRabbitSuspended     = "passiontech.dev/first-seen-rabbitmq-suspended"
	AnnoFirstSeenDragonflyLinkStorm  = "passiontech.dev/first-seen-dragonfly-linkstorm"
	AnnoFirstSeenOLMUnhealthy        = "passiontech.dev/first-seen-olm-unhealthy"
	AnnoFirstSeenStatefulMasterless  = "passiontech.dev/first-seen-stateful-masterless"
	AnnoFirstSeenOperatorWorkqueue   = "passiontech.dev/first-seen-operator-workqueue"
	AnnoFirstSeenLinkerdEndpointSync = "passiontech.dev/first-seen-linkerd-endpoint-sync"
	AnnoFirstSeenArgoCDAppStuck      = "passiontech.dev/first-seen-argocd-app-stuck"
	// AnnoFirstSeenStormGateHold is descheduler-storm-gate's persisted
	// first-seen stamp for a passiontech.dev/storm-gate-hold="true"
	// hold — the hold annotation carries no timestamp of its own, so
	// the maintenance-hold-stale MaintenanceHoldStale warning (>2h continuous hold)
	// measures from this map on the descheduler Deployment.
	AnnoFirstSeenStormGateHold = "passiontech.dev/first-seen-storm-gate-hold"
	// AnnoFirstSeenNHCPause is the same persisted first-seen window
	// for a NodeHealthCheck whose spec.pauseRequests has been
	// non-empty — the maintenance-hold-stale MaintenanceHoldStale warning rides this
	// map on the NHC object itself.
	AnnoFirstSeenNHCPause = "passiontech.dev/first-seen-nhc-pause"
	// AnnoLastLinkerdOpaquePatch is linkerd-protocol-detection-stall's
	// durable stamp on the owning Deployment/StatefulSet — a GitOps
	// (Flux/ArgoCD) managed workload whose pod template keeps losing
	// opaque-ports to force/selfHeal must not trigger a 30m
	// patch-vs-revert fight (6h cooldown).
	AnnoLastLinkerdOpaquePatch = "passiontech.dev/last-linkerd-opaque-patch"
	// AnnoLastLinkerdIssuerRollout is cert-drift-auditor's durable
	// linkerd-identity issuer-rotation rollout stamp — the persisted
	// half of the 30m re-roll cooldown (survives operator restarts).
	AnnoLastLinkerdIssuerRollout = "passiontech.dev/last-linkerd-issuer-rollout"
	// AnnoLastKargoRefresh is kargo-promotion-health's persisted
	// cooldown for its warehouse-refresh merge-patches.
	AnnoLastKargoRefresh = "passiontech.dev/last-kargo-refresh"
	// AnnoLastLinkerdEndpointSyncHeal is linkerd-endpoint-sync's
	// durable bounce stamp on the desynced Service — the persisted
	// half of the escalating per-service destination-bounce cooldown
	// (survives operator restarts).
	AnnoLastLinkerdEndpointSyncHeal = "passiontech.dev/last-linkerd-endpoint-sync-heal"
	// AnnoLastOLMOperatorHeal is olm-subscription-health's durable
	// stamp on the olm-operator Deployment — the persisted half of
	// the 1h operator-bounce cooldown (survives operator restarts).
	AnnoLastOLMOperatorHeal = "passiontech.dev/last-olm-operator-heal"
	// AnnoLastLocalPVProvisionerHeal is localpv-stranded-pods' durable
	// stamp on the openebs-localpv-provisioner Deployment — the
	// persisted half of the 1h provisioner-bounce cooldown.
	AnnoLastLocalPVProvisionerHeal = "passiontech.dev/last-localpv-provisioner-heal"
	// AnnoAllowEmptySecretKey opts an ExternalSecret out of the
	// externalsecret-nudge empty/whitespace-key audit (some Secrets
	// legitimately carry empty values).
	AnnoAllowEmptySecretKey = "passiontech.dev/allow-empty-secret-key"
	// AnnoRolledConfigHash is the EXTERNAL contract: fluentbit-roller
	// stamps it on the fluent-bit Secret so other tooling sees which
	// fluent.io/config-hash was last rolled out. Value must never
	// change.
	AnnoRolledConfigHash = "passiontech.dev/rolled-config-hash"
)

// ---------------------------------------------------------------------------
// passiontech.dev/* — internal-owned TAINT keys (node markers, not
// annotations; the storm-gate and webhook-guard both read these off
// Node objects).
// ---------------------------------------------------------------------------
const (
	// TaintKubeletUnresponsive is kubelet-reaper's mark on a node
	// whose kubelet stopped reporting.
	TaintKubeletUnresponsive = "passiontech.dev/kubelet-unresponsive"
	// TaintNetworkPartitioned is partition-evictor's mark on a
	// network-partitioned node.
	TaintNetworkPartitioned = "passiontech.dev/network-partitioned"
	// TaintCPUSteal is cpu-steal-taint-sync's mark on a worker under
	// sustained hypervisor steal pressure — PreferNoSchedule, drains
	// new placements only.
	TaintCPUSteal = "passiontech.dev/cpu-steal"
	// TaintNodeHangPreCordon is nodehealth's node-hang pre-cordon
	// mark — stamped while the deeper hang verdict is still being
	// confirmed so the scheduler stops packing new pods onto a node
	// that is about to be fenced.
	TaintNodeHangPreCordon = "passiontech.dev/node-hang-precordon"
)

// RemediationTaints is the canonical list of EVERY remediation
// taint this platform stamps — kubelet-reaper, partition-evictor,
// nodehealth (node-hang pre-cordon), and cpu-steal-taint-sync.
// Callers that must survive or reason about remediation nodes
// (storm gate census, Cilium L2 stale-holder checks, fencing
// decisions) iterate this single list so adding a new remediation
// taint touches one place — mirrors the 4-key REQUIRED_TAINTS
// list in passiontech-fluxcd scripts/check-taint-sync.sh, which is
// its own static gate across descheduler/node-ops/SNR manifests.
var RemediationTaints = []string{
	TaintKubeletUnresponsive, TaintNetworkPartitioned,
	TaintNodeHangPreCordon, TaintCPUSteal,
}

// ---------------------------------------------------------------------------
// EXTERNAL contracts — keys owned by tooling outside this controller.
// The values below must never change.
// ---------------------------------------------------------------------------
const (
	// AnnoFluentConfigHash is stamped BY fluent-bit's own tooling on
	// its config Secret; fluentbit-roller only reads it.
	AnnoFluentConfigHash = "fluent.io/config-hash"
	// TaintKuredNodeReboot is the taint kured places on a node it is
	// rebooting; metrics-server-patcher tolerates it.
	TaintKuredNodeReboot = "weave.works/kured-node-reboot"
	// AnnoFluxRequestedAt / AnnoFluxResetAt / AnnoFluxForceAt are
	// flux's reconcile-control annotations —
	// helmrelease-unlocker and flux-helmrelease-retries stamp them on
	// HelmReleases and source objects to nudge a reconcile
	// (resetAt/forceAt bump the counters flux checks so a retry it
	// would otherwise dedupe goes through).
	AnnoFluxRequestedAt = "reconcile.fluxcd.io/requestedAt"
	AnnoFluxResetAt     = "reconcile.fluxcd.io/resetAt"
	AnnoFluxForceAt     = "reconcile.fluxcd.io/forceAt"
	// AnnoKargoRefresh is kargo's own refresh-request annotation —
	// kargo-promotion-health stamps it on a Warehouse to nudge a
	// credential/artifact refresh. Value must never change.
	AnnoKargoRefresh = "kargo.akuity.io/refresh"
	// AnnoVolumeSelectedNode is the kube-scheduler's late-binding
	// marker on a PVC — the node the volume was selected for (the
	// openebs localpv provisioner provisions hostpath claims against
	// it). localpv-stranded-pods reads it as the "a node was picked
	// but the volume never landed" gate: a Pending hostpath claim
	// without it has no selected node, so it is not
	// stalled-provisioning evidence. Value must never change
	// (upstream key).
	AnnoVolumeSelectedNode = "volume.kubernetes.io/selected-node"
)

// The third external key — weave.works/kured-node-lock, the reboot
// drain coordination annotation kured holds on its DaemonSet —
// already lives in this package as KuredLockAnno (maintenance.go,
// the maintenance mutex) and is deliberately not redeclared here.

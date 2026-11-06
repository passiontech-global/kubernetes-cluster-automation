// annos.go — the central registry of annotation/label/taint KEYS the
// controller reads or stamps. Every key below was gathered verbatim
// from the modules; NONE are migrated here — this file is the single
// place the values are spelled out, and call sites adopt the consts
// in a follow-up wave.
//
// Two ownership classes matter:
//
//   - EXTERNAL contract keys (marked per const) are written or read
//     by tooling outside this controller — the fluent-bit config
//     hash annotations, the kured reboot keys. Their VALUES MUST
//     NEVER CHANGE: renaming one silently breaks the integration.
//   - Internal-owned keys — the whole node.ops/* family plus the
//     *.passiontech.dev domains — answer only to this codebase.
//     Renames are still persistence-visible (a renamed stamp reads
//     as "never stamped" until re-written), but nothing off-cluster
//     depends on them.
//
// Naming: AnnoXxx for annotations, LabelXxx for labels, TaintXxx for
// taint keys — the same domain literal is used as a taint key by the
// node-side modules (a taint named "Anno" would invite misuse).
package kube

// ---------------------------------------------------------------------------
// node.ops/* — internal-owned annotations (the operator's own stamps).
// The last-* family are durable cooldown stamps read via AnnoTime;
// see anno.go for the two accepted timestamp formats.
// ---------------------------------------------------------------------------
const (
	// AnnoLastHelmUnlock is helmrelease-unlocker's durable
	// pending-secret unlock stamp on the HelmRelease.
	AnnoLastHelmUnlock = "node.ops/last-helm-unlock"
	// AnnoLastHelmStallUnwedge is helmrelease-unlocker's stall-unwedge
	// stamp (suspended-too-long unwedge cooldown).
	AnnoLastHelmStallUnwedge = "node.ops/last-helm-stall-unwedge"
	// AnnoLastImmutableJobHeal is helmrelease-unlocker's
	// immutable-Job recreate stamp.
	AnnoLastImmutableJobHeal = "node.ops/last-immutable-job-heal"
	// AnnoLastSourceNudge is helmrelease-unlocker's flux source
	// reconcile-nudge stamp.
	AnnoLastSourceNudge = "node.ops/last-source-nudge"
	// AnnoLastESNudge is externalsecret-nudge's per-ES nudge stamp —
	// persisted alongside the legacy unix force-sync annotation.
	AnnoLastESNudge = "node.ops/last-es-nudge"
	// AnnoLastOperatorHeal is the watchdogs' operator-leader-heal
	// stamp on the healed operator.
	AnnoLastOperatorHeal = "node.ops/last-operator-heal"
	// AnnoLastDragonflyOperatorHeal / AnnoLastDragonflyPodHeal are
	// the datastore stateful-masterless check's two dragonfly heal
	// stamps (operator bounce vs direct pod bounce).
	AnnoLastDragonflyOperatorHeal = "node.ops/last-dragonfly-operator-heal"
	AnnoLastDragonflyPodHeal      = "node.ops/last-dragonfly-pod-heal"
	// AnnoACMEOrderResets is cert-manager-reaper's count of ACME
	// order resets stamped on the order.
	AnnoACMEOrderResets = "node.ops/acme-order-resets"
	// AnnoStartingDeadlinePatched is cronjob-catchup's marker that a
	// CronJob's startingDeadlineSeconds was already patched once.
	AnnoStartingDeadlinePatched = "node.ops/starting-deadline-patched"
	// AnnoEphemeralLocalPV marks a nodehealth-stranded pod as localPV
	// ephemeral — safe to reap with its node.
	AnnoEphemeralLocalPV = "node.ops/ephemeral-localpv"
	// AnnoPreCordonedBy records which controller pre-cordoned a
	// hanging node (nodehealth node-hang path).
	AnnoPreCordonedBy = "node.ops/precordoned-by"
	// AnnoAutoRollOnDelete opts a StatefulSet into
	// statefulset-roller's roll-on-delete.
	AnnoAutoRollOnDelete = "node.ops/auto-roll-ondelete"
	// AnnoEvictOnPartition opts a pod/namespace into
	// partition-evictor's partitioned-node eviction.
	AnnoEvictOnPartition = "node.ops/evict-on-partition"
	// AnnoQuarantinedEndpoints is apiserver-endpoint-guard's record
	// of endpoints it removed from the apiserver Service.
	AnnoQuarantinedEndpoints = "node.ops/quarantined-endpoints"
	// AnnoCircuitBrokenWebhooks is webhook-guard's open-circuit
	// record — the webhooks currently being skipped.
	AnnoCircuitBrokenWebhooks = "node.ops/circuit-broken-webhooks"
)

// ---------------------------------------------------------------------------
// node.ops/* — internal-owned TAINT keys (node markers, not
// annotations; the storm-gate and webhook-guard both read these off
// Node objects).
// ---------------------------------------------------------------------------
const (
	// TaintKubeletUnresponsive is kubelet-reaper's mark on a node
	// whose kubelet stopped reporting.
	TaintKubeletUnresponsive = "node.ops/kubelet-unresponsive"
	// TaintNetworkPartitioned is partition-evictor's mark on a
	// network-partitioned node.
	TaintNetworkPartitioned = "node.ops/network-partitioned"
)

// ---------------------------------------------------------------------------
// node-ops.passiontech.dev/* — the legacy internal domain (predates
// the node.ops short form); still internal-owned.
// ---------------------------------------------------------------------------
const (
	// AnnoLastCoreDNSRestart is coredns-watchdog's restart stamp.
	AnnoLastCoreDNSRestart = "node-ops.passiontech.dev/last-coredns-restart"
	// AnnoCatchup is cronjob-catchup's annotation marker on a CronJob
	// it already caught up.
	AnnoCatchup = "node-ops.passiontech.dev/catchup"
	// LabelMissedCatchup is cronjob-catchup's LABEL marking a Job it
	// spawned for a missed CronJob schedule.
	LabelMissedCatchup = "node-ops.passiontech.dev/missed-catchup"
)

// ---------------------------------------------------------------------------
// passiontech.dev/* — mixed ownership.
// ---------------------------------------------------------------------------
const (
	// AnnoStormGateHold / AnnoStormGateDecision are
	// descheduler-storm-gate's node annotations recording an active
	// hold and the last verdict — internal-owned.
	AnnoStormGateHold     = "passiontech.dev/storm-gate-hold"
	AnnoStormGateDecision = "passiontech.dev/storm-gate-decision"
	// AnnoRolledConfigHash is the EXTERNAL contract: fluentbit-roller
	// stamps it on the fluent-bit Secret so other tooling sees which
	// fluent.io/config-hash was last rolled out. Value must never
	// change.
	AnnoRolledConfigHash = "passiontech.dev/rolled-config-hash"
)

// ---------------------------------------------------------------------------
// *.passiontech.dev domain-specific — internal-owned.
// ---------------------------------------------------------------------------
const (
	// AnnoConcourseBaselineNodeFSGiB is concourse-janitor's recorded
	// baseline node filesystem size on the node.
	AnnoConcourseBaselineNodeFSGiB = "concourse.passiontech.dev/baseline-nodefs-gib"
	// AnnoWatchdogForceResync is cftunnel-proxy-watchdog's annotation
	// an operator sets to force a tunnel proxy resync.
	AnnoWatchdogForceResync = "watchdog.passiontech.dev/force-resync"
)

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
)

// The third external key — weave.works/kured-node-lock, the reboot
// drain coordination annotation kured holds on its DaemonSet —
// already lives in this package as KuredLockAnno (maintenance.go,
// the maintenance mutex) and is deliberately not redeclared here.

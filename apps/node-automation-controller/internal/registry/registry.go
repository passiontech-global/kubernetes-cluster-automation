// registry.go — the module registry: the single registration table
// for every node-ops module. The table is assembled from two
// explicitly-ordered slices — moduleRows here (the Setup-carrying
// modules: system patchers, node sweeps, apiserver guards, janitors,
// integration unstuckers) and healthRows in registry_health.go (the
// CheckReg health-sweep roster plus the sweep module itself).
// slices.Concat preserves the historical flat-table order exactly —
// the ops contract (slice order, Name/Group/GateEnv/DefaultOn
// values) is byte-identical to the registry that used to sit in
// cmd/manager/modules.go. The -modules allowlist machinery
// (ParseModulesFlag / FilterModules / ValidGroups) and the boot-time
// wiring loop (SetupModules) live in modules_flag.go. Lives in
// internal/ (not cmd/manager) so the table is importable by other
// packages and tests.
package registry

import (
	"slices"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/apiserverendpointguard"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/apiserviceguard"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/integration/certdriftauditor"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/integration/certmanagerreaper"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/integration/ciliumidentityauditor"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/integration/externalsecretnudge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/integration/helmreleaseunlocker"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/integration/velerobackupauditor"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/janitor/concoursejanitor"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/janitor/cronjobcatchup"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/janitor/evictedpodjanitor"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/janitor/failedjobsjanitor"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/janitor/orphanendpointslicecleaner"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/janitor/volumeattachmentcleaner"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/janitor/zombiesidecarreaper"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/node/ciliumtaintreaper"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/node/csrwatcher"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/node/deadnodesweeper"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/node/deschedulerstormgate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/node/kubeletreaper"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/node/nodelabeler"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/node/partitionevictor"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/node/pdbdeadlockwatchdog"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/cftunnelproxywatchdog"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/corednspatcher"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/corednswatchdog"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/fluentbitroller"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/konnectivitypatcher"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/metricsserverpatcher"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/statefulsetroller"
)

// Modules is the single registration point for every node-ops
// module — one shared.Module row each: the ops name, the
// REGISTRATION gate env (when the module has one) and either the
// uniform `Setup(d shared.Deps) error` entry point or, for
// health-sweep check rows, a CheckReg contributing a check to the
// cluster-health-probes roster. Registration gates live
// here and nowhere else: SetupModules evaluates GateEnv/DefaultOn
// and stamps Deps.Disabled, so the env var is named in exactly one
// place instead of being re-resolved inside each module's Setup.
// Modules still resolve their own knobs and SUB-feature gates from
// env inside Setup (the same flag ConfigMaps the shell-operator
// read — see the contract in cmd/manager/main.go's header comment),
// so adding a module is one import + one row here and nothing in
// main().
//
// GateEnv semantics match envx.Gate: DefaultOn=false is the opt-in
// convention (enabled only on "true"); DefaultOn=true opts out only
// on an explicit "false". An empty GateEnv means always-on. Gates
// that only alter run behavior while the module still registers —
// CSR_APPROVER_ENABLED approve mode, HELM_STALL_UNWEDGE_ENABLED,
// CILIUM_IDENTITY_GC_ENABLED, WEBHOOK_CIRCUIT_BREAKER_ENABLED,
// UNMESHED_POD_REMEDIATION_ENABLED —
// are NOT listed: the module keeps reading those itself.
//
// The slice (not a map) makes registration order deterministic — the
// concatenated sequence below is the boot order. No module may
// depend on it anyway: every module wires only its own runnables, so
// the stability is for log readability, not correctness.
//
// Name is the module's ops/queue name — it labels the run-error
// counters and appears in boot logs, so it must stay byte-stable
// for anyone grepping journalctl or querying Prometheus.
//
// Group is the module's blast-radius set — a `-modules @<group>`
// allowlist entry expands to the whole section. The group strings
// below are an ops contract like Name: they land in Deployment args
// and runbooks, so they must stay byte-stable, and re-grouping a
// module changes what a pinned @-entry selects.
//
// Modules is an exported package-level var, not a func accessor:
// the table IS the contract — a copied slice would give readers a
// snapshot they could mutate without boot noticing, and every
// consumer (main, tests, docs tooling) wants this exact ordering.
// Treat it as read-only; appending or reordering here changes the
// boot order and the -modules expansion surface.
const (
	groupSystem      = "system"      // kube-system component patchers and watchdogs
	groupNode        = "node"        // Node lifecycle and health sweeps
	groupAPIServer   = "apiserver"   // apiserver integrity guards
	groupJanitors    = "janitors"    // Resource cleanup sweeps
	groupIntegration = "integration" // Third-party controller unstuckers
	groupHealth      = "health"      // Cluster health probes
)

// Modules concatenates the two section tables — moduleRows first,
// then the health-sweep roster — so the flat sequence is identical
// to the historical single-literal table.
var Modules = slices.Concat(moduleRows, healthRows)

// moduleRows is the Setup-carrying half of the registry — every row
// wires runnables (reconcilers, periodics) via its module's Setup.
// The health-sweep CheckReg rows live in registry_health.go.
var moduleRows = []shared.Module{
	// kube-system component patchers and watchdogs.
	{Name: "konnectivity-patcher", Group: groupSystem, Setup: konnectivitypatcher.Setup},
	{Name: "fluent-bit-config-roller", Group: groupSystem, GateEnv: "FLUENTBIT_ROLLER_ENABLED", Setup: fluentbitroller.Setup},
	{Name: "coredns-stale-watchdog", Group: groupSystem, Setup: corednswatchdog.Setup},
	{Name: "coredns-patcher", Group: groupSystem, GateEnv: "COREDNS_PATCHER_ENABLED", DefaultOn: true, Setup: corednspatcher.Setup},
	{Name: "metrics-server-patcher", Group: groupSystem, GateEnv: "METRICS_SERVER_PATCHER_ENABLED", DefaultOn: true, Setup: metricsserverpatcher.Setup},
	{Name: "cf-tunnel-proxy-watchdog", Group: groupSystem, GateEnv: "CF_TUNNEL_WATCHDOG_ENABLED", DefaultOn: true, Setup: cftunnelproxywatchdog.Setup},
	{Name: "statefulset-ondelete-roller", Group: groupSystem, GateEnv: "STATEFULSET_ONDELETE_ROLLER_ENABLED", DefaultOn: true, Setup: statefulsetroller.Setup},

	// Node lifecycle and health sweeps.
	{Name: "cilium-taint-reaper", Group: groupNode, GateEnv: "CILIUM_TAINT_REAPER_ENABLED", Setup: ciliumtaintreaper.Setup},
	{Name: "descheduler-storm-gate", Group: groupNode, Setup: deschedulerstormgate.Setup},
	{Name: "node-labeler", Group: groupNode, Setup: nodelabeler.Setup},
	// The three latency-sensitive probes draw from their own client-go
	// rate limiter (ProbeClients → SetupModules hands ProbeCS/ProbeDyn
	// as CS/Dyn): a janitor delete burst draining the shared bucket
	// must not queue-delay the probes behind it.
	{Name: "kubelet-liveness-reaper", Group: groupNode, ProbeClients: true, Setup: kubeletreaper.Setup},
	{Name: "partition-pod-evictor", Group: groupNode, Setup: partitionevictor.Setup},
	{Name: "dead-node-sweeper", Group: groupNode, ProbeClients: true, Setup: deadnodesweeper.Setup},
	{Name: "csr-watcher", Group: groupNode, Setup: csrwatcher.Setup},
	{Name: "pdb-deadlock-watchdog", Group: groupNode, GateEnv: "PDB_WATCHDOG_ENABLED", DefaultOn: true, Setup: pdbdeadlockwatchdog.Setup},

	// apiserver integrity guards.
	{Name: "admission-webhook-guard", Group: groupAPIServer, Setup: webhookguard.Setup},
	{Name: "apiserver-endpoint-guard", Group: groupAPIServer, ProbeClients: true, Setup: apiserverendpointguard.Setup},
	{Name: "apiservice-guard", Group: groupAPIServer, GateEnv: "APISERVICE_GUARD_ENABLED", DefaultOn: true, Setup: apiserviceguard.Setup},

	// Resource cleanup sweeps.
	{Name: "failed-jobs-janitor", Group: groupJanitors, Setup: failedjobsjanitor.Setup},
	{Name: "evicted-pod-janitor", Group: groupJanitors, Setup: evictedpodjanitor.Setup},
	{Name: "cronjob-catchup", Group: groupJanitors, Setup: cronjobcatchup.Setup},
	{Name: "concourse-workdir-janitor", Group: groupJanitors, GateEnv: "CONCOURSE_JANITOR_ENABLED", Setup: concoursejanitor.Setup},
	{Name: "volumeattachment-cleaner", Group: groupJanitors, GateEnv: "VOLUMEATTACHMENT_CLEANER_ENABLED", DefaultOn: true, Setup: volumeattachmentcleaner.Setup},
	{Name: "zombie-sidecar-reaper", Group: groupJanitors, GateEnv: "ZOMBIE_SIDECAR_REAPER_ENABLED", DefaultOn: true, Setup: zombiesidecarreaper.Setup},
	{Name: "orphan-endpointslice-cleaner", Group: groupJanitors, GateEnv: "ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED", DefaultOn: true, Setup: orphanendpointslicecleaner.Setup},

	// Third-party controller unstuckers (dynamic client /
	// CRD types).
	{Name: "helmrelease-unlocker", Group: groupIntegration, Setup: helmreleaseunlocker.Setup},
	{Name: "externalsecret-nudge", Group: groupIntegration, GateEnv: "EXTERNALSECRET_NUDGE_ENABLED", Setup: externalsecretnudge.Setup},
	{Name: "certmanager-reaper", Group: groupIntegration, GateEnv: "CERTMANAGER_REAPER_ENABLED", Setup: certmanagerreaper.Setup},
	{Name: "cilium-identity-auditor", Group: groupIntegration, GateEnv: "CILIUM_IDENTITY_AUDITOR_ENABLED", Setup: ciliumidentityauditor.Setup},
	{Name: "cert-drift-auditor", Group: groupIntegration, GateEnv: "CERT_DRIFT_AUDITOR_ENABLED", DefaultOn: true, Setup: certdriftauditor.Setup},
	{Name: "velero-backup-auditor", Group: groupIntegration, GateEnv: "VELERO_BACKUP_AUDITOR_ENABLED", DefaultOn: true, Setup: velerobackupauditor.Setup},
}

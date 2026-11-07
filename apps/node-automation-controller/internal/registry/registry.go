// registry.go — the module registry: the single registration table
// for every node-ops module plus the -modules allowlist machinery
// (ParseModulesFlag / FilterModules / ValidGroups) and the boot-time
// wiring loop (SetupModules). Lives in internal/ (not cmd/manager)
// so the table is importable by other packages and tests — the ops
// contract (slice order, Name/Group/GateEnv/DefaultOn values) is
// byte-identical to the registry that used to sit in
// cmd/manager/modules.go.
package registry

import (
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/apiserverendpointguard"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/apiserviceguard"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/clusterhealthprobes"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops"
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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
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
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Modules is the single registration point for every node-ops
// module — one shared.Module row each: the ops name, the
// REGISTRATION gate env (when the module has one) and the uniform
// `Setup(d shared.Deps) error` entry point. Registration gates live
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
// sequence below is the boot order. No module may depend on it
// anyway: every module wires only its own runnables, so the
// stability is for log readability, not correctness.
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

var Modules = []shared.Module{
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
	{Name: "kubelet-liveness-reaper", Group: groupNode, Setup: kubeletreaper.Setup},
	{Name: "partition-pod-evictor", Group: groupNode, Setup: partitionevictor.Setup},
	{Name: "dead-node-sweeper", Group: groupNode, Setup: deadnodesweeper.Setup},
	{Name: "csr-watcher", Group: groupNode, Setup: csrwatcher.Setup},
	{Name: "pdb-deadlock-watchdog", Group: groupNode, GateEnv: "PDB_WATCHDOG_ENABLED", DefaultOn: true, Setup: pdbdeadlockwatchdog.Setup},

	// apiserver integrity guards.
	{Name: "admission-webhook-guard", Group: groupAPIServer, Setup: webhookguard.Setup},
	{Name: "apiserver-endpoint-guard", Group: groupAPIServer, Setup: apiserverendpointguard.Setup},
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

	// Cluster health probes.
	//
	// The W13 gitops check rows carry CheckReg instead of Setup:
	// they contribute a check into the cluster-health-probes roster
	// (SetupModules collects the enabled rows' registrations into
	// Deps.CheckRegs — see
	// internal/health/clusterhealthprobes/check_modules.go) rather
	// than registering runnables, so no ordering constraint exists
	// between these rows and the cluster-health-probes row. Each
	// check gates on its own NODE_AUTOMATION_*_ENABLED flag and is
	// selectable by name via -modules — but it still requires the
	// cluster-health-probes module to actually run the sweep.
	{Name: "flux-kustomization-health", Group: groupHealth, GateEnv: "NODE_AUTOMATION_FLUX_KUSTOMIZATION_HEALTH_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: gitops.CheckNameFluxKustomizationHealth, New: gitops.NewFluxKustomizationHealthCheck}},
	{Name: "workload-scale-flapping", Group: groupHealth, GateEnv: "NODE_AUTOMATION_WORKLOAD_SCALE_FLAPPING_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: gitops.CheckNameWorkloadScaleFlapping, New: gitops.NewWorkloadScaleFlappingCheck}},
	{Name: "imagepull-secret-auditor", Group: groupHealth, GateEnv: "NODE_AUTOMATION_IMAGEPULL_SECRET_AUDITOR_ENABLED", DefaultOn: true, CheckReg: &shared.CheckReg{Name: gitops.CheckNameImagePullSecretAuditor, New: gitops.NewImagePullSecretAuditorCheck}},
	{Name: "cluster-health-probes", Group: groupHealth, GateEnv: "CLUSTER_HEALTH_PROBES_ENABLED", DefaultOn: true, Setup: clusterhealthprobes.Setup},
}

// ParseModulesFlag splits the -modules flag value into entries —
// comma-separated, whitespace-tolerant, empty entries dropped so a
// trailing comma or an all-whitespace value behaves as "unset". An
// entry is either a module ops name or a "@<group>" group selector;
// which one is resolved by FilterModules, not here.
func ParseModulesFlag(s string) []string {
	var names []string
	for n := range strings.SplitSeq(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	return names
}

// FilterModules resolves the -modules allowlist against the
// registry. An empty names slice means "flag unset" and returns the
// full registry untouched. Otherwise entries are module ops names
// or "@<group>" selectors — an @-entry expands to every module
// whose Group matches (a module with an empty Group can never match
// one: "@x" is looked up against "@"+Group, so Group="" would need
// a bare "@" entry, and even that is guarded out). The result is
// exactly the selected modules in REGISTRY order (not argv order)
// with repeats collapsed, so boot order stays deterministic however
// the operator wrote the list. An unrecognized name OR @group is a
// boot error, not a skip — a typo'd allowlist silently running the
// wrong subset is worse than refusing to start — so the error names
// the offenders plus every valid name and every valid group.
func FilterModules(names []string) ([]shared.Module, error) {
	if len(names) == 0 {
		return Modules, nil
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	var out []shared.Module
	valid := make([]string, 0, len(Modules))
	// matched tracks which allowlist entries selected ≥1 module. `want`
	// cannot double for this — an @group must stay live for its WHOLE
	// section, so consuming it on first match would truncate the
	// expansion at the first member.
	matched := make(map[string]bool, len(names))
	for _, m := range Modules {
		valid = append(valid, m.Name)
		switch {
		case want[m.Name]:
			matched[m.Name] = true
		case m.Group != "" && want["@"+m.Group]:
			matched["@"+m.Group] = true
		default:
			continue
		}
		out = append(out, m)
	}
	if len(matched) < len(want) {
		// Report the offenders in the operator's argv order — the
		// entries that matched nothing.
		var bad []string
		seen := make(map[string]bool)
		for _, n := range names {
			if !matched[n] && !seen[n] {
				bad = append(bad, n)
				seen[n] = true
			}
		}
		return nil, fmt.Errorf("unknown module name(s) or @group(s) %s — valid names: %s — valid groups: %s",
			strings.Join(bad, ", "), strings.Join(valid, ", "),
			strings.Join(ValidGroups(), ", "))
	}
	return out, nil
}

// ValidGroups lists the registry's "@<group>" selectors in
// first-seen registry order — what an operator may write after "@"
// in -modules — for the unknown-entry error message. Deriving it
// from the registry (instead of hardcoding the constants) means a
// new group can never ship unstamped rows and a stale help list at
// the same time.
func ValidGroups() []string {
	seen := make(map[string]bool)
	var groups []string
	for _, m := range Modules {
		if m.Group != "" && !seen[m.Group] {
			seen[m.Group] = true
			groups = append(groups, "@"+m.Group)
		}
	}
	return groups
}

// SetupModules wires the allowlisted modules on the manager,
// registry order. The queue's error-metric series are predeclared
// for the FULL registry first — /metrics must expose the complete
// 0-valued fleet even on a Deployment where -modules (or a gate)
// runs only a subset, so a mid-flight flag change can never gap a
// series. Then `mods` goes through two passes:
//
//  1. Gate evaluation + CheckReg collection. Each row's GateEnv
//     (when set) is resolved ONCE here. Health-sweep check rows
//     (CheckReg instead of Setup) contribute their registration
//     into regs only while their own gate is ON — a gated-off or
//     unselected check row simply never reaches the roster, which
//     IS the per-check gate the rows exist for.
//  2. Runnable wiring, registry order. Every row's Deps gets the
//     collected regs stamped — only the cluster-health-probes sweep
//     reads them, and because collection finished before ANY Setup
//     ran, a check row may sit anywhere relative to it (the old
//     "check rows must precede cluster-health-probes" constraint is
//     gone). A module whose gate is off still has its Setup
//     invoked, but with Deps.Disabled stamped so it can parse its
//     knobs (warning on bad values) while registering nothing;
//     CheckReg rows carry Setup == nil and are skipped. A returned
//     error aborts boot: a module that fails to register is a
//     broken operator, not a degraded one.
func SetupModules(deps shared.Deps, mods []shared.Module) error {
	for _, m := range Modules {
		metrics.PredeclareQueue(m.Name)
	}
	var regs []shared.CheckReg
	gatedOff := make(map[string]bool, len(mods))
	for _, m := range mods {
		if m.GateEnv != "" && !envx.Gate(m.GateEnv, m.DefaultOn) {
			gatedOff[m.Name] = true
			continue
		}
		if m.CheckReg != nil {
			regs = append(regs, *m.CheckReg)
		}
	}
	for _, m := range mods {
		d := deps
		d.Name = m.Name
		d.CheckRegs = regs
		if gatedOff[m.Name] {
			d.Disabled = true
			d.Log.WithName(m.Name).Info("disabled — module not registered", "gate", m.GateEnv)
		}
		if m.Setup == nil {
			continue // CheckReg row — its check already went into regs
		}
		if err := m.Setup(d); err != nil {
			d.Log.WithName(m.Name).Error(err, "unable to setup module")
			return err
		}
	}
	return nil
}

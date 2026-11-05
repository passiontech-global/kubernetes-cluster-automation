package main

import (
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/apiserver/apiserverendpointguard"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/apiserver/apiserviceguard"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/apiserver/webhookguard"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/clusterhealthprobes"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/integration/certdriftauditor"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/integration/certmanagerreaper"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/integration/ciliumidentityauditor"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/integration/externalsecretnudge"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/integration/helmreleaseunlocker"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/integration/velerobackupauditor"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/janitor/concoursejanitor"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/janitor/cronjobcatchup"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/janitor/evictedpodjanitor"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/janitor/failedjobsjanitor"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/janitor/orphanendpointslicecleaner"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/janitor/volumeattachmentcleaner"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/janitor/zombiesidecarreaper"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/node/ciliumtaintreaper"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/node/csrwatcher"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/node/deadnodesweeper"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/node/deschedulerstormgate"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/node/kubeletreaper"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/node/nodelabeler"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/node/partitionevictor"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/node/pdbdeadlockwatchdog"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/cftunnelproxywatchdog"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/corednspatcher"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/corednswatchdog"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/fluentbitroller"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/konnectivitypatcher"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/metricsserverpatcher"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/statefulsetroller"
)

// modules is the single registration point for every node-ops module —
// one shared.Module row each: the ops name, the REGISTRATION gate env
// (when the module has one) and the uniform `Setup(d shared.Deps)
// error` entry point. Registration gates live here and nowhere else:
// setupModules evaluates GateEnv/DefaultOn and stamps Deps.Disabled,
// so the env var is named in exactly one place instead of being
// re-resolved inside each module's Setup. Modules still resolve their
// own knobs and SUB-feature gates from env inside Setup (the same
// flag ConfigMaps the shell-operator read — see the contract in
// main.go's header comment), so adding a module is one import + one
// row here and nothing in main().
//
// GateEnv semantics match shared.Gate: DefaultOn=false is the opt-in
// convention (enabled only on "true"); DefaultOn=true opts out only
// on an explicit "false". An empty GateEnv means always-on. Gates
// that only alter run behavior while the module still registers —
// CSR_APPROVER_ENABLED approve mode, HELM_STALL_UNWEDGE_ENABLED,
// EXTERNALSECRET_NUDGE_ENABLED, CILIUM_IDENTITY_GC_ENABLED,
// WEBHOOK_CIRCUIT_BREAKER_ENABLED, UNMESHED_POD_REMEDIATION_ENABLED —
// are NOT listed: the module keeps reading those itself.
//
// The slice (not a map) makes registration order deterministic — the
// sequence below is the boot order. No module may depend on it
// anyway: every module wires only its own runnables, so the stability
// is for log readability, not correctness.
//
// Name is the module's ops/queue name — it labels the run-error
// counters and appears in boot logs, so it must stay byte-stable for
// anyone grepping journalctl or querying Prometheus.
var modules = []shared.Module{
	// kube-system component patchers and watchdogs.
	{Name: "konnectivity-patcher", Setup: konnectivitypatcher.Setup},
	{Name: "fluent-bit-config-roller", GateEnv: "FLUENTBIT_ROLLER_ENABLED", Setup: fluentbitroller.Setup},
	{Name: "coredns-stale-watchdog", Setup: corednswatchdog.Setup},
	{Name: "coredns-patcher", GateEnv: "COREDNS_PATCHER_ENABLED", DefaultOn: true, Setup: corednspatcher.Setup},
	{Name: "metrics-server-patcher", GateEnv: "METRICS_SERVER_PATCHER_ENABLED", DefaultOn: true, Setup: metricsserverpatcher.Setup},
	{Name: "cf-tunnel-proxy-watchdog", GateEnv: "CF_TUNNEL_WATCHDOG_ENABLED", DefaultOn: true, Setup: cftunnelproxywatchdog.Setup},
	{Name: "statefulset-ondelete-roller", GateEnv: "STATEFULSET_ONDELETE_ROLLER_ENABLED", DefaultOn: true, Setup: statefulsetroller.Setup},

	// Node lifecycle and health sweeps.
	{Name: "cilium-taint-reaper", GateEnv: "CILIUM_TAINT_REAPER_ENABLED", Setup: ciliumtaintreaper.Setup},
	{Name: "descheduler-storm-gate", Setup: deschedulerstormgate.Setup},
	{Name: "node-labeler", Setup: nodelabeler.Setup},
	{Name: "kubelet-liveness-reaper", Setup: kubeletreaper.Setup},
	{Name: "partition-pod-evictor", Setup: partitionevictor.Setup},
	{Name: "dead-node-sweeper", Setup: deadnodesweeper.Setup},
	{Name: "csr-watcher", Setup: csrwatcher.Setup},
	{Name: "pdb-deadlock-watchdog", GateEnv: "PDB_WATCHDOG_ENABLED", DefaultOn: true, Setup: pdbdeadlockwatchdog.Setup},

	// apiserver integrity guards.
	{Name: "admission-webhook-guard", Setup: webhookguard.Setup},
	{Name: "apiserver-endpoint-guard", Setup: apiserverendpointguard.Setup},
	{Name: "apiservice-guard", GateEnv: "APISERVICE_GUARD_ENABLED", DefaultOn: true, Setup: apiserviceguard.Setup},

	// Resource cleanup sweeps.
	{Name: "failed-jobs-janitor", Setup: failedjobsjanitor.Setup},
	{Name: "evicted-pod-janitor", Setup: evictedpodjanitor.Setup},
	{Name: "cronjob-catchup", Setup: cronjobcatchup.Setup},
	{Name: "concourse-workdir-janitor", GateEnv: "CONCOURSE_JANITOR_ENABLED", Setup: concoursejanitor.Setup},
	{Name: "volumeattachment-cleaner", GateEnv: "VOLUMEATTACHMENT_CLEANER_ENABLED", DefaultOn: true, Setup: volumeattachmentcleaner.Setup},
	{Name: "zombie-sidecar-reaper", GateEnv: "ZOMBIE_SIDECAR_REAPER_ENABLED", DefaultOn: true, Setup: zombiesidecarreaper.Setup},
	{Name: "orphan-endpointslice-cleaner", GateEnv: "ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED", DefaultOn: true, Setup: orphanendpointslicecleaner.Setup},

	// Third-party controller unstuckers (dynamic client /
	// CRD types).
	{Name: "helmrelease-unlocker", Setup: helmreleaseunlocker.Setup},
	{Name: "externalsecret-nudge", Setup: externalsecretnudge.Setup},
	{Name: "certmanager-reaper", GateEnv: "CERTMANAGER_REAPER_ENABLED", Setup: certmanagerreaper.Setup},
	{Name: "cilium-identity-auditor", GateEnv: "CILIUM_IDENTITY_AUDITOR_ENABLED", Setup: ciliumidentityauditor.Setup},
	{Name: "cert-drift-auditor", GateEnv: "CERT_DRIFT_AUDITOR_ENABLED", DefaultOn: true, Setup: certdriftauditor.Setup},
	{Name: "velero-backup-auditor", GateEnv: "VELERO_BACKUP_AUDITOR_ENABLED", DefaultOn: true, Setup: velerobackupauditor.Setup},

	// Cluster health probes.
	{Name: "cluster-health-probes", GateEnv: "CLUSTER_HEALTH_PROBES_ENABLED", DefaultOn: true, Setup: clusterhealthprobes.Setup},
}

// parseModulesFlag splits the -modules flag value into names —
// comma-separated, whitespace-tolerant, empty entries dropped so a
// trailing comma or an all-whitespace value behaves as "unset".
func parseModulesFlag(s string) []string {
	var names []string
	for n := range strings.SplitSeq(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	return names
}

// filterModules resolves the -modules allowlist against the registry.
// An empty names slice means "flag unset" and returns the full
// registry untouched. Otherwise it returns exactly the named modules
// in REGISTRY order (not argv order), so boot order stays
// deterministic however the operator wrote the list. An unrecognized
// name is a boot error, not a skip — a typo'd allowlist silently
// running the wrong subset is worse than refusing to start — so the
// error names both the offenders and every valid name.
func filterModules(names []string) ([]shared.Module, error) {
	if len(names) == 0 {
		return modules, nil
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	var out []shared.Module
	valid := make([]string, 0, len(modules))
	for _, m := range modules {
		valid = append(valid, m.Name)
		if want[m.Name] {
			out = append(out, m)
			delete(want, m.Name) // matched — also dedupes repeat names
		}
	}
	if len(want) > 0 {
		// Report the offenders in the operator's argv order — what is
		// left in `want` is exactly the names that matched nothing.
		var bad []string
		for _, n := range names {
			if want[n] {
				bad = append(bad, n)
				delete(want, n)
			}
		}
		return nil, fmt.Errorf("unknown module name(s) %s — valid names: %s",
			strings.Join(bad, ", "), strings.Join(valid, ", "))
	}
	return out, nil
}

// setupModules wires the allowlisted modules on the manager, registry
// order. The two loops are deliberate: the queue's error-metric
// series are predeclared for the FULL registry — /metrics must
// expose the complete 0-valued fleet even on a Deployment where
// -modules (or a gate) runs only a subset, so a mid-flight flag
// change can never gap a series — while only `mods` get the gate
// check + Setup call. Each row's GateEnv (when set) is resolved ONCE
// here: a module whose gate is off still has its Setup invoked, but
// with Deps.Disabled stamped so it can parse its knobs (warning on
// bad values) while registering nothing. A returned error aborts
// boot: a module that fails to register is a broken operator, not a
// degraded one.
func setupModules(deps shared.Deps, mods []shared.Module) error {
	for _, m := range modules {
		metrics.PredeclareQueue(m.Name)
	}
	for _, m := range mods {
		d := deps
		if m.GateEnv != "" && !shared.Gate(m.GateEnv, m.DefaultOn) {
			d.Disabled = true
			d.Log.WithName(m.Name).Info("disabled — module not registered", "gate", m.GateEnv)
		}
		if err := m.Setup(d); err != nil {
			d.Log.WithName(m.Name).Error(err, "unable to setup module")
			return err
		}
	}
	return nil
}

package main

import (
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

// modules is the single registration point for every node-ops module.
// The map (not a slice) keeps registration order deliberately random —
// no module may rely on another being wired first. Every module has
// the uniform signature `Setup(d shared.Deps) error` and resolves its
// own feature gates/knobs from env inside Setup (the same flag
// ConfigMaps the shell-operator read — see the contract in
// main.go's header comment), so adding a module is one import + one
// map entry here and nothing in main().
//
// The map key is the module's ops name — it appears in boot logs and
// must stay stable for anyone grepping journalctl.
var modules = map[string]func(shared.Deps) error{
	// kube-system component patchers and watchdogs.
	"konnectivity-patcher":        konnectivitypatcher.Setup,
	"fluent-bit-config-roller":    fluentbitroller.Setup,
	"coredns-stale-watchdog":      corednswatchdog.Setup,
	"coredns-patcher":             corednspatcher.Setup,
	"metrics-server-patcher":      metricsserverpatcher.Setup,
	"cf-tunnel-proxy-watchdog":    cftunnelproxywatchdog.Setup,
	"statefulset-ondelete-roller": statefulsetroller.Setup,

	// Node lifecycle and health sweeps.
	"cilium-taint-reaper":     ciliumtaintreaper.Setup,
	"descheduler-storm-gate":  deschedulerstormgate.Setup,
	"node-labeler":            nodelabeler.Setup,
	"kubelet-liveness-reaper": kubeletreaper.Setup,
	"partition-pod-evictor":   partitionevictor.Setup,
	"dead-node-sweeper":       deadnodesweeper.Setup,
	"csr-watcher":             csrwatcher.Setup,
	"pdb-deadlock-watchdog":   pdbdeadlockwatchdog.Setup,

	// apiserver integrity guards.
	"admission-webhook-guard":  webhookguard.Setup,
	"apiserver-endpoint-guard": apiserverendpointguard.Setup,
	"apiservice-guard":         apiserviceguard.Setup,

	// Resource cleanup sweeps.
	"failed-jobs-janitor":          failedjobsjanitor.Setup,
	"evicted-pod-janitor":          evictedpodjanitor.Setup,
	"cronjob-catchup":              cronjobcatchup.Setup,
	"concourse-workdir-janitor":    concoursejanitor.Setup,
	"volumeattachment-cleaner":     volumeattachmentcleaner.Setup,
	"zombie-sidecar-reaper":        zombiesidecarreaper.Setup,
	"orphan-endpointslice-cleaner": orphanendpointslicecleaner.Setup,

	// Third-party controller unstuckers (dynamic client /
	// CRD types).
	"helmrelease-unlocker":    helmreleaseunlocker.Setup,
	"externalsecret-nudge":    externalsecretnudge.Setup,
	"certmanager-reaper":      certmanagerreaper.Setup,
	"cilium-identity-auditor": ciliumidentityauditor.Setup,
	"cert-drift-auditor":      certdriftauditor.Setup,
	"velero-backup-auditor":   velerobackupauditor.Setup,

	// Cluster health probes.
	"cluster-health-probes": clusterhealthprobes.Setup,
}

// setupModules wires every module on the manager. A module's Setup
// reads its own env gates — a disabled module logs and registers
// nothing (same contract as before). A returned error aborts boot:
// a module that fails to register is a broken operator, not a
// degraded one.
func setupModules(deps shared.Deps) error {
	log := deps.Log.WithName("main")
	for name, setup := range modules {
		if err := setup(deps); err != nil {
			log.Error(err, "unable to setup module", "module", name)
			return err
		}
	}
	return nil
}

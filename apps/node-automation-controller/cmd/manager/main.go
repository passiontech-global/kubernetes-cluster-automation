// node-automation-controller — Go operator (controller-runtime)
// replacing the shell-operator Deployment + 10 bash hooks in
// passiontech-fluxcd (infrastructure/base/node-ops/node-ops-operator).
//
// Interface contract kept 1:1 so the surrounding GitOps stack is
// untouched:
//   - Prometheus metrics on :9115/metrics (ServiceMonitor scrapes the
//     "metrics" containerPort).
//   - Health/readiness probes on :8081/healthz and :8081/readyz.
//   - Legacy counter shell_operator_hook_run_errors_total{queue} is
//     still emitted (see internal/metrics) so existing alerts fire.
//   - Feature gates via env (same flag ConfigMaps as before):
//     CILIUM_TAINT_REAPER_ENABLED, FLUENTBIT_ROLLER_ENABLED,
//     NODE_LABELER_CONFIG_PATH.
//   - The ported kubectl-CronJob modules are default-ON:
//     COREDNS_PATCHER_ENABLED / _ZONE_WHEN / _ZONE_MIN_DOMAINS,
//     METRICS_SERVER_PATCHER_ENABLED, CF_TUNNEL_WATCHDOG_ENABLED /
//     _NAMESPACE / _INTERVAL — an explicit "false" opts out.
//   - Proportional replica pinning (replaces the
//     cluster-proportional-autoscaler Deployments):
//     COREDNS_MIN_REPLICAS / COREDNS_NODES_PER_REPLICA (default 4/1),
//     METRICS_SERVER_MIN_REPLICAS / METRICS_SERVER_NODES_PER_REPLICA
//     (default 3/1). minReplicas<=0 disables the pin and leaves
//     .spec.replicas untouched so standalone CPA can be re-enabled.
//   - The ported kuberhealthy HealthChecks are default-ON too:
//     CLUSTER_HEALTH_PROBES_ENABLED / _INTERVAL plus the per-check
//     HEALTH_* knobs (see internal/clusterhealthprobes/cluster_health_probes.go).
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

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
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/cftunnelproxywatchdog"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/corednspatcher"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/corednswatchdog"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/fluentbitroller"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/konnectivitypatcher"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/metricsserverpatcher"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/system/statefulsetroller"
)

var version = "dev"

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// stripManagedFields is the shared managedFields stripper — a factory
// product built once, not re-allocated per transformed object.
var stripManagedFields = cache.TransformStripManagedFields()

// defaultCacheTransform trims informer memory: managedFields is a
// large chunk of every cached object and .Status.Images alone is
// 50-80% of a Node's size — no module reads either field. Wired as
// DefaultTransform (not a per-type ByObject.Transform) so it covers
// the default Node informer too: Node has no ByObject entry — the
// sweep controllers' watches create that informer from the Default*
// settings.
func defaultCacheTransform(obj interface{}) (interface{}, error) {
	if _, err := stripManagedFields(obj); err != nil {
		return nil, err
	}
	if n, ok := obj.(*corev1.Node); ok {
		n.Status.Images = nil
	}
	return obj, nil
}

func main() {
	var metricsAddr, probeAddr string
	var showVersion, leaderElect bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9115",
		"address the Prometheus metrics endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"address the health/readiness probe endpoints bind to")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&leaderElect, "leader-elect", false,
		"enable leader election via a coordination.k8s.io Lease — "+
			"required when running more than one replica")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if showVersion {
		fmt.Printf("node-automation-controller %s\n", version)
		os.Exit(0)
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("main")

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	cfg := ctrl.GetConfigOrDie()

	// Cache must mirror RBAC: several types are list/watch-locked to a
	// single object via resourceNames, so informers MUST carry the
	// matching field/label selector or the API returns Forbidden.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		// Active/passive HA (--leader-elect): every runnable is
		// lease-gated (plain Runnables default NeedLeaderElection()=true,
		// so `periodic` sweepers and all reconcilers only run on the
		// leader) while informers, metrics and probes stay warm on
		// standbys. ReleaseOnCancel hands the Lease over on graceful
		// shutdown — rolling-update failover ~2s vs the ~15s lease
		// timeout on crash.
		LeaderElection:                leaderElect,
		LeaderElectionID:              "node-automation-controller.node-ops",
		LeaderElectionReleaseOnCancel: true,
		Cache: cache.Options{
			DefaultTransform: defaultCacheTransform,
			ByObject: map[client.Object]cache.ByObject{
				// kube-system Role: daemonsets resourceNames
				// [konnectivity-agent].
				&appsv1.DaemonSet{}: {
					Namespaces: map[string]cache.Config{"kube-system": {}},
					Field: fields.SelectorFromSet(
						fields.Set{"metadata.name": "konnectivity-agent"}),
				},
				// kube-system Role: deployments get/list/watch (no
				// resourceNames — the informer must see BOTH coredns and
				// metrics-server; a single metadata.name field selector
				// cannot express that, so the name pinning lives in the
				// reconciler predicates instead).
				&appsv1.Deployment{}: {
					Namespaces: map[string]cache.Config{"kube-system": {}},
				},
				// ClusterRole: secrets resourceNames [passiontech-pipeline]
				// (all namespaces; lives in fluent-system).
				&corev1.Secret{}: {
					Field: fields.SelectorFromSet(
						fields.Set{"metadata.name": "passiontech-pipeline"}),
				},
				// cilium component Role: pods in kube-system — informer is
				// only started when CILIUM_TAINT_REAPER_ENABLED=true (see
				// Setup, which now returns nil before
				// registering when disabled), so clusters without the
				// component (and thus without pods watch RBAC) never open
				// this watch. No other module watches Pods.
				&corev1.Pod{}: {
					Namespaces: map[string]cache.Config{"kube-system": {}},
					Label:      labels.SelectorFromSet(labels.Set{"k8s-app": "cilium"}),
				},
			},
		},
	})
	if err != nil {
		log.Error(err, "unable to create manager")
		os.Exit(1)
	}

	// Direct (uncached) clientset — RBAC intentionally grants no watch
	// on most types (pods/services/jobs/webhookconfigs/...), so all
	// reads outside the informer types go through this.
	//
	// The endpoint-guard warning filter is attached BEFORE the
	// clientset is built: the guard writes the deprecated corev1
	// Endpoints object deliberately on hosted planes, and installing
	// the handler on the shared config lets
	// Setup reuse THIS clientset instead of
	// cloning cfg into a second one — which would duplicate the
	// http.Transport and its TLS connection pool just to silence one
	// warning header.
	cfg.WarningHandler = apiserverendpointguard.NewWarningHandler()
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "unable to create clientset")
		os.Exit(1)
	}
	// Dynamic client for CRD types (helmreleases, cert-manager,
	// externalsecrets, medik8s, cilium) — no typed clients in-tree.
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "unable to create dynamic client")
		os.Exit(1)
	}

	mc := moduleConfigFromEnv()

	if err := setupModules(mgr, cs, dyn, mc); err != nil {
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "unable to add healthz check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "unable to add readyz check")
		os.Exit(1)
	}

	log.Info("starting manager", "version", version,
		"leaderElection", leaderElect, "metricsAddr", metricsAddr,
		"probeAddr", probeAddr, "nodeLabelerConfig", mc.labelerPath,
		"ciliumTaintReaper", mc.ciliumEnabled, "fluentBitRoller", mc.fluentbitEnabled,
		"certManagerReaper", mc.certReaperEnabled, "ciliumAudit", mc.ciliumAuditEnabled,
		"externalSecretNudge", mc.esNudgeEnabled, "csrApprove", mc.csrApproveEnabled,
		"concourseJanitor", mc.concourseJanitorEnabled,
		"corednsPatcher", mc.corednsPatcherEnabled,
		"corednsZoneWhen", mc.corednsZoneWhen,
		"corednsZoneMinDomains", mc.corednsZoneMinDomains,
		"corednsMinReplicas", mc.corednsMinReplicas,
		"corednsNodesPerReplica", mc.corednsNodesPerReplica,
		"metricsServerPatcher", mc.metricsServerPatcherEnabled,
		"metricsServerMinReplicas", mc.metricsServerMinReplicas,
		"metricsServerNodesPerReplica", mc.metricsServerNodesPerReplica,
		"cfTunnelWatchdog", mc.cfTunnelWatchdogEnabled,
		"cfTunnelWatchdogNamespace", mc.cfTunnelWatchdogNamespace,
		"cfTunnelWatchdogInterval", mc.cfTunnelWatchdogInterval,
		"clusterHealthProbes", mc.clusterHealthProbesEnabled,
		"volumeAttachmentCleaner", mc.volumeAttachmentCleanerEnabled,
		"pdbWatchdog", mc.pdbWatchdogEnabled,
		"certDriftAuditor", mc.certDriftAuditorEnabled,
		"apiServiceGuard", mc.apiServiceGuardEnabled,
		"zombieSidecarReaper", mc.zombieSidecarReaperEnabled,
		"orphanEndpointSliceCleaner", mc.orphanEndpointSliceEnabled,
		"statefulSetOnDeleteRoller", mc.statefulSetRollerEnabled,
		"veleroBackupAuditor", mc.veleroBackupAuditorEnabled)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited")
		os.Exit(1)
	}
}

// moduleConfig holds the env-resolved feature gates and config paths
// the modules need — the same flags the shell-operator read from its
// ConfigMaps (see header contract).
type moduleConfig struct {
	ciliumEnabled                  bool
	fluentbitEnabled               bool
	certReaperEnabled              bool
	ciliumAuditEnabled             bool
	esNudgeEnabled                 bool
	csrApproveEnabled              bool
	labelerPath                    string
	concourseJanitorEnabled        bool
	corednsPatcherEnabled          bool
	corednsZoneWhen                string
	corednsZoneMinDomains          int
	corednsMinReplicas             int
	corednsNodesPerReplica         int
	metricsServerPatcherEnabled    bool
	metricsServerMinReplicas       int
	metricsServerNodesPerReplica   int
	cfTunnelWatchdogEnabled        bool
	cfTunnelWatchdogNamespace      string
	cfTunnelWatchdogInterval       time.Duration
	clusterHealthProbesEnabled     bool
	volumeAttachmentCleanerEnabled bool
	pdbWatchdogEnabled             bool
	certDriftAuditorEnabled        bool
	apiServiceGuardEnabled         bool
	zombieSidecarReaperEnabled     bool
	orphanEndpointSliceEnabled     bool
	statefulSetRollerEnabled       bool
	veleroBackupAuditorEnabled     bool
}

// moduleConfigFromEnv resolves every feature-gate env var once, after
// the clients exist and before any module is wired.
func moduleConfigFromEnv() moduleConfig {
	return moduleConfig{
		ciliumEnabled:           os.Getenv("CILIUM_TAINT_REAPER_ENABLED") == "true",
		fluentbitEnabled:        os.Getenv("FLUENTBIT_ROLLER_ENABLED") == "true",
		certReaperEnabled:       os.Getenv("CERTMANAGER_REAPER_ENABLED") == "true",
		ciliumAuditEnabled:      os.Getenv("CILIUM_IDENTITY_AUDITOR_ENABLED") == "true",
		esNudgeEnabled:          os.Getenv("EXTERNALSECRET_NUDGE_ENABLED") == "true",
		csrApproveEnabled:       os.Getenv("CSR_APPROVER_ENABLED") == "true",
		labelerPath:             getenv("NODE_LABELER_CONFIG_PATH", "/etc/node-labeler/labels.txt"),
		concourseJanitorEnabled: os.Getenv("CONCOURSE_JANITOR_ENABLED") == "true",
		// The three ported patcher/watchdog CronJobs were always-on
		// base components — default-ON here too (explicit "false"
		// opts a cluster out), unlike the opt-in gates above.
		corednsPatcherEnabled:        os.Getenv("COREDNS_PATCHER_ENABLED") != "false",
		corednsZoneWhen:              getenv("COREDNS_PATCHER_ZONE_WHEN", "DoNotSchedule"),
		corednsZoneMinDomains:        getenvInt("COREDNS_PATCHER_ZONE_MIN_DOMAINS", 2),
		corednsMinReplicas:           getenvInt("COREDNS_MIN_REPLICAS", 4),
		corednsNodesPerReplica:       getenvInt("COREDNS_NODES_PER_REPLICA", 1),
		metricsServerPatcherEnabled:  os.Getenv("METRICS_SERVER_PATCHER_ENABLED") != "false",
		metricsServerMinReplicas:     getenvInt("METRICS_SERVER_MIN_REPLICAS", 3),
		metricsServerNodesPerReplica: getenvInt("METRICS_SERVER_NODES_PER_REPLICA", 1),
		cfTunnelWatchdogEnabled:      os.Getenv("CF_TUNNEL_WATCHDOG_ENABLED") != "false",
		cfTunnelWatchdogNamespace: getenv("CF_TUNNEL_WATCHDOG_NAMESPACE",
			"cloudflare-tunnel-system"),
		cfTunnelWatchdogInterval: getenvDuration("CF_TUNNEL_WATCHDOG_INTERVAL",
			5*time.Minute),
		// The kuberhealthy checker Pods ran always-on — default-ON
		// here too; the HEALTH_* check knobs are read inside the
		// prober package (Setup).
		clusterHealthProbesEnabled: os.Getenv("CLUSTER_HEALTH_PROBES_ENABLED") != "false",
		// The self-healing / gray-failure defense modules default ON
		// like the ported CronJobs — an explicit "false" opts a
		// cluster out via the base-flags ConfigMap.
		volumeAttachmentCleanerEnabled: os.Getenv("VOLUMEATTACHMENT_CLEANER_ENABLED") != "false",
		pdbWatchdogEnabled:             os.Getenv("PDB_WATCHDOG_ENABLED") != "false",
		certDriftAuditorEnabled:        os.Getenv("CERT_DRIFT_AUDITOR_ENABLED") != "false",
		apiServiceGuardEnabled:         os.Getenv("APISERVICE_GUARD_ENABLED") != "false",
		zombieSidecarReaperEnabled:     os.Getenv("ZOMBIE_SIDECAR_REAPER_ENABLED") != "false",
		orphanEndpointSliceEnabled:     os.Getenv("ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED") != "false",
		statefulSetRollerEnabled:       os.Getenv("STATEFULSET_ONDELETE_ROLLER_ENABLED") != "false",
		veleroBackupAuditorEnabled:     os.Getenv("VELERO_BACKUP_AUDITOR_ENABLED") != "false",
	}
}

// setupModules registers every node-ops module on the manager. The map
// (not a slice) keeps registration order deliberately random — no
// module may rely on another being wired first.
func setupModules(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, mc moduleConfig) error {
	log := ctrl.Log.WithName("main")
	for name, setup := range map[string]func() error{
		// kube-system component patchers and watchdogs.
		"konnectivity-patcher":     func() error { return konnectivitypatcher.Setup(mgr, cs) },
		"fluent-bit-config-roller": func() error { return fluentbitroller.Setup(mgr, cs, mc.fluentbitEnabled) },
		"coredns-stale-watchdog":   func() error { return corednswatchdog.Setup(mgr, cs) },
		"coredns-patcher": func() error {
			return corednspatcher.Setup(mgr, cs,
				mc.corednsPatcherEnabled, mc.corednsZoneWhen, mc.corednsZoneMinDomains,
				mc.corednsMinReplicas, mc.corednsNodesPerReplica)
		},
		"metrics-server-patcher": func() error {
			return metricsserverpatcher.Setup(mgr, cs, mc.metricsServerPatcherEnabled,
				mc.metricsServerMinReplicas, mc.metricsServerNodesPerReplica)
		},
		"cf-tunnel-proxy-watchdog": func() error {
			return cftunnelproxywatchdog.Setup(mgr, cs,
				mc.cfTunnelWatchdogEnabled, mc.cfTunnelWatchdogNamespace,
				mc.cfTunnelWatchdogInterval)
		},
		"statefulset-ondelete-roller": func() error {
			return statefulsetroller.Setup(mgr, cs, mc.statefulSetRollerEnabled)
		},

		// Node lifecycle and health sweeps.
		"cilium-taint-reaper":     func() error { return ciliumtaintreaper.Setup(mgr, cs, mc.ciliumEnabled) },
		"descheduler-storm-gate":  func() error { return deschedulerstormgate.Setup(mgr, cs, dyn) },
		"node-labeler":            func() error { return nodelabeler.Setup(mgr, cs, mc.labelerPath) },
		"kubelet-liveness-reaper": func() error { return kubeletreaper.Setup(mgr, cs) },
		"partition-pod-evictor":   func() error { return partitionevictor.Setup(mgr, cs) },
		"dead-node-sweeper":       func() error { return deadnodesweeper.Setup(mgr, cs, dyn) },
		"csr-watcher":             func() error { return csrwatcher.Setup(mgr, cs, mc.csrApproveEnabled) },
		"pdb-deadlock-watchdog":   func() error { return pdbdeadlockwatchdog.Setup(mgr, cs, mc.pdbWatchdogEnabled) },

		// apiserver integrity guards.
		"admission-webhook-guard":  func() error { return webhookguard.Setup(mgr, cs) },
		"apiserver-endpoint-guard": func() error { return apiserverendpointguard.Setup(mgr, cs) },
		"apiservice-guard": func() error {
			return apiserviceguard.Setup(mgr, cs, dyn, mc.apiServiceGuardEnabled)
		},

		// Resource cleanup sweeps.
		"failed-jobs-janitor": func() error { return failedjobsjanitor.Setup(mgr, cs) },
		"evicted-pod-janitor": func() error { return evictedpodjanitor.Setup(mgr, cs) },
		"cronjob-catchup":     func() error { return cronjobcatchup.Setup(mgr, cs) },
		"concourse-workdir-janitor": func() error {
			return concoursejanitor.Setup(mgr, cs, dyn,
				mc.concourseJanitorEnabled)
		},
		"volumeattachment-cleaner": func() error {
			return volumeattachmentcleaner.Setup(mgr, cs, mc.volumeAttachmentCleanerEnabled)
		},
		"zombie-sidecar-reaper": func() error {
			return zombiesidecarreaper.Setup(mgr, cs, dyn, mc.zombieSidecarReaperEnabled)
		},
		"orphan-endpointslice-cleaner": func() error {
			return orphanendpointslicecleaner.Setup(mgr, cs, dyn, mc.orphanEndpointSliceEnabled)
		},

		// Third-party controller unstuckers (dynamic client /
		// CRD types).
		"helmrelease-unlocker":    func() error { return helmreleaseunlocker.Setup(mgr, cs, dyn) },
		"externalsecret-nudge":    func() error { return externalsecretnudge.Setup(mgr, cs, dyn, mc.esNudgeEnabled) },
		"certmanager-reaper":      func() error { return certmanagerreaper.Setup(mgr, cs, dyn, mc.certReaperEnabled) },
		"cilium-identity-auditor": func() error { return ciliumidentityauditor.Setup(mgr, cs, dyn, mc.ciliumAuditEnabled) },
		"cert-drift-auditor": func() error {
			return certdriftauditor.Setup(mgr, cs, dyn, mc.certDriftAuditorEnabled)
		},
		"velero-backup-auditor": func() error {
			return velerobackupauditor.Setup(mgr, cs, dyn, mc.veleroBackupAuditorEnabled)
		},

		// Cluster health probes.
		"cluster-health-probes": func() error {
			return clusterhealthprobes.Setup(mgr, cs,
				mc.clusterHealthProbesEnabled)
		},
	} {
		if err := setup(); err != nil {
			log.Error(err, "unable to setup module", "module", name)
			return err
		}
	}
	return nil
}

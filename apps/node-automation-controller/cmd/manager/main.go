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
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller"
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
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
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
			// node-ops Role: configmaps get/list/watch (converge
			// trigger watches every CM in this namespace).
			&corev1.ConfigMap{}: {
				Namespaces: map[string]cache.Config{"node-ops": {}},
			},
			// cilium component Role: pods in kube-system — informer is
			// only started when CILIUM_TAINT_REAPER_ENABLED=true (see
			// SetupCiliumTaintReaper), so clusters without the
			// component (and thus without pods watch RBAC) never open
			// this watch.
			&corev1.Pod{}: {
				Namespaces: map[string]cache.Config{"kube-system": {}},
				Label:      labels.SelectorFromSet(labels.Set{"k8s-app": "cilium"}),
			},
		}},
	})
	if err != nil {
		log.Error(err, "unable to create manager")
		os.Exit(1)
	}

	// Direct (uncached) clientset — RBAC intentionally grants no watch
	// on most types (pods/services/jobs/webhookconfigs/...), so all
	// reads outside the informer types go through this.
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

	if err := setupModules(mgr, cs, dyn, cfg, mc); err != nil {
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
		"ciliumTaintReaper", mc.ciliumEnabled, "fluentBitRoller", mc.fluentbitEnabled)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited")
		os.Exit(1)
	}
}

// moduleConfig holds the env-resolved feature gates and config paths
// the modules need — the same flags the shell-operator read from its
// ConfigMaps (see header contract).
type moduleConfig struct {
	ciliumEnabled               bool
	fluentbitEnabled            bool
	certReaperEnabled           bool
	ciliumAuditEnabled          bool
	esNudgeEnabled              bool
	csrApproveEnabled           bool
	labelerPath                 string
	concourseJanitorEnabled     bool
	concourseJanitorScript      string
	corednsPatcherEnabled       bool
	corednsZoneWhen             string
	corednsZoneMinDomains       int
	metricsServerPatcherEnabled bool
	cfTunnelWatchdogEnabled     bool
	cfTunnelWatchdogNamespace   string
	cfTunnelWatchdogInterval    time.Duration
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
		concourseJanitorScript: getenv("CONCOURSE_JANITOR_SCRIPT_PATH",
			"/etc/concourse-janitor/prune.sh"),
		// The three ported patcher/watchdog CronJobs were always-on
		// base components — default-ON here too (explicit "false"
		// opts a cluster out), unlike the opt-in gates above.
		corednsPatcherEnabled:       os.Getenv("COREDNS_PATCHER_ENABLED") != "false",
		corednsZoneWhen:             getenv("COREDNS_PATCHER_ZONE_WHEN", "DoNotSchedule"),
		corednsZoneMinDomains:       getenvInt("COREDNS_PATCHER_ZONE_MIN_DOMAINS", 2),
		metricsServerPatcherEnabled: os.Getenv("METRICS_SERVER_PATCHER_ENABLED") != "false",
		cfTunnelWatchdogEnabled:     os.Getenv("CF_TUNNEL_WATCHDOG_ENABLED") != "false",
		cfTunnelWatchdogNamespace: getenv("CF_TUNNEL_WATCHDOG_NAMESPACE",
			"cloudflare-tunnel-system"),
		cfTunnelWatchdogInterval: getenvDuration("CF_TUNNEL_WATCHDOG_INTERVAL",
			5*time.Minute),
	}
}

// setupModules registers every node-ops module on the manager. The map
// (not a slice) keeps registration order deliberately random — no
// module may rely on another being wired first.
func setupModules(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, cfg *rest.Config, mc moduleConfig) error {
	log := ctrl.Log.WithName("main")
	for name, setup := range map[string]func() error{
		"konnectivity-patcher":     func() error { return controller.SetupKonnectivityPatcher(mgr, cs) },
		"cilium-taint-reaper":      func() error { return controller.SetupCiliumTaintReaper(mgr, cs, mc.ciliumEnabled) },
		"descheduler-storm-gate":   func() error { return controller.SetupDeschedulerStormGate(mgr, cs) },
		"node-labeler":             func() error { return controller.SetupNodeLabeler(mgr, cs, mc.labelerPath) },
		"fluent-bit-config-roller": func() error { return controller.SetupFluentBitRoller(mgr, cs, mc.fluentbitEnabled) },
		"coredns-stale-watchdog":   func() error { return controller.SetupCoreDNSWatchdog(mgr, cs) },
		"kubelet-liveness-reaper":  func() error { return controller.SetupKubeletReaper(mgr, cs) },
		"admission-webhook-guard":  func() error { return controller.SetupWebhookGuard(mgr, cs) },
		"partition-pod-evictor":    func() error { return controller.SetupPartitionEvictor(mgr, cs) },
		"failed-jobs-janitor":      func() error { return controller.SetupFailedJobsJanitor(mgr, cs) },
		"converge-trigger":         func() error { return controller.SetupConvergeTrigger(mgr, cs) },
		"dead-node-sweeper":        func() error { return controller.SetupDeadNodeSweeper(mgr, cs, dyn) },
		"helmrelease-unlocker":     func() error { return controller.SetupHelmReleaseUnlocker(mgr, cs, dyn) },
		"externalsecret-nudge":     func() error { return controller.SetupExternalSecretNudge(mgr, cs, dyn, mc.esNudgeEnabled) },
		"evicted-pod-janitor":      func() error { return controller.SetupEvictedPodJanitor(mgr, cs) },
		"cronjob-catchup":          func() error { return controller.SetupCronJobCatchup(mgr, cs) },
		"certmanager-reaper":       func() error { return controller.SetupCertManagerReaper(mgr, cs, dyn, mc.certReaperEnabled) },
		"cilium-identity-auditor":  func() error { return controller.SetupCiliumIdentityAuditor(mgr, cs, dyn, mc.ciliumAuditEnabled) },
		"csr-watcher":              func() error { return controller.SetupCSRWatcher(mgr, cs, mc.csrApproveEnabled) },
		"apiserver-endpoint-guard": func() error { return controller.SetupAPIServerEndpointGuard(mgr, cs) },
		"concourse-workdir-janitor": func() error {
			return controller.SetupConcourseWorkdirJanitor(mgr, cs, cfg,
				mc.concourseJanitorEnabled, mc.concourseJanitorScript)
		},
		"coredns-patcher": func() error {
			return controller.SetupCoreDNSPatcher(mgr, cs,
				mc.corednsPatcherEnabled, mc.corednsZoneWhen, mc.corednsZoneMinDomains)
		},
		"metrics-server-patcher": func() error {
			return controller.SetupMetricsServerPatcher(mgr, cs, mc.metricsServerPatcherEnabled)
		},
		"cf-tunnel-proxy-watchdog": func() error {
			return controller.SetupCFTunnelProxyWatchdog(mgr, cs,
				mc.cfTunnelWatchdogEnabled, mc.cfTunnelWatchdogNamespace,
				mc.cfTunnelWatchdogInterval)
		},
	} {
		if err := setup(); err != nil {
			log.Error(err, "unable to setup module", "module", name)
			return err
		}
	}
	return nil
}

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
//     HEALTH_* knobs (see internal/clusterhealthprobes).
//   - `-modules name1,name2,@group` runs only the listed modules —
//     registry ops names from internal/registry, or a whole registry
//     section via an @-selector (@system, @node, @apiserver,
//     @janitors, @integration, @health); default: all — blast-radius
//     control for isolating a module or splitting auditors from
//     healers across Deployments.
//
// Registration gates (the *_ENABLED flags that decide whether a
// module wires anything at all) live in the shared.Module registry —
// see internal/registry; registry.SetupModules evaluates them and
// stamps Deps.Disabled. Modules still resolve their own knobs and
// sub-feature gates from env inside Setup — see
// internal/shared/env.go for the parsing helpers.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/apiserverendpointguard"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/registry"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

var version = "dev"

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

// buildCacheOptions assembles the informer cache shape. The cache
// must mirror RBAC: several types are list/watch-locked to a single
// object via resourceNames, so informers MUST carry the matching
// field/label selector or the API returns Forbidden.
func buildCacheOptions() cache.Options {
	return cache.Options{
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
			// only started when CILIUM_TAINT_REAPER_ENABLED=true (the
			// registry gate in internal/registry hands the module
			// Deps.Disabled, so it registers nothing when off), so
			// clusters without the component (and thus without pods
			// watch RBAC) never open this watch. No other module
			// watches Pods.
			&corev1.Pod{}: {
				Namespaces: map[string]cache.Config{"kube-system": {}},
				Label:      labels.SelectorFromSet(labels.Set{"k8s-app": "cilium"}),
			},
		},
	}
}

// buildMgrOptions assembles ctrl.Options from the parsed flag values.
// leaseDuration/renewDeadline/retryPeriod carry the flag values where
// 0 means "operator did not set it": the matching Options fields are
// *time.Duration and nil means "controller-runtime default", which is
// exactly what the zero flag value keeps.
func buildMgrOptions(scheme *runtime.Scheme, metricsAddr, probeAddr string,
	leaderElect bool, leaseDuration, renewDeadline, retryPeriod time.Duration) ctrl.Options {
	mgrOptions := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		// Active/passive HA (--leader-elect): every runnable is
		// lease-gated (plain Runnables default NeedLeaderElection()=true,
		// so `periodic` sweepers and all reconcilers only run on the
		// leader) while informers, metrics and probes stay warm on
		// standbys. ReleaseOnCancel hands the Lease over on graceful
		// shutdown — rolling-update failover ~2s vs up to LeaseDuration
		// on crash (15s default; deployments pass 180s).
		LeaderElection:                leaderElect,
		LeaderElectionID:              "node-automation-controller.node-ops",
		LeaderElectionReleaseOnCancel: true,
		Cache:                         buildCacheOptions(),
	}
	if leaseDuration > 0 {
		mgrOptions.LeaseDuration = &leaseDuration
	}
	if renewDeadline > 0 {
		mgrOptions.RenewDeadline = &renewDeadline
	}
	if retryPeriod > 0 {
		mgrOptions.RetryPeriod = &retryPeriod
	}
	return mgrOptions
}

func main() {
	var metricsAddr, probeAddr, modulesFilter string
	var showVersion, leaderElect bool
	var leaseDuration, renewDeadline, retryPeriod time.Duration
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9115",
		"address the Prometheus metrics endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"address the health/readiness probe endpoints bind to")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&leaderElect, "leader-elect", false,
		"enable leader election via a coordination.k8s.io Lease — "+
			"required when running more than one replica")
	// Lease timing knobs. 0 = unset: the matching *time.Duration field
	// in ctrl.Options stays nil and controller-runtime keeps its
	// compiled-in defaults (15s/10s/2s) — running without these flags
	// is byte-for-byte the old behavior. Deployments pass explicit
	// values via args (see node-automation-controller/deployment.yaml
	// in passiontech-fluxcd: 180s/120s/5s, sized for the multi-minute
	// Nebula dataplane blips of incident 2026-11-04 where the 10s
	// RenewDeadline was eaten by the 5s lease-client timeout →
	// "leader election lost" → fleet-wide manager restarts).
	// The required ordering LeaseDuration > RenewDeadline >
	// RetryPeriod*JitterFactor(1.2) is already enforced by client-go's
	// NewLeaderElector — an invalid combo fails mgr.Start → exit 1 →
	// visible CrashLoopBackOff, so no extra validation here.
	flag.DurationVar(&leaseDuration, "leader-elect-lease-duration", 0,
		"duration non-leader candidates wait before force-acquiring the "+
			"Lease; 0 keeps the controller-runtime default (15s)")
	flag.DurationVar(&renewDeadline, "leader-elect-renew-deadline", 0,
		"duration the leader retries renewing the Lease before giving "+
			"up; 0 keeps the controller-runtime default (10s)")
	flag.DurationVar(&retryPeriod, "leader-elect-retry-period", 0,
		"interval between Lease renew/acquire attempts; 0 keeps the "+
			"controller-runtime default (2s)")
	// Blast-radius allowlist: an empty value (the default) runs the
	// whole registry; otherwise only the named modules — or every
	// module in a named @group — wire their runnables. Metrics
	// predeclaration is NOT affected — every queue's series still
	// exists so /metrics shows the full fleet.
	flag.StringVar(&modulesFilter, "modules", "",
		"comma-separated module names or @groups to run (default: all); "+
			"names are the registry ops names from internal/registry "+
			"and @<group> expands to a whole section (e.g. @janitors)")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if showVersion {
		fmt.Printf("node-automation-controller %s\n", version)
		os.Exit(0)
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("main")

	// Resolve the -modules allowlist before touching the cluster: an
	// unknown name fails boot here (fail fast — a typo'd allowlist
	// silently running the wrong subset is worse than not starting).
	moduleNames := registry.ParseModulesFlag(modulesFilter)
	mods, err := registry.FilterModules(moduleNames)
	if err != nil {
		log.Error(err, "invalid -modules allowlist")
		os.Exit(1)
	}
	if len(moduleNames) > 0 {
		log.Info("modules allowlist active", "count", len(mods),
			"names", strings.Join(moduleNames, ","))
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	cfg := ctrl.GetConfigOrDie()

	mgr, err := ctrl.NewManager(cfg,
		buildMgrOptions(scheme, metricsAddr, probeAddr, leaderElect,
			leaseDuration, renewDeadline, retryPeriod))
	if err != nil {
		log.Error(err, "unable to create manager")
		os.Exit(1)
	}

	// Direct (uncached) clientset — RBAC intentionally grants no watch
	// on most types (pods/services/jobs/webhookconfigs/...), so all
	// reads outside the informer types go through this.
	//
	// The endpoint-guard warning filter is attached BEFORE the
	// clients are built: the guard writes the deprecated Endpoints
	// object deliberately on hosted planes, and installing the
	// handler on the shared config lets Setup reuse THIS dynamic
	// client instead of cloning cfg into a second one — which would
	// duplicate the http.Transport and its TLS connection pool just
	// to silence one warning header.
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

	deps := shared.Deps{Mgr: mgr, CS: cs, Dyn: dyn, Log: ctrl.Log}
	if err := registry.SetupModules(deps, mods); err != nil {
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
		"probeAddr", probeAddr,
		// 0s in this line means "controller-runtime default" — see the
		// flag comments above.
		"leaseDuration", leaseDuration, "renewDeadline", renewDeadline,
		"retryPeriod", retryPeriod)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited")
		os.Exit(1)
	}
}

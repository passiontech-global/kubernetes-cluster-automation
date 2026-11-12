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
//     healers across Deployments. Health-sweep check names are
//     registry names too: a check row contributes a check to the
//     cluster-health-probes roster rather than a runnable, so
//     "dns-status-internal,cluster-health-probes" sweeps just that
//     check while a check row selected alone wires nothing (and
//     cluster-health-probes selected alone sweeps an empty roster).
//
// Registration gates (the *_ENABLED flags that decide whether a
// module wires anything at all) live in the shared.Module registry —
// see internal/registry; registry.SetupModules evaluates them and
// stamps Deps.Disabled. Modules still resolve their own knobs and
// sub-feature gates from env inside Setup — see libs/hostkit/envx
// for the parsing helpers (the Getenv*/Gate strict family; its
// warnings are routed into the logr pipeline by internal/shared).
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/apiserverendpointguard"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/leaderelect"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/registry"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
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

// pprofHandlers returns the net/http/pprof endpoint table wired as
// ExtraHandlers on the metrics server — one mux, one port, no extra
// listener or Service change. "/debug/pprof/" (pprof.Index) dispatches
// the named profiles (heap, goroutine, block, mutex, allocs,
// threadcreate); cmdline/profile/symbol/trace need their dedicated
// handlers.
func pprofHandlers() map[string]http.Handler {
	return map[string]http.Handler{
		"/debug/pprof/":        http.HandlerFunc(pprof.Index),
		"/debug/pprof/cmdline": http.HandlerFunc(pprof.Cmdline),
		"/debug/pprof/profile": http.HandlerFunc(pprof.Profile),
		"/debug/pprof/symbol":  http.HandlerFunc(pprof.Symbol),
		"/debug/pprof/trace":   http.HandlerFunc(pprof.Trace),
	}
}

// resolveLeaderNamespace resolves the namespace the leader-election
// Lease lives in — read ONCE here (cmd/manager is the only place
// raw filesystem access is allowed) so controller-runtime's elector
// and the dead-leader Preemptor can never disagree about it: two
// different defaults would have the standby preempting a Lease in a
// namespace the leader never uses. The service-account namespace
// file is the pod's own namespace; the "node-ops" fallback matches
// the deployment's pinned namespace for out-of-cluster runs
// (envtest, local dev).
func resolveLeaderNamespace() string {
	const saNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	if b, err := os.ReadFile(saNamespaceFile); err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns
		}
	}
	return leaderelect.DefaultNamespace
}

// buildMgrOptions assembles ctrl.Options from the parsed flag values.
// leaseDuration/renewDeadline/retryPeriod carry the flag values where
// 0 means "operator did not set it": the matching Options fields are
// *time.Duration and nil means "controller-runtime default", which is
// exactly what the zero flag value keeps. leaderNS is the resolved
// election namespace — passed explicitly so it can never drift from
// the Preemptor's view of the same Lease.
func buildMgrOptions(scheme *runtime.Scheme, metricsAddr, probeAddr string,
	leaderElect bool, leaseDuration, renewDeadline, retryPeriod time.Duration,
	leaderNS string, leaderLock resourcelock.Interface) ctrl.Options {
	mgrOptions := ctrl.Options{
		Scheme: scheme,
		// pprof rides the metrics listener (:9115 — ClusterIP/headless
		// Service, no ingress): heap/goroutine/block profiles are the
		// memory-triage evidence for the leader working-set plateau
		// that OOMKilled the pod at the 256Mi limit (2026-11-09).
		// Same convention as kubelet/kube-scheduler, which ship pprof
		// on their debug endpoints by default.
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			ExtraHandlers: pprofHandlers(),
		},
		HealthProbeBindAddress: probeAddr,
		// Active/passive HA (--leader-elect): every runnable is
		// lease-gated (plain Runnables default NeedLeaderElection()=true,
		// so `periodic` sweepers and all reconcilers only run on the
		// leader) while informers, metrics and probes stay warm on
		// standbys. ReleaseOnCancel hands the Lease over on graceful
		// shutdown — rolling-update failover ~2s vs up to LeaseDuration
		// on crash (15s default; deployments pass 180s).
		LeaderElection:          leaderElect,
		LeaderElectionNamespace: leaderNS,
		// Lease name follows the upstream election-id convention
		// (<name>.<domain> — cf. e1f13584.medik8s.io); domain is the
		// same passiontech.dev registry the annotations use.
		LeaderElectionID:              leaderElectionID,
		LeaderElectionReleaseOnCancel: true,
		// Custom lock: releaseGuardedLock refuses a release write
		// when the Lease's holder is already another replica —
		// without it a demoted leader's deferred tryRelease wipes
		// the NEW leader's record after the LeaseLossWatchdog
		// preemption (see leaderelection.go).
		LeaderElectionResourceLockInterface: leaderLock,
		Cache:                               buildCacheOptions(),
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

// leasePreemptRunnable adapts leaderelect.Preemptor to a
// controller-runtime Runnable that must run on standbys too —
// NeedLeaderElection()=false is the whole point: the replica that
// is NOT the leader is exactly the one that must shorten the Lease
// when the leader's node dies (selfheal-alert-coverage fast dead-leader preemption).
type leasePreemptRunnable struct {
	preemptor *leaderelect.Preemptor
	log       logr.Logger
}

// NeedLeaderElection returns false deliberately — see the type
// comment: a lease-gated sweep could never run on the standby that
// needs to act.
func (r *leasePreemptRunnable) NeedLeaderElection() bool { return false }

func (r *leasePreemptRunnable) Start(ctx context.Context) error {
	// Startup jitter: every standby replica wires this runnable at
	// boot — without a staggered first pass all of them GET the
	// Lease (and prime their frozen-window clocks) in lockstep.
	// A random delay inside one sweep interval de-synchronizes the
	// first observation; the ticker cadence is unchanged after.
	jitter := time.Duration(rand.Int64N(int64(leaderelect.SweepInterval)))
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(jitter):
	}
	ticker := time.NewTicker(leaderelect.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reason, err := r.preemptor.Sweep(ctx)
			switch {
			case err != nil:
				r.log.Error(err, "leader lease preempt sweep failed")
			case reason != "":
				metrics.LeaderLeasePreemptionsTotal.
					WithLabelValues(reason).Inc()
				r.log.Info("leader lease preempted — holder proved dead",
					"reason", reason)
			}
		}
	}
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
			"(health-sweep check names count as module names — a check "+
			"row still needs cluster-health-probes to run) and "+
			"@<group> expands to a whole section (e.g. @janitors)")
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
	if err := tuneClientConfig(cfg); err != nil {
		log.Error(err, "unable to tune kube client config")
		os.Exit(1)
	}

	// The endpoint-guard warning filter is installed BEFORE anything
	// is built from this config — ctrl.NewManager first, then the
	// clients: the manager derives its own cached client and REST
	// mapper's transports from cfg when it is constructed, and
	// buildKubeClients clones the same config for the direct clients.
	// A handler assigned only after NewManager returns would reach
	// buildKubeClients but not the manager's captured copy of the
	// config, so the guard's Endpoints write on hosted planes could
	// still surface as a manager-side warning. Installing it here also
	// lets Setup reuse THIS dynamic client instead of cloning cfg into
	// a second one — which would duplicate the http.Transport and its
	// TLS connection pool just to silence one warning header.
	cfg.WarningHandler = apiserverendpointguard.NewWarningHandler()

	// leaseStolen is the LeaseLossWatchdog's flag, shared with the
	// releaseGuardedLock: once the watchdog proves a foreign holder it
	// sets the flag BEFORE cancelling the work context, so the old
	// leader's deferred tryRelease (LeaderElectionReleaseOnCancel)
	// is refused instead of wiping the new leader's Lease record.
	var leaseStolen atomic.Bool
	leaderNS := resolveLeaderNamespace()
	// The guarded resource lock is built only when election is on —
	// ctrl.Options ignores the interface otherwise, and building it
	// unconditionally would spend three client constructions on a
	// binary that never campaigns.
	var leaderLock resourcelock.Interface
	if leaderElect {
		var err error
		leaderLock, err = buildLeaderLock(cfg, scheme, leaderNS,
			renewDeadline, &leaseStolen)
		if err != nil {
			log.Error(err, "unable to build leader election lock")
			os.Exit(1)
		}
	}
	mgr, err := ctrl.NewManager(cfg,
		buildMgrOptions(scheme, metricsAddr, probeAddr, leaderElect,
			leaseDuration, renewDeadline, retryPeriod, leaderNS, leaderLock))
	if err != nil {
		log.Error(err, "unable to create manager")
		os.Exit(1)
	}

	clients, err := buildKubeClients(cfg)
	if err != nil {
		log.Error(err, "unable to create kube clients")
		os.Exit(1)
	}
	cs, dyn, meta := clients.cs, clients.dyn, clients.meta
	probeCS, probeDyn := clients.probeCS, clients.probeDyn

	// The global heal budget — the aggregate blast-radius cap every
	// heal-gated module shares (platform/heal consults it inside
	// AllowedV, so the per-target cooldowns keep working and only
	// the fleet-wide rate is throttled). NODE_AUTOMATION_HEAL_
	// BUDGET_MAX=0 disables the gate; the exhaustion counter is
	// wired through the package's hook because platform cannot
	// import internal/metrics (depguard leaf rule).
	heal.ConfigureBudget(
		envx.GetenvInt("NODE_AUTOMATION_HEAL_BUDGET_MAX", 10),
		envx.GetenvDuration("NODE_AUTOMATION_HEAL_BUDGET_WINDOW", 5*time.Minute))
	heal.SetBudgetExhaustedHook(metrics.HealBudgetExhaustedTotal.Inc)

	// The SSA ping-pong defense — a heal re-patching the same object
	// past the loop threshold inside the window while a Flux GitOps
	// manager owns fields on it skips the write and reports instead
	// of fighting the drift (platform/heal consults the gate at the
	// desired-state patch sites). NODE_AUTOMATION_HEAL_FLUX_CONFLICT_
	// LOOP_MAX=0 disables the gate; conflicts count on
	// node_automation_heal_gitops_conflict_total (alert
	// GitOpsAutoHealConflict) — fix the drift in Git, not in the
	// live object.
	heal.ConfigureFluxConflictLoop(
		envx.GetenvInt("NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX", 3),
		envx.GetenvDuration("NODE_AUTOMATION_HEAL_FLUX_CONFLICT_WINDOW", 30*time.Minute))
	heal.SetFluxConflictHook(func(sig heal.FluxConflictSignal) {
		metrics.HealGitOpsConflictTotal.WithLabelValues(sig.Manager).Inc()
		ctrl.Log.WithName("heal").Info("GitOpsAutoHealConflict: heal patch skipped — "+
			"Flux Heal-Revert Loop (fix the drift in Git)",
			"kind", sig.Kind, "namespace", sig.Namespace,
			"name", sig.Name, "manager", sig.Manager, "key", sig.Key)
	})

	// The per-target non-convergent circuit breaker — the other half
	// of the budget above: one (module,node) remediated 3 times
	// inside 3h without the target converging defers further
	// remediation until the window expires or the target reports
	// healthy (RecordTargetHealthy from each module's recovery path).
	shared.WireTargetBreaker(cs)

	deps := shared.Deps{Mgr: mgr, CS: cs, Dyn: dyn, Meta: meta,
		ProbeCS: probeCS, ProbeDyn: probeDyn, Log: ctrl.Log}
	if err := registry.SetupModules(deps, mods); err != nil {
		os.Exit(1)
	}

	// workCtx wraps the signal context so the LeaseLossWatchdog can
	// stop the entire manager on a proven foreign lease holder —
	// cancelling propagates to every runnable group (leader-gated
	// modules included) and the deferred leader-election release
	// runs under releaseGuardedLock, which leaseStolen has already
	// armed against clobbering the new holder's record.
	workCtx, workCancel := context.WithCancel(ctrl.SetupSignalHandler())
	defer workCancel()

	// selfheal-alert-coverage fast dead-leader lease preemption: without it a leader
	// whose node dies holds the 180s LeaseDuration while every heal
	// module on the standby idles. The sweep runs on every replica
	// and shortens the Lease to 1s only when the holder is provably
	// dead — gated on -leader-elect because without election there
	// is no Lease object to preempt.
	if leaderElect {
		if err := mgr.Add(&leasePreemptRunnable{
			// probeCS, not cs: the preemptor's Lease/pod/node reads
			// are exactly the watch-cache-served snapshots the probe
			// clientset exists for — a dead-holder proof must not
			// queue behind the shared client's heavier reads.
			preemptor: &leaderelect.Preemptor{CS: probeCS, Namespace: leaderNS},
			log:       ctrl.Log.WithName("leader-lease-preemptor"),
		}); err != nil {
			log.Error(err, "unable to add leader lease preemptor")
			os.Exit(1)
		}
		// LeaseLossWatchdog: the leader-side half of the same
		// contract — poll the Lease every 5s and, on a foreign
		// holder, cancel the work context below so all leader-gated
		// modules stop inside one poll interval instead of riding
		// out the Active-Active Split-Brain window.
		if err := mgr.Add(&leaseLossWatchdog{
			cs:        probeCS,
			namespace: leaderNS,
			selfID:    leaderLock.Identity(),
			stolen:    &leaseStolen,
			cancel:    workCancel,
			log:       ctrl.Log.WithName("lease-loss-watchdog"),
		}); err != nil {
			log.Error(err, "unable to add lease loss watchdog")
			os.Exit(1)
		}
	}

	// cluster-maintenance-stamper: the dedicated L1↔L3 write half —
	// the ONLY writer of passiontech.dev/cluster-maintenance-until
	// (Verdict.Active is read-only): stamps it on every node under
	// cluster upgrade, or only the target node under node-level
	// maintenance, and removes controller-owned stamps once
	// maintenance ends. First pass on Start, then every 30s. Plain
	// Runnable ⇒ leader-gated when election is on, always-on in
	// single-replica mode.
	if err := mgr.Add(&maintenanceStamperRunnable{
		cs: cs, dyn: dyn,
		log: ctrl.Log.WithName("cluster-maintenance-stamper"),
	}); err != nil {
		log.Error(err, "unable to add cluster maintenance stamper")
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
	if err := mgr.Start(workCtx); err != nil {
		log.Error(err, "manager exited")
		os.Exit(1)
	}
}

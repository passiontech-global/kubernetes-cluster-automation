// coredns_patcher.go — port of the coredns-topology-spread CronJob
// (infrastructure/base/scaling/coredns/coredns-topology-spread.yaml in
// passiontech-fluxcd, plus the cicd override single-zone-topology-patch.yaml).
//
// Keeps deployment kube-system/coredns at the pinned probe timeouts
// (incl. livenessProbe.failureThreshold=5), rollingUpdate
// maxUnavailable=1, resources and topologySpreadConstraints. The
// Deployment is owned by
// the k0s stack applier, which reverts it on every apply — its stock
// manifest carries a required hostname podAntiAffinity (max 1 pod
// kube-dns per node) so a surge pod can never schedule, and the 1s
// default probe timeouts mass-kill pods under node load.
//
// Spread policy (config-driven, was ZONE_WHEN/ZONE_MIN_DOMAINS):
// zone = DoNotSchedule + minDomains=2 on multi-zone clusters —
// guarantees >=1 DNS backend per zone so service topology keeps
// resolving locally during an inter-DC degrade; cicd (single zone)
// runs ScheduleAnyway with no minDomains — DoNotSchedule on a
// 1-domain cluster would wedge the rollout forever. hostname =
// ScheduleAnyway: ~1 pod/node steady state, surge still schedules.
// nodeTaintsPolicy/nodeAffinityPolicy=Honor keep tainted/drained
// nodes out of the domain calculation so DoNotSchedule can't lock
// the rollout. The watch patches drift back in <1s; the 15m requeue
// replaces the old hourly crontab.
//
// Proportional scaling (replaces cluster-proportional-autoscaler):
// when minReplicas>0 the reconciler also pins .spec.replicas to the
// CPA "linear" formula with includeUnschedulableNodes=true —
// max(minReplicas, ceil(totalNodes/nodesPerReplica)) — and a Node
// watch re-reconciles on every node add/remove. minReplicas<=0
// disables the pin (the Deployment keeps its own .spec.replicas) so
// a cluster can re-enable the standalone CPA without being fought.
//
// Corefile negative-cache guard (negative-cache-guard): the kube-system/coredns
// ConfigMap is k0s-managed and drifts back to a bare `cache 30`,
// which negative-caches NXDOMAIN for the full SOA TTL — a Job pod
// that outraces endpointslice-controller at deploy time eats a
// 30s-cached NXDOMAIN and dies on backoffLimit. The reconciler
// rewrites a denial-less cache directive to `cache 30 { success
// 9984 30; denial 9984 5 }`, capping negative caching at 5s while
// keeping the 30s positive cache.
//
// File layout: this file holds the module contract, the watch/setup wiring
// (Setup) and the Reconcile pipeline; coredns_patch.go the drift check and
// strategic-merge patch body; coredns_corefile.go the Corefile
// negative-cache reconcile (negative-cache-guard).
package corednspatcher

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/pinnedworkload"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

var (
	corednsWantReq = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("25m"),
		corev1.ResourceMemory: resource.MustParse("64Mi"),
	}
	corednsWantLim = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("1000m"),
		corev1.ResourceMemory: resource.MustParse("256Mi"),
	}
)

type corednsPatcher struct {
	cs              kubernetes.Interface
	nodeReader      kube.CachedNodeReader
	reader          kube.CachedObjectReader
	zoneWhen        string
	minDomains      int
	minReplicas     int
	nodesPerReplica int
}

// The watch wiring below installs this package-level predicate
// verbatim — tests exercise the exact unit the controller runs
// instead of introspecting controller-runtime internals. The Node
// watch predicate is the shared pinnedworkload.NodeCountChanges.

// onlyCoreDNSDeployment pins the For() watch to kube-system/coredns —
// the informer sees every kube-system Deployment.
var onlyCoreDNSDeployment = pinnedworkload.OnlyNamespacedName("kube-system", "coredns")

// Setup reconciles only the coredns Deployment (the
// informer sees every kube-system Deployment — the predicate pins
// ns/name). Clusters without the module (COREDNS_PATCHER_ENABLED=
// false, resolved by setupModules into Deps.Disabled — e.g. ones
// managing coredns themselves) skip registration entirely.
//
// minReplicas/nodesPerReplica are the CPA-linear replica pin — see
// pinnedworkload.ReplicaPin. minReplicas<=0 disables the pin entirely.
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, configFromEnv, func(cfg corednsPatcherConfig) error {
		// zoneWhen lands verbatim in the whenUnsatisfiable field of the
		// rendered patch — a typo is not caught until the apiserver
		// rejects the invalid enum, at which point the Deployment
		// perpetually reads as drifted and every reconcile fails (eternal
		// error loop). Validate at boot instead — but disable only this
		// module: a returned error would propagate through setupModules
		// and abort ALL 32 modules for one ConfigMap typo. The error is
		// still loud: logged at Error level and counted on the queue's
		// error metric.
		switch corev1.UnsatisfiableConstraintAction(cfg.zoneWhen) {
		case corev1.DoNotSchedule, corev1.ScheduleAnyway:
		default:
			err := fmt.Errorf("invalid zoneWhen %q — must be %q or %q "+
				"(UnsatisfiableConstraintAction); module disabled",
				cfg.zoneWhen, corev1.DoNotSchedule, corev1.ScheduleAnyway)
			logf.Log.WithName(d.Name).Error(err, "setup failed")
			metrics.IncError(d.Name)
			return nil
		}
		logf.Log.WithName(d.Name).Info("registered",
			"zoneWhen", cfg.zoneWhen, "zoneMinDomains", cfg.zoneMinDomains,
			"minReplicas", cfg.minReplicas, "nodesPerReplica", cfg.nodesPerReplica)
		b := ctrl.NewControllerManagedBy(d.Mgr).
			Named(d.Name).
			For(&appsv1.Deployment{}, builder.WithPredicates(onlyCoreDNSDeployment))
		// Node add/remove changes the proportional replica total; the
		// watch is registered only while the pin is enabled — see
		// pinnedworkload.ReplicaPin.WatchNodes.
		b = pinnedworkload.ReplicaPin{
			MinReplicas:     cfg.minReplicas,
			NodesPerReplica: cfg.nodesPerReplica,
		}.WatchNodes(b, "coredns-patcher-sweep")
		r := &corednsPatcher{cs: d.CS, nodeReader: d.CachedClient(), zoneWhen: cfg.zoneWhen,
			minDomains: cfg.zoneMinDomains, minReplicas: cfg.minReplicas, nodesPerReplica: cfg.nodesPerReplica,
			reader: d.CachedClient()}
		// CountReconcile owns the returned-error accounting — one
		// IncError per non-nil Reconcile return; the reconcile body
		// never IncErrors an error it returns.
		return b.Complete(shared.CountReconcile(d.Name, r.Reconcile))
	})
}

// corednsPatcherConfig is the module's env-resolved knob set — what
// the old moduleConfigFromEnv returned, now carried through
// SetupWithConfig's parse step.
type corednsPatcherConfig struct {
	zoneWhen        string
	zoneMinDomains  int
	minReplicas     int
	nodesPerReplica int
}

// configFromEnv resolves the COREDNS_* knobs. SetupWithConfig runs it
// BEFORE the Deps.Disabled gate — the old moduleConfigFromEnv
// resolved them at boot regardless of enabled state, so an
// unparseable COREDNS_* value still warns on a disabled module.
func configFromEnv() corednsPatcherConfig {
	return corednsPatcherConfig{
		zoneWhen:        envx.Getenv("COREDNS_PATCHER_ZONE_WHEN", "DoNotSchedule"),
		zoneMinDomains:  envx.GetenvInt("COREDNS_PATCHER_ZONE_MIN_DOMAINS", 2),
		minReplicas:     envx.GetenvInt("COREDNS_MIN_REPLICAS", 4),
		nodesPerReplica: envx.GetenvInt("COREDNS_NODES_PER_REPLICA", 1),
	}
}

// Reconcile delegates to the shared pinned-Deployment skeleton —
// this module only supplies the kube-system/coredns identity, the
// drift check and the patch body — then reconciles the Corefile's
// negative-cache cap on the same requeue cadence (the ConfigMap is
// not watched; the 15m requeue plus every Deployment reconcile is
// fresh enough for a drift k0s only re-applies on stack changes).
func (r *corednsPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	res, err := pinnedworkload.DeploymentSpec{
		CS:         r.cs,
		Reader:     r.reader,
		NodeReader: r.nodeReader,
		Namespace:  "kube-system",
		Name:       "coredns",
		Container:  "coredns",
		Replicas: pinnedworkload.ReplicaPin{
			MinReplicas:     r.minReplicas,
			NodesPerReplica: r.nodesPerReplica,
		},
		NoDriftLog: "probes/resources/topology/replicas already pinned - nothing to do",
		Drifted: func(d *appsv1.Deployment, wantReplicas int32) bool {
			return corednsNeedsPatch(d, r.zoneWhen, r.minDomains, wantReplicas)
		},
		PatchBody: func(wantReplicas int32) ([]byte, error) {
			return corednsPatchBody(r.zoneWhen, r.minDomains, wantReplicas)
		},
	}.Reconcile(ctx)
	if err != nil {
		return res, err
	}
	if err := r.reconcileCorefile(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return res, nil
}

// metrics_server_patcher.go — port of the metrics-server-topology-spread
// CronJob (infrastructure/base/scaling/metrics-server/
// metrics-server-topology-spread.yaml in passiontech-fluxcd).
//
// Keeps deployment kube-system/metrics-server at the pinned args,
// probe timeouts, resources, soft spread constraints and explicit
// toleration list. It is a built-in k0s stack addon — k0s reverts the
// manifest on every stack apply, and the stock manifest has NO spread
// constraint (observed: 3/3 pods packed into one zone -> metrics lost
// with the site) and 1s probe timeouts (overload -> probe starvation
// -> liveness-kill churn, nonprod datahub 2026-09-14).
//
// Spread stays soft (ScheduleAnyway on zone + hostname): prefer one
// pod per zone, but still schedule with a zone down. Tolerations are
// an explicit list, NEVER a wildcard Exists — Exists tolerates
// node.kubernetes.io/unschedulable too, so a pod evicted off a cordon
// would reschedule right back onto it -> drain treadmill (upgrade
// incident 2026-10-30). The args list must be rewritten in full:
// args is a plain list — strategic merge would replace it anyway.
// Watch reverts drift in <1s; the 15m requeue replaces the old hourly
// crontab.
//
// Proportional scaling (replaces cluster-proportional-autoscaler):
// when minReplicas>0 the reconciler also pins .spec.replicas to the
// CPA "linear" formula with includeUnschedulableNodes=true —
// max(minReplicas, ceil(totalNodes/nodesPerReplica)) — and a Node
// watch re-reconciles on every node add/remove. minReplicas<=0
// disables the pin (the Deployment keeps its own .spec.replicas) so
// a cluster can re-enable the standalone CPA without being fought.
package metricsserverpatcher

import (
	"context"
	"encoding/json"
	"errors"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/pinnedworkload"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Exact patch body from the CronJob — strategic merge lands the
// container changes by name; args are a plain list and get replaced
// wholesale, so the full wanted arg set is spelled out.
var metricsServerPatch = []byte(`{"spec":{"template":{"spec":{"containers":[{"name":"metrics-server","args":["--cert-dir=/tmp","--secure-port=10250","--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname","--kubelet-use-node-status-port","--metric-resolution=30s","--kubelet-request-timeout=25s"],"livenessProbe":{"timeoutSeconds":5},"readinessProbe":{"timeoutSeconds":5},"resources":{"requests":{"cpu":"20m","memory":"96Mi"},"limits":{"cpu":"200m","memory":"384Mi"}}}],"topologySpreadConstraints":[{"maxSkew":1,"topologyKey":"topology.kubernetes.io/zone","whenUnsatisfiable":"ScheduleAnyway","labelSelector":{"matchLabels":{"k8s-app":"metrics-server"}}},{"maxSkew":1,"topologyKey":"kubernetes.io/hostname","whenUnsatisfiable":"ScheduleAnyway","labelSelector":{"matchLabels":{"k8s-app":"metrics-server"}}}],"affinity":null,"tolerations":[{"key":"node-role.kubernetes.io/control-plane","operator":"Exists","effect":"NoSchedule"},{"key":"node-role.kubernetes.io/master","operator":"Exists","effect":"NoSchedule"},{"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute"},{"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute"},{"key":"node.kubernetes.io/disk-pressure","operator":"Exists","effect":"NoSchedule"},{"key":"node.kubernetes.io/memory-pressure","operator":"Exists","effect":"NoSchedule"},{"key":"node.kubernetes.io/pid-pressure","operator":"Exists","effect":"NoSchedule"},{"key":"node.kubernetes.io/network-unavailable","operator":"Exists","effect":"NoSchedule"},{"key":"weave.works/kured-node-reboot","operator":"Exists","effect":"PreferNoSchedule"},{"key":"CriticalAddonsOnly","operator":"Exists"}]}}}}`)

var (
	metricsServerWantReqCPU = resource.MustParse("20m")
	metricsServerWantReqMem = resource.MustParse("96Mi")
	metricsServerWantLimCPU = resource.MustParse("200m")
	metricsServerWantLimMem = resource.MustParse("384Mi")
)

// metricsServerWantArgs is the exact args list the patch installs —
// args is a plain list the strategic merge replaces wholesale, so the
// drift check must compare the WHOLE list: any pinned arg missing OR
// any arg present that the patch would drop counts as drift (a check
// covering only some pinned args would leave the rest permanently
// unpatched).
var metricsServerWantArgs = []string{
	"--cert-dir=/tmp",
	"--secure-port=10250",
	"--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
	"--kubelet-use-node-status-port",
	"--metric-resolution=30s",
	"--kubelet-request-timeout=25s",
}

type metricsServerPatcher struct {
	cs              kubernetes.Interface
	nodeReader      kube.CachedNodeReader
	minReplicas     int
	nodesPerReplica int
}

// The watch wiring below installs this package-level predicate
// verbatim — tests exercise the exact unit the controller runs
// instead of introspecting controller-runtime internals. The Node
// watch predicate is the shared pinnedworkload.NodeCountChanges.

// onlyMetricsServerDeployment pins the For() watch to
// kube-system/metrics-server — the informer sees every kube-system
// Deployment.
var onlyMetricsServerDeployment = pinnedworkload.OnlyNamespacedName("kube-system", "metrics-server")

// Setup reconciles only the metrics-server
// Deployment (the informer sees every kube-system Deployment — the
// predicate pins ns/name). METRICS_SERVER_PATCHER_ENABLED=false
// (resolved by setupModules into Deps.Disabled) skips registration
// entirely.
//
// minReplicas/nodesPerReplica are the CPA-linear replica pin — see
// pinnedworkload.ReplicaPin. minReplicas<=0 disables the pin entirely.
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, configFromEnv, func(cfg metricsServerPatcherConfig) error {
		logf.Log.WithName(d.Name).Info("registered",
			"minReplicas", cfg.minReplicas, "nodesPerReplica", cfg.nodesPerReplica)
		b := ctrl.NewControllerManagedBy(d.Mgr).
			Named(d.Name).
			For(&appsv1.Deployment{}, builder.WithPredicates(onlyMetricsServerDeployment))
		// Node add/remove changes the proportional replica total; the
		// watch is registered only while the pin is enabled — see
		// pinnedworkload.ReplicaPin.WatchNodes.
		b = pinnedworkload.ReplicaPin{
			MinReplicas:     cfg.minReplicas,
			NodesPerReplica: cfg.nodesPerReplica,
		}.WatchNodes(b, "metrics-server-patcher-sweep")
		r := &metricsServerPatcher{cs: d.CS, nodeReader: d.Mgr.GetClient(),
			minReplicas: cfg.minReplicas, nodesPerReplica: cfg.nodesPerReplica}
		// CountReconcile owns the returned-error accounting — one
		// IncError per non-nil Reconcile return; the reconcile body
		// never IncErrors an error it returns.
		return b.Complete(shared.CountReconcile(d.Name, r.Reconcile))
	})
}

// metricsServerPatcherConfig is the module's env-resolved knob set.
type metricsServerPatcherConfig struct {
	minReplicas     int
	nodesPerReplica int
}

// configFromEnv resolves the METRICS_SERVER_* knobs. SetupWithConfig
// runs it before the Deps.Disabled gate — see corednspatcher: invalid
// knob values must warn even when the module is disabled.
func configFromEnv() metricsServerPatcherConfig {
	return metricsServerPatcherConfig{
		minReplicas:     envx.GetenvInt("METRICS_SERVER_MIN_REPLICAS", 3),
		nodesPerReplica: envx.GetenvInt("METRICS_SERVER_NODES_PER_REPLICA", 1),
	}
}

// Reconcile delegates to the shared pinned-Deployment skeleton —
// this module only supplies the kube-system/metrics-server identity,
// the drift check and the patch body.
func (r *metricsServerPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	return pinnedworkload.DeploymentSpec{
		CS:         r.cs,
		NodeReader: r.nodeReader,
		Namespace:  "kube-system",
		Name:       "metrics-server",
		Container:  "metrics-server",
		Replicas: pinnedworkload.ReplicaPin{
			MinReplicas:     r.minReplicas,
			NodesPerReplica: r.nodesPerReplica,
		},
		NoDriftLog: "args/probes/resources/topology/tolerations/replicas already pinned - nothing to do",
		Drifted:    metricsServerNeedsPatch,
		PatchBody:  metricsServerPatchBody,
	}.Reconcile(ctx)
}

// metricsServerPatchBody renders the pinned CronJob patch plus the
// proportional .spec.replicas entry. wantReplicas<=0 returns the body
// untouched — strategic merge then leaves the Deployment's replica
// count alone, so disabled scaling never fights a re-enabled CPA.
func metricsServerPatchBody(wantReplicas int32) ([]byte, error) {
	if wantReplicas <= 0 {
		return metricsServerPatch, nil
	}
	var body map[string]any
	if err := json.Unmarshal(metricsServerPatch, &body); err != nil {
		return nil, err
	}
	spec, ok := body["spec"].(map[string]any)
	if !ok {
		return nil, errors.New("metricsServerPatch missing spec object")
	}
	spec["replicas"] = wantReplicas
	return json.Marshal(body)
}

// metricsServerNeedsPatch reports whether the Deployment lacks any
// pinned field — args, probe timeouts, requests/limits, cleared
// affinity, tolerations, spread constraints, or (when proportional
// scaling is on, wantReplicas>0) a drifted .spec.replicas. A missing
// metrics-server container counts as drifted (same as the shell's
// empty jsonpath probe). The toleration guard mirrors the shell's
// `tol_ok` probe plus the incident fix: a wildcard Exists toleration
// (empty key tolerates EVERYTHING, incl. unschedulable) is drift; an
// explicit not-ready entry is required.
func metricsServerNeedsPatch(d *appsv1.Deployment, wantReplicas int32) bool {
	// Replica drift only counts when the pin is enabled — a nil
	// .spec.replicas defaults to 1 at the API but still means "we
	// never pinned it", so it counts as drifted too.
	if wantReplicas > 0 &&
		(d.Spec.Replicas == nil || *d.Spec.Replicas != wantReplicas) {
		return true
	}
	ps := d.Spec.Template.Spec
	for i := range ps.Containers {
		c := &ps.Containers[i]
		if c.Name != "metrics-server" {
			continue
		}
		if metricsServerArgsDrifted(c.Args) {
			return true
		}
		if c.LivenessProbe == nil || c.LivenessProbe.TimeoutSeconds != 5 ||
			c.ReadinessProbe == nil || c.ReadinessProbe.TimeoutSeconds != 5 {
			return true
		}
		reqCPU := c.Resources.Requests[corev1.ResourceCPU]
		reqMem := c.Resources.Requests[corev1.ResourceMemory]
		limCPU := c.Resources.Limits[corev1.ResourceCPU]
		limMem := c.Resources.Limits[corev1.ResourceMemory]
		if reqCPU.Cmp(metricsServerWantReqCPU) != 0 ||
			reqMem.Cmp(metricsServerWantReqMem) != 0 ||
			limCPU.Cmp(metricsServerWantLimCPU) != 0 ||
			limMem.Cmp(metricsServerWantLimMem) != 0 {
			return true
		}
		if ps.Affinity != nil {
			return true
		}
		if metricsServerTolerationsDrifted(ps.Tolerations) {
			return true
		}
		return !metricsServerTopologyOK(ps.TopologySpreadConstraints)
	}
	return true
}

// metricsServerArgsDrifted reports whether the live args list differs
// from metricsServerWantArgs as a multiset — a missing pinned arg and
// an extra arg the patch would drop are BOTH drift, matching the
// replace-whole-list semantics of the strategic merge.
func metricsServerArgsDrifted(args []string) bool {
	counts := make(map[string]int, len(metricsServerWantArgs))
	for _, a := range metricsServerWantArgs {
		counts[a]++
	}
	for _, a := range args {
		counts[a]--
	}
	for _, n := range counts {
		if n != 0 {
			return true
		}
	}
	return false
}

// metricsServerWantTolerations is the explicit set the patch pins —
// no wildcard Exists (it tolerates node.kubernetes.io/unschedulable
// too, the drain-treadmill bug of 2026-10-30).
var metricsServerWantTolerations = []corev1.Toleration{
	{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
	{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
	{Key: "node.kubernetes.io/disk-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/memory-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/pid-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/network-unavailable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: kube.TaintKuredNodeReboot, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectPreferNoSchedule},
	{Key: "CriticalAddonsOnly", Operator: corev1.TolerationOpExists},
}

// metricsServerTolerationsDrifted: a wildcard Exists toleration (no
// key) means drift, every wanted toleration must be present, and any
// toleration NOT in the pinned set is drift too — .spec.tolerations
// is +listType=atomic, so the patch replaces it wholesale; the check
// must see every entry the patch would actually wipe, otherwise an
// addon-injected toleration is silently deleted by a patch the drift
// check never asked for.
func metricsServerTolerationsDrifted(tols []corev1.Toleration) bool {
	for _, t := range tols {
		if t.Operator == corev1.TolerationOpExists && t.Key == "" {
			return true // wildcard: tolerates unschedulable — the treadmill bug
		}
	}
	for _, w := range metricsServerWantTolerations {
		found := false
		for _, t := range tols {
			if tolerationMatches(&t, &w) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	for i := range tols {
		found := false
		for j := range metricsServerWantTolerations {
			if tolerationMatches(&tols[i], &metricsServerWantTolerations[j]) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

// tolerationMatches compares the identity fields the pinned set is
// keyed on — key/operator/effect plus tolerationSeconds. nil vs set
// matters: a seconds value injected onto a wanted toleration by
// another actor changes what the pod actually tolerates, and the
// atomic-list patch would wipe it — it must read as drift, not match.
func tolerationMatches(t, w *corev1.Toleration) bool {
	if t.Key != w.Key || t.Operator != w.Operator || t.Effect != w.Effect {
		return false
	}
	if t.TolerationSeconds == nil || w.TolerationSeconds == nil {
		return t.TolerationSeconds == nil && w.TolerationSeconds == nil
	}
	return *t.TolerationSeconds == *w.TolerationSeconds
}

// metricsServerTopologyOK requires both soft constraints: zone and
// hostname ScheduleAnyway maxSkew=1, each selector k8s-app=metrics-server.
func metricsServerTopologyOK(tscs []corev1.TopologySpreadConstraint) bool {
	zoneOK, hostOK := false, false
	for _, c := range tscs {
		if c.WhenUnsatisfiable != corev1.ScheduleAnyway ||
			c.MaxSkew != 1 ||
			c.LabelSelector == nil ||
			c.LabelSelector.MatchLabels["k8s-app"] != "metrics-server" {
			continue
		}
		switch c.TopologyKey {
		case "topology.kubernetes.io/zone":
			zoneOK = true
		case "kubernetes.io/hostname":
			hostOK = true
		}
	}
	return zoneOK && hostOK
}

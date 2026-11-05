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
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
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
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the controller name, the setup log lines and
	// every IncError label come from one place.
	queue           string
	minReplicas     int
	nodesPerReplica int
}

// The watch wiring below installs these package-level predicates
// verbatim — tests exercise the exact units the controller runs
// instead of introspecting controller-runtime internals.

// onlyMetricsServerDeployment pins the For() watch to
// kube-system/metrics-server — the informer sees every kube-system
// Deployment.
var onlyMetricsServerDeployment = predicate.NewPredicateFuncs(func(o client.Object) bool {
	return o.GetNamespace() == "kube-system" &&
		o.GetName() == "metrics-server"
})

// nodeCountChanges is the Node watch predicate — node add/remove
// changes the proportional replica total. The formula's
// includeUnschedulableNodes=true counts EVERY Node object, so updates
// (cordon flips, ~20s kubelet heartbeats) can never change the count
// and must not enqueue — only create/delete fire.
var nodeCountChanges = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return true },
	DeleteFunc:  func(event.DeleteEvent) bool { return true },
	UpdateFunc:  func(event.UpdateEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
}

// Setup reconciles only the metrics-server
// Deployment (the informer sees every kube-system Deployment — the
// predicate pins ns/name). METRICS_SERVER_PATCHER_ENABLED=false
// (resolved by setupModules into Deps.Disabled) skips registration
// entirely.
//
// minReplicas/nodesPerReplica are the CPA-linear replica pin — see
// proportionalReplicas. minReplicas<=0 disables the pin entirely.
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, configFromEnv, func(cfg metricsServerPatcherConfig) error {
		logf.Log.WithName(d.Name).Info("registered",
			"minReplicas", cfg.minReplicas, "nodesPerReplica", cfg.nodesPerReplica)
		b := ctrl.NewControllerManagedBy(d.Mgr).
			Named(d.Name).
			For(&appsv1.Deployment{}, builder.WithPredicates(onlyMetricsServerDeployment))
		if cfg.minReplicas > 0 {
			// Node add/remove changes the proportional replica total —
			// see nodeCountChanges for why only create/delete fire.
			// Collapses to one fixed key: Reconcile ignores the request
			// name anyway. With the pin disabled the count is never read,
			// so the watch is not registered at all.
			b = b.Watches(&corev1.Node{},
				handler.EnqueueRequestsFromMapFunc(shared.SweepRequests("metrics-server-patcher-sweep")),
				builder.WithPredicates(nodeCountChanges))
		}
		return b.Complete(&metricsServerPatcher{cs: d.CS, queue: d.Name,
			minReplicas: cfg.minReplicas, nodesPerReplica: cfg.nodesPerReplica})
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
		minReplicas:     shared.GetenvInt("METRICS_SERVER_MIN_REPLICAS", 3),
		nodesPerReplica: shared.GetenvInt("METRICS_SERVER_NODES_PER_REPLICA", 1),
	}
}

func (r *metricsServerPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 15 * time.Minute}

	d, err := r.cs.AppsV1().Deployments("kube-system").
		Get(ctx, "metrics-server", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// cluster without the k0s metrics-server addon
		log.Info("SKIP: deployment not found", "deployment", "kube-system/metrics-server")
		return res, nil
	}
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("get deployment kube-system/metrics-server: %w", err)
	}

	// Proportional replica pin — disabled when minReplicas<=0
	// (wantReplicas stays 0: neither needsPatch nor the patch body
	// touches .spec.replicas then).
	wantReplicas := int32(0)
	if r.minReplicas > 0 {
		nodes, err := shared.ListNodes(ctx, r.cs)
		if err != nil {
			metrics.IncError(r.queue)
			return ctrl.Result{}, fmt.Errorf("list nodes for proportional replica count: %w", err)
		}
		wantReplicas = shared.ProportionalReplicas(len(nodes), r.minReplicas, r.nodesPerReplica)
	}

	if !metricsServerNeedsPatch(d, wantReplicas) {
		log.Info("args/probes/resources/topology/tolerations/replicas already pinned - nothing to do",
			"deployment", "kube-system/metrics-server", "wantReplicas", wantReplicas)
		return res, nil
	}
	// A missing metrics-server container reads as drift, but the
	// strategic-merge patch below merges containers BY NAME — applied
	// to a spec without it, it would append a container entry with no
	// image that the apiserver rejects forever. We cannot reconstruct
	// the image, so warn and leave the Deployment for the stack
	// applier rather than emitting a guaranteed-invalid patch.
	if !shared.PodSpecHasContainer(&d.Spec.Template.Spec, "metrics-server") {
		log.Info("WARN: metrics-server container missing from pod spec — "+
			"skipping patch (strategic merge cannot create it without an image)",
			"deployment", "kube-system/metrics-server")
		return res, nil
	}
	patch, err := metricsServerPatchBody(wantReplicas)
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("render patch body for deployment kube-system/metrics-server: %w", err)
	}
	log.Info("PATCH: metrics-server drifted — restoring pinned spec",
		"deployment", "kube-system/metrics-server", "wantReplicas", wantReplicas)
	if _, err := r.cs.AppsV1().Deployments("kube-system").Patch(ctx,
		"metrics-server", types.StrategicMergePatchType,
		patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("patch deployment kube-system/metrics-server: %w", err)
	}
	return res, nil
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
	{Key: "weave.works/kured-node-reboot", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectPreferNoSchedule},
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

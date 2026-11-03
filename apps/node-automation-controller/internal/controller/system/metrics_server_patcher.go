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
package system

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
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

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
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

type metricsServerPatcher struct {
	cs              kubernetes.Interface
	minReplicas     int
	nodesPerReplica int
}

// SetupMetricsServerPatcher reconciles only the metrics-server
// Deployment (the informer sees every kube-system Deployment — the
// predicate pins ns/name). enabled=false skips registration entirely.
//
// minReplicas/nodesPerReplica are the CPA-linear replica pin — see
// proportionalReplicas. minReplicas<=0 disables the pin entirely.
func SetupMetricsServerPatcher(mgr ctrl.Manager, cs kubernetes.Interface, enabled bool, minReplicas, nodesPerReplica int) error {
	if !enabled {
		return nil
	}
	b := ctrl.NewControllerManagedBy(mgr).
		Named("metrics-server-patcher").
		For(&appsv1.Deployment{}, builder.WithPredicates(
			predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetNamespace() == "kube-system" &&
					o.GetName() == "metrics-server"
			})))
	if minReplicas > 0 {
		// Node add/remove changes the proportional replica total. The
		// formula's includeUnschedulableNodes=true counts EVERY Node
		// object, so updates (cordon flips, ~20s kubelet heartbeats)
		// can never change the count and must not enqueue — only
		// create/delete fire. Collapses to one fixed key: Reconcile
		// ignores the request name anyway. With the pin disabled the
		// count is never read, so the watch is not registered at all.
		b = b.Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(shared.SweepRequests("metrics-server-patcher-sweep")),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return true },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				GenericFunc: func(event.GenericEvent) bool { return false },
			}))
	}
	return b.Complete(&metricsServerPatcher{cs: cs,
		minReplicas: minReplicas, nodesPerReplica: nodesPerReplica})
}

func (r *metricsServerPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 15 * time.Minute}

	d, err := r.cs.AppsV1().Deployments("kube-system").
		Get(ctx, "metrics-server", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return res, nil // cluster without the k0s metrics-server addon
	}
	if err != nil {
		metrics.IncError("metrics-server-patcher")
		return ctrl.Result{}, err
	}

	// Proportional replica pin — disabled when minReplicas<=0
	// (wantReplicas stays 0: neither needsPatch nor the patch body
	// touches .spec.replicas then).
	wantReplicas := int32(0)
	if r.minReplicas > 0 {
		nodes, err := shared.ListNodes(ctx, r.cs)
		if err != nil {
			metrics.IncError("metrics-server-patcher")
			return ctrl.Result{}, err
		}
		wantReplicas = proportionalReplicas(len(nodes), r.minReplicas, r.nodesPerReplica)
	}

	if !metricsServerNeedsPatch(d, wantReplicas) {
		log.Info("args/probes/resources/topology/tolerations/replicas already pinned - nothing to do")
		return res, nil
	}
	patch, err := metricsServerPatchBody(wantReplicas)
	if err != nil {
		metrics.IncError("metrics-server-patcher")
		return ctrl.Result{}, err
	}
	log.Info("PATCH: metrics-server drifted — restoring pinned spec",
		"deployment", "kube-system/metrics-server", "wantReplicas", wantReplicas)
	if _, err := r.cs.AppsV1().Deployments("kube-system").Patch(ctx,
		"metrics-server", types.StrategicMergePatchType,
		patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError("metrics-server-patcher")
		return ctrl.Result{}, err
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
		return nil, fmt.Errorf("metricsServerPatch missing spec object")
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
		if !slices.Contains(c.Args, "--metric-resolution=30s") ||
			!slices.Contains(c.Args, "--kubelet-request-timeout=25s") {
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
// key) means drift, and every wanted toleration must be present.
func metricsServerTolerationsDrifted(tols []corev1.Toleration) bool {
	for _, t := range tols {
		if t.Operator == corev1.TolerationOpExists && t.Key == "" {
			return true // wildcard: tolerates unschedulable — the treadmill bug
		}
	}
	for _, w := range metricsServerWantTolerations {
		found := false
		for _, t := range tols {
			if t.Key == w.Key && t.Operator == w.Operator && t.Effect == w.Effect {
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

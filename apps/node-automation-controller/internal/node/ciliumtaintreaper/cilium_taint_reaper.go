// cilium_taint_reaper.go — port of hooks/15-cilium-taint-reaper.sh.
//
// Reaps stale `node.cilium.io/agent-not-ready` taints. The cilium
// agent sets the taint while not ready and removes it once on the
// readiness transition — if that single Node update fails or races
// (API churn during upgrades, agent restart mid-rollout), the taint
// wedges forever even though the agent is healthy => node stops
// scheduling (NoSchedule) or worse evicts pods (NoExecute). Seen for
// real on nonprod 2026-09-16 after a cilium upgrade.
//
// Safety: only reaps when the cilium pod ON THAT NODE is Running +
// Ready + not terminating (the cilium readiness probe is the daemon
// healthz); a pod that isn't ready means the taint is doing its job.
//
// Runs only when enabled (CILIUM_TAINT_REAPER_ENABLED — set by the
// cilium component); on cicd/Calico clusters it no-ops and the pod
// informer is never started.
package ciliumtaintreaper

import (
	"context"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

const ciliumNotReadyTaint = "node.cilium.io/agent-not-ready"

type ciliumTaintReaper struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the controller name and every IncError label
	// come from one place.
	queue   string
	enabled bool
}

// The watch wiring below installs these package-level units
// verbatim — tests exercise the exact predicate/mapfunc the
// controller runs instead of introspecting controller-runtime
// internals.

// nodeSweepRequests collapses every Node event onto the single fixed
// sweep key (see shared.SweepRequests).
var nodeSweepRequests = shared.SweepRequests("cilium-taint-reaper-sweep")

// ciliumPodSweepRequests maps a scheduled cilium pod onto the same
// fixed sweep key; an unscheduled pod carries no verdict signal and
// enqueues nothing.
var ciliumPodSweepRequests handler.MapFunc = func(_ context.Context, o client.Object) []reconcile.Request {
	if o.(*corev1.Pod).Spec.NodeName == "" {
		return nil // unscheduled pod carries no verdict signal
	}
	return shared.FixedSweepRequest("cilium-taint-reaper-sweep")
}

// ciliumTaintChanges is the Node watch predicate — the bash jqFilter:
// fire only when THIS taint's entries change, otherwise every kubelet
// heartbeat (~20s/node) would enqueue a full-cluster sweep.
var ciliumTaintChanges = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return true },
	DeleteFunc:  func(event.DeleteEvent) bool { return true },
	GenericFunc: func(event.GenericEvent) bool { return true },
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldN, ok1 := e.ObjectOld.(*corev1.Node)
		newN, ok2 := e.ObjectNew.(*corev1.Node)
		if !ok1 || !ok2 {
			return true
		}
		return !reflect.DeepEqual(ciliumStaleTaints(oldN), ciliumStaleTaints(newN))
	},
}

func Setup(d shared.Deps) error {
	mgr, cs := d.Mgr, d.CS
	// Clusters without the cilium component (and thus without pods
	// watch RBAC) skip registration entirely — CILIUM_TAINT_REAPER_ENABLED
	// is opt-in, resolved by setupModules into Deps.Disabled: no
	// controller, no informer, no RequeueAfter loop. The manager
	// cache's cilium-pod ByObject entry exists only for this module.
	if d.Disabled {
		return nil
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named(d.Name).
		// Watches with a single fixed workqueue key, not For(): the
		// reconcile ignores req.Name and always sweeps the whole
		// cluster, so per-node keys only produced N duplicate queued
		// requests + N independent RequeueAfter timers per informer
		// sync. One key collapses both to a single sweep (see
		// shared.SweepRequests). Predicate semantics are unchanged.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(nodeSweepRequests),
			builder.WithPredicates(ciliumTaintChanges)).
		// Also react when a node's cilium pod flips Ready/not-Ready.
		// The pod informer is already scoped to kube-system +
		// k8s-app=cilium (manager cache options) and only exists
		// because this module registered, so no extra predicate is
		// needed. Same fixed sweep key — the reconcile never read
		// the pod's node name anyway.
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(ciliumPodSweepRequests)).
		// Registration implies the gate was on, so enabled is
		// unconditionally true here — the field and its Reconcile
		// check now only matter for literally-constructed reapers
		// in tests.
		Complete(&ciliumTaintReaper{cs: cs, queue: d.Name, enabled: true})
}

func (r *ciliumTaintReaper) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 10 * time.Minute}
	if !r.enabled {
		log.Info("skip: CILIUM_TAINT_REAPER_ENABLED != true")
		return res, nil
	}

	// Sweep every node like bash — a node/pod event is only the
	// trigger, the verdict always covers the whole cluster.
	nodes, err := shared.ListNodes(ctx, r.cs)
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("list nodes: %w", err)
	}

	reaped := 0
	for i := range nodes {
		node := &nodes[i]
		if !shared.HasTaint(node.Spec.Taints, ciliumNotReadyTaint) {
			continue
		}
		pods, err := r.cs.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=cilium",
			FieldSelector: "spec.nodeName=" + node.Name,
		})
		if err != nil {
			metrics.IncError(r.queue)
			return ctrl.Result{}, fmt.Errorf("list cilium pods on node %s: %w", node.Name, err)
		}
		if len(pods.Items) == 0 {
			log.Info("SKIP: taint present but no cilium pod on node",
				"node", node.Name)
			continue
		}
		// The verdict must read EVERY cilium pod on the node — during
		// a rollout the old (terminating/unready) and new agents can
		// coexist, and reading only Items[0] makes the outcome depend
		// on apiserver list order. ANY healthy agent means the taint
		// is stale; reap only then.
		var healthy *corev1.Pod
		for i := range pods.Items {
			if ciliumPodHealthy(&pods.Items[i]) {
				healthy = &pods.Items[i]
				break
			}
		}
		if healthy != nil {
			log.Info("REAP: agent healthy but stale taint -> removing",
				"node", node.Name, "pod", healthy.Name)
			if err := shared.UntaintNode(ctx, r.cs, node.Name, ciliumNotReadyTaint); err != nil {
				metrics.IncError(r.queue)
				return ctrl.Result{}, fmt.Errorf("remove taint %s on node %s: %w",
					ciliumNotReadyTaint, node.Name, err)
			}
			reaped++
		} else {
			pod := &pods.Items[0] // first pod, for diagnostics only
			log.Info("KEEP: no healthy agent -> taint is doing its job",
				"node", node.Name, "pods", len(pods.Items),
				"pod", pod.Name,
				"phase", pod.Status.Phase,
				"terminating", pod.DeletionTimestamp != nil,
				"ready", shared.PodReadyCond(pod))
		}
	}
	log.Info("sweep done", "reaped", reaped, "nodes", len(nodes))
	return res, nil
}

// ciliumStaleTaints is the bash jqFilter projection — only the
// agent-not-ready taint entries, so unrelated taint edits don't fire.
func ciliumStaleTaints(n *corev1.Node) []corev1.Taint {
	var out []corev1.Taint
	for _, t := range n.Spec.Taints {
		if t.Key == ciliumNotReadyTaint {
			out = append(out, t)
		}
	}
	return out
}

// ciliumPodHealthy mirrors the bash "|Running|True" probe: not
// terminating, phase Running and Ready condition True.
func ciliumPodHealthy(p *corev1.Pod) bool {
	return p.DeletionTimestamp == nil &&
		p.Status.Phase == corev1.PodRunning && shared.PodReadyCond(p)
}

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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

type ciliumTaintReaper struct {
	cs kubernetes.Interface
	// nodeReader is the informer-backed node read — the sweep's
	// whole-cluster census rides the Node watch this reconciler
	// already registers; UntaintNode still re-Gets on the direct
	// clientset before acting.
	nodeReader kube.CachedNodeReader
	// podReader is the informer-backed cilium-pod read (same manager
	// client as nodeReader — the Pod watch this reconciler registers
	// keeps the cache fresh). Nil (test fixtures) falls back to the
	// direct clientset list. The untaint WRITE never rides this:
	// destructive actions confirm and patch on the direct clientset.
	podReader kube.CachedNodeReader
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
// enqueues nothing. The assert must be comma-ok: informer delete
// delivery can surface a cache.DeletedFinalStateUnknown tombstone
// whose unwrapped .Obj (or any non-Pod object reaching the mapper)
// panics a hard assertion — a non-Pod carries no verdict signal.
var ciliumPodSweepRequests handler.MapFunc = func(_ context.Context, o client.Object) []reconcile.Request {
	pod, ok := o.(*corev1.Pod)
	if !ok {
		return nil
	}
	if pod.Spec.NodeName == "" {
		return nil // unscheduled pod carries no verdict signal
	}
	return shared.FixedSweepRequest("cilium-taint-reaper-sweep")
}

// ciliumTaintChanges is the Node watch predicate — the bash jqFilter:
// fire only when THIS taint's entries change, otherwise every kubelet
// heartbeat (~20s/node) would enqueue a full-cluster sweep.
var ciliumTaintChanges = shared.NodeUpdatePredicate(true, func(oldN, newN *corev1.Node) bool {
	return !equality.Semantic.DeepEqual(ciliumStaleTaints(oldN), ciliumStaleTaints(newN))
})

func Setup(d shared.Deps) error {
	mgr, cs := d.Mgr, d.CS
	// Clusters without the cilium component (and thus without pods
	// watch RBAC) skip registration entirely — CILIUM_TAINT_REAPER_ENABLED
	// is opt-in, resolved by setupModules into Deps.Disabled: no
	// controller, no informer, no RequeueAfter loop. The manager
	// cache's cilium-pod ByObject entry exists only for this module.
	return shared.SetupNoConfig(d, func() error {
		cached := d.CachedClient()
		r := &ciliumTaintReaper{cs: cs, nodeReader: cached, podReader: cached}
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
			Complete(shared.CountReconcile(d.Name, r.Reconcile))
	})
}

func (r *ciliumTaintReaper) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 10 * time.Minute}

	// Sweep every node like bash — a node/pod event is only the
	// trigger, the verdict always covers the whole cluster.
	nodes, err := kube.ListNodesCached(ctx, r.nodeReader, r.cs)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list nodes: %w", err)
	}

	// Collect the tainted nodes first: with none, the cilium pod
	// list is never issued — the steady state pays only the node
	// list, the same cost the old per-node lookups had.
	var tainted []*corev1.Node
	for i := range nodes {
		if kube.HasTaint(nodes[i].Spec.Taints, kube.TaintCiliumAgentNotReady) {
			tainted = append(tainted, &nodes[i])
		}
	}
	if len(tainted) == 0 {
		log.Info("sweep done", "reaped", 0, "nodes", len(nodes))
		return res, nil
	}

	// ONE label-selected read indexed by node — through the informer
	// cache when wired (the Pod watch this reconciler registers keeps
	// it fresh: the manager cache's cilium-pod ByObject entry is
	// scoped to kube-system + k8s-app=cilium, exactly this selector,
	// so the verdict reads memory instead of paying an apiserver LIST
	// per sweep), else the direct clientset (unwired test fixtures).
	// The untaint below never rides the cache: kube.UntaintNode
	// confirms and patches on the direct clientset, the only safe
	// path for a destructive write.
	var pods []corev1.Pod
	if r.podReader != nil {
		var cached corev1.PodList
		if err := r.podReader.List(ctx, &cached, client.InNamespace("kube-system"),
			client.MatchingLabels{"k8s-app": "cilium"}); err != nil {
			return ctrl.Result{}, fmt.Errorf("list cilium pods: %w", err)
		}
		pods = cached.Items
	} else {
		listed, err := kube.ListAll(ctx,
			metav1.ListOptions{
				Limit:         kube.DefaultListPageSize,
				LabelSelector: "k8s-app=cilium",
			},
			kube.Pods(r.cs, "kube-system"))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("list cilium pods: %w", err)
		}
		pods = listed
	}
	// The old sweep issued a kube-system List per tainted node (an N+1
	// on the apiserver); indexing spec.nodeName in-code reproduces the
	// per-node field-selector scoping exactly (a pod pinned to a
	// different node lands under ITS key, an unscheduled one under
	// "").
	podsByNode := make(map[string][]*corev1.Pod)
	for i := range pods {
		p := &pods[i]
		podsByNode[p.Spec.NodeName] = append(podsByNode[p.Spec.NodeName], p)
	}

	reaped := 0
	for _, node := range tainted {
		onNode := podsByNode[node.Name]
		if len(onNode) == 0 {
			log.Info("SKIP: taint present but no cilium pod on node",
				"node", node.Name)
			continue
		}
		// The verdict must read EVERY cilium pod on the node — during
		// a rollout the old (terminating/unready) and new agents can
		// coexist, and reading only the first pod makes the outcome
		// depend on apiserver list order. ANY healthy agent means the
		// taint is stale; reap only then.
		var healthy *corev1.Pod
		for _, p := range onNode {
			if ciliumPodHealthy(p) {
				healthy = p
				break
			}
		}
		if healthy != nil {
			// Live confirmation before the destructive write: the
			// cache verdict above rides the informer and can lag the
			// apiserver (the Node and Pod watches are independent —
			// a mid-rollout pod replacement lands in one before the
			// other), so re-GET the agent on the direct clientset
			// immediately before removing the taint and require the
			// SAME pod (UID), still non-terminating and still
			// healthy (ciliumPodHealthy re-checks the termination
			// timestamp alongside Running+Ready). Any divergence
			// keeps the taint — the safe direction, and the next
			// sweep re-evaluates on fresher cache.
			live, err := r.cs.CoreV1().Pods(healthy.Namespace).
				Get(ctx, healthy.Name, metav1.GetOptions{})
			if err != nil || live.UID != healthy.UID || !ciliumPodHealthy(live) {
				log.Info("SKIP: live agent diverged from cached verdict -> taint kept",
					"node", node.Name, "pod", healthy.Name,
					"getErr", err != nil,
					"uidMatch", err == nil && live.UID == healthy.UID,
					"healthy", err == nil && ciliumPodHealthy(live))
				continue
			}
			log.Info("REAP: agent healthy but stale taint -> removing",
				"node", node.Name, "pod", healthy.Name)
			if err := kube.UntaintNode(ctx, r.cs, node.Name, kube.TaintCiliumAgentNotReady); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove taint %s on node %s: %w",
					kube.TaintCiliumAgentNotReady, node.Name, err)
			}
			reaped++
		} else {
			pod := onNode[0] // first pod, for diagnostics only
			log.Info("KEEP: no healthy agent -> taint is doing its job",
				"node", node.Name, "pods", len(onNode),
				"pod", pod.Name,
				"phase", pod.Status.Phase,
				"terminating", pod.DeletionTimestamp != nil,
				"ready", kube.PodReadyCond(pod))
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
		if t.Key == kube.TaintCiliumAgentNotReady {
			out = append(out, t)
		}
	}
	return out
}

// ciliumPodHealthy mirrors the bash "|Running|True" probe: not
// terminating, phase Running and Ready condition True.
func ciliumPodHealthy(p *corev1.Pod) bool {
	return p.DeletionTimestamp == nil &&
		p.Status.Phase == corev1.PodRunning && kube.PodReadyCond(p)
}

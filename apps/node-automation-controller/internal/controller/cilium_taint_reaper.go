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
package controller

import (
	"context"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
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

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const ciliumNotReadyTaint = "node.cilium.io/agent-not-ready"

type ciliumTaintReaper struct {
	cs      kubernetes.Interface
	enabled bool
}

func SetupCiliumTaintReaper(mgr ctrl.Manager, cs kubernetes.Interface, enabled bool) error {
	b := ctrl.NewControllerManagedBy(mgr).
		Named("cilium-taint-reaper").
		For(&corev1.Node{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(event.CreateEvent) bool { return true },
			DeleteFunc:  func(event.DeleteEvent) bool { return true },
			GenericFunc: func(event.GenericEvent) bool { return true },
			// bash jqFilter: fire only when THIS taint's entries change —
			// without it every kubelet heartbeat (~20s/node) would
			// enqueue a full-cluster sweep.
			UpdateFunc: func(e event.UpdateEvent) bool {
				oldN, ok1 := e.ObjectOld.(*corev1.Node)
				newN, ok2 := e.ObjectNew.(*corev1.Node)
				if !ok1 || !ok2 {
					return true
				}
				return !reflect.DeepEqual(ciliumStaleTaints(oldN), ciliumStaleTaints(newN))
			},
		}))
	if enabled {
		// Also react when a node's cilium pod flips Ready/not-Ready.
		// The pod informer is already scoped to kube-system +
		// k8s-app=cilium (manager cache options) and only exists when
		// enabled, so no extra predicate is needed.
		b = b.Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, o client.Object) []reconcile.Request {
				node := o.(*corev1.Pod).Spec.NodeName
				if node == "" {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: types.NamespacedName{Name: node},
				}}
			}))
	}
	return b.Complete(&ciliumTaintReaper{cs: cs, enabled: enabled})
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
	nodes, err := listNodes(ctx, r.cs)
	if err != nil {
		metrics.IncError("cilium-taint-reaper")
		return ctrl.Result{}, err
	}

	reaped := 0
	for i := range nodes {
		node := &nodes[i]
		if !hasTaint(node.Spec.Taints, ciliumNotReadyTaint) {
			continue
		}
		pods, err := r.cs.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=cilium",
			FieldSelector: "spec.nodeName=" + node.Name,
		})
		if err != nil {
			metrics.IncError("cilium-taint-reaper")
			return ctrl.Result{}, err
		}
		if len(pods.Items) == 0 {
			log.Info("SKIP: taint present but no cilium pod on node",
				"node", node.Name)
			continue
		}
		pod := &pods.Items[0]
		if ciliumPodHealthy(pod) {
			log.Info("REAP: agent healthy but stale taint -> removing",
				"node", node.Name, "pod", pod.Name)
			if err := untaintNode(ctx, r.cs, node.Name, ciliumNotReadyTaint); err != nil {
				metrics.IncError("cilium-taint-reaper")
				return ctrl.Result{}, err
			}
			reaped++
		} else {
			log.Info("KEEP: agent not healthy -> taint is doing its job",
				"node", node.Name, "pod", pod.Name,
				"phase", pod.Status.Phase,
				"terminating", pod.DeletionTimestamp != nil,
				"ready", podReadyCond(pod))
		}
	}
	log.Info("sweep done", "reaped", reaped)
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
		p.Status.Phase == corev1.PodRunning && podReadyCond(p)
}

// podReadyCond reports whether the pod's Ready condition is True.
func podReadyCond(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

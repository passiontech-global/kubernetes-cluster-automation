// descheduler_storm_gate.go — port of
// hooks/20-descheduler-storm-gate.sh.
//
// Gates deploy kube-system/descheduler on cluster health (kured
// philosophy: don't "rebalance" during an incident — LowNodeUtilization
// would keep shoving pods onto nodes that are flapping/overloaded and
// slow recovery, incident 2026-09-14).
//
// Storm verdict (kubectl-equivalent, no Prometheus):
//
//	a) every node must have Ready=True;
//	b) no node may hold a True condition from stormConds (NPD
//	   watchdog-state-monitor latches, network-problem-detector
//	   K8sExporter, kubelet pressure);
//	c) no node may carry a stormTaints key (set by reaper/evictor).
//
// Storm -> scale to 0, clear -> back to 1. The verdict + evidence is
// recorded in annotation passiontech.dev/storm-gate-decision for
// post-incident debugging; passiontech.dev/storm-gate-hold=true is a
// manual hold (game-day/runbook) that skips scaling. An API failure
// aborts the reconcile — never a "clear" verdict on empty data.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	stormGateHoldAnno     = "passiontech.dev/storm-gate-hold"
	stormGateDecisionAnno = "passiontech.dev/storm-gate-decision"
)

// stormConds mirrors STORM_CONDS (see package comment for sources).
var stormConds = []corev1.NodeConditionType{
	"KubeletRuntimeStall", "KubeletWatchWedge", "PodTeardownWedged",
	"WatchdogStale", "HostNetworkProblems", "ClusterNetworkProblems",
	"HostNetworkProblem", "ClusterNetworkProblem", "MemoryPressure",
	"DiskPressure", "NetworkUnavailable",
}

// stormTaints mirrors STORM_TAINTS.
var stormTaints = []string{
	"node.ops/kubelet-unresponsive", "node.ops/network-partitioned",
}

type deschedulerStormGate struct {
	cs kubernetes.Interface
}

func SetupDeschedulerStormGate(mgr ctrl.Manager, cs kubernetes.Interface) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("descheduler-storm-gate").
		// Watches with a single fixed workqueue key, not For(): the
		// reconcile ignores req.Name and always sweeps the whole
		// cluster, so per-node keys only produced N duplicate queued
		// requests + N independent RequeueAfter timers per informer
		// sync. One key collapses both to a single sweep (see
		// sweepRequests). Predicate semantics are unchanged.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(sweepRequests("descheduler-storm-gate-sweep")),
			builder.WithPredicates(predicate.Funcs{
				// Fire only when the fields the verdict reads actually
				// changed (bash jqFilter equivalent: {conds: type=status,
				// taints: keys}). Comparing raw Status.Conditions would fire
				// on every kubelet heartbeat — lastHeartbeatTime/Reason/
				// Message churn constantly.
				UpdateFunc: func(e event.UpdateEvent) bool {
					oldN, ok1 := e.ObjectOld.(*corev1.Node)
					newN, ok2 := e.ObjectNew.(*corev1.Node)
					if !ok1 || !ok2 {
						return true
					}
					return !reflect.DeepEqual(condStatusMap(oldN), condStatusMap(newN)) ||
						!reflect.DeepEqual(taintKeys(oldN), taintKeys(newN))
				},
				// Node add/remove changes the storm verdict too.
				CreateFunc:  func(event.CreateEvent) bool { return true },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				GenericFunc: func(event.GenericEvent) bool { return true },
			})).
		Complete(&deschedulerStormGate{cs: cs})
}

func (r *deschedulerStormGate) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 5 * time.Minute}

	nodes, err := listNodes(ctx, r.cs)
	if err != nil {
		metrics.IncError("descheduler-storm-gate")
		return ctrl.Result{}, err
	}

	var notReady, bad, tainted []string
	for i := range nodes {
		n := &nodes[i]
		if !nodeReady(n) {
			notReady = append(notReady, n.Name)
		}
		for _, c := range n.Status.Conditions {
			if c.Status == corev1.ConditionTrue &&
				slices.Contains(stormConds, c.Type) {
				bad = append(bad, n.Name+" "+string(c.Type))
			}
		}
		for _, t := range n.Spec.Taints {
			if slices.Contains(stormTaints, t.Key) {
				tainted = append(tainted, n.Name+" "+t.Key)
			}
		}
	}

	want := int32(1)
	verdict := "clear"
	if len(notReady) > 0 || len(bad) > 0 || len(tainted) > 0 {
		want, verdict = 0, "storm"
	}

	deploy, err := r.cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Info("SKIP: no descheduler deployment on this cluster",
			"verdict", verdict)
		return res, nil
	}
	if err != nil {
		metrics.IncError("descheduler-storm-gate")
		return ctrl.Result{}, err
	}

	if deploy.Annotations[stormGateHoldAnno] == "true" {
		log.Info("storm-gate HOLD (annotation "+stormGateHoldAnno+
			") - verdict computed but not scaling", "verdict", verdict)
		return res, nil
	}

	cur := int32(-1)
	curStr := ""
	if deploy.Spec.Replicas != nil {
		cur = *deploy.Spec.Replicas
		curStr = strconv.Itoa(int(cur))
	}
	decision := fmt.Sprintf("%s verdict=%s want=%d cur=%s not_ready=[%s] bad=[%s] tainted=[%s]",
		time.Now().UTC().Format(time.RFC3339), verdict, want, curStr,
		strings.Join(notReady, "\n"), strings.Join(bad, "\n"),
		strings.Join(tainted, "\n"))

	switch {
	case cur != want:
		log.Info("storm-gate: scaling replicas",
			"verdict", verdict, "from", curStr, "to", want,
			"notReady", notReady, "bad", bad, "tainted", tainted)
		w := want
		deploy.Spec.Replicas = &w
		if _, err := r.cs.AppsV1().Deployments("kube-system").
			Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
			metrics.IncError("descheduler-storm-gate")
			return ctrl.Result{}, err
		}
		if err := annotateStormDecision(ctx, r.cs, decision); err != nil {
			metrics.IncError("descheduler-storm-gate")
			return ctrl.Result{}, err
		}
	case deploy.Annotations[stormGateDecisionAnno] == "":
		// Replicas already right but no decision recorded yet —
		// annotate anyway so the verdict is auditable (bash elif).
		if err := annotateStormDecision(ctx, r.cs, decision); err != nil {
			metrics.IncError("descheduler-storm-gate")
			return ctrl.Result{}, err
		}
	default:
		log.Info("storm-gate: nothing to do",
			"verdict", verdict, "replicas", want)
	}
	return res, nil
}

// condStatusMap is the jqFilter projection: condition type -> status,
// dropping churny fields (lastHeartbeatTime, reason, message).
func condStatusMap(n *corev1.Node) map[corev1.NodeConditionType]corev1.ConditionStatus {
	m := make(map[corev1.NodeConditionType]corev1.ConditionStatus, len(n.Status.Conditions))
	for _, c := range n.Status.Conditions {
		m[c.Type] = c.Status
	}
	return m
}

// taintKeys is the jqFilter projection: taint keys in order.
func taintKeys(n *corev1.Node) []string {
	keys := make([]string, 0, len(n.Spec.Taints))
	for _, t := range n.Spec.Taints {
		keys = append(keys, t.Key)
	}
	return keys
}

// annotateStormDecision merge-patches the decision annotation onto the
// descheduler Deployment (kubectl annotate --overwrite equivalent).
func annotateStormDecision(ctx context.Context, cs kubernetes.Interface, value string) error {
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				stormGateDecisionAnno: value,
			},
		},
	})
	if err != nil {
		return err
	}
	_, err = cs.AppsV1().Deployments("kube-system").Patch(ctx,
		"descheduler", types.MergePatchType, payload, metav1.PatchOptions{})
	return err
}

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
//
// 2.7 — Cluster Maintenance Mutex. On top of the storm signals the
// gate also holds the descheduler at 0 while any deliberate
// maintenance is in flight, because rebalancing mid-maintenance
// fights the operator doing the work:
//
//	a) any node spec.unschedulable — a cordon/drain is running;
//	b) DaemonSet kube-system/kured carrying the
//	   weave.works/kured-node-lock annotation — a reboot drain in
//	   progress;
//	c) an autopilot.k0sproject.io/v1beta2 Plan exists whose
//	   status.state is neither Schedulable nor Completed — a k0s
//	   cluster upgrade is in flight.
//
// concourse-workdir-janitor shares the same three signals (it defers
// its worker wipe cycle entirely) — keep the checks in sync.
package deschedulerstormgate

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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	stormGateHoldAnno     = "passiontech.dev/storm-gate-hold"
	stormGateDecisionAnno = "passiontech.dev/storm-gate-decision"

	// kuredLockAnno is the reboot-coordination lock kured holds
	// while a node drains for its reboot window (2.7 signal b).
	kuredLockAnno = "weave.works/kured-node-lock"
	// kuredDaemonSet is where the lock annotation lives.
	kuredDaemonSetNS   = "kube-system"
	kuredDaemonSetName = "kured"
)

// autopilotPlanGVR is the k0s autopilot Plan resource — a Plan in a
// non-terminal state means a cluster upgrade is in flight (2.7
// signal c).
var autopilotPlanGVR = shared.AutopilotPlanGVR

// stormConds mirrors STORM_CONDS (see package comment for sources).
// NebulaIsolated/NebulaDegraded/NebulaPMTUBlackhole are the
// node-host-agent overlay conditions; KernelHungTasks,
// KernelSlabLeak, ClockUnsynchronized, CalicoFelixDown and
// CiliumIPAMExhausted are the node-problem-detector/CNI latches that
// make rebalancing actively harmful — same posture as the existing
// network-problem conditions.
var stormConds = []corev1.NodeConditionType{
	"KubeletRuntimeStall", "KubeletWatchWedge", "PodTeardownWedged",
	"WatchdogStale", "HostNetworkProblems", "ClusterNetworkProblems",
	"HostNetworkProblem", "ClusterNetworkProblem", "MemoryPressure",
	"DiskPressure", "NetworkUnavailable", "FilesystemReadOnly",
	"NebulaIsolated", "NebulaDegraded", "NebulaPMTUBlackhole",
	"KernelHungTasks", "KernelSlabLeak", "ClockUnsynchronized",
	"CalicoFelixDown", "CiliumIPAMExhausted",
}

// stormTaints mirrors STORM_TAINTS.
var stormTaints = []string{
	"node.ops/kubelet-unresponsive", "node.ops/network-partitioned",
}

type deschedulerStormGate struct {
	cs kubernetes.Interface
	// dyn reads the autopilot Plan CR for maintenance-mutex
	// signal (c) — no typed client exists for it.
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the controller name and every IncError label
	// come from one place.
	queue string
}

// The watch wiring below installs these package-level units
// verbatim — tests exercise the exact predicate/mapfunc the
// controller runs instead of introspecting controller-runtime
// internals.

// nodeSweepRequests collapses every Node event onto the single fixed
// sweep key (see shared.SweepRequests).
var nodeSweepRequests = shared.SweepRequests("descheduler-storm-gate-sweep")

// stormSignalChanges is the Node watch predicate — fire only when the
// fields the verdict reads actually changed (bash jqFilter
// equivalent: {conds: type=status, taints: keys}). Comparing raw
// Status.Conditions would fire on every kubelet heartbeat —
// lastHeartbeatTime/Reason/Message churn constantly.
var stormSignalChanges = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldN, ok1 := e.ObjectOld.(*corev1.Node)
		newN, ok2 := e.ObjectNew.(*corev1.Node)
		if !ok1 || !ok2 {
			return true
		}
		return oldN.Spec.Unschedulable != newN.Spec.Unschedulable ||
			!reflect.DeepEqual(condStatusMap(oldN), condStatusMap(newN)) ||
			!reflect.DeepEqual(taintKeys(oldN), taintKeys(newN))
	},
	// Node add/remove changes the storm verdict too.
	CreateFunc:  func(event.CreateEvent) bool { return true },
	DeleteFunc:  func(event.DeleteEvent) bool { return true },
	GenericFunc: func(event.GenericEvent) bool { return true },
}

func Setup(d shared.Deps) error {
	return ctrl.NewControllerManagedBy(d.Mgr).
		Named(d.Name).
		// Watches with a single fixed workqueue key, not For(): the
		// reconcile ignores req.Name and always sweeps the whole
		// cluster, so per-node keys only produced N duplicate queued
		// requests + N independent RequeueAfter timers per informer
		// sync. One key collapses both to a single sweep (see
		// shared.SweepRequests). Predicate semantics are unchanged.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(nodeSweepRequests),
			builder.WithPredicates(stormSignalChanges)).
		Complete(&deschedulerStormGate{cs: d.CS, dyn: d.Dyn, queue: d.Name})
}

func (r *deschedulerStormGate) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 5 * time.Minute}

	nodes, err := shared.ListNodes(ctx, r.cs)
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("list nodes: %w", err)
	}
	if len(nodes) == 0 {
		// An empty-but-successful node list is an apiserver/RBAC
		// flap, never a real cluster — without this gate the scan
		// below yields a "clear" verdict and scales the descheduler
		// back up on blind data (same fail-closed posture as the
		// statefulset-ondelete-roller's nodesSafe check).
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("empty node list (API flap) — refusing to compute a verdict")
	}

	var notReady, bad, tainted, cordoned []string
	now := time.Now()
	for i := range nodes {
		n := &nodes[i]
		if !shared.NodeReady(n) {
			notReady = append(notReady, n.Name)
		}
		// Only an ACTIVE cordon is a storm signal — a node statically
		// cordoned past the cordon window is deliberate state, and
		// counting it would pin the descheduler at 0 forever.
		if shared.NodeActivelyCordoned(n, now) {
			cordoned = append(cordoned, n.Name)
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

	// The deployment-exists check runs BEFORE the maintenance mutex:
	// on a cluster without descheduler there is nothing to gate, so
	// the kured GET + autopilot plans LIST (and their failure modes,
	// including an unwired dyn client) must not run at all.
	deploy, err := r.cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Info("SKIP: no descheduler deployment on this cluster")
		return res, nil
	}
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("get deployment kube-system/descheduler: %w", err)
	}

	// 2.7 maintenance mutex (signals b + c — signal a is the
	// `cordoned` list above): deliberate maintenance gates the
	// descheduler exactly like a storm does.
	maintenance, err := r.maintenanceEvidence(ctx)
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, err
	}

	want := int32(1)
	verdict := "clear"
	if len(notReady) > 0 || len(bad) > 0 || len(tainted) > 0 ||
		len(cordoned) > 0 || len(maintenance) > 0 {
		want, verdict = 0, "storm"
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
	decision := fmt.Sprintf("%s verdict=%s want=%d cur=%s not_ready=[%s] bad=[%s] tainted=[%s] cordoned=[%s] maintenance=[%s]",
		time.Now().UTC().Format(time.RFC3339), verdict, want, curStr,
		strings.Join(notReady, "\n"), strings.Join(bad, "\n"),
		strings.Join(tainted, "\n"), strings.Join(cordoned, "\n"),
		strings.Join(maintenance, "\n"))

	switch {
	case cur != want:
		log.Info("storm-gate: scaling replicas",
			"verdict", verdict, "from", curStr, "to", want,
			"notReady", notReady, "bad", bad, "tainted", tainted,
			"cordoned", cordoned, "maintenance", maintenance)
		// Merge-patch spec.replicas only — a full-object Update on a
		// cached Get races any concurrent spec edit (HPA, gitops)
		// and would clobber it or fail on resourceVersion.
		patch, err := json.Marshal(map[string]any{
			"spec": map[string]any{"replicas": want},
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("marshal replicas patch: %w", err)
		}
		if _, err := r.cs.AppsV1().Deployments("kube-system").
			Patch(ctx, "descheduler", types.MergePatchType, patch,
				metav1.PatchOptions{}); err != nil {
			metrics.IncError(r.queue)
			return ctrl.Result{}, fmt.Errorf(
				"scale deployment kube-system/descheduler to %d replicas: %w",
				want, err)
		}
		if err := annotateStormDecision(ctx, r.cs, decision); err != nil {
			metrics.IncError(r.queue)
			return ctrl.Result{}, err
		}
	case deploy.Annotations[stormGateDecisionAnno] == "":
		// Replicas already right but no decision recorded yet —
		// annotate anyway so the verdict is auditable (bash elif).
		if err := annotateStormDecision(ctx, r.cs, decision); err != nil {
			metrics.IncError(r.queue)
			return ctrl.Result{}, err
		}
	default:
		log.Info("storm-gate: nothing to do",
			"verdict", verdict, "replicas", want)
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// 2.7 — Cluster Maintenance Mutex (signals b + c; signal a is the
// spec.unschedulable scan inside Reconcile). Keep in sync with the
// copy inside concourse-workdir-janitor.
// ---------------------------------------------------------------------------

// maintenanceEvidence returns the human-readable evidence strings for
// maintenance-mutex signals (b) kured lock and (c) active autopilot
// Plan — an empty slice means "no maintenance in flight". A missing
// kured DaemonSet or an absent autopilot CRD is not evidence; real
// API failures are errors — a "clear" verdict must never be computed
// on blind data.
func (r *deschedulerStormGate) maintenanceEvidence(ctx context.Context) ([]string, error) {
	var ev []string

	// (b) kured holding its node-lock annotation means a reboot
	// drain is in progress right now.
	ds, err := r.cs.AppsV1().DaemonSets(kuredDaemonSetNS).
		Get(ctx, kuredDaemonSetName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// kured not installed on this cluster — no signal.
	case err != nil:
		return nil, fmt.Errorf("get daemonset %s/%s (maintenance mutex): %w",
			kuredDaemonSetNS, kuredDaemonSetName, err)
	default:
		if v := ds.Annotations[kuredLockAnno]; v != "" {
			ev = append(ev, "kured-lock="+v)
		}
	}

	// (c) Any autopilot Plan outside its terminal states means a
	// k0s upgrade is in flight. An absent CRD is not evidence —
	// clusters without autopilot skip quietly. A missing dynamic
	// client is a wiring bug, not "no signal" — unverifiable fails
	// closed like every other check in this function.
	if r.dyn == nil {
		return nil, fmt.Errorf("no dynamic client — autopilot plan check unverifiable (maintenance mutex)")
	}
	plans, err := r.dyn.Resource(autopilotPlanGVR).
		List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// autopilot CRD not installed — no signal.
	case err != nil:
		return nil, fmt.Errorf("list autopilot plans (maintenance mutex): %w", err)
	default:
		for i := range plans.Items {
			state, _, _ := unstructured.NestedString(
				plans.Items[i].Object, "status", "state")
			if state != "Schedulable" && state != "Completed" {
				ev = append(ev, fmt.Sprintf("plan=%s state=%s",
					plans.Items[i].GetName(), state))
			}
		}
	}
	return ev, nil
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
		return fmt.Errorf("marshal %s patch: %w", stormGateDecisionAnno, err)
	}
	if _, err := cs.AppsV1().Deployments("kube-system").Patch(ctx,
		"descheduler", types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch %s on deployment kube-system/descheduler: %w",
			stormGateDecisionAnno, err)
	}
	return nil
}

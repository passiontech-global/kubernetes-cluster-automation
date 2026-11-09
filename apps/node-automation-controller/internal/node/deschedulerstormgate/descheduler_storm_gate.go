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
//	c) no node may carry a stormTaints key (set by reaper/evictor);
//	d) preemption-cascade-signal — no PriorityClass preemption cascade: more than
//	   stormPreemptionMax reason=Preempted events inside
//	   stormPreemptionWindow is a domino eviction storm (a
//	   high-priority pod preempts victims that preempt their own
//	   victims) — the descheduler's evictions would add another
//	   wave on top.
//	e) image-pull-storm-gate — no cluster-wide image-pull storm: stormImagePullMinPods
//	   pods or stormImagePullMinNamespaces namespaces with containers
//	   waiting in ImagePullBackOff/ErrImagePull mean images are not
//	   landing; rescheduling pods onto other nodes just spreads
//	   unrunnable pods around (kube.ImagePullStallReason /
//	   CountImagePullStalledPods, the census the roller defers on
//	   too).
//
// Storm -> scale to 0, clear -> back to 1. The verdict + evidence is
// recorded in annotation passiontech.dev/storm-gate-decision for
// post-incident debugging; passiontech.dev/storm-gate-hold=true is a
// manual hold (game-day/runbook) that skips scaling. An API failure
// aborts the reconcile — never a "clear" verdict on empty data.
//
// maintenance-hold-stale — forgotten maintenance holds are warned about: a hold kept
// "true" continuously past maintenanceHoldStaleAfter fires ONE
// Warning event MaintenanceHoldStale on the descheduler Deployment
// (first-seen tracked under kube.AnnoFirstSeenStormGateHold — the
// hold annotation itself carries no timestamp), and a NodeHealthCheck
// whose spec.pauseRequests has been non-empty equally long fires the
// same warning on the NHC object (kube.AnnoFirstSeenNHCPause). No NHC
// watcher exists in this controller, so the NHC probe rides this
// module's 5m sweep — one warning per hold/pause episode, re-armed
// only when the hold releases.
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
// concourse-workdir-janitor defers on the same three signals — all
// of them now live in internal/shared (MaintenanceActive plus the
// per-signal *Evidence helpers), the single canonical implementation
// every deferring module runs.
package deschedulerstormgate

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

const (
	stormGateHoldAnno     = kube.AnnoStormGateHold
	stormGateDecisionAnno = kube.AnnoStormGateDecision

	// preemption-cascade-signal — preemption-cascade knobs, matched to
	// scheduler-watchdog's: an ordinary scheduler emits a handful
	// of Preempted events during placement churn; more than the
	// ceiling inside the window is a domino cascade.
	stormPreemptionWindow = 5 * time.Minute
	stormPreemptionMax    = 15

	// image-pull-storm-gate — image-pull storm thresholds (storm signal (e)): 3
	// stuck pods in one namespace is one broken Deployment, but
	// three pods anywhere — or members of sets in TWO namespaces —
	// is a cluster-level pull problem (same shape as the image-pull-storm
	// health check's classification, tightened to the gating
	// verdict).
	stormImagePullMinPods       = 3
	stormImagePullMinNamespaces = 2

	// maintenance-hold-stale — a maintenance hold (storm-gate-hold annotation or a
	// NodeHealthCheck spec.pauseRequests) kept continuously past
	// this age is a forgotten one: the Warning
	// MaintenanceHoldStale event asks the operator to confirm it is
	// still wanted. One warning per episode — re-armed only when
	// the hold releases.
	maintenanceHoldStaleAfter  = 2 * time.Hour
	maintenanceHoldStaleReason = "MaintenanceHoldStale"
	// stormHoldLedgerKey is the single ledger key the descheduler
	// Deployment's hold first-seen stamp rides.
	stormHoldLedgerKey = "kube-system/descheduler"
)

// stormConds mirrors STORM_CONDS (see package comment for sources) —
// names come from nodecond.StormGateNames, the single source of truth
// shared with the node-host-agent, so this list can no longer drift
// from the names the agent actually emits (the agent's spellings
// SystemdSessionBloat/ConntrackPressure/JournaldUnreadable/
// ControlPlaneCertReloadStale replaced the controller's legacy
// SystemdSessionLeak/ConntrackExhausted/JournaldWedged/
// ControlPlaneFrozen, and CiliumBPFMapPressure joined the set).
// NebulaIsolated/NebulaDegraded/NebulaPMTUBlackhole are the
// node-host-agent overlay conditions; KernelHungTasks,
// KernelSlabLeak, KernelResourceExhaustion, CgroupDyingLeak,
// MemoryPSIThrashing, ClockUnsynchronized, ClockSkewDetected
// (node-hang-extra-conds — chrony still synced but >2s offset), InodePressure,
// KubeletPLEGUnhealthy, CalicoFelixDown, CiliumIPAMExhausted and the
// remaining Cilium* latches are the
// node-problem-detector/kubelet/CNI latches that make rebalancing
// actively harmful — same posture as the existing network-problem
// conditions.
var stormConds = kube.CondTypes(nodecond.StormGateNames)

// stormCondHeartbeatMaxAge is how old a nodereporter-owned storm
// condition's lastHeartbeatTime may be before its True stops gating
// the verdict — the reporter re-stamps it every ~2m while alive, so a
// frozen or absent stamp means the value is a zombie left by a dead
// agent (same 10m convention as nodehealth's precordon gate).
const stormCondHeartbeatMaxAge = 10 * time.Minute

// stormTaints mirrors STORM_TAINTS — now driven by
// kube.RemediationTaints so all four remediation taints (incl.
// node-hang-precordon and cpu-steal) count toward the gate and a
// new remediation taint cannot silently bypass it (W19-T1).
var stormTaints = kube.RemediationTaints

type deschedulerStormGate struct {
	cs kubernetes.Interface
	// nodeReader is the informer-backed node read — the storm
	// verdict's census rides the Node watch this reconciler
	// already registers instead of an apiserver LIST per run.
	nodeReader kube.CachedNodeReader
	// dyn reads the autopilot Plan CR for maintenance-mutex
	// signal (c) — no typed client exists for it.
	dyn dynamic.Interface
	// recorder emits the maintenance-hold-stale MaintenanceHoldStale warnings — the
	// manager-provided event recorder. nil (StubManager tests)
	// drops the event rather than panicking.
	recorder events.EventRecorder
	// holdSeen persists the storm-gate-hold first-seen window across
	// operator restarts (the annotation half is
	// kube.AnnoFirstSeenStormGateHold on the Deployment);
	// holdWarned is the emitted-once tracker for the current hold
	// episode (a SeenSet key, not a gauge — there is no series, only
	// one Warning per episode). nhcSeen/nhcWarned are the same pair
	// for NodeHealthCheck pauseRequests, keyed per NHC object.
	// All zero-value ready — literal-constructed test fixtures need
	// no Setup path; the reconciler is single-keyed so no lock.
	holdSeen   state.FirstSeenLedger
	holdWarned state.SeenSet
	nhcSeen    state.FirstSeenLedger
	nhcWarned  state.SeenSet
	// now is the clock seam — tests pin it so the cordon-window and
	// decision-stamp reads are deterministic. nil → time.Now.
	now shared.Clock
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
	// SetupNoConfig honors Deps.Disabled before the builder ever
	// runs — a gated-off module registers no controller, no watch,
	// no informer.
	return shared.SetupNoConfig(d, func() error {
		r := &deschedulerStormGate{cs: d.CS, nodeReader: d.Mgr.GetClient(), dyn: d.Dyn, now: shared.SystemClock,
			recorder: d.Mgr.GetEventRecorder(d.Name)}
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
			Complete(shared.CountReconcile(d.Name, r.Reconcile))
	})
}

// Reconcile runs one storm-gate sweep: collect the node-local and
// cluster-wide storm evidence, then — unless the deployment is
// absent or a manual hold is set — scale kube-system/descheduler
// to match the verdict. Evidence collection lives in
// descheduler_storm_signals.go; the verdict/scale act in
// descheduler_storm_act.go.
func (r *deschedulerStormGate) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 5 * time.Minute}
	now := r.now.Now()

	ev, err := r.nodeStormSignals(ctx, now)
	if err != nil {
		return ctrl.Result{}, err
	}

	// The deployment-exists check runs BEFORE the maintenance mutex:
	// on a cluster without descheduler there is nothing to gate, so
	// the kured GET + autopilot plans LIST (and their failure modes,
	// including an unwired dyn client) must not run at all.
	deploy, err := r.cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Info("SKIP: no descheduler deployment on this cluster")
		// The stamp dies with the object — the in-RAM half of the
		// hold bookkeeping must die with it too, or a deployment
		// recreated later (hold still set) would inherit a window
		// measured against the previous object's lifetime.
		r.holdSeen.Forget(stormHoldLedgerKey)
		r.holdWarned.Forget(stormHoldLedgerKey)
		return res, nil
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get deployment kube-system/descheduler: %w", err)
	}

	// maintenance-hold-stale (NHC half): a NodeHealthCheck whose spec.pauseRequests has
	// been non-empty past maintenanceHoldStaleAfter is a forgotten
	// maintenance pause — warn once. It sits behind the
	// deployment-exists skip like the mutex reads: a cluster without
	// descheduler never pays for (or fails on) the NHC list, and a
	// nil dynamic client errors the reconcile instead of reading as
	// "nothing paused" (fail closed). An absent CRD is an empty
	// scan.
	if err := r.checkNHCPauseStale(ctx, now, log); err != nil {
		return ctrl.Result{}, err
	}

	// 2.7 maintenance mutex (signals b + c — signal a is the
	// `cordoned` list inside nodeStormSignals): deliberate
	// maintenance gates the descheduler exactly like a storm does.
	maintenance, err := r.maintenanceEvidence(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	ev.maintenance = maintenance

	// The cluster-wide storm reads run AFTER the deployment-exists
	// skip so a cluster without descheduler never pays for (or fails
	// on) them; a list error aborts the reconcile — never a "clear"
	// verdict on blind data.
	if err := r.clusterStormSignals(ctx, now, ev); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.applyVerdict(ctx, deploy, ev, now, log); err != nil {
		return ctrl.Result{}, err
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// 2.7 — Cluster Maintenance Mutex (signals b + c; signal a is the
// NodeActivelyCordoned scan inside Reconcile).
// ---------------------------------------------------------------------------

// maintenanceEvidence returns the human-readable evidence strings for
// maintenance-mutex signals (b) kured lock, (c) active autopilot
// Plan and (d) in-flight medik8s remediations (SNR/FAR/
// NodeMaintenance) — an empty slice means "no maintenance in
// flight". The checks themselves are the shared mutex helpers (one
// implementation for every deferring module): a missing kured
// DaemonSet or an absent autopilot/medik8s CRD is not evidence;
// real API failures — including a nil dynamic client — are errors,
// so a "clear" verdict is never computed on blind data.
func (r *deschedulerStormGate) maintenanceEvidence(ctx context.Context) ([]string, error) {
	kured, err := kube.KuredLockEvidence(ctx, r.cs)
	if err != nil {
		return nil, err
	}
	plans, err := kube.AutopilotPlanEvidence(ctx, r.dyn)
	if err != nil {
		return nil, err
	}
	remediations, err := kube.Medik8sRemediationEvidence(ctx, r.dyn)
	if err != nil {
		return nil, err
	}
	return append(append(kured, plans...), remediations...), nil
}

// ---------------------------------------------------------------------------
// maintenance-hold-stale — forgotten maintenance holds (MaintenanceHoldStale).
// ---------------------------------------------------------------------------

// checkHoldStale fires the one-per-episode MaintenanceHoldStale
// Warning for a storm-gate-hold="true" annotation held continuously
// past maintenanceHoldStaleAfter. The hold annotation carries no
// timestamp, so the window lives under
// kube.AnnoFirstSeenStormGateHold on the Deployment (the annotation
// half of heal.FirstSeenPersisted — a restart resumes the window
// instead of re-arming it) with r.holdSeen as the in-RAM half. The
// Warning rides the manager's event recorder; a nil recorder
// (StubManager tests) drops it rather than panicking.
func (r *deschedulerStormGate) checkHoldStale(ctx context.Context,
	deploy *appsv1.Deployment, now time.Time, log logr.Logger) {
	if !heal.FirstSeenPersisted(ctx, log, &r.holdSeen, deploy,
		kube.AnnoFirstSeenStormGateHold, stormHoldLedgerKey,
		maintenanceHoldStaleAfter, now, r.deployAnnoPatch()) {
		return // window not yet held out — nothing to warn about
	}
	if !r.holdWarned.Add(stormHoldLedgerKey) {
		return // this episode already warned — no spam on re-reconciles
	}
	if r.recorder != nil {
		r.recorder.Eventf(deploy, nil, corev1.EventTypeWarning,
			maintenanceHoldStaleReason, "StormGateHoldStale",
			"storm-gate hold annotation %s has been \"true\" for more than %s — "+
				"confirm the maintenance hold is still wanted",
			stormGateHoldAnno, maintenanceHoldStaleAfter)
	}
	log.Info("WARN: storm-gate hold is stale",
		"deployment", stormHoldLedgerKey,
		"annotation", stormGateHoldAnno,
		"heldForMoreThan", maintenanceHoldStaleAfter)
}

// deployAnnoPatch delivers the hold's first-seen stamp merge patch
// onto the descheduler Deployment — the same merge-patch-only
// contract the scale path runs (no full-object Update that would
// race a concurrent spec edit).
func (r *deschedulerStormGate) deployAnnoPatch() func(context.Context, []byte) error {
	return func(ctx context.Context, data []byte) error {
		if _, err := r.cs.AppsV1().Deployments("kube-system").Patch(ctx,
			"descheduler", types.MergePatchType, data, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf(
				"patch first-seen annotation on deployment kube-system/descheduler: %w", err)
		}
		return nil
	}
}

// checkNHCPauseStale is the NHC half of maintenance-hold-stale: every NodeHealthCheck
// whose spec.pauseRequests has been non-empty past
// maintenanceHoldStaleAfter gets the same one-per-episode
// MaintenanceHoldStale Warning on the NHC object itself, window
// tracked under kube.AnnoFirstSeenNHCPause. A released pause clears
// the stamp (re-arms the full window for the next pause) and resets
// the emitted-once marker; objects that vanish take their ledger
// entries with them via the live prune. NHC is cluster-scoped, so
// keys are bare names. One stamp key per object and one visit per
// sweep — the patch closure needs no read-back mirror into the
// listed object (olmCRPatch mirrors because several live reasons
// share ONE CSV's map; here nothing re-reads the annotation after
// the patch).
func (r *deschedulerStormGate) checkNHCPauseStale(ctx context.Context,
	now time.Time, log logr.Logger) error {
	if r.dyn == nil {
		return errors.New(
			"no dynamic client — NodeHealthCheck pause-staleness probe unverifiable")
	}
	list, err := kube.ListAllUnstructured(ctx,
		r.dyn.Resource(kube.GVRNodeHealthCheck),
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return nil // CRD absent on this cluster — nothing to probe
	case err != nil:
		return fmt.Errorf("list nodehealthchecks (pause staleness): %w", err)
	}
	live := make(map[string]bool, len(list.Items))
	for i := range list.Items {
		obj := &list.Items[i]
		key := obj.GetName()
		live[key] = true
		pauseRequests, _, _ := unstructured.NestedStringSlice(
			obj.Object, "spec", "pauseRequests")
		if len(pauseRequests) == 0 {
			// Pause released — the episode ended: drop the stamp and
			// the emitted-once marker so a later pause warns fresh.
			if err := heal.ClearPersistedFirstSeen(ctx, log, &r.nhcSeen,
				obj, kube.AnnoFirstSeenNHCPause, key, r.nhcAnnoPatch(obj)); err != nil {
				log.Info("WARN: NHC pause first-seen clear failed — "+
					"a stale stamp could fast-trip a recurrence",
					"nodehealthcheck", key, "error", err)
			}
			r.nhcWarned.Forget(key)
			continue
		}
		if !heal.FirstSeenPersisted(ctx, log, &r.nhcSeen, obj,
			kube.AnnoFirstSeenNHCPause, key,
			maintenanceHoldStaleAfter, now, r.nhcAnnoPatch(obj)) {
			continue // window not yet held out
		}
		if !r.nhcWarned.Add(key) {
			continue // this pause episode already warned — no spam
		}
		if r.recorder != nil {
			r.recorder.Eventf(obj, nil, corev1.EventTypeWarning,
				maintenanceHoldStaleReason, "NodeHealthCheckPauseStale",
				"spec.pauseRequests has been non-empty for more than %s — "+
					"confirm the pause is still wanted",
				maintenanceHoldStaleAfter)
		}
		log.Info("WARN: NodeHealthCheck pause is stale",
			"nodehealthcheck", key,
			"pauseRequests", len(pauseRequests))
	}
	r.nhcWarned.Prune(func(key string) bool { return live[key] })
	r.nhcSeen.Prune(func(key string) bool { return live[key] })
	return nil
}

// nhcAnnoPatch delivers the NHC's first-seen stamp merge patch via
// the dynamic client (cluster-scoped resource — no namespace).
func (r *deschedulerStormGate) nhcAnnoPatch(
	obj *unstructured.Unstructured) func(context.Context, []byte) error {
	return func(ctx context.Context, data []byte) error {
		_, err := r.dyn.Resource(kube.GVRNodeHealthCheck).Patch(ctx,
			obj.GetName(), types.MergePatchType, data, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch %s on nodehealthcheck %s: %w",
				kube.AnnoFirstSeenNHCPause, obj.GetName(), err)
		}
		return nil
	}
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
// descheduler Deployment (kubectl annotate --overwrite equivalent) —
// used on the steady-replicas path only; the scale path folds the
// same annotation into its replicas patch above.
func annotateStormDecision(ctx context.Context, cs kubernetes.Interface, value string) error {
	payload, err := kube.MergePatchAnnos(map[string]any{
		stormGateDecisionAnno: value,
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

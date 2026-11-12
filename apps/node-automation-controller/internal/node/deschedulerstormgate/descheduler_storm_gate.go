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
//
// File layout: this file holds the module contract, the gate
// constants/struct, the watch wiring call in Setup, and the
// Reconcile pipeline plus the decision annotation patch;
// descheduler_storm_signals.go the evidence collection,
// descheduler_storm_act.go the verdict/scale act,
// descheduler_storm_watch.go the Node watch predicate and node
// projections, descheduler_storm_hold.go the
// maintenance-hold-stale warnings.
package deschedulerstormgate

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
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
// new remediation taint cannot silently bypass it (remediation-taint-detect).
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
	// maintVerdict memoizes the maintenance-mutex evaluation (the
	// exact kube.Verdict pattern partition-evictor hangs on its
	// sweep): the Node watch fans every storm-signal flip into this
	// single-key sweep, and without the memo each node-event
	// reconcile re-paid the mutex's 3+ dynamic API reads (kured get,
	// autopilot Plan list, medik8s remediation lists). One
	// evaluation per verdict TTL (~1m, kube.verdictTTL), error
	// verdicts sticky for the window too — fail closed. Zero value
	// ready (expired — evaluates on first use).
	maintVerdict *maintenance.Verdict
	// now is the clock seam — tests pin it so the cordon-window and
	// decision-stamp reads are deterministic. nil → time.Now.
	now shared.Clock
}

func Setup(d shared.Deps) error {
	// SetupNoConfig honors Deps.Disabled before the builder ever
	// runs — a gated-off module registers no controller, no watch,
	// no informer.
	return shared.SetupNoConfig(d, func() error {
		r := &deschedulerStormGate{
			maintVerdict: d.Maintenance, cs: d.CS, nodeReader: d.Mgr.GetClient(), dyn: d.Dyn, now: shared.SystemClock,
			recorder: d.Mgr.GetEventRecorder(d.Name)}
		if r.maintVerdict == nil {
			// Tests wire Deps literally (Maintenance unset): fall
			// back to a private memoized verdict — the pre-extraction
			// per-module kube.Verdict semantics.
			r.maintVerdict = &maintenance.Verdict{}
		}
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
	// Memoized on the reconciler (r.maintVerdict, ~1m TTL): a node
	// storm-signal flip fans one of these sweeps into the queue, so
	// without the memo every node-event reconcile re-paid the
	// mutex's 3+ dynamic reads. Active returns the canonical
	// first-signal evidence (why) — the decision annotation carries
	// that one string rather than the old full multi-signal list,
	// the same evidence every other deferring module records. A nil
	// dyn client or a real API failure still errors the reconcile
	// (fail closed) and is sticky for the TTL window.
	held, why, err := r.maintVerdict.Active(ctx, r.cs, r.dyn, now)
	if err != nil {
		return ctrl.Result{}, err
	}
	if held {
		ev.maintenance = []string{why}
	}

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

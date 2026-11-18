// pdb-deadlock-watchdog — runtime auditor for PodDisruptionBudgets
// that silently deadlock drains (C2).
//
// A PDB reporting status.expectedPods > 0 with
// status.disruptionsAllowed == 0 is a drain blocker: the eviction API
// refuses every voluntary disruption, so `kubectl drain`, kured
// reboots and k0s upgrades stall on it forever with no error —
// workloads look healthy while node maintenance is wedged.
//
// Three distinct root causes are surfaced through the `reason` label
// of node_automation_pdb_drain_blocked, each gated by its own
// "continuously for N" window so a deploy-time zero-disruption blip
// or a mid-rollout status flap never pages:
//
//   - impossible_policy (>=10m): status.desiredHealthy >=
//     status.expectedPods — the PDB can mathematically never open a
//     disruption slot (minAvailable >= replicas, or a maxUnavailable
//     that rounds to 0 against the live pod count). No amount of
//     waiting helps; the spec itself has to change.
//   - cordoned_node_blocked (>=15m): at least one node is
//     spec.unschedulable AND disruptions stay pinned at 0 — the
//     classic half-finished drain: the cordon keeps replacement pods
//     pending, so currentHealthy never reaches desiredHealthy and
//     every subsequent eviction is refused. Self-reinforcing
//     deadlock, not a transient.
//   - prolonged_zero_disruptions (>=30m): disruptionsAllowed has been
//     0 for half an hour regardless of root cause — the catch-all for
//     a stuck PDB controller (lost pod watch, selector drifted off
//     every pod, controller outage freezing status).
//
// Multiple reasons can hold for the same PDB at once — the label is a
// root-cause attribution, not a winner-takes-all verdict.
//
// Detect-only: the module exports the gauge and warn-logs; it never
// patches or deletes a PDB — the fix is a human choosing to relax
// minAvailable, finish the cordoned drain, or restart the stuck
// controller.
package pdbdeadlockwatchdog

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// reason label values for metrics.PDBDrainBlocked — keep in sync
	// with the metric's Help text and the alert rules consuming it.
	pdbReasonImpossiblePolicy = "impossible_policy"
	pdbReasonCordonedNode     = "cordoned_node_blocked"
	pdbReasonProlonged        = "prolonged_zero_disruptions"

	// Per-reason "continuously for" thresholds — ordered shortest to
	// longest so a mathematically impossible PDB surfaces first, then
	// the cordon deadlock, then the generic catch-all. The sweep runs
	// every 5m, so each threshold spans at least two consecutive
	// cycles before it can fire.
	pdbImpossibleMinAge = 10 * time.Minute
	pdbCordonedMinAge   = 15 * time.Minute
	pdbProlongedMinAge  = 30 * time.Minute

	// pdbReliefPodMinAge is the pod-level unready fuse for the
	// cordoned-block relief: the failing pod must have been
	// Ready=False at least this long before the PDB patch / pod
	// delete is even considered — a pod that just flapped during
	// the drain is not the wedge.
	pdbReliefPodMinAge = 5 * time.Minute
	// pdbReliefDeleteMinAge is the stricter fuse for the pod-DELETE
	// fallback (the Flux-gate-denied path): the pod must be
	// continuously unready this long before a raw delete is spent.
	pdbReliefDeleteMinAge = 30 * time.Minute
	// pdbReliefCooldown bounds PDB patches per object and pod
	// deletes per pod.
	pdbReliefCooldown = 30 * time.Minute
)

// pdbConfig is the module's env-resolved knob set — read ONCE in
// Setup before the Disabled gate (SetupWithConfig ordering).
type pdbConfig struct {
	// unhealthyEvictionPatch allows the spec patch that sets
	// unhealthyPodEvictionPolicy=AlwaysAllow on a blocked PDB
	// (PDB_UNHEALTHY_EVICTION_PATCH_ENABLED, default true).
	unhealthyEvictionPolicyPatch bool
	// cordonedUnhealthyRelief allows the pod-delete fallback that
	// unblocks a cordoned-node drain when the PDB patch cannot
	// land (PDB_CORDONED_UNHEALTHY_RELIEF_ENABLED, default true).
	cordonedUnhealthyRelief bool
}

// pdbConfigFromEnv resolves the PDB_* knobs.
func pdbConfigFromEnv() pdbConfig {
	return pdbConfig{
		unhealthyEvictionPolicyPatch: envx.Gate("PDB_UNHEALTHY_EVICTION_PATCH_ENABLED", true),
		cordonedUnhealthyRelief:      envx.Gate("PDB_CORDONED_UNHEALTHY_RELIEF_ENABLED", true),
	}
}

var (
	// node_automation_pdb_unhealthy_policy_patched_total counts
	// successful unhealthyPodEvictionPolicy=AlwaysAllow patches the
	// cordoned-block relief delivered.
	pdbUnhealthyPolicyPatchedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_automation_pdb_unhealthy_policy_patched_total",
		Help: "PDBs patched to unhealthyPodEvictionPolicy=AlwaysAllow by the cordoned-block relief — pdb-deadlock-watchdog.",
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(pdbUnhealthyPolicyPatchedTotal)
}

// drainBlockedKey is the blockedEmitted ledger's dedup key — one
// node_automation_pdb_drain_blocked series per
// (namespace, pdb, reason) tuple.
type drainBlockedKey struct {
	ns, name, reason string
}

type pdbDeadlockWatchdog struct {
	cs         kubernetes.Interface
	dyn        dynamic.Interface
	nodeReader kube.CachedNodeReader
	// maintenance is the shared maintenance-mutex verdict the relief
	// heals gate on (nil falls back to a fresh verdict per call).
	maintenance *maintenance.Verdict
	// cfg carries the PDB_* env knobs resolved in Setup.
	cfg pdbConfig
	// heals is the relief cooldown ledger — PDB patches key per
	// "<ns>/<name>", pod deletes per "<ns>/<name>/<pod>".
	heals state.CooldownSet
	// firstSeen records when each "<ns>/<name>/<reason>" precondition
	// STARTED holding — "continuously >= N" means now-firstSeen >= N
	// with no gap. Any cycle where the precondition drops deletes the
	// entry, restarting the window; any cycle where the PDB vanishes
	// prunes all of its entries.
	firstSeen state.FirstSeenLedger
	// blockedEmitted tracks which (ns, pdb, reason) tuples had their
	// node_automation_pdb_drain_blocked series Set last sweep — a
	// reason that resolves gets its series deleted outright
	// (DeleteLabelValues, same hygiene as ForgetAPIBackend) instead
	// of pinning at its last value forever.
	blockedEmitted state.GaugeLedger[drainBlockedKey]
	// now is the wall-clock seam so tests can age sightings without
	// sleeping 30 minutes.
	now shared.Clock
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name comes from one place.
	queue string
}

// Setup registers the 5-minute sweep when the
// PDB_WATCHDOG_ENABLED flag is on (resolved by setupModules into
// Deps.Disabled). Disabled clusters register nothing at all — same
// contract as cilium-taint-reaper: no runnable, no periodic
// cluster-wide LIST against the apiserver. The PDB_* relief knobs
// parse BEFORE the Disabled gate (SetupWithConfig ordering) so a
// malformed value still warns on a gated-off module.
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, pdbConfigFromEnv,
		func(cfg pdbConfig) error {
			w := &pdbDeadlockWatchdog{
				cs:          d.CS,
				dyn:         d.Dyn,
				nodeReader:  d.CachedClient(),
				maintenance: d.Maintenance,
				cfg:         cfg,
				now:         shared.SystemClock,
				queue:       d.Name,
			}
			return shared.AddPeriodic(d.Mgr, w.queue, 5*time.Minute, w.run)
		})
}

func (w *pdbDeadlockWatchdog) run(ctx context.Context) error {
	w.blockedEmitted.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)

	// Node list first — "at least one cordoned node" is a cluster-wide
	// input to the per-PDB verdict. Failing to read it must abort the
	// run: treating it as "no cordon" would silently clear every
	// cordoned_node_blocked series mid-incident. pinned-volume-guard:
	// NodeActivelyCordoned — a statically-cordoned node past the
	// cordon-active window is deliberate state, not a drain in
	// flight, and must not pin cordoned_node_blocked forever.
	now := w.now.Now()
	w.heals.PruneExpired(now, pdbReliefCooldown)
	nodes, err := kube.ListNodesCached(ctx, w.nodeReader, w.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	// cordoned is the actively-cordoned node name set — cluster-wide
	// evidence alone is not enough for cordoned_node_blocked: the
	// PDB's own pods must actually sit on one of these nodes (an
	// unrelated cordon must not pin every blocked PDB's series).
	cordoned := map[string]bool{}
	for i := range nodes {
		if kube.NodeActivelyCordoned(&nodes[i], now) {
			cordoned[nodes[i].Name] = true
		}
	}
	anyCordoned := len(cordoned) > 0
	nodes = nil

	pdbs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PodDisruptionBudgets(w.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list poddisruptionbudgets: %w", err)
	}
	// seen collects every "<ns>/<name>/<reason>" key whose precondition
	// held THIS cycle — the prune pass below treats anything else in
	// firstSeen as either resolved or gone.
	seen := make(map[string]struct{})
	flagged := 0
	for i := range pdbs {
		p := &pdbs[i]
		// The shared base condition for every reason: the PDB is
		// actually blocking drains right now. expectedPods == 0 means
		// it protects nothing (selector drifted off every pod — status
		// noise, not a deadlock); disruptionsAllowed > 0 means the
		// eviction API can proceed.
		blocked := p.Status.ExpectedPods > 0 && p.Status.DisruptionsAllowed == 0
		// cordoned_node_blocked requires the PDB's own pods on a
		// cordoned node — computed lazily so the pod list only runs
		// for PDBs that are actually blocking right now.
		cordonedBlocked := false
		if blocked && anyCordoned {
			cordonedBlocked = w.pdbPodsOnCordonedNodes(ctx, p, cordoned)
		}
		reasons := []struct {
			name   string
			holds  bool
			minAge time.Duration
		}{
			{pdbReasonImpossiblePolicy,
				blocked && p.Status.DesiredHealthy >= p.Status.ExpectedPods,
				pdbImpossibleMinAge},
			{pdbReasonCordonedNode, cordonedBlocked, pdbCordonedMinAge},
			{pdbReasonProlonged, blocked, pdbProlongedMinAge},
		}
		reported := false
		for _, r := range reasons {
			if !r.holds {
				continue
			}
			key := p.Namespace + "/" + p.Name + "/" + r.name
			seen[key] = struct{}{}
			first, tracked := w.firstSeen.Observe(key, now)
			if !tracked {
				// First sighting — the ledger just opened the
				// continuity window; the gauge stays unset until
				// the reason holds across its full threshold
				// without a gap.
				continue
			}
			if now.Sub(first) < r.minAge {
				continue
			}
			w.blockedEmitted.Set(metrics.PDBDrainBlocked, 1,
				drainBlockedKey{ns: p.Namespace, name: p.Name, reason: r.name},
				p.Namespace, p.Name, r.name)
			reported = true
			log.Info("PDB blocking drains",
				"pdb", p.Namespace+"/"+p.Name, "reason", r.name,
				"expectedPods", p.Status.ExpectedPods,
				"desiredHealthy", p.Status.DesiredHealthy,
				"currentHealthy", p.Status.CurrentHealthy,
				"since", first.Format(time.RFC3339))
			// The cordoned-node deadlock is the one reason with an
			// automated relief: patch unhealthyPodEvictionPolicy or
			// delete the wedged pod so the drain can finish.
			if r.name == pdbReasonCordonedNode {
				w.relieveCordonedBlock(ctx, log, now, p, cordoned)
			}
		}
		if reported {
			flagged++
		}
	}
	pdbs = nil

	// Prune first-seen entries for reasons that stopped holding or
	// PDBs that vanished — "continuously" resets on any gap.
	w.firstSeen.Prune(func(key string) bool {
		_, ok := seen[key]
		return ok
	})
	// Series hygiene is the ledger's job: every tuple emitted last
	// sweep that was not re-asserted this sweep is deleted outright —
	// a stale label set must not outlive its object (same
	// DeleteLabelValues hygiene as ForgetAPIBackend). Prune runs
	// only after a complete, verified sweep: the early returns above
	// keep a partial/failed list from pruning live series.
	w.blockedEmitted.Prune(metrics.PDBDrainBlocked.DeleteLabelValues)
	// Post-prune the first-seen ledger holds exactly the keys still
	// tracked — the same set `seen` collected this cycle.
	log.Info("sweep done", "flagged", flagged, "tracked", len(seen))
	return nil
}

// pdbPodsOnCordonedNodes reports whether at least one pod the PDB
// selects sits on an actively-cordoned node — the cordon keeps its
// replacement from scheduling, which is what makes the drain
// deadlock real. A pod in a terminal phase does not count (it is
// already on its way out). Fail closed: an unreadable selector or a
// failed pod list keeps the flag (a false cordoned_node_blocked is
// loud; a silently-cleared one hides a live drain wedge).
func (w *pdbDeadlockWatchdog) pdbPodsOnCordonedNodes(ctx context.Context,
	p *policyv1.PodDisruptionBudget, cordoned map[string]bool) bool {

	if p.Spec.Selector == nil {
		return false // policy/v1 nil selector matches no pods
	}
	sel, err := metav1.LabelSelectorAsSelector(p.Spec.Selector)
	if err != nil {
		logf.FromContext(ctx).Error(err, "PDB selector unparseable — keeping cordoned verdict",
			"pdb", p.Namespace+"/"+p.Name)
		return true
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		Limit:         kube.DefaultListPageSize,
		LabelSelector: sel.String(),
	}, kube.Pods(w.cs, p.Namespace))
	if err != nil {
		metrics.IncError(w.queue)
		logf.FromContext(ctx).Error(err, "PDB pod list failed — keeping cordoned verdict",
			"pdb", p.Namespace+"/"+p.Name)
		return true
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == "" || !cordoned[pod.Spec.NodeName] {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// cordoned-block relief (P2-#10)
// ---------------------------------------------------------------------------

// pdbReliefErrReasons is the container waiting-reason set marking a
// pod as wedged rather than merely unready — the same hard-error
// spellings the rollout unstickers use. A pod unready for probe
// flapping without a container error is left alone: deleting it
// just recreates the same unready pod.
var pdbReliefErrReasons = map[string]bool{
	"CrashLoopBackOff":           true,
	"ImagePullBackOff":           true,
	"ErrImagePull":               true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"InvalidImageName":           true,
}

// pdbDBQuorumLabels are pod labels binding a pod to a stateful data
// store's cluster membership — deleting one can breach quorum, so
// the pod-delete fallback never touches them (the PDB patch path is
// label-agnostic: it changes eviction accounting, not pod count).
var pdbDBQuorumLabels = []string{
	"cnpg.io/cluster",
	"postgres-operator.crunchydata.com/cluster",
	"pgv2.percona.com/cluster",
	"everest.percona.com/cluster",
	"pxc.percona.com/cluster",
	"psmdb.percona.com/cluster",
	"scylla.scylladb.com/cluster",
	"apps.rabbitmq.com/cluster",
}

// relieveCordonedBlock runs once per sweep per PDB whose
// cordoned_node_blocked reason just fired: find the failing pod on
// an actively-cordoned node, then either patch the PDB's
// unhealthyPodEvictionPolicy to AlwaysAllow (the preferred fix —
// unhealthy pods stop counting against the healthy budget so the
// drain can proceed) or, when the patch cannot land, delete the
// wedged pod so it reschedules onto a schedulable node.
//
// Every mutation passes the shared heal gate (cooldown →
// maintenance mutex → heal budget) and Flux-managed PDBs pass
// heal.FluxPatchGate — a Git source pinning IfHealthyBudget must
// not be fought; the pod-delete fallback exists precisely for that
// case.
func (w *pdbDeadlockWatchdog) relieveCordonedBlock(ctx context.Context,
	log logr.Logger, now time.Time, pdb *policyv1.PodDisruptionBudget,
	cordoned map[string]bool) {

	if !w.cfg.cordonedUnhealthyRelief {
		return
	}
	pod := w.failingPodOnCordonedNode(ctx, pdb, cordoned)
	if pod == nil {
		return
	}

	// Patch path: only when the knob allows it AND the policy is
	// unset or still IfHealthyBudget — an explicit AlwaysAllow
	// means the PDB block is about healthy-pod count, which this
	// relief cannot fix. The patch is a spec write, not a pod
	// kill: it gates on the cluster-wide-only maintenance scope
	// (AllowedUpgradeOnly — a node cordon, including the one this
	// relief exists to finish, must not defer it) and consumes no
	// heal-budget grant; the per-PDB cooldown stays on w.heals.
	policy := pdb.Spec.UnhealthyPodEvictionPolicy
	if w.cfg.unhealthyEvictionPolicyPatch &&
		(policy == nil || *policy == policyv1.IfHealthyBudget) {

		key := pdb.Namespace + "/" + pdb.Name
		if w.heals.CooledDown(key, pdbReliefCooldown, now) {
			return // recently patched — give the PDB controller time
		}
		proceed, unverifiable := heal.AllowedUpgradeOnly(ctx, log, w.maintenance,
			w.cs, w.dyn, "pdb/"+key, now)
		switch {
		case unverifiable:
			metrics.IncError(w.queue)
			return
		case proceed:
			if heal.FluxPatchGate("pdb", pdb, "pdb/"+key, now) {
				if w.patchUnhealthyEvictionPolicy(ctx, log, now, pdb, key) {
					return
				}
			}
			// Flux owns the PDB or PDB patch RBAC is forbidden — fall
			// through to the pod-delete fallback below.
		default:
			return // cluster-wide hold — deferred
		}
	}

	// Pod-delete fallback: the wedged pod must be unready far longer
	// than the patch evidence fuse and must not carry a DB quorum
	// label — deleting a quorum member to unblock a drain trades a
	// maintenance stall for a data-store outage.
	if unreadyFor, ok := kube.PodUnreadyFor(pod, now); !ok ||
		unreadyFor < pdbReliefDeleteMinAge {
		return
	}
	if podHasDBQuorumLabel(pod) {
		log.Info("PDB relief: skipping pod delete — DB quorum member",
			"pdb", pdb.Namespace+"/"+pdb.Name,
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	key := pdb.Namespace + "/" + pdb.Name + "/" + pod.Name
	// The pod sits on the cordoned node this relief exists to free —
	// the classic mutex would defer on that very cordon, so the gate
	// is cluster-wide-only (a control-plane upgrade still holds).
	proceed, unverifiable := heal.AllowedClusterWideOnly(ctx, log, w.maintenance,
		w.cs, w.dyn, &w.heals, key, pdbReliefCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(w.queue)
		return
	case !proceed:
		return
	}
	deleted, err := heal.DeletePod(ctx, w.cs, &w.heals, key, pod, now)
	if err != nil {
		metrics.IncError(w.queue)
		log.Error(err, "PDB relief pod delete failed",
			"pdb", pdb.Namespace+"/"+pdb.Name,
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	if !deleted {
		// Clean deferral (L1 hold, quorum reservation, 404/409) — no
		// mutation executed, so the gate's grant goes back exactly
		// once (heal.RefundGrant contract).
		heal.RefundGrant(now)
		return
	}
	log.Info("ACTION: deleted wedged pod to unblock cordoned drain",
		"pdb", pdb.Namespace+"/"+pdb.Name,
		"pod", pod.Namespace+"/"+pod.Name)
}

// failingPodOnCordonedNode returns the first pod matching the PDB's
// selector that sits on an actively-cordoned node, is not in a
// terminal phase, has been Ready=False for >= pdbReliefPodMinAge,
// and carries a container waiting in a hard-error reason. nil when
// no pod qualifies — the PDB block then has no pod-level wedge this
// relief can act on.
func (w *pdbDeadlockWatchdog) failingPodOnCordonedNode(ctx context.Context,
	pdb *policyv1.PodDisruptionBudget,
	cordoned map[string]bool) *corev1.Pod {

	if pdb.Spec.Selector == nil {
		return nil
	}
	sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil {
		return nil
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		Limit:         kube.DefaultListPageSize,
		LabelSelector: sel.String(),
	}, kube.Pods(w.cs, pdb.Namespace))
	if err != nil {
		metrics.IncError(w.queue)
		logf.FromContext(ctx).Error(err, "PDB relief pod list failed",
			"pdb", pdb.Namespace+"/"+pdb.Name)
		return nil
	}
	now := w.now.Now()
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == "" || !cordoned[pod.Spec.NodeName] {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		unreadyFor, ok := kube.PodUnreadyFor(pod, now)
		if !ok || unreadyFor < pdbReliefPodMinAge {
			continue
		}
		if !podInReliefErrorState(pod) {
			continue
		}
		return pod
	}
	return nil
}

// podInReliefErrorState reports whether any container is waiting in
// a hard-error reason — the signature that a delete-and-reschedule
// (onto a schedulable node) can actually fix.
func podInReliefErrorState(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Waiting != nil && pdbReliefErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && pdbReliefErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	for _, cs := range pod.Status.EphemeralContainerStatuses {
		if cs.State.Waiting != nil && pdbReliefErrReasons[cs.State.Waiting.Reason] {
			return true
		}
	}
	return false
}

// podHasDBQuorumLabel reports whether the pod carries any stateful
// data-store cluster-membership label — the delete fallback's
// hard exclusion.
func podHasDBQuorumLabel(pod *corev1.Pod) bool {
	for _, k := range pdbDBQuorumLabels {
		if pod.Labels[k] != "" {
			return true
		}
	}
	return false
}

// patchUnhealthyEvictionPolicy merge-patches the PDB's
// spec.unhealthyPodEvictionPolicy to AlwaysAllow — unhealthy pods
// stop counting against desiredHealthy, so the eviction API opens
// slots again and the cordoned drain completes. The caller already
// passed the heal gate and FluxPatchGate.
func (w *pdbDeadlockWatchdog) patchUnhealthyEvictionPolicy(ctx context.Context,
	log logr.Logger, now time.Time, pdb *policyv1.PodDisruptionBudget,
	key string) bool {

	patch := []byte(`{"spec":{"unhealthyPodEvictionPolicy":"AlwaysAllow"}}`)
	_, err := w.cs.PolicyV1().PodDisruptionBudgets(pdb.Namespace).Patch(
		ctx, pdb.Name, types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.Info("WARN: PDB unhealthyPodEvictionPolicy patch forbidden (RBAC) — falling back to pod delete",
				"pdb", pdb.Namespace+"/"+pdb.Name)
			return false
		}
		metrics.IncError(w.queue)
		log.Error(err, "PDB unhealthyPodEvictionPolicy patch failed",
			"pdb", pdb.Namespace+"/"+pdb.Name)
		return true
	}
	w.heals.Stamp(key, now)
	pdbUnhealthyPolicyPatchedTotal.Inc()
	log.Info("ACTION: patched PDB unhealthyPodEvictionPolicy=AlwaysAllow",
		"pdb", pdb.Namespace+"/"+pdb.Name)
	return true
}

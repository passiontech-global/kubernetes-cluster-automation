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

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
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
)

// drainBlockedKey is the blockedEmitted ledger's dedup key — one
// node_automation_pdb_drain_blocked series per
// (namespace, pdb, reason) tuple.
type drainBlockedKey struct {
	ns, name, reason string
}

type pdbDeadlockWatchdog struct {
	cs         kubernetes.Interface
	nodeReader kube.CachedNodeReader
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
// cluster-wide LIST against the apiserver.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		w := &pdbDeadlockWatchdog{
			cs:         d.CS,
			nodeReader: d.CachedClient(),
			now:        shared.SystemClock,
			queue:      d.Name,
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

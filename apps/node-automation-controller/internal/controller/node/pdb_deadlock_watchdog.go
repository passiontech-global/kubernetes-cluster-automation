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
package node

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	pdbDeadlockQueue = "pdb-deadlock-watchdog"

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

type pdbDeadlockWatchdog struct {
	cs kubernetes.Interface
	// firstSeen records when each "<ns>/<name>/<reason>" precondition
	// STARTED holding — "continuously >= N" means now-firstSeen >= N
	// with no gap. Any cycle where the precondition drops deletes the
	// entry, restarting the window; any cycle where the PDB vanishes
	// prunes all of its entries (and their gauge series).
	firstSeen map[string]time.Time
	// nowFn is the wall-clock seam so tests can age sightings without
	// sleeping 30 minutes.
	nowFn func() time.Time
}

// SetupPDBDeadlockWatchdog registers the 5-minute sweep when the
// PDB_WATCHDOG_ENABLED flag is on. Disabled clusters register nothing
// at all — same contract as cilium-taint-reaper: no runnable, no
// periodic cluster-wide LIST against the apiserver.
func SetupPDBDeadlockWatchdog(mgr ctrl.Manager, cs kubernetes.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(pdbDeadlockQueue).Info("disabled — module not registered")
		return nil
	}
	w := &pdbDeadlockWatchdog{
		cs:        cs,
		firstSeen: map[string]time.Time{},
		nowFn:     time.Now,
	}
	return shared.AddPeriodic(mgr, pdbDeadlockQueue, 5*time.Minute, w.run)
}

func (w *pdbDeadlockWatchdog) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	if w.firstSeen == nil {
		// Lazy-init for direct-constructed fixtures — same guard the
		// other ledgers carry (Setup always initializes).
		w.firstSeen = map[string]time.Time{}
	}

	// Node list first — "at least one cordoned node" is a cluster-wide
	// input to the per-PDB verdict. Failing to read it must abort the
	// run: treating it as "no cordon" would silently clear every
	// cordoned_node_blocked series mid-incident.
	nodes, err := shared.ListNodes(ctx, w.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	anyCordoned := false
	for i := range nodes {
		if nodes[i].Spec.Unschedulable {
			anyCordoned = true
			break
		}
	}
	nodes = nil

	pdbs, err := w.cs.PolicyV1().PodDisruptionBudgets(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list poddisruptionbudgets: %w", err)
	}

	now := w.nowFn()
	// seen collects every "<ns>/<name>/<reason>" key whose precondition
	// held THIS cycle — the prune pass below treats anything else in
	// firstSeen as either resolved or gone.
	seen := make(map[string]struct{})
	flagged := 0
	for i := range pdbs.Items {
		p := &pdbs.Items[i]
		// The shared base condition for every reason: the PDB is
		// actually blocking drains right now. expectedPods == 0 means
		// it protects nothing (selector drifted off every pod — status
		// noise, not a deadlock); disruptionsAllowed > 0 means the
		// eviction API can proceed.
		blocked := p.Status.ExpectedPods > 0 && p.Status.DisruptionsAllowed == 0
		reasons := []struct {
			name   string
			holds  bool
			minAge time.Duration
		}{
			{pdbReasonImpossiblePolicy,
				blocked && p.Status.DesiredHealthy >= p.Status.ExpectedPods,
				pdbImpossibleMinAge},
			{pdbReasonCordonedNode, blocked && anyCordoned, pdbCordonedMinAge},
			{pdbReasonProlonged, blocked, pdbProlongedMinAge},
		}
		reported := false
		for _, r := range reasons {
			if !r.holds {
				continue
			}
			key := p.Namespace + "/" + p.Name + "/" + r.name
			seen[key] = struct{}{}
			first, ok := w.firstSeen[key]
			if !ok {
				// First sighting — open the continuity window; the
				// gauge stays unset until the reason holds across its
				// full threshold without a gap.
				w.firstSeen[key] = now
				continue
			}
			if now.Sub(first) < r.minAge {
				continue
			}
			metrics.PDBDrainBlocked.
				WithLabelValues(p.Namespace, p.Name, r.name).Set(1)
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

	// Prune first-seen entries — and their gauge series — for reasons
	// that stopped holding or PDBs that vanished. "Continuously"
	// resets on any gap, and a stale label set must not outlive its
	// object (same DeleteLabelValues hygiene as ForgetAPIBackend: the
	// series disappears rather than lingering at 0 forever).
	for key := range w.firstSeen {
		if _, ok := seen[key]; ok {
			continue
		}
		delete(w.firstSeen, key)
		// Keys are built as ns/name/reason; ns+name are DNS-1123
		// identifiers so "/" is unambiguous. Deleting a series that
		// was never set is a harmless no-op.
		if parts := strings.SplitN(key, "/", 3); len(parts) == 3 {
			metrics.PDBDrainBlocked.
				DeleteLabelValues(parts[0], parts[1], parts[2])
		}
	}
	log.Info("sweep done", "flagged", flagged, "tracked", len(w.firstSeen))
	return nil
}

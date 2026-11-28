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
// File layout: this file holds the module setup, sweep entry, and
// per-namespace pod list cache; pdb_relief.go holds cordoned-node
// relief (unhealthyPodEvictionPolicy patch + pod-delete fallback);
// pdb_overlap.go holds overlapping-PDB detection.
package pdbdeadlockwatchdog

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
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

	pdbImpossibleMinAge = 10 * time.Minute
	pdbCordonedMinAge   = 15 * time.Minute
	pdbProlongedMinAge  = 30 * time.Minute

	pdbReliefPodMinAge    = 5 * time.Minute
	pdbReliefDeleteMinAge = 30 * time.Minute
	pdbReliefCooldown     = 30 * time.Minute

	pdbOverlapEventCooldown = 30 * time.Minute
	pdbOverlapEventReason   = "OverlappingPDBDetected"
	pdbOverlapMaxSamplePods = 5
)

type pdbConfig struct {
	unhealthyEvictionPolicyPatch bool
	cordonedUnhealthyRelief      bool
}

func pdbConfigFromEnv() pdbConfig {
	return pdbConfig{
		unhealthyEvictionPolicyPatch: envx.Gate("PDB_UNHEALTHY_EVICTION_PATCH_ENABLED", true),
		cordonedUnhealthyRelief:      envx.Gate("PDB_CORDONED_UNHEALTHY_RELIEF_ENABLED", true),
	}
}

var (
	pdbUnhealthyPolicyPatchedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_automation_pdb_unhealthy_policy_patched_total",
		Help: "PDBs patched to unhealthyPodEvictionPolicy=AlwaysAllow by the cordoned-block relief — pdb-deadlock-watchdog.",
	})

	pdbOverlappingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_pdb_overlapping",
		Help: "1 while two or more PodDisruptionBudgets select the same non-terminal Pod in a namespace — pdb-deadlock-watchdog.",
	}, []string{"namespace", "pdbs"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(pdbUnhealthyPolicyPatchedTotal, pdbOverlappingGauge)
}

type drainBlockedKey struct {
	ns, name, reason string
}

type pdbOverlapKey struct {
	ns, pdbs string
}

type pdbDeadlockWatchdog struct {
	cs                   kubernetes.Interface
	dyn                  dynamic.Interface
	nodeReader           kube.CachedNodeReader
	maintenance          *maintenance.Verdict
	cfg                  pdbConfig
	heals                state.CooldownSet
	firstSeen            state.FirstSeenLedger
	blockedEmitted       state.GaugeLedger[drainBlockedKey]
	overlapEventCooldown state.CooldownSet
	overlapEmitted       state.GaugeLedger[pdbOverlapKey]
	now                  shared.Clock
	queue                string
}

// Setup registers the 5-minute sweep when PDB_WATCHDOG_ENABLED is on.
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

type nsPodsEntry struct {
	pods []corev1.Pod
	err  error
}

// nsPodsCache memoizes non-terminal pod lists per namespace within a single
// sweep so blocked-PDB evaluation and overlap detection share at most one
// LIST per namespace and count at most one error on failure.
type nsPodsCache struct {
	cs    kubernetes.Interface
	queue string
	byNS  map[string]nsPodsEntry
}

func (c *nsPodsCache) get(ctx context.Context, ns string) ([]corev1.Pod, error) {
	if c.byNS != nil {
		if e, ok := c.byNS[ns]; ok {
			return e.pods, e.err
		}
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(c.cs, ns))
	if err != nil {
		metrics.IncError(c.queue)
	}
	if c.byNS == nil {
		c.byNS = map[string]nsPodsEntry{}
	}
	c.byNS[ns] = nsPodsEntry{pods: pods, err: err}
	return pods, err
}

func (w *pdbDeadlockWatchdog) run(ctx context.Context) error {
	w.blockedEmitted.Begin()
	w.overlapEmitted.Begin()
	log := logf.FromContext(ctx)

	now := w.now.Now()
	w.heals.PruneExpired(now, pdbReliefCooldown)
	w.overlapEventCooldown.PruneExpired(now, pdbOverlapEventCooldown)
	nodes, err := kube.ListNodesCached(ctx, w.nodeReader, w.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
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

	nsPods := &nsPodsCache{cs: w.cs, queue: w.queue}
	seen := make(map[string]struct{})
	flagged := 0
	for i := range pdbs {
		p := &pdbs[i]
		blocked := p.Status.ExpectedPods > 0 && p.Status.DisruptionsAllowed == 0
		cordonedBlocked := false
		var pdbPods []corev1.Pod
		podsListed := false
		if blocked && anyCordoned {
			cordonedBlocked, pdbPods, podsListed = w.pdbPodsOnCordonedNodes(ctx, p, cordoned, nsPods)
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
			if !tracked || now.Sub(first) < r.minAge {
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
			if r.name == pdbReasonCordonedNode && podsListed {
				w.relieveCordonedBlockWithPods(ctx, log, now, p, cordoned, pdbPods, true)
			}
		}
		if reported {
			flagged++
		}
	}

	w.detectOverlappingPDBs(ctx, log, now, pdbs, nsPods)
	pdbs = nil

	w.firstSeen.Prune(func(key string) bool {
		_, ok := seen[key]
		return ok
	})
	w.blockedEmitted.Prune(metrics.PDBDrainBlocked.DeleteLabelValues)
	w.overlapEmitted.Prune(pdbOverlappingGauge.DeleteLabelValues)
	log.Info("sweep done", "flagged", flagged, "tracked", len(seen))
	return nil
}

func (w *pdbDeadlockWatchdog) pdbPodsOnCordonedNodes(ctx context.Context,
	p *policyv1.PodDisruptionBudget, cordoned map[string]bool,
	nsPods *nsPodsCache) (blocked bool, matching []corev1.Pod, listOK bool) {

	if p.Spec.Selector == nil {
		return false, nil, true
	}
	sel, err := metav1.LabelSelectorAsSelector(p.Spec.Selector)
	if err != nil {
		logf.FromContext(ctx).Error(err, "PDB selector unparseable — keeping cordoned verdict",
			"pdb", p.Namespace+"/"+p.Name)
		return true, nil, false
	}
	allNSPods, err := nsPods.get(ctx, p.Namespace)
	if err != nil {
		logf.FromContext(ctx).Error(err, "PDB pod list failed — keeping cordoned verdict",
			"pdb", p.Namespace+"/"+p.Name)
		return true, nil, false
	}
	for i := range allNSPods {
		pod := &allNSPods[i]
		if !sel.Matches(labels.Set(pod.Labels)) {
			continue
		}
		matching = append(matching, *pod)
		if pod.Spec.NodeName == "" || !cordoned[pod.Spec.NodeName] {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		blocked = true
	}
	return blocked, matching, true
}

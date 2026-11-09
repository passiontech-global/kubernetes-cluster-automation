// partition_evictor_sweep.go — one run of the partition-pod-evictor
// sweep, split into named phases: census the informer-cache nodes,
// re-confirm flagged nodes against the LIVE API, untaint recovered
// nodes, fence flagged nodes with the partition taint, then evict
// eligible pods under the cap / circuit breaker / maintenance
// mutex. Split out of partition_evictor.go — see that file for the
// module contract and the eligibility rules.
package partitionevictor

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// partitionSweep carries one run's census + action state between
// the phases run() sequences: the cached node list, the flagged
// (partitioned) set, the live-confirmed action set, and the
// evictable-node denominator the mesh-wide guard reads.
type partitionSweep struct {
	e       *partitionEvictor
	log     logr.Logger
	now     time.Time
	nodes   []corev1.Node
	byName  map[string]*corev1.Node
	flagged map[string]bool
	total   int
	action  map[string]bool
}

// census lists the nodes (informer cache when wired) and flags the
// ones whose NWPD network condition has been True past
// partitionMinAge. Control planes are counted nowhere — k0s control
// planes run no kubelet and no evictable workload, so a partition
// condition there must neither taint nor dilute the mesh-wide
// denominator.
func (s *partitionSweep) census(ctx context.Context) error {
	nodes, err := kube.ListNodesCached(ctx, s.e.nodeReader, s.e.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	s.nodes = nodes
	s.byName = make(map[string]*corev1.Node, len(nodes))
	s.flagged = map[string]bool{}
	for i := range nodes {
		s.byName[nodes[i].Name] = &nodes[i]
		if kube.IsControlPlane(&nodes[i]) {
			continue
		}
		s.total++
		if nodePartitioned(&nodes[i], s.now) {
			s.flagged[nodes[i].Name] = true
		}
	}
	return nil
}

// confirmLive re-confirms every flagged node against the LIVE API
// before anything acts on it. The census above rides the informer
// cache — watch-fresh in the happy path, but seconds-to-minutes
// behind under backlog — and eviction is destructive: a partition
// that healed inside the lag window must not cost live pods.
// Detection stays on the cache; the action set does not trust it.
func (s *partitionSweep) confirmLive(ctx context.Context) {
	s.action = make(map[string]bool, len(s.flagged))
	for name := range s.flagged {
		live, err := s.e.cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			// Fail closed: no live confirmation, no eviction this
			// sweep. The node stays in `flagged`, so an
			// unconfirmable suspect still counts toward the
			// mesh-wide guard below.
			metrics.IncError(s.e.queue)
			s.log.Error(err, "live node get failed — skipping node this sweep", "node", name)
			continue
		}
		if nodePartitioned(live, s.now) {
			s.action[name] = true
			continue
		}
		// Live truth overrides the cache: drop the node from
		// `flagged` so the recovery untaint below (and the
		// mesh-wide guard) see it healed.
		delete(s.flagged, name)
		// Partition healed — the node's own convergence evidence:
		// clear its breaker history now rather than waiting out the
		// window.
		heal.RecordTargetHealthy(s.e.queue, name)
		s.log.Info("partition healed — skipping evict", "node", name)
	}
}

// untaintRecovered lifts the taint on nodes that recovered —
// before the early exits, exactly like bash. A node the cache
// still showed flagged but the live Get disproved is recovered
// too: confirmLive removed it from `flagged`, so this existing
// path untaints it.
func (s *partitionSweep) untaintRecovered(ctx context.Context) {
	for i := range s.nodes {
		n := &s.nodes[i]
		if kube.HasTaint(n.Spec.Taints, partitionTaintKey) && !s.flagged[n.Name] {
			if err := kube.UntaintNode(ctx, s.e.cs, n.Name, partitionTaintKey); err != nil {
				metrics.IncError(s.e.queue)
				s.log.Error(err, "untaint failed", "node", n.Name)
				continue
			}
			s.log.Info("UNTAINT: network partition cleared", "node", n.Name)
			// Recovery untainted — the episode converged: clear the
			// node's breaker history so the next partition starts
			// from zero instead of tripping a circuit half filled by
			// the last one.
			heal.RecordTargetHealthy(s.e.queue, n.Name)
		}
	}
}

// sortedFlagged returns the flagged node names sorted — the guard
// logs and any name-ordered pass read a deterministic set.
func (s *partitionSweep) sortedFlagged() []string {
	names := make([]string, 0, len(s.flagged))
	for name := range s.flagged {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// sortedAction returns the live-confirmed node names sorted — the
// taint and eviction passes act only on LIVE-confirmed nodes.
func (s *partitionSweep) sortedAction() []string {
	names := make([]string, 0, len(s.action))
	for name := range s.action {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// taintFlagged fences EVERY live-confirmed flagged node with the
// partition taint before any eviction — the eviction cap below
// bounds pod churn, not fencing. Breaking out of a combined loop
// on cap would leave later flagged nodes schedulable until the
// next run while their pods sit on a blackholed node.
func (s *partitionSweep) taintFlagged(ctx context.Context) {
	for _, name := range s.sortedAction() {
		node := s.byName[name]
		if !kube.HasTaint(node.Spec.Taints, partitionTaintKey) {
			// Per-target non-convergent circuit breaker — a node the
			// controller already acted on limit times inside the
			// window defers the re-taint. A FRESHLY flagged node has
			// no history and always fences on the first sweep: the
			// breaker never blocks first-line fencing, only the
			// re-patch churn of a node that will not converge (each
			// recovery untaint clears the history — see above).
			// Defer semantics: log, skip this node, never an error.
			if allowed, reason := heal.TryAcquireTarget(s.e.queue, name, s.now); !allowed {
				s.log.Info("DEFER: heal target circuit open — taint skipped",
					"node", name, "reason", reason)
				continue
			}
			if err := kube.TaintNode(ctx, s.e.cs, name, partitionTaintKey, "true", corev1.TaintEffectNoSchedule); err != nil {
				metrics.IncError(s.e.queue)
				s.log.Error(err, "taint failed", "node", name)
			} else {
				s.log.Info("TAINT: network partitioned -> NoSchedule", "node", name)
			}
		}
	}
}

// evictPods runs the pod-eviction pass: resolve the pinned-volume
// set, pass the maintenance mutex + global heal budget, then delete
// eligible pods off each live-confirmed node under partitionEvictCap.
// Every tolerated sub-failure IncErrors the queue and continues —
// the pass never returns an error.
func (s *partitionSweep) evictPods(ctx context.Context) {
	names := s.sortedAction()

	// Resolve the eviction set once per run: the Setup-parsed env
	// allow-list plus the annotation opt-in (checked per pod inside
	// the loop). One node-scoped cluster-wide list per flagged node
	// beats 1+len(namespaces) namespaced lists — RBAC already grants
	// cluster-wide pod list (dead-node-sweeper reads the same way).
	namespaces := s.e.evictNamespaces()

	// pinned-volume-guard — resolve the node-pinned PVC set once per run: pods
	// mounted to local-path / openebs-hostpath volumes can only run
	// on the node holding the data, so evicting them off a
	// partitioned node is useless churn. A PVC list failure skips
	// the whole eviction pass (fail closed — taints above still
	// fence new scheduling).
	pinnedPVCs, err := s.e.nodePinnedPVCs(ctx)
	if err != nil {
		metrics.IncError(s.e.queue)
		s.log.Error(err, "pvc list failed — pod eviction skipped this run")
		return
	}

	// Maintenance mutex + global heal budget — evictions kill LIVE
	// pods, so they defer while a cordon/drain/kured reboot or a k0s
	// upgrade is in flight (the taints above still fence the flagged
	// nodes — fencing is not destructive). heal.Gate runs the
	// nil-heals-ledger preamble: this module's pacing is partitionEvictCap,
	// not a CooldownSet — its mutex and budget gates are what apply,
	// shared via e.verdict so the sweep pays one evaluation.
	// Unverifiable fails closed and IncErrors the queue like every
	// other tolerated sub-failure.
	if s.e.dyn != nil {
		proceed, unverifiable := heal.Gate(ctx, s.log, &s.e.verdict,
			s.e.cs, s.e.dyn, "partition-evictor", s.now)
		if unverifiable {
			metrics.IncError(s.e.queue)
			return
		}
		if !proceed {
			return
		}
	}

	evicted := 0
loop:
	for _, name := range names {
		pods, err := kube.ListAll(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + name,
			Limit:         kube.DefaultListPageSize,
		}, kube.Pods(s.e.cs, metav1.NamespaceAll))
		if err != nil {
			metrics.IncError(s.e.queue)
			s.log.Error(err, "list pods failed", "node", name)
			continue
		}
		// Per-target breaker charge state for this node's pass —
		// spent lazily on the first real victim below, so a sweep
		// with nothing to evict never banks against the node.
		charged := false
		for i := range pods {
			p := &pods[i]
			if evicted >= partitionEvictCap {
				s.log.Info("SKIP rest: cap reached", "cap", partitionEvictCap,
					"node", name)
				break loop
			}
			// Belt: the spec.nodeName field selector scopes the
			// server-side list, but fake clientsets ignore field
			// selectors — and a dropped/broken selector must never
			// turn a node-local sweep into a cluster-wide eviction.
			if p.Spec.NodeName != name {
				continue
			}
			if !partitionEvictable(p, namespaces) {
				continue
			}
			// Node-pinned volume — the pod can only ever run on
			// this node again; deleting it just recreates the same
			// stranded pod (or a Pending one) on the broken host.
			if podOnNodePinnedPVC(p, pinnedPVCs) {
				continue
			}
			// Per-target non-convergent circuit breaker, eviction
			// side: a sweep that evicts off a node spends ONE grant
			// (the batch is one heal of the target), charged lazily
			// on the first real victim. Past limit evicting sweeps
			// inside the window the rest defer — pods keep sitting
			// on a fenced node rather than the controller churning
			// them off it forever. Defer, never an error.
			if !charged {
				if allowed, reason := heal.TryAcquireTarget(s.e.queue, name, s.now); !allowed {
					s.log.Info("DEFER: heal target circuit open — evictions skipped",
						"node", name, "reason", reason)
					continue loop
				}
				charged = true
			}
			s.log.Info("EVICT: pod off partitioned node",
				"pod", p.Namespace+"/"+p.Name, "node", name)
			// UID precondition: the listed pod could be replaced by a
			// same-named fresh pod before the delete lands — never
			// kill the replacement. NotFound is already the goal
			// state (another actor finished the eviction first) —
			// tolerated, no error accounting.
			if err := s.e.cs.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
				kube.UIDDeleteOptions(p.UID, "")); err != nil && !apierrors.IsNotFound(err) {
				metrics.IncError(s.e.queue)
				s.log.Error(err, "evict failed", "pod", p.Namespace+"/"+p.Name,
					"node", name)
			}
			evicted++ // bash counts the attempt against the cap too
		}
	}
	s.log.Info("sweep done", "evicted", evicted, "flaggedNodes", len(s.flagged))
}

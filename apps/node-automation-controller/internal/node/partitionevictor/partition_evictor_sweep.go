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
	flagged map[string]bool
	total   int
	action  map[string]bool
	// taintedNode/breakerCharged carry the taint pass's outcome into
	// the eviction pass: a node is evictable only once its
	// NoSchedule fence actually landed (pods deleted off an
	// unfenced node would just reschedule back onto it), and a
	// node whose taint already spent a breaker grant must not pay
	// a second one for the same sweep's evictions.
	taintedNode    map[string]bool
	breakerCharged map[string]bool
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
	s.flagged = map[string]bool{}
	for i := range nodes {
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
			if apierrors.IsNotFound(err) {
				// Node deleted between census and confirm — nothing
				// left to evict or untaint. Drop it from `flagged`
				// and move on without error accounting: it must not
				// count toward the mesh-wide guard, and a vanished
				// node is not an error. (Whatever taint the cache
				// still shows is dead state; untaintRecovered's live
				// Get skips the node the same way.)
				delete(s.flagged, name)
				s.log.Info("node gone since census — nothing to evict", "node", name)
				continue
			}
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
// path untaints it. The cached spec is stale by the same
// seconds-to-minutes lag confirmLive exists for, so the untaint
// mirrors the confirmLive discipline: live Get first, and a node
// that vanished, still reports any partition condition True live
// (vouched or zombie — see livePartitionTrue), or fails to confirm
// is left fenced this sweep. Untainting off stale cache could
// un-fence a node that is in fact still blackholed, the mirror
// image of evicting on a healed partition.
func (s *partitionSweep) untaintRecovered(ctx context.Context) {
	for i := range s.nodes {
		n := &s.nodes[i]
		if !kube.HasTaint(n.Spec.Taints, partitionTaintKey) || s.flagged[n.Name] {
			continue
		}
		live, err := s.e.cs.CoreV1().Nodes().Get(ctx, n.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// Node deleted since census — its taint died with it;
			// nothing to lift.
			continue
		}
		if err != nil {
			// Fail closed: unconfirmable means the fence stays up
			// this sweep — the next run retries.
			metrics.IncError(s.e.queue)
			s.log.Error(err, "live node get failed — untaint skipped this sweep", "node", n.Name)
			continue
		}
		if livePartitionTrue(live) {
			// The live API still reports a partition condition True —
			// still partitioned, or a zombie/fresh latch nobody can
			// vouch for. Either way the cache aged the flag out but
			// the partition has not provably healed: keep the fence,
			// skip this sweep.
			s.log.Info("partition condition still True live — untaint skipped", "node", n.Name)
			continue
		}
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
	s.taintedNode = map[string]bool{}
	s.breakerCharged = map[string]bool{}
	for _, name := range s.sortedAction() {
		// Live-confirm the fence before trusting it: the census's
		// cached spec is stale by the same seconds-to-minutes lag
		// confirmLive exists for — a fence removed live while the
		// cache still shows it must not let evictions fire onto an
		// unfenced node (deleted pods would reschedule straight
		// back onto the blackholed host).
		live, err := s.e.cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// Node vanished inside the recovery window — nothing to
			// fence or evict; benign skip, not an error (same
			// treatment confirmLive and untaintRecovered give it).
			s.log.Info("SKIP: node gone at live confirm", "node", name)
			continue
		}
		if err != nil {
			// Fail closed: no live fence confirmation, no eviction
			// this sweep — the next run retries.
			metrics.IncError(s.e.queue)
			s.log.Error(err, "live node get failed — evictions skipped this sweep", "node", name)
			continue
		}
		if kube.HasTaint(live.Spec.Taints, partitionTaintKey) {
			// Already fenced live — evictions may proceed without a
			// new grant (the fence predates this sweep).
			s.taintedNode[name] = true
			continue
		}
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
		s.breakerCharged[name] = true // grant consumed — evict rides it
		if err := kube.TaintNode(ctx, s.e.cs, name, partitionTaintKey, "true", corev1.TaintEffectNoSchedule); err != nil {
			metrics.IncError(s.e.queue)
			s.log.Error(err, "taint failed", "node", name)
		} else {
			s.taintedNode[name] = true
			s.log.Info("TAINT: network partitioned -> NoSchedule", "node", name)
		}
	}
}

// evictPods runs the pod-eviction pass: resolve the pinned-volume
// set, pass the maintenance mutex + global heal budget, then evict
// eligible pods off each live-confirmed node under partitionEvictCap
// — through the policy/v1 Eviction API (heal.EvictPod), never a raw
// Delete, so a covering PodDisruptionBudget holds: its 429 refusal
// is a DEFERRAL (no error metering, no cap spend). Every other
// tolerated sub-failure IncErrors the queue and continues —
// the pass never returns an error.
func (s *partitionSweep) evictPods(ctx context.Context) {
	names := s.sortedAction()

	// Nothing can be evicted until at least one node's NoSchedule
	// fence landed — when every taint attempt failed (API error or
	// closed breaker) each loop iteration below would `continue`
	// anyway, so skip the PVC census and the heal-budget gate
	// entirely on an all-fence-failed sweep.
	fenced := 0
	for _, name := range names {
		if s.taintedNode[name] {
			fenced++
		}
	}
	if fenced == 0 {
		s.log.Info("sweep done", "evicted", 0, "flaggedNodes", len(s.flagged))
		return
	}

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
	// nodes — fencing is not destructive). The gate is acquired
	// LAZILY on the first pod that survives every eligibility check
	// and memoized for the rest of the pass (the mutex verdict is
	// already memoized on e.verdict; the budget grant is sweep-wide,
	// matching the old upfront call's one-grant-per-sweep shape).
	// Spending it up front burned a fleet-wide grant every sweep for
	// as long as a node sat tainted with nothing evictable on it —
	// all pods pinned, all system, or the cap already spent by an
	// earlier node — and the budget exists to unlock a DELIVERED
	// eviction, which an empty candidate set never produces.
	// Unverifiable fails closed and IncErrors the queue like every
	// other tolerated sub-failure; a deny (held mutex or spent
	// budget) ends the pass — the verdict cannot un-hold and the
	// budget cannot refill inside one sweep.
	gateChecked, gateProceed, gateUnverifiable := false, false, false
	evicted := 0
	// delivered/errN account the sweep grant's outcome — a pass
	// that delivered nothing and saw no actuation error refunds
	// the grant below (same contract as heal.EvictPodV's refusal
	// refund, applied sweep-wide since this module spends ONE
	// grant per pass, not per pod; refused attempts need no
	// counter — they are the no-delivery case by definition).
	deliveredN, errN := 0, 0
loop:
	for _, name := range names {
		// Never evict off a node whose NoSchedule fence did not
		// land this sweep — the taint API error or a closed breaker
		// leaves the node schedulable, and deleted pods would be
		// rescheduled straight back onto the blackholed host.
		if !s.taintedNode[name] {
			continue
		}
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
		// inherited from the taint step: a node fenced AND evicted
		// in the same sweep spends ONE grant, not two.
		charged := s.breakerCharged[name]
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
			// First pod that would actually be evicted acquires the
			// sweep-wide maintenance+budget gate — before the breaker
			// charge below, so a denied gate cannot spend a
			// per-target grant on an eviction that will not fire.
			if !gateChecked {
				gateChecked = true
				if s.e.dyn != nil {
					gateProceed, gateUnverifiable = heal.Gate(ctx, s.log,
						&s.e.verdict, s.e.cs, s.e.dyn,
						"partition-evictor", s.now)
				} else {
					gateProceed = true // nil dyn — gate skipped, proceed
				}
			}
			if gateUnverifiable {
				metrics.IncError(s.e.queue)
				return
			}
			if !gateProceed {
				// Mutex held or budget spent — every later candidate
				// defers identically this sweep.
				break loop
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
			// policy/v1 Eviction, never a raw Delete: the apiserver
			// enforces any covering PodDisruptionBudget and consumes
			// a disruption slot atomically, where a raw Delete
			// bypasses every PDB and could take a workload's last
			// Ready replica. heal.EvictPod is the shared
			// UID-preconditioned implementation; the heals ledger is
			// nil — this module paces via partitionEvictCap, not a
			// CooldownSet (nil skips the stamp, the documented
			// DeletePod/EvictPod contract). The UID precondition
			// stands: the listed pod could be replaced by a
			// same-named fresh pod before the eviction lands — never
			// kill the replacement. NotFound is already the goal
			// state (another actor finished the eviction first) —
			// tolerated, no error accounting.
			delivered, refused, err := heal.EvictPod(ctx, s.e.cs, nil, name, p, s.now)
			switch {
			case refused:
				// HTTP 429 — a PDB with disruptionsAllowed==0 refused
				// the eviction. A deferral, never an error: no
				// IncError, and the attempt must NOT consume the cap
				// — it made no progress, and spending the cap on
				// refusals would starve the real victims queued
				// behind them. The next sweep retries once
				// disruptions free up.
				s.log.Info("DEFER: PDB refused eviction — pod stays until disruptions free up",
					"pod", p.Namespace+"/"+p.Name, "node", name)
				continue
			case err != nil && !apierrors.IsNotFound(err):
				errN++
				metrics.IncError(s.e.queue)
				s.log.Error(err, "evict failed", "pod", p.Namespace+"/"+p.Name,
					"node", name)
			}
			if delivered {
				deliveredN++
			}
			evicted++ // every attempt but a 429 refusal counts against the cap
		}
	}
	// The sweep grant bought no heal when NOTHING was delivered and
	// no actuation even errored — every attempt PDB/hold/reservation-
	// refused, every candidate breaker-deferred (zero attempts), or
	// every eviction answered NotFound (pod already gone — goal
	// state, no mutation by us). Hand it back so a PDB-hung or
	// breaker-open partition cannot burn the fleet budget every
	// sweep (same accounting as EvictPodV's per-pod refund, folded
	// to the one-grant-per-pass shape this module uses). Any
	// delivery keeps the grant; an API error keeps it too — an
	// attempted actuation that failed is the documented "spent
	// token" case.
	if gateProceed && deliveredN == 0 && errN == 0 {
		heal.RefundGrant(s.now)
	}
	s.log.Info("sweep done", "evicted", evicted, "flaggedNodes", len(s.flagged))
}

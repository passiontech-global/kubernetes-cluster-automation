// snapshot.go — the per-sweep cluster-state snapshot: lazy, memoized
// cluster-wide LISTs shared by every check inside one run() cycle.
//
// Before this, ~30 of the 41 sweep checks each issued their own
// cluster-wide Pods/Nodes/EndpointSlices/Services/Namespaces LIST —
// ~17 full pod LISTs and ~11 node LISTs per 5-minute cycle — the
// single largest apiserver read load this module produced. The
// sweep is serial and most checks read the same cluster truth, so
// one shared snapshot replaces them all: each resource LISTs at most
// once per run() and every check reads the memoized copy.
//
// The snapshot lives on the sweep's context, not on Deps: run()
// installs a fresh one via WithSweepSnapshot at the top of each
// cycle, so expiry is structural — there is no TTL to tune and no
// cross-cycle staleness possible. Checks invoked outside a sweep
// (unit tests driving check.Run directly, ad-hoc helpers) get an
// empty snapshot per call, which preserves the old "list fresh
// every call" semantics exactly — a test that mutates the fake
// clientset between two Run calls sees the new fixtures.
//
// The ctx each memoized LIST runs under is the ctx WithSweepSnapshot
// captured (or the caller's own ctx outside a sweep) — NEVER the
// per-check ctx passed to AllXxx: each check's Run gets a
// WithTimeout(ctx, PerCheck) child, so a LIST under the first
// caller's ctx could die with that check's deadline and cache a
// context.DeadlineExceeded every later check then reads as a real
// apiserver failure — one slow check poisoning the whole roster.
// The snapshot ctx gets its own bound (snapshotListTimeout) so a
// wedged apiserver read still cannot stall the sweep forever.
//
// Mutation + staleness: a check that deletes a pod or mutates a
// node mid-sweep must invalidate what it changed so later checks
// re-list instead of acting on the pre-mutation view (a stale pod
// would otherwise be evaluated — and possibly re-healed — as if
// still alive; UID-preconditioned deletes make that harmless but
// noisy). InvalidatePods/InvalidateNodes/InvalidateEndpointSlices/
// InvalidateLeases each drop exactly the kind the mutation touched —
// Nodes additionally force the next AllNodes to bypass the
// just-patched informer cache — InvalidateSweep remains the blanket
// for Service/Namespace-level mutations, and its reset list is
// registered once at construction so a NEW census kind cannot be
// forgotten the way the Lease census was (a mid-sweep Lease
// delete/patch used to stay visible to every later check). The
// snapshot is read-only: callers must not mutate returned objects
// in place (several checks sort/filter — sort a copy).
//
// The per-kind readers live in sibling files grouped by census
// family — snapshot_pods.go, snapshot_nodes.go,
// snapshot_workloads.go, snapshot_cluster.go, snapshot_crds.go —
// this file keeps the shared memo[T] primitive, its ctx plumbing,
// and the Invalidate* write-side API.
package probefw

import (
	"context"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// snapshotListTimeout bounds one memoized LIST below the sweep ctx —
// a dedicated snapshot deadline, deliberately NOT any single check's
// PerCheck ctx (an expiring per-check ctx would cache its
// DeadlineExceeded and fail every later check in the cycle). Sized
// at the default PerCheck budget: a cluster-wide read slower than
// that is a real apiserver problem and caches as a legitimate shared
// failure, not a poisoned one.
const snapshotListTimeout = 2 * time.Minute

// sweepCtxKey is the context key WithSweepSnapshot installs the
// per-sweep memoizer under. Unexported: the sweep attaches it once
// and Deps methods resolve it, so no other package can inject one.
type sweepCtxKey struct{}

// memo is the generic (value, err, loaded) triple every census kind
// carries, replacing the hand-rolled (mu, items, err, set) quads
// that made InvalidateSweep a hand-maintained list of kinds — the
// leases census was missing from it, so a mid-sweep Lease mutation
// stayed visible to every later check. T is the WHOLE memoized
// value: a slice for censuses ([]corev1.Pod), a map for the derived
// joins (map[string]string).
//
// Locking: the sweep drives its checks serially inside one
// shared.Periodic goroutine, but check BODIES increasingly fan out
// into bounded worker pools (per-pod probes), so any two goroutines
// can now reach the same memoized read at once. The mutex guards
// all fields: same-kind readers serialize on the first load (the
// second waits for the memo instead of double-LISTing or racing the
// write), different kinds never contend. Locks are only ever taken
// one at a time per goroutine (the derived joins take their own
// lock, then the census's), so there is no ordering cycle to
// deadlock on.
//
// The FIRST caller pays the load — including its error, which is
// memoized with it (a transient apiserver failure must read
// identically to every check in the cycle rather than costing a
// retry storm) — and every later caller reads the copy.
type memo[T any] struct {
	mu    sync.Mutex
	items T
	err   error
	set   bool
	// forceCS is the nodes-only one-shot: InvalidateNodes arms it so
	// the NEXT load reads d.CS directly instead of the informer
	// cache (which lags a just-patched node by the sync delay). It
	// is consumed INSIDE the first-load critical section — a reader
	// can never observe "armed" without also performing the forced
	// load, and two racing readers cannot split the decision.
	forceCS bool
}

// get returns the memoized (items, err), running load on the first
// call. load receives the consumed forceCS flag — only the nodes
// census branches on it; every other kind ignores the parameter.
func (m *memo[T]) get(load func(forceCS bool) (T, error)) (T, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.set {
		m.set = true
		force := m.forceCS
		m.forceCS = false
		m.items, m.err = load(force)
	}
	return m.items, m.err
}

// reset returns the memo to its never-loaded state — items, err,
// loaded flag AND any armed forceCS (InvalidateNodes re-arms after
// via resetForced).
func (m *memo[T]) reset() {
	m.mu.Lock()
	var zero T
	m.items, m.err, m.set, m.forceCS = zero, nil, false, false
	m.mu.Unlock()
}

// resetForced is reset + arm in ONE critical section — the
// post-invalidate nodes read must bypass the informer cache, and a
// reader slipping between two separate reset/arm calls could pay a
// cached load and leave the arm dangling.
func (m *memo[T]) resetForced() {
	m.mu.Lock()
	var zero T
	m.items, m.err, m.set = zero, nil, false
	m.forceCS = true
	m.mu.Unlock()
}

// sweepSnapshot carries one sweep's memoized reads. Every census is
// a memo[T]; the derived placement/key joins (NodeZones, PodNodes,
// LeaseIndex, ServiceIndex) are memos of their own so they invalidate
// alongside their census. unstructReads stays a map — the dynamic
// reads are unbounded in kind (gateway-api routes, scylla clusters,
// flux releases, ...), so the same (items, err) pair hangs off a map
// keyed by the comparable GVR struct under one family mutex.
//
// resets is the blanket-invalidation list, bound ONCE at
// construction: InvalidateSweep iterates it so a newly added census
// kind joins the reset set by being declared — it cannot be forgotten
// the way the Lease census was.
type sweepSnapshot struct {
	ctx context.Context

	pods         memo[[]corev1.Pod]
	nodes        memo[[]corev1.Node]
	slices       memo[[]discoveryv1.EndpointSlice]
	services     memo[[]corev1.Service]
	namespaces   memo[[]corev1.Namespace]
	events       memo[[]corev1.Event]
	pvcs         memo[[]corev1.PersistentVolumeClaim]
	statefulSets memo[[]appsv1.StatefulSet]
	deployments  memo[[]appsv1.Deployment]
	daemonSets   memo[[]appsv1.DaemonSet]
	leases       memo[[]coordinationv1.Lease]

	// Derived joins — memoized like the censuses: the derived error
	// is the census's own, and each drops WITH its census (a join
	// built from the pre-mutation view is the same stale read in
	// map form).
	nodeZones    memo[map[string]string]
	podNodes     memo[map[string]string]
	leaseIndex   memo[map[types.NamespacedName]*coordinationv1.Lease]
	serviceIndex memo[map[types.NamespacedName]*corev1.Service]

	// AllUnstructured memoizes per GVR instead of per field — see
	// the type comment above. Lazy-built: both the
	// WithSweepSnapshot path and the fallback snapshot start nil.
	muUnstructs   sync.Mutex
	unstructReads map[schema.GroupVersionResource]*unstructRead

	// resets is every memo's reset, bound at construction — see the
	// type comment. InvalidateSweep runs it wholesale, then re-arms
	// the nodes forceCS read via resetForced.
	resets []func()
}

// unstructRead is the per-GVR memoized dynamic read behind
// AllUnstructured — the (items, err) half of the census triple; map
// presence is the loaded flag.
type unstructRead struct {
	items []unstructured.Unstructured
	err   error
}

// newSweepSnapshot builds an empty snapshot and binds its blanket
// reset list — every memo declared on the struct joins the list at
// construction, so InvalidateSweep can never drift behind the field
// set the way the hand-maintained drop list did.
func newSweepSnapshot(ctx context.Context) *sweepSnapshot {
	s := &sweepSnapshot{ctx: ctx}
	s.resets = []func(){
		s.pods.reset, s.nodes.reset, s.slices.reset,
		s.services.reset, s.namespaces.reset, s.events.reset,
		s.pvcs.reset, s.statefulSets.reset, s.deployments.reset,
		s.daemonSets.reset, s.leases.reset,
		s.nodeZones.reset, s.podNodes.reset,
		s.leaseIndex.reset, s.serviceIndex.reset,
	}
	return s
}

// WithSweepSnapshot installs a fresh, empty snapshot on ctx — the
// sweep-root calls it once per run() so the whole check roster
// shares the cycle's cluster reads. The snapshot captures ctx as its
// LIST context: the sweep parent outlives every per-check PerCheck
// child, so one check's expired deadline can no longer poison the
// shared census. Safe to call on a ctx that already carries one (the
// old snapshot is simply replaced).
func WithSweepSnapshot(ctx context.Context) context.Context {
	return context.WithValue(ctx, sweepCtxKey{}, newSweepSnapshot(ctx))
}

// snap returns the ctx-carried snapshot, or a fresh one when ctx
// carries none — the direct-Run (test/ad-hoc) path, where per-call
// freshness is the correct legacy semantics and the caller's own ctx
// is the right LIST deadline.
func sweepSnap(ctx context.Context) *sweepSnapshot {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		return s
	}
	return newSweepSnapshot(ctx)
}

// listCtx returns the ctx one memoized LIST runs under: the
// snapshot's captured ctx (sweep ctx inside a sweep, caller ctx
// outside) bounded by snapshotListTimeout — never the calling
// check's PerCheck ctx, whose deadline belongs to that check alone.
// caller is the fallback for a snapshot that somehow captured none.
func (s *sweepSnapshot) listCtx(caller context.Context) (context.Context, context.CancelFunc) {
	base := s.ctx
	if base == nil {
		base = caller
	}
	return context.WithTimeout(base, snapshotListTimeout)
}

// InvalidatePods drops only the pod census on the ctx-carried
// snapshot — the common case of "a check deleted a pod". Nodes,
// EndpointSlices, Services and Namespaces keep their memoized reads:
// a pod delete changes none of them, and a blanket invalidate used
// to make every later check pay for LISTs that could not have gone
// stale. The pod-derived join (PodNodes) drops WITH the census — a
// pre-delete placement map would misplace the dead pod's endpoints
// for every later check. A no-op outside a sweep.
func (d *Deps) InvalidatePods(ctx context.Context) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		s.pods.reset()
		s.podNodes.reset()
	}
}

// InvalidateNodes drops only the node census — the post-remediation
// twin of InvalidatePods (a check untainted/cordoned/patched a node).
// It ALSO arms the next AllNodes to read directly from d.CS instead
// of the informer cache: the cache lags the apiserver by the informer
// sync delay, so a node patched a few milliseconds ago would
// otherwise be re-read in its PRE-patch shape by every later check in
// the same sweep — exactly the staleness class the patch was meant
// to fix (verdicts acting on a taint that is already gone, or still
// present, in the cached copy). One direct read suffices: its result
// is memoized, and the sweep's remaining checks consume that. The
// node-derived join (NodeZones) drops with the census for the same
// pod-derived-join reason InvalidatePods drops PodNodes — a join
// built from the pre-patch view is the same stale read in map form.
// A no-op outside a sweep.
func (d *Deps) InvalidateNodes(ctx context.Context) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		s.nodes.resetForced()
		s.nodeZones.reset()
	}
}

// InvalidateEndpointSlices drops only the EndpointSlice census — the
// mirror of InvalidateNodes for a check that deleted a slice (the
// desync remediations do): later checks must re-list instead of
// evaluating the pre-delete slice set, while Services/Namespaces
// keep their memoized reads a slice delete cannot stale. A no-op
// outside a sweep.
func (d *Deps) InvalidateEndpointSlices(ctx context.Context) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		s.slices.reset()
	}
}

// InvalidateLeases drops the Lease census AND its ns/name index —
// the lease twin of InvalidatePods for a check that deleted or
// patched a Lease mid-sweep (the cilium L2 announce-lease guard's
// stale-holder delete, the operator-leader heal's stamp patch). A
// no-op outside a sweep.
func (d *Deps) InvalidateLeases(ctx context.Context) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		s.leases.reset()
		s.leaseIndex.reset()
	}
}

// InvalidateSweep drops every memoized read on the ctx-carried
// snapshot — call it after a check mutates cluster state beyond pod
// deletes (node taint/cordon, EndpointSlice delete, Service or
// Namespace mutation) so later checks re-list fresh data instead of
// acting on the pre-mutation view. The reset list was bound at
// construction, so every declared census — including the Lease
// census the hand-maintained list used to forget — drops here. The
// nodes forced re-read is re-armed afterwards: the blanket reset
// cleared it, and a sweep-wide mutation is exactly the case the
// direct clientset read exists for. A no-op outside a sweep (each
// call already sees fresh data).
func (d *Deps) InvalidateSweep(ctx context.Context) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		for _, reset := range s.resets {
			reset()
		}
		s.muUnstructs.Lock()
		s.unstructReads = nil
		s.muUnstructs.Unlock()
		// The wholesale reset cleared the nodes forceCS arm — re-arm
		// it atomically (resetForced is idempotent on an already-
		// reset memo: it only re-asserts set=false + forceCS=true).
		s.nodes.resetForced()
	}
}

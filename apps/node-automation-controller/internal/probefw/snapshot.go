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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// snapshotListTimeout bounds one memoized LIST below the sweep ctx —
// a dedicated snapshot deadline, deliberately NOT any single check's
// PerCheck ctx (an expiring per-check ctx would cache its
// DeadlineExceeded and fail every later check in the cycle). Sized
// at the default PerCheck budget: a cluster-wide read slower than
// that is a real apiserver problem and caches as a legitimate shared
// failure, not a poisoned one.
const snapshotListTimeout = 2 * time.Minute

// snapshotListOpts is the ListOptions every census read shares.
// ResourceVersion "0" routes the LIST to the apiserver's in-memory
// watch cache: ONE response for the whole census instead of
// HealthListPageSize-bounded pages — under kube-apiserver-on-Kine
// each page was a separate SQL round-trip against the datastore
// (the paged-read amplification the snapshot exists to kill), and a
// paged read can also straddle writes (page N and page N+1 served
// at different resourceVersions), which a census must never do —
// the cache answers the whole list at one version. pageOpts strips
// the Limit companion on the wire; it stays in the literal so the
// page bound is still documented for the day the RV changes.
func snapshotListOpts() metav1.ListOptions {
	return metav1.ListOptions{
		Limit:           HealthListPageSize,
		ResourceVersion: "0",
	}
}

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
// verifySnapshots is the test-only mutation guard: when enabled,
// every memo fingerprints its items at load and re-verifies on each
// later get — an in-place write to a shared census object (the
// map/slice mutation bug class the sweep overlay exists to kill)
// panics inside the offending read instead of silently corrupting
// every later check's view. probetest's init() enables it, so every
// test binary that links the shared scaffolding gets the guard;
// production binaries never import probetest and pay nothing (the
// flag stays false — no hashing, no behavior change).
var verifySnapshots atomic.Bool

// EnableSnapshotVerify turns on the memo mutation guard — called
// once from probetest's init; idempotent and irreversible (a test
// binary wants it everywhere).
func EnableSnapshotVerify() { verifySnapshots.Store(true) }

// fingerprintValue renders one memoized payload deterministically —
// fmt's %#v sorts map keys, so the same logical census always hashes
// identically regardless of Go's map iteration order.
func fingerprintValue[T any](v T) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%#v", v) // hash.Hash writes never fail
	return hex.EncodeToString(h.Sum(nil))
}

type memo[T any] struct {
	mu    sync.Mutex
	items T
	err   error
	set   bool
	// verifyHash is the load-time content fingerprint — populated
	// only under verifySnapshots (test binaries); "" disables the
	// per-get re-check.
	verifyHash string
	// fetchedAt is the wall-clock instant the load ran — the
	// "as-of" timestamp age-window checks must measure against.
	// p.Now() at CHECK-run time lags the fetch by however long the
	// worker queue delayed this check (up to PerCheck × pool depth
	// behind the sweep's first reader), which would overstate every
	// window the census feeds — a Lease renewed 9m before the fetch
	// reads 11m-stale to a check that ran 2m late. Real time.Now,
	// not the injected clock: renewTime is an apiserver wall-clock
	// value and the honest "when did we read it" is wall-clock too
	// (production Deps.Now IS time.Now; test fixtures derive their
	// timestamps from time.Now() as well).
	fetchedAt time.Time
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
// The FIRST caller's result — error included — is memoized for the
// sweep (the census contract: a transient apiserver failure must
// read identically to every check in the cycle rather than costing
// a retry storm per check).
func (m *memo[T]) get(load func(forceCS bool) (T, error)) (T, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.set {
		m.set = true
		force := m.forceCS
		m.forceCS = false
		m.items, m.err = load(force)
		m.fetchedAt = time.Now()
		if verifySnapshots.Load() {
			m.verifyHash = fingerprintValue(m.items)
		}
	} else {
		m.verifyLocked()
	}
	return m.items, m.err
}

// getLive is get's no-memoize-on-error twin for wire reads whose
// transient failure must NOT be replayed to later callers —
// PromQuery's Prometheus round-trip today. The load still runs
// under m.mu so identical concurrent queries never double-fly, but
// m.set flips ONLY on a successful load: a failed query leaves the
// memo empty and the next caller retries the wire. That removes
// the reset-after-get race the prom memo used to carry — a sibling
// get landing between get's unlock and the caller's m.reset() read
// the just-memoized error and replayed it for the rest of the
// sweep. (Census memos keep memoizing errors on purpose — see
// get.)
func (m *memo[T]) getLive(load func() (T, error)) (T, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.set {
		m.verifyLocked()
		return m.items, m.err
	}
	items, err := load()
	if err != nil {
		// Not memoized — set stays false so the next caller
		// retries instead of inheriting this transient failure.
		return items, err
	}
	m.items, m.err, m.set = items, nil, true
	m.fetchedAt = time.Now()
	if verifySnapshots.Load() {
		m.verifyHash = fingerprintValue(m.items)
	}
	return m.items, nil
}

// verifyLocked re-checks the load-time fingerprint — caller MUST
// hold m.mu. Shared by get/getLive's hit path and verify()'s
// post-sweep sweep.
func (m *memo[T]) verifyLocked() {
	if m.verifyHash != "" &&
		fingerprintValue(m.items) != m.verifyHash {
		// The shared census was written in place — exactly the
		// corruption the sweep overlay routes around. Panicking
		// surfaces it at the read (or the post-sweep verify)
		// instead of silently corrupting every later check's view
		// (test builds only — verifyHash is never populated in
		// production).
		panic(fmt.Sprintf(
			"probefw: sweep snapshot census %T mutated in place", m.items))
	}
}

// verify re-checks the memo's fingerprint under its own lock — the
// per-memo half of VerifySweepSnapshotUnmutated.
func (m *memo[T]) verify() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifyLocked()
}

// fetched reports when the memoized load ran — zero until the first
// get completes (callers pair it with the census read, which is what
// populates it).
func (m *memo[T]) fetched() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fetchedAt
}

// reset returns the memo to its never-loaded state — items, err,
// loaded flag, fetchedAt AND any armed forceCS (InvalidateNodes
// re-arms after via resetForced).
func (m *memo[T]) reset() {
	m.mu.Lock()
	var zero T
	m.items, m.err, m.set, m.forceCS = zero, nil, false, false
	m.fetchedAt = time.Time{}
	m.verifyHash = ""
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
	m.fetchedAt = time.Time{}
	m.verifyHash = ""
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
	// Lazy workload censuses — populated only when a check actually
	// asks (the plan's "lazy getters"): ReplicaSets ride the
	// metadata-only path (ObjectMeta is all the ownership joins
	// read), CronJobs/PDBs stay typed because their consumers read
	// spec fields. Declared here so InvalidateSweep drops them with
	// the rest — a mid-sweep workload mutation must not leave a
	// stale census behind for the next check.
	replicaSets memo[[]metav1.PartialObjectMetadata]
	cronJobs    memo[[]batchv1.CronJob]
	pdbs        memo[[]policyv1.PodDisruptionBudget]

	// Derived joins — memoized like the censuses: the derived error
	// is the census's own, and each drops WITH its census (a join
	// built from the pre-mutation view is the same stale read in
	// map form).
	nodeZones    memo[map[string]string]
	podNodes     memo[podNodeIndex]
	leaseIndex   memo[map[types.NamespacedName]*coordinationv1.Lease]
	serviceIndex memo[map[types.NamespacedName]*corev1.Service]

	// AllUnstructured memoizes per GVR instead of per field — see
	// the type comment above. Each entry is a full memo[T] so one
	// GVR's LIST serializes on ITS OWN lock: the parallel check
	// workers that fan out across different CRDs no longer queue
	// behind a single family mutex (and InvalidateSweep resets each
	// memo in place — a reader holding an entry pointer can never
	// observe a map swap mid-read).
	muUnstructs   sync.Mutex
	unstructReads map[schema.GroupVersionResource]*memo[[]unstructured.Unstructured]

	// promQueries dedupes identical instant PromQL strings inside
	// one sweep — several checks issue the same vector (kube-state
	// series, linkerd metrics) and each used to pay a full
	// Prometheus round-trip (~75 queries/cycle measured). Successes
	// memoize for the sweep (getLive); FAILURES deliberately do
	// not — a transient Prometheus error must not replay to every
	// later identical query (the old get+reset pair raced a sibling
	// read between unlock and reset). The map is NOT in resets —
	// Prometheus data lags apiserver mutations by a scrape interval
	// anyway, so mid-sweep invalidation would buy nothing but a
	// second round-trip.
	promMu      sync.Mutex
	promQueries map[string]*memo[[]promq.Sample]

	// resets is every memo's reset, bound at construction — see the
	// type comment. InvalidateSweep runs it wholesale, then re-arms
	// the nodes forceCS read via resetForced.
	resets []func()
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
		s.replicaSets.reset, s.cronJobs.reset, s.pdbs.reset,
		s.nodeZones.reset, s.podNodes.reset,
		s.leaseIndex.reset, s.serviceIndex.reset,
		s.resetUnstructs,
	}
	return s
}

// promMemo returns the per-key memo for this sweep — created
// lazily on first use, shared by every later identical key. The
// caller composes the key (PromQuery uses endpoint+query); the
// map itself is key-agnostic.
func (s *sweepSnapshot) promMemo(key string) *memo[[]promq.Sample] {
	s.promMu.Lock()
	defer s.promMu.Unlock()
	if s.promQueries == nil {
		s.promQueries = map[string]*memo[[]promq.Sample]{}
	}
	m, ok := s.promQueries[key]
	if !ok {
		m = &memo[[]promq.Sample]{}
		s.promQueries[key] = m
	}
	return m
}

// resetUnstructs drops every per-GVR dynamic memo — the unstructured
// twin of the typed resets. Entries reset IN PLACE (never map-swap):
// a worker mid-Load on one GVR finishes its read, then the reset
// clears it so the NEXT reader re-lists — identical semantics to the
// typed memos' reset().
func (s *sweepSnapshot) resetUnstructs() {
	s.muUnstructs.Lock()
	defer s.muUnstructs.Unlock()
	for _, m := range s.unstructReads {
		m.reset()
	}
}

// WithSweepSnapshot installs a fresh, empty snapshot on ctx — the
// sweep-root calls it once per run() so the whole check roster
// shares the cycle's cluster reads. The snapshot captures ctx as its
// LIST context: the sweep parent outlives every per-check PerCheck
// child, so one check's expired deadline can no longer poison the
// shared census. Safe to call on a ctx that already carries one (the
// old snapshot is simply replaced).
//
// It also installs the sweep write-overlay (kube.WithSweepOverlay)
// on the same ctx: the census stays read-only and mid-sweep
// annotation patches / pod deletes land as overlay deltas the later
// checks resolve through EffectiveAnno/IsPodDeleted instead of
// mutating the shared objects (the data race the overlay exists to
// remove) or invalidating whole censuses (the re-LIST storm
// MarkPodDeleted replaces).
func WithSweepSnapshot(ctx context.Context) context.Context {
	snap := newSweepSnapshot(ctx)
	ctx = context.WithValue(ctx, sweepCtxKey{}, snap)
	return kube.WithSweepOverlay(ctx)
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
		// The wholesale reset cleared the nodes forceCS arm — re-arm
		// it atomically (resetForced is idempotent on an already-
		// reset memo: it only re-asserts set=false + forceCS=true).
		s.nodes.resetForced()
	}
}

// verifyUnmutated re-checks EVERY loaded memo's load-time
// fingerprint — the post-sweep half of the mutation guard. The
// per-get verifyLocked catches a write between two reads of the
// same memo; this catches the residue that shape cannot see: a
// census object mutated in place AFTER its memo's last read (the
// sweep's final checks never re-read it, so no get ever observes
// the corruption). Same panic contract — a mutated shared census
// is a bug, never a verdict. No-op for memos never loaded and for
// the whole snapshot when verifySnapshots is off (verifyHash is
// only populated under the test flag, so production pays nothing).
func (s *sweepSnapshot) verifyUnmutated() {
	// Typed censuses + derived joins — one verify per memo.
	s.pods.verify()
	s.nodes.verify()
	s.slices.verify()
	s.services.verify()
	s.namespaces.verify()
	s.events.verify()
	s.pvcs.verify()
	s.statefulSets.verify()
	s.deployments.verify()
	s.daemonSets.verify()
	s.leases.verify()
	s.replicaSets.verify()
	s.cronJobs.verify()
	s.pdbs.verify()
	s.nodeZones.verify()
	s.podNodes.verify()
	s.leaseIndex.verify()
	s.serviceIndex.verify()
	// The unbounded-kind dynamic reads and the deduped Prometheus
	// queries are memos too — same in-place-mutation bug class.
	s.muUnstructs.Lock()
	for _, m := range s.unstructReads {
		m.verify()
	}
	s.muUnstructs.Unlock()
	s.promMu.Lock()
	for _, m := range s.promQueries {
		m.verify()
	}
	s.promMu.Unlock()
}

// VerifySweepSnapshotUnmutated is the post-sweep entry point of the
// snapshot mutation guard: pass the ctx the sweep ran under (the
// one WithSweepSnapshot installed) AFTER the checks finish and every
// census memo's fingerprint is re-verified against its load-time
// state — catching in-place writes that landed after a memo's last
// read, which the per-get guard cannot observe. It PANICS on the
// first mutated payload, exactly like the per-read guard: a shared
// census written in place is a bug to fix, not a condition to
// report. Outside a sweep (or with EnableSnapshotVerify never
// armed — i.e. every production binary) it is a no-op.
func VerifySweepSnapshotUnmutated(ctx context.Context) {
	sweepSnap(ctx).verifyUnmutated()
}

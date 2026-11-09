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
// noisy). InvalidatePods/InvalidateNodes/InvalidateEndpointSlices
// each drop exactly the kind the mutation touched — Nodes additionally
// force the next AllNodes to bypass the just-patched informer cache —
// and InvalidateSweep remains the blanket for Service/Namespace-level
// mutations. The snapshot is read-only: callers must not mutate
// returned objects in place (several checks sort/filter — sort a
// copy).
//
// The per-kind readers live in sibling files grouped by census
// family — snapshot_pods.go, snapshot_nodes.go,
// snapshot_workloads.go, snapshot_cluster.go, snapshot_crds.go —
// this file keeps the shared memoizer struct, its ctx plumbing, and
// the Invalidate* write-side API.
package probefw

import (
	"context"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

// sweepSnapshot memoizes one sweep's cluster-wide reads. Each field
// triples as (items, err, loaded): the FIRST caller pays the LIST —
// including its error, which is memoized with it (a transient
// apiserver failure must read identically to every check in the
// cycle rather than costing a retry storm) — and every later caller
// reads the copy.
//
// Locking: the sweep drives its checks serially inside one
// shared.Periodic goroutine, but check BODIES increasingly fan out
// into bounded worker pools (per-pod probes), so any two goroutines
// can now reach the same memoized read at once. Every kind therefore
// carries its own sync.Mutex guarding its triple: same-kind readers
// serialize on the first LIST (the second waits for the memo instead
// of double-LISTing or racing the write), different kinds never
// contend. Locks are only ever taken one at a time per goroutine
// (the derived joins take their own lock, then the census's), so
// there is no ordering cycle to deadlock on.
//
// ctx is the snapshot's LIST context: captured at WithSweepSnapshot
// (the sweep ctx) or the caller's ctx in the direct-Run path. It
// must outlive any single check's PerCheck deadline — see the file
// header for the poisoning bug that motivates it.
type sweepSnapshot struct {
	ctx context.Context

	muPods  sync.Mutex
	pods    []corev1.Pod
	podsErr error
	podsSet bool

	muNodes sync.Mutex
	// nodesForceCS is InvalidateNodes' one-shot "the next AllNodes
	// must bypass the informer cache" flag: a check that just
	// patched a node cannot trust the cache read (it lags the
	// apiserver by the informer sync delay), so the re-read goes
	// straight to d.CS. Consumed by that next AllNodes; the
	// memoized result then serves the rest of the sweep.
	nodesForceCS bool
	nodes        []corev1.Node
	nodesErr     error
	nodesSet     bool

	muSlices  sync.Mutex
	slices    []discoveryv1.EndpointSlice
	slicesErr error
	slicesSet bool

	muServices  sync.Mutex
	services    []corev1.Service
	servicesErr error
	servicesSet bool

	muNamespaces  sync.Mutex
	namespaces    []corev1.Namespace
	namespacesErr error
	namespacesSet bool

	muEvents  sync.Mutex
	events    []corev1.Event
	eventsErr error
	eventsSet bool

	muPVCs  sync.Mutex
	pvcs    []corev1.PersistentVolumeClaim
	pvcsErr error
	pvcsSet bool

	muStatefulSets  sync.Mutex
	statefulSets    []appsv1.StatefulSet
	statefulSetsErr error
	statefulSetsSet bool

	muDeployments  sync.Mutex
	deployments    []appsv1.Deployment
	deploymentsErr error
	deploymentsSet bool

	muDaemonSets  sync.Mutex
	daemonSets    []appsv1.DaemonSet
	daemonSetsErr error
	daemonSetsSet bool

	muCRDs  sync.Mutex
	crds    []unstructured.Unstructured
	crdsErr error
	crdsSet bool

	// AllUnstructured memoizes per GVR instead of per field — the
	// dynamic reads are unbounded in kind (gateway-api routes,
	// scylla clusters, flux releases, ...), so the same
	// (items, err) pair hangs off a map keyed by the
	// comparable GVR struct, guarded by one mutex for the whole
	// family. Lazy-built: both the WithSweepSnapshot path and the
	// fallback snapshot start nil.
	muUnstructs   sync.Mutex
	unstructReads map[schema.GroupVersionResource]*unstructRead

	// nodeZones/podNodes are the memoized placement JOINS derived
	// from the pods/nodes censuses — several checks need the maps,
	// not the raw lists, and rebuilding them per check meant each
	// consumer re-walked the same census. They memoize like the
	// censuses: the derived error is the census's own.
	muNodeZones  sync.Mutex
	nodeZones    map[string]string
	nodeZonesErr error
	nodeZonesSet bool

	muPodNodes  sync.Mutex
	podNodes    map[string]string
	podNodesErr error
	podNodesSet bool
}

// unstructRead is the per-GVR memoized dynamic read behind
// AllUnstructured — the (items, err) half of the census triple; map
// presence is the loaded flag.
type unstructRead struct {
	items []unstructured.Unstructured
	err   error
}

// WithSweepSnapshot installs a fresh, empty snapshot on ctx — the
// sweep-root calls it once per run() so the whole check roster
// shares the cycle's cluster reads. The snapshot captures ctx as its
// LIST context: the sweep parent outlives every per-check PerCheck
// child, so one check's expired deadline can no longer poison the
// shared census. Safe to call on a ctx that already carries one (the
// old snapshot is simply replaced).
func WithSweepSnapshot(ctx context.Context) context.Context {
	return context.WithValue(ctx, sweepCtxKey{},
		&sweepSnapshot{ctx: ctx})
}

// snap returns the ctx-carried snapshot, or a fresh one when ctx
// carries none — the direct-Run (test/ad-hoc) path, where per-call
// freshness is the correct legacy semantics and the caller's own ctx
// is the right LIST deadline.
func sweepSnap(ctx context.Context) *sweepSnapshot {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		return s
	}
	return &sweepSnapshot{ctx: ctx}
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
		s.muPods.Lock()
		s.pods, s.podsErr, s.podsSet = nil, nil, false
		s.muPods.Unlock()
		s.muPodNodes.Lock()
		s.podNodes, s.podNodesErr, s.podNodesSet = nil, nil, false
		s.muPodNodes.Unlock()
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
		s.muNodes.Lock()
		s.nodes, s.nodesErr, s.nodesSet = nil, nil, false
		s.nodesForceCS = true
		s.muNodes.Unlock()
		s.muNodeZones.Lock()
		s.nodeZones, s.nodeZonesErr, s.nodeZonesSet = nil, nil, false
		s.muNodeZones.Unlock()
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
		s.muSlices.Lock()
		s.slices, s.slicesErr, s.slicesSet = nil, nil, false
		s.muSlices.Unlock()
	}
}

// InvalidateSweep drops every memoized read on the ctx-carried
// snapshot — call it after a check mutates cluster state beyond pod
// deletes (node taint/cordon, EndpointSlice delete, Service or
// Namespace mutation) so later checks re-list fresh data instead of
// acting on the pre-mutation view. Each kind resets under its own
// lock (no struct copy: the snapshot carries mutexes now, and
// copying one under a concurrent reader would race the lock values).
// A no-op outside a sweep (each call already sees fresh data).
func (d *Deps) InvalidateSweep(ctx context.Context) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		d.InvalidatePods(ctx)
		d.InvalidateNodes(ctx)
		d.InvalidateEndpointSlices(ctx)
		for _, drop := range []func(){
			func() {
				s.muServices.Lock()
				s.services, s.servicesErr, s.servicesSet = nil, nil, false
				s.muServices.Unlock()
			},
			func() {
				s.muNamespaces.Lock()
				s.namespaces, s.namespacesErr, s.namespacesSet = nil, nil, false
				s.muNamespaces.Unlock()
			},
			func() {
				s.muEvents.Lock()
				s.events, s.eventsErr, s.eventsSet = nil, nil, false
				s.muEvents.Unlock()
			},
			func() {
				s.muPVCs.Lock()
				s.pvcs, s.pvcsErr, s.pvcsSet = nil, nil, false
				s.muPVCs.Unlock()
			},
			func() {
				s.muStatefulSets.Lock()
				s.statefulSets, s.statefulSetsErr, s.statefulSetsSet = nil, nil, false
				s.muStatefulSets.Unlock()
			},
			func() {
				s.muDeployments.Lock()
				s.deployments, s.deploymentsErr, s.deploymentsSet = nil, nil, false
				s.muDeployments.Unlock()
			},
			func() {
				s.muDaemonSets.Lock()
				s.daemonSets, s.daemonSetsErr, s.daemonSetsSet = nil, nil, false
				s.muDaemonSets.Unlock()
			},
			func() {
				s.muCRDs.Lock()
				s.crds, s.crdsErr, s.crdsSet = nil, nil, false
				s.muCRDs.Unlock()
			},
			func() {
				s.muUnstructs.Lock()
				s.unstructReads = nil
				s.muUnstructs.Unlock()
			},
		} {
			drop()
		}
	}
}

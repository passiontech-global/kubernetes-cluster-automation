package probefw

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// podCensusView returns src minus this sweep's pod tombstones,
// memoized per (census identity, podTombstoneGen): an unchanged
// generation means the filtered slice computed earlier is still
// exact, so every AllPods caller shares it — read-only like every
// other snapshot payload. Outside a sweep the overlay is absent
// (gen stays 0) and the src-identity half still keys the cache.
func (s *sweepSnapshot) podCensusView(ctx context.Context,
	src []corev1.Pod) []corev1.Pod {

	gen := kube.PodTombstoneGen(ctx)
	s.podViewMu.Lock()
	defer s.podViewMu.Unlock()
	if s.podFiltered != nil && s.podViewGen == gen &&
		elemSliceSame(s.podViewSrc, src) {
		return s.podFiltered
	}
	out := kube.FilterPodTombstones(ctx, src)
	s.podViewGen, s.podViewSrc, s.podFiltered = gen, src, out
	return out
}

// podNodeView returns the PodNodes placement map minus the pods the
// overlay has tombstoned, memoized per (index source identity,
// podTombstoneGen). idxSrc is the filtered census slice the index
// memo was built from — it changes exactly when the index rebuilds
// (census invalidation), so the pair keys "same index + same
// tombstone set" without re-walking the map per call. The returned
// map is SHARED across callers — snapshot payloads are read-only.
func (s *sweepSnapshot) podNodeView(ctx context.Context,
	idxSrc []corev1.Pod, idx podNodeIndex) map[string]string {

	gen := kube.PodTombstoneGen(ctx)
	s.podViewMu.Lock()
	if s.podNodesView != nil && s.podNodesViewGen == gen &&
		elemSliceSame(s.podNodesViewSrc, idxSrc) {
		out := s.podNodesView
		s.podViewMu.Unlock()
		return out
	}
	s.podViewMu.Unlock()
	// Build outside the lock — two racing readers may both build,
	// last store wins, both results are identical.
	out := make(map[string]string, len(idx.node))
	for key, node := range idx.node {
		if uid, ok := idx.uid[key]; ok && kube.IsPodDeleted(ctx, uid) {
			continue
		}
		out[key] = node
	}
	s.podViewMu.Lock()
	s.podNodesViewGen, s.podNodesViewSrc, s.podNodesView =
		gen, idxSrc, out
	s.podViewMu.Unlock()
	return out
}

// sweepSnap returns the ctx-carried snapshot, or a fresh one when ctx
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
		for _, m := range s.memos {
			m.reset()
		}
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
	for _, m := range s.memos {
		m.verify()
	}
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

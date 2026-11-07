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
// node mid-sweep must call InvalidatePods/InvalidateSweep so later
// checks re-list instead of acting on the pre-mutation view (a
// stale pod would otherwise be evaluated — and possibly re-healed —
// as if still alive; UID-preconditioned deletes make that harmless
// but noisy). The snapshot is read-only: callers must not mutate
// returned objects in place (several checks sort/filter — sort a
// copy).
package probefw

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
// reads the copy. The serial sweep needs no locking.
//
// ctx is the snapshot's LIST context: captured at WithSweepSnapshot
// (the sweep ctx) or the caller's ctx in the direct-Run path. It
// must outlive any single check's PerCheck deadline — see the file
// header for the poisoning bug that motivates it.
type sweepSnapshot struct {
	ctx context.Context

	pods    []corev1.Pod
	podsErr error
	podsSet bool

	nodes    []corev1.Node
	nodesErr error
	nodesSet bool

	slices    []discoveryv1.EndpointSlice
	slicesErr error
	slicesSet bool

	services    []corev1.Service
	servicesErr error
	servicesSet bool

	namespaces    []corev1.Namespace
	namespacesErr error
	namespacesSet bool

	// nodeZones/podNodes are the memoized placement JOINS derived
	// from the pods/nodes censuses — several checks need the maps,
	// not the raw lists, and rebuilding them per check meant each
	// consumer re-walked the same census. They memoize like the
	// censuses: the derived error is the census's own.
	nodeZones    map[string]string
	nodeZonesErr error
	nodeZonesSet bool

	podNodes    map[string]string
	podNodesErr error
	podNodesSet bool
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
		s.pods, s.podsErr, s.podsSet = nil, nil, false
		s.podNodes, s.podNodesErr, s.podNodesSet = nil, nil, false
	}
}

// InvalidateSweep drops every memoized read on the ctx-carried
// snapshot — call it after a check mutates cluster state beyond pod
// deletes (node taint/cordon, EndpointSlice delete, Service or
// Namespace mutation) so later checks re-list fresh data instead of
// acting on the pre-mutation view. A no-op outside a sweep (each
// call already sees fresh data).
func (d *Deps) InvalidateSweep(ctx context.Context) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		*s = sweepSnapshot{ctx: s.ctx}
	}
}

// AllPods returns the sweep's cluster-wide pod census — one paged
// LIST per run(), memoized; outside a sweep it lists fresh per call
// (the pre-snapshot semantics).
func (d *Deps) AllPods(ctx context.Context) ([]corev1.Pod, error) {
	s := sweepSnap(ctx)
	if !s.podsSet {
		s.podsSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.pods, s.podsErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Pods(d.CS, metav1.NamespaceAll))
	}
	return s.pods, s.podsErr
}

// AllNodes is the node twin of AllPods — the replacement for the
// per-check kube.ListNodes calls.
func (d *Deps) AllNodes(ctx context.Context) ([]corev1.Node, error) {
	s := sweepSnap(ctx)
	if !s.nodesSet {
		s.nodesSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.nodes, s.nodesErr = kube.ListNodesCached(lctx, d.NodeReader, d.CS)
	}
	return s.nodes, s.nodesErr
}

// AllEndpointSlices is the discovery twin — the shared census the
// endpoint-desync checks used to each list on their own.
func (d *Deps) AllEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, error) {
	s := sweepSnap(ctx)
	if !s.slicesSet {
		s.slicesSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.slices, s.slicesErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.EndpointSlices(d.CS, metav1.NamespaceAll))
	}
	return s.slices, s.slicesErr
}

// AllServices is the service twin.
func (d *Deps) AllServices(ctx context.Context) ([]corev1.Service, error) {
	s := sweepSnap(ctx)
	if !s.servicesSet {
		s.servicesSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.services, s.servicesErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Services(d.CS, metav1.NamespaceAll))
	}
	return s.services, s.servicesErr
}

// AllNamespaces is the namespace twin.
func (d *Deps) AllNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	s := sweepSnap(ctx)
	if !s.namespacesSet {
		s.namespacesSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.namespaces, s.namespacesErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Namespaces(d.CS))
	}
	return s.namespaces, s.namespacesErr
}

// PodsIn filters the shared census to one namespace — the client-side
// equivalent of Pods(ns).List for the namespace-scoped readers. The
// returned slice is freshly allocated; elements still alias the
// snapshot's pod structs, so treat them read-only like AllPods.
func (d *Deps) PodsIn(ctx context.Context, ns string) ([]*corev1.Pod, error) {
	pods, err := d.AllPods(ctx)
	if err != nil {
		return nil, err
	}
	var out []*corev1.Pod
	for i := range pods {
		if pods[i].Namespace == ns {
			out = append(out, &pods[i])
		}
	}
	return out, nil
}

// PodsMatching filters the shared census to one namespace (""
// = cluster-wide) plus a label selector — the client-side equivalent
// of Pods(ns).List{LabelSelector: sel} for the equality-based
// selectors the checks use. An unparseable selector is a caller bug
// surfaced as an error (the apiserver would have rejected it too).
func (d *Deps) PodsMatching(ctx context.Context, ns, selector string) ([]*corev1.Pod, error) {
	sel, err := labels.Parse(selector)
	if err != nil {
		return nil, fmt.Errorf("parse label selector %q: %w", selector, err)
	}
	pods, err := d.AllPods(ctx)
	if err != nil {
		return nil, err
	}
	var out []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if ns != "" && pod.Namespace != ns {
			continue
		}
		if sel.Matches(labels.Set(pod.Labels)) {
			out = append(out, pod)
		}
	}
	return out, nil
}

// NodeZones is the memoized node → topology-zone join the
// zone-aware checks used to each rebuild inline from AllNodes —
// the stateful site-skew signatures place endpoints and STS
// replicas through it, the zone-starvation check derives its
// worker-zone set on top. A zoneless node maps to "" — value-
// identical to a missing key for every consumer (they read the
// zone, never test presence). Built on the shared node census:
// the first caller pays that LIST, the error memoizes with the
// join exactly like the census errors do. The map is read-only —
// the serial sweep shares it across checks.
func (d *Deps) NodeZones(ctx context.Context) (map[string]string, error) {
	s := sweepSnap(ctx)
	if !s.nodeZonesSet {
		s.nodeZonesSet = true
		var nodes []corev1.Node
		nodes, s.nodeZonesErr = d.AllNodes(ctx)
		if s.nodeZonesErr == nil {
			s.nodeZones = make(map[string]string, len(nodes))
			for i := range nodes {
				s.nodeZones[nodes[i].Name] =
					nodes[i].Labels[corev1.LabelTopologyZone]
			}
		}
	}
	return s.nodeZones, s.nodeZonesErr
}

// PodNodes is the pod twin: "ns/name" → spec.nodeName over the
// shared pod census — the placement join the endpoint zone
// resolvers walk as their last fallback (a slice's own zone and
// nodeName hints can lag a rebinding; the pod's bound node is the
// ground truth) and the targetRef → node hop the skew checks make.
// Same memoized-error posture as NodeZones, and pod-derived — a
// mid-sweep pod delete stales it, so InvalidatePods drops it
// alongside the census. Read-only like every snapshot payload.
func (d *Deps) PodNodes(ctx context.Context) (map[string]string, error) {
	s := sweepSnap(ctx)
	if !s.podNodesSet {
		s.podNodesSet = true
		var pods []corev1.Pod
		pods, s.podNodesErr = d.AllPods(ctx)
		if s.podNodesErr == nil {
			s.podNodes = make(map[string]string, len(pods))
			for i := range pods {
				s.podNodes[pods[i].Namespace+"/"+pods[i].Name] =
					pods[i].Spec.NodeName
			}
		}
	}
	return s.podNodes, s.podNodesErr
}

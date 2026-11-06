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
// Mutation + staleness: a check that deletes a pod or mutates a
// node mid-sweep must call InvalidateSweep so later checks re-list
// instead of acting on the pre-mutation view (a stale pod would
// otherwise be evaluated — and possibly re-healed — as if still
// alive; UID-preconditioned deletes make that harmless but noisy).
// The snapshot is read-only: callers must not mutate returned
// objects in place (several checks sort/filter — sort a copy).
package probefw

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

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
type sweepSnapshot struct {
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
}

// WithSweepSnapshot installs a fresh, empty snapshot on ctx — the
// sweep-root calls it once per run() so the whole check roster
// shares the cycle's cluster reads. Safe to call on a ctx that
// already carries one (the old snapshot is simply replaced).
func WithSweepSnapshot(ctx context.Context) context.Context {
	return context.WithValue(ctx, sweepCtxKey{}, &sweepSnapshot{})
}

// snap returns the ctx-carried snapshot, or a fresh one when ctx
// carries none — the direct-Run (test/ad-hoc) path, where per-call
// freshness is the correct legacy semantics.
func sweepSnap(ctx context.Context) *sweepSnapshot {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		return s
	}
	return &sweepSnapshot{}
}

// InvalidateSweep drops every memoized read on the ctx-carried
// snapshot — call it after a check mutates cluster state (pod
// delete, node taint/cordon, EndpointSlice delete) so later checks
// re-list fresh data instead of acting on the pre-mutation view.
// A no-op outside a sweep (each call already sees fresh data).
func (d *Deps) InvalidateSweep(ctx context.Context) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		*s = sweepSnapshot{}
	}
}

// AllPods returns the sweep's cluster-wide pod census — one paged
// LIST per run(), memoized; outside a sweep it lists fresh per call
// (the pre-snapshot semantics).
func (d *Deps) AllPods(ctx context.Context) ([]corev1.Pod, error) {
	s := sweepSnap(ctx)
	if !s.podsSet {
		s.podsSet = true
		s.pods, s.podsErr = kube.ListAll(ctx,
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
		s.nodes, s.nodesErr = kube.ListNodes(ctx, d.CS)
	}
	return s.nodes, s.nodesErr
}

// AllEndpointSlices is the discovery twin — the shared census the
// endpoint-desync checks used to each list on their own.
func (d *Deps) AllEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, error) {
	s := sweepSnap(ctx)
	if !s.slicesSet {
		s.slicesSet = true
		s.slices, s.slicesErr = kube.ListAll(ctx,
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
		s.services, s.servicesErr = kube.ListAll(ctx,
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
		s.namespaces, s.namespacesErr = kube.ListAll(ctx,
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

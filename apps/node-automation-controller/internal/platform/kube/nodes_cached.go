// nodes_cached.go — the informer-backed twin of ListNodes. The
// manager's cache already mirrors Nodes with .Status.Images and
// managedFields stripped (see buildCacheOptions in cmd/manager), and
// every reconciler that watches &corev1.Node{} keeps that informer
// warm — yet the read paths still paid a full apiserver LIST per
// sweep. ListNodesCached routes the read-only censuses through the
// cache client instead; the only cache-adjacent reads that stay on
// the direct clientset are the confirm-before-act re-Gets
// (TaintNode/UntaintNode) — the maintenance-mutex verdict's node
// census rides the cache too since Verdict.NodeReader carries the
// informer client, while every destructive act still re-confirms
// live.
package kube

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CachedNodeReader is the minimal read shape the manager's
// cache-backed client satisfies — client.Reader (mgr.GetClient)
// implements it. A nil reader means "no cache wired" (tests,
// StubManager, literally-built fixtures): ListNodesCached falls back
// to the direct ListNodes then, so call sites work unchanged
// outside a running manager.
type CachedNodeReader interface {
	List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error
}

// ListNodesCached returns the node census from the informer cache
// when r is non-nil, else the direct clientset read ListNodes always
// did. Cache reads are watch-fresh (milliseconds behind the
// apiserver) — fine for read-only verdicts; anything that gates a
// destructive act must still confirm on the direct clientset.
//
// NOTE: cached Nodes have .Status.Images nil and managedFields
// stripped (the manager's DefaultTransform) — every call site here
// reads labels/taints/conditions/spec only.
func ListNodesCached(ctx context.Context, r CachedNodeReader,
	cs kubernetes.Interface) ([]corev1.Node, error) {

	if r == nil {
		return ListNodes(ctx, cs)
	}
	var nl corev1.NodeList
	if err := r.List(ctx, &nl); err != nil {
		return nil, err
	}
	return nl.Items, nil
}

// CountNotReadyNodesCached is the storm-gate census over the cached
// node read — the informer-backed twin of the CountNotReadyNodes
// list+count the module loops ran directly. Same cache discipline as
// ListNodesCached: nil reader (tests, fixtures) falls back to the
// direct clientset path.
func CountNotReadyNodesCached(ctx context.Context, r CachedNodeReader,
	cs kubernetes.Interface) (int, error) {

	nodes, err := ListNodesCached(ctx, r, cs)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range nodes {
		if !NodeReady(&nodes[i]) {
			n++
		}
	}
	return n, nil
}

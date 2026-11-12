// snapshot_pods.go — the pod census readers of the per-sweep
// snapshot: AllPods plus its namespace/selector filters and the
// pod-derived PodNodes placement join (split out of snapshot.go —
// see its header for the memoizer contract).
package probefw

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// AllPods returns the sweep's cluster-wide pod census — one paged
// LIST per run(), memoized; outside a sweep it lists fresh per call
// (the pre-snapshot semantics). Pods deleted mid-sweep are hidden
// by the overlay tombstones (kube.FilterPodTombstones) — the O(1)
// replacement for the per-delete InvalidatePods re-LIST storm: the
// memoized census stays valid, the tombstone set does the hiding.
func (d *Deps) AllPods(ctx context.Context) ([]corev1.Pod, error) {
	s := sweepSnap(ctx)
	pods, err := s.pods.get(func(bool) ([]corev1.Pod, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.Pods(d.CS, metav1.NamespaceAll))
	})
	if err != nil {
		return nil, err
	}
	// The tombstone filter is generation-cached on the snapshot —
	// repeated AllPods calls between pod deletes share the ONE
	// filtered slice instead of re-copying the census each time.
	return s.podCensusView(ctx, pods), nil
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

// podNodeIndex is the memoized PodNodes payload: the "ns/name" →
// spec.nodeName placement map plus the parallel "ns/name" → UID
// lookup the per-read tombstone filter needs — the placement keys
// carry no UID and kube.IsPodDeleted is keyed by UID, so the join
// must remember it. One memo so the pair can never diverge across
// an invalidation.
type podNodeIndex struct {
	node map[string]string
	uid  map[string]types.UID
	// src is the filtered AllPods slice this index was built from —
	// the podNodeView cache keys on its backing-array identity, so
	// the placement view rebuilds exactly when the index does (a
	// census invalidation) or the tombstone generation bumps.
	src []corev1.Pod
}

// PodNodes is the pod twin: "ns/name" → spec.nodeName over the
// shared pod census — the placement join the endpoint zone
// resolvers walk as their last fallback (a slice's own zone and
// nodeName hints can lag a rebinding; the pod's bound node is the
// ground truth) and the targetRef → node hop the skew checks make.
// Same memoized-error posture as NodeZones.
//
// Deleted pods are filtered on EVERY read, not just at memo build:
// AllPods hides tombstoned pods (kube.FilterPodTombstones) but the
// O(1) MarkPodDeleted path deliberately does NOT invalidate the
// derived join — a pod deleted after the first PodNodes call would
// otherwise keep its placement entry for every later check in the
// sweep. The filtered view itself is generation-cached on the
// snapshot (podNodeView): between tombstone bumps every caller
// shares the ONE map instead of re-walking the index per call. The
// returned map is SHARED — snapshot payloads are read-only.
func (d *Deps) PodNodes(ctx context.Context) (map[string]string, error) {
	s := sweepSnap(ctx)
	idx, err := s.podNodes.get(func(bool) (podNodeIndex, error) {
		pods, err := d.AllPods(ctx)
		if err != nil {
			return podNodeIndex{}, err
		}
		idx := podNodeIndex{
			node: make(map[string]string, len(pods)),
			uid:  make(map[string]types.UID, len(pods)),
			src:  pods,
		}
		for i := range pods {
			key := pods[i].Namespace + "/" + pods[i].Name
			idx.node[key] = pods[i].Spec.NodeName
			idx.uid[key] = pods[i].UID
		}
		return idx, nil
	})
	if err != nil {
		return nil, err
	}
	return s.podNodeView(ctx, idx.src, idx), nil
}

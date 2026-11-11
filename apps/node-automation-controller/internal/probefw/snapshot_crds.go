// snapshot_crds.go — the dynamic-client census readers of the
// per-sweep snapshot: the per-GVR AllUnstructured family (split out
// of snapshot.go — see its header for the memoizer contract).
package probefw

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// AllUnstructured is the per-GVR twin for CR instances: one paged
// dynamic LIST per (sweep, GVR), memoized in a per-GVR map under one
// family mutex. The raw apiserver error is memoized verbatim — the
// checks keep their own IsNotFound/IsNoMatchError interpretation
// ("CRD absent on this cluster") exactly as before the snapshot;
// sharing the memo means they also share one failed read instead of
// each retrying a broken GVR within the cycle. A nil Dyn is a wiring
// bug surfaced as an error.
//
// Callers that only need a SLICE of each object (the kine
// large-object audit measuring serialized size) must not route the
// CRD GVR through here: the memo pins every CRD's OpenAPI schema —
// 80–150 MiB of unstructured content — on the heap for the rest of
// the sweep. Those callers stream kube.ListEach pages instead and
// let each page's objects die with the page.
func (d *Deps) AllUnstructured(ctx context.Context,
	gvr schema.GroupVersionResource) ([]unstructured.Unstructured, error) {
	if d.Dyn == nil {
		return nil, fmt.Errorf("no dynamic client — %s census unverifiable",
			gvr.Resource)
	}
	s := sweepSnap(ctx)
	s.muUnstructs.Lock()
	defer s.muUnstructs.Unlock()
	if s.unstructReads == nil {
		s.unstructReads = map[schema.GroupVersionResource]*unstructRead{}
	}
	read := s.unstructReads[gvr]
	if read == nil {
		read = &unstructRead{}
		s.unstructReads[gvr] = read
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		read.items, read.err = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.DynamicPage(d.Dyn.Resource(gvr)))
	}
	return read.items, read.err
}

// AllUnstructuredFirst is AllUnstructured's first-serving-GVR
// variant for CRDs that ship multiple served versions (HelmRelease
// v2+v2beta2): candidates are tried in order through the same
// per-sweep memoizer — each GVR's LIST is still paid at most once
// per cycle — and the first success wins. The error contract is
// kube.ListFirstGVR's verbatim: NotFound/NoMatch marks "not served",
// a real failure is preferred over benign misses when nothing
// lists, so the caller can tell "CRD absent" (IsNotFound /
// IsNoMatchError on the result → Pass) from "API broken" (Infra).
func (d *Deps) AllUnstructuredFirst(ctx context.Context,
	gvrs []schema.GroupVersionResource) ([]unstructured.Unstructured,
	schema.GroupVersionResource, error) {

	return kube.ListFirstGVR(ctx, gvrs, d.AllUnstructured)
}

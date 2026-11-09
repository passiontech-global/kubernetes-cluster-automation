// snapshot_crds.go — the dynamic-client census readers of the
// per-sweep snapshot: AllCRDs plus the per-GVR AllUnstructured
// family (split out of snapshot.go — see its header for the
// memoizer contract).
package probefw

import (
	"context"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// gvrCustomResourceDefinitions is the apiextensions/v1 CRD GVR —
// cluster-scoped, read through the dynamic client (no typed client
// for apiextensions in this module's imports).
var gvrCustomResourceDefinitions = schema.GroupVersionResource{
	Group: "apiextensions.k8s.io", Version: "v1",
	Resource: "customresourcedefinitions",
}

// AllCRDs is the CRD twin — the shared definition census that tells
// which operator CRDs exist before a check walks their instances
// (absent CRD = check skips, one census instead of one probe per
// check). A nil Dyn is a wiring bug surfaced as an error, memoized
// like a LIST failure — every CRD-reading check in the cycle reads
// the same failure instead of each re-deriving it.
func (d *Deps) AllCRDs(ctx context.Context) ([]unstructured.Unstructured, error) {
	if d.Dyn == nil {
		return nil, errors.New("no dynamic client — CRD census unverifiable")
	}
	s := sweepSnap(ctx)
	s.muCRDs.Lock()
	defer s.muCRDs.Unlock()
	if !s.crdsSet {
		s.crdsSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.crds, s.crdsErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.DynamicPage(d.Dyn.Resource(gvrCustomResourceDefinitions)))
	}
	return s.crds, s.crdsErr
}

// AllUnstructured is the per-GVR twin for CR instances: one paged
// dynamic LIST per (sweep, GVR), memoized in a per-GVR map under one
// family mutex. The raw apiserver error is memoized verbatim — the
// checks keep their own IsNotFound/IsNoMatchError interpretation
// ("CRD absent on this cluster") exactly as before the snapshot;
// sharing the memo means they also share one failed read instead of
// each retrying a broken GVR within the cycle. A nil Dyn is a wiring
// bug surfaced as an error.
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

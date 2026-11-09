// list_unstructured.go — the cluster-wide paged dynamic List most
// CR-scanning modules repeat: walk kube.ListAll/DynamicPage at the
// shared page bound and rewrap the items as an UnstructuredList.
// Three identical wrappers hand-roll exactly this shape
// (helmrelease_unlocker.listAllPages, velero_backup_auditor.veleroList,
// externalsecretnudge's listFirst/listES bodies); this is the one
// shared builder on top of the existing list.go primitives — the
// wrappers keep their GVR-fallback loops, only the paging rewrites.
// ListFirstGVR/ListFirstUnstructured below ARE the shared fallback
// loop itself.
package kube

import (
	"context"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// ListAllUnstructured pages a dynamic List to completion and returns
// the items as an UnstructuredList — the shape every CR-scanning
// sweep wants back (the wrappers returned the list type only to keep
// .Items iteration natural). opts carries the caller's selectors; a
// zero Limit takes kube.DefaultListPageSize, the bound every
// hand-rolled wrapper passed, so an unbounded single response cannot
// haul the whole resource across the wire.
//
// Returns nil (not an empty list) when the first page errors,
// matching ListAll's `return nil, err` contract.
func ListAllUnstructured(ctx context.Context, ri dynamic.ResourceInterface,
	opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if opts.Limit == 0 {
		opts.Limit = DefaultListPageSize
	}
	items, err := ListAll(ctx, opts, DynamicPage(ri))
	if err != nil {
		return nil, err
	}
	return &unstructured.UnstructuredList{Items: items}, nil
}

// ListFirstGVR tries each candidate GVR in order through list and
// returns the first successful result plus the GVR that answered —
// the multi-served-version probe shape (a CRD served at v1 AND
// v1beta1: the current version is tried first, the previous storage
// version is the fallback). list is the caller's paged read for one
// GVR (kube.ListAllUnstructured for direct dynamic clients,
// probefw.Deps.AllUnstructured for the sweep-memoized one), so the
// fallback loop is shared while each layer keeps its own read path.
//
// Error contract: a NotFound/NoMatch candidate is the "not served"
// shape — remembered as benign and skipped. Any other failure is a
// REAL api problem (RBAC, throttling, timeout) remembered
// separately; when NO candidate lists, a real error wins over benign
// misses so the caller reports the actual problem instead of the
// last candidate's 404. An all-benign sweep returns the first benign
// error — callers distinguish "not installed" (IsNotFound /
// IsNoMatchError on the result) from "API broken". An empty gvrs is
// a caller bug and errors loudly rather than returning a zero T.
func ListFirstGVR[T any](ctx context.Context,
	gvrs []schema.GroupVersionResource,
	list func(context.Context, schema.GroupVersionResource) (T, error)) (T, schema.GroupVersionResource, error) {

	var zero T
	if len(gvrs) == 0 {
		return zero, schema.GroupVersionResource{},
			errors.New("ListFirstGVR: no candidate GVRs")
	}
	var benignErr, realErr error
	for _, gvr := range gvrs {
		items, err := list(ctx, gvr)
		if err == nil {
			return items, gvr, nil
		}
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			if benignErr == nil {
				benignErr = err
			}
			continue
		}
		if realErr == nil {
			realErr = err
		}
	}
	if realErr != nil {
		return zero, schema.GroupVersionResource{}, realErr
	}
	return zero, schema.GroupVersionResource{}, benignErr
}

// ListFirstUnstructured is ListFirstGVR bound to the direct dynamic
// client at the shared page bound — the shape the integration/janitor
// modules' GVR-fallback lists want back as an UnstructuredList.
func ListFirstUnstructured(ctx context.Context, dyn dynamic.Interface,
	gvrs []schema.GroupVersionResource, opts metav1.ListOptions) (
	*unstructured.UnstructuredList, schema.GroupVersionResource, error) {

	return ListFirstGVR(ctx, gvrs,
		func(ctx context.Context, gvr schema.GroupVersionResource) (*unstructured.UnstructuredList, error) {
			return ListAllUnstructured(ctx, dyn.Resource(gvr), opts)
		})
}

// list_unstructured.go — the cluster-wide paged dynamic List most
// CR-scanning modules repeat: walk kube.ListAll/DynamicPage at the
// shared page bound and rewrap the items as an UnstructuredList.
// Three identical wrappers hand-roll exactly this shape
// (helmrelease_unlocker.listAllPages, velero_backup_auditor.veleroList,
// externalsecretnudge's listFirst/listES bodies); this is the one
// shared builder on top of the existing list.go primitives — the
// wrappers keep their GVR-fallback loops, only the paging rewrites.
package kube

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

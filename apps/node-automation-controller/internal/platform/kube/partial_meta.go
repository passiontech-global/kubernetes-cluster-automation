// partial_meta.go — metadata-only cluster reads: the
// PartialObjectMetadata LIST that carries ObjectMeta (name, ns,
// labels, annotations, ownerRefs, timestamps, UID) without the
// resource payload. For the audit/census consumers that only ever
// look at metadata — CRD sprawl scans, webhook-config audits,
// external-secret nudges — a full-object LIST pulls every CR's
// status blob and embedded spec across the wire and pins it in
// etcd→apiserver→client RAM for the whole sweep. The metadata
// endpoint returns the same objects minus the payload: same RBAC
// verb (list), a fraction of the bytes.
//
// ListPartialOrFallback is the single entry point. It prefers the
// metadata client (Deps.Meta, built in cmd/manager off the shared
// base transport). A metadata-client error NEVER falls back to a
// full-object list: a genuine apiserver failure (RBAC, 5xx, timeout,
// 404/NoMatch, 429) must surface as itself — silently re-issuing the
// same read as a heavier full-object LIST would mask the outage AND
// double the load. Fallback exists ONLY for "this client cannot
// serve the metadata endpoint" — a nil meta client (the hundreds of
// unit tests that construct Deps{CS: fakeCS} with no Meta: the fake
// metadata client is opt-in, the fake clientsets are not), an HTTP
// 406 NotAcceptable (an apiserver or aggregated layer that does not
// serve meta.k8s.io/v1 PartialObjectMetadata for the GVR), and the
// client-go fake's unregistered-scheme rejection — all cases where
// the metadata read itself is impossible, not merely failing.
//
// When a fallback IS needed the typed clientset runs BEFORE the
// dynamic client for every built-in GVR (core/v1, apps/v1, batch/v1,
// policy/v1, discovery.k8s.io/v1, storage.k8s.io/v1,
// coordination.k8s.io/v1, certificates.k8s.io/v1,
// admissionregistration.k8s.io/v1): the typed fakes every existing
// unit test builds answer all of them, while the fake dynamic client
// panics on GVRs its scheme never registered. The dynamic client
// remains the catch-all for CRDs and any built-in the typed switch
// does not cover — the typed GVR table + List switch live in
// partial_meta_typed.go.
package kube

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
)

// crdListPageSize is the page bound the dynamic fallback applies to
// non-core GVRs when the caller left Limit unset — CRD objects are
// the payload-heavy case this helper exists for, and an unbounded
// first page of unstructured CRs is exactly the RAM spike the
// metadata path avoids. Callers wanting a different page size pass
// it in opts.Limit; built-in fallbacks page at DefaultListPageSize.
const crdListPageSize int64 = 25

// ListPartialOrFallback lists objects of gvr in namespace as
// metadata-only PartialObjectMetadata, paginating to completion
// (the ListAll contract — the returned slice is the whole result).
//
// namespace is the list scope: metav1.NamespaceAll for
// cluster-wide, a name for namespaced reads, "" for cluster-scoped
// GVRs (both forms reach the cluster-scoped endpoint).
//
// opts carries LabelSelector/FieldSelector/Limit — Limit is the
// PAGE size, not a result cap. A nil meta client skips straight to
// the fallbacks; a meta error that means "the metadata endpoint
// cannot serve this resource" (see metaUnsupported) degrades to
// them too, while every other meta error is returned verbatim —
// the fallback must never mask a real apiserver failure with a
// heavier read of the same broken endpoint.
func ListPartialOrFallback(ctx context.Context,
	meta metadata.Interface,
	fallbackCS kubernetes.Interface,
	fallbackDyn dynamic.Interface,
	gvr schema.GroupVersionResource,
	namespace string,
	opts metav1.ListOptions) ([]metav1.PartialObjectMetadata, error) {

	var firstErr error
	if meta != nil {
		items, err := listPartialViaMeta(ctx, meta, gvr, namespace, opts)
		if err == nil {
			return items, nil
		}
		// Only "the metadata endpoint cannot serve this GVR"
		// degrades to the full-object fallbacks — a genuine API
		// error (RBAC denial, 5xx, timeout, 404/NoMatch, 429, ctx
		// cancellation) is returned as itself rather than masked by
		// a heavier re-read that fails the same way while doubling
		// the load on an already-sick apiserver.
		if !metaUnsupported(err) {
			return nil, err
		}
		firstErr = err
	}
	// Built-in GVRs prefer the typed clientset: it is the path the
	// fake clientsets in tests answer universally, and the typed
	// List is the same read the pre-metadata code made. CRDs and
	// uncovered built-ins fall through to the dynamic client.
	if fallbackCS != nil && typedFallbackCovers(gvr) {
		items, err := listPartialViaTyped(ctx, fallbackCS, gvr,
			namespace, opts)
		if err == nil {
			return items, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if fallbackDyn != nil {
		items, err := listPartialViaDynamic(ctx, fallbackDyn, gvr,
			namespace, opts)
		if err == nil {
			return items, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("no client available for metadata list of %s", gvr)
}

// metaUnsupported reports whether a metadata-list failure means the
// metadata ENDPOINT itself cannot serve the resource — the only
// error class allowed to trigger the heavier fallbacks. Everything
// else surfaces verbatim: a 404/NoMatch (the GVR genuinely is not
// served), 403 RBAC denial, 429 throttling, context cancellation,
// or a plain transport failure must not be masked by a second,
// heavier read of the same broken endpoint.
func metaUnsupported(err error) bool {
	// 406 Not Acceptable: the apiserver — or an aggregated apiserver
	// in front of it — does not serve meta.k8s.io/v1
	// PartialObjectMetadata for this resource.
	if apierrors.IsNotAcceptable(err) {
		return true
	}
	// The client-go metadata fake's scheme/tracker rejects resources
	// it never registered — a test-harness limitation, not an API
	// failure; the typed/dynamic fallbacks exist precisely for it.
	return runtime.IsNotRegisteredError(err)
}

// listPartialViaMeta pages the metadata client. PartialObjectMetadataList
// embeds ListMeta, so GetContinue supplies the next-page token.
func listPartialViaMeta(ctx context.Context, meta metadata.Interface,
	gvr schema.GroupVersionResource, namespace string,
	opts metav1.ListOptions) ([]metav1.PartialObjectMetadata, error) {

	getter := meta.Resource(gvr)
	var ri metadata.ResourceInterface = getter
	if namespace != "" {
		ri = getter.Namespace(namespace)
	}
	var out []metav1.PartialObjectMetadata
	for {
		list, err := ri.List(ctx, pageOpts(opts))
		if err != nil {
			return nil, err
		}
		out = append(out, list.Items...)
		next := list.GetContinue()
		if next == "" {
			return out, nil
		}
		opts.Continue = next
	}
}

// listPartialViaDynamic pages the dynamic client and projects each
// unstructured item down to its metadata. For non-core GVRs an unset
// Limit gets crdListPageSize — the fallback exists for tests and
// degraded-apiserver windows, not as the steady-state read path.
func listPartialViaDynamic(ctx context.Context, dyn dynamic.Interface,
	gvr schema.GroupVersionResource, namespace string,
	opts metav1.ListOptions) (out []metav1.PartialObjectMetadata, err error) {

	// The dynamic FAKE panics on a GVR its scheme never registered
	// (the unregistered-List guard NewFakeDyn documents); the real
	// client returns an error for the same condition. Convert the
	// panic to an error so callers see a normal failure — the
	// production client never panics, this only fires under test
	// fakes.
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("dynamic list %s: %v", gvr, r)
		}
	}()

	// Clamp the page bound both ways so no caller can request an
	// unbounded first page of unstructured objects — the RAM spike
	// this helper exists to avoid. An unset Limit gets the group
	// default (CRDs page small — they are the payload-heavy case);
	// an explicit Limit above the shared page ceiling is capped
	// (pagination still reaches every item, just in smaller pages).
	if gvr.Group != "" && (opts.Limit <= 0 || opts.Limit > crdListPageSize) {
		opts.Limit = crdListPageSize
	} else if opts.Limit <= 0 || opts.Limit > DefaultListPageSize {
		opts.Limit = DefaultListPageSize
	}
	getter := dyn.Resource(gvr)
	var ri dynamic.ResourceInterface = getter
	if namespace != "" {
		ri = getter.Namespace(namespace)
	}
	for {
		list, lerr := ri.List(ctx, pageOpts(opts))
		if lerr != nil {
			return nil, lerr
		}
		for i := range list.Items {
			out = append(out, partialFromUnstructured(&list.Items[i]))
		}
		next := list.GetContinue()
		if next == "" {
			return out, nil
		}
		opts.Continue = next
	}
}

// partialFromUnstructured projects one unstructured item to
// PartialObjectMetadata: TypeMeta verbatim, ObjectMeta decoded from
// the "metadata" member. A missing/malformed metadata block yields
// the TypeMeta-only object — the apiserver always writes one, so a
// gap here means a hand-built fixture, and an empty ObjectMeta is
// the honest projection of it.
func partialFromUnstructured(u *unstructured.Unstructured) metav1.PartialObjectMetadata {
	pom := metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: u.GetAPIVersion(),
			Kind:       u.GetKind(),
		},
	}
	if md, ok := u.Object["metadata"].(map[string]interface{}); ok {
		_ = runtime.DefaultUnstructuredConverter.FromUnstructured(
			md, &pom.ObjectMeta)
	}
	return pom
}

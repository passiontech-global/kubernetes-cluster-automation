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
// does not cover.
package kube

import (
	"context"
	"fmt"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
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
	if opts.Limit <= 0 {
		if gvr.Group != "" {
			opts.Limit = crdListPageSize
		} else {
			opts.Limit = DefaultListPageSize
		}
	} else if opts.Limit > DefaultListPageSize {
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

// typedFallbackCovers reports whether listPartialViaTyped has a
// typed client path for gvr — the built-in groups the metadata-only
// consumers census. Kept as an explicit table (not inferred from
// the switch) so ListPartialOrFallback can prefer the typed client
// only where it actually answers.
func typedFallbackCovers(gvr schema.GroupVersionResource) bool {
	switch gvr.Group {
	case "":
		if gvr.Version != "v1" {
			return false
		}
		switch gvr.Resource {
		case "pods", "services", "endpoints", "configmaps", "secrets",
			"serviceaccounts", "persistentvolumeclaims",
			"persistentvolumes", "namespaces", "nodes", "events",
			"resourcequotas", "limitranges":
			return true
		}
	case "apps":
		if gvr.Version == "v1" {
			switch gvr.Resource {
			case "deployments", "replicasets", "statefulsets", "daemonsets":
				return true
			}
		}
	case "batch":
		if gvr.Version == "v1" {
			switch gvr.Resource {
			case "jobs", "cronjobs":
				return true
			}
		}
	case "policy":
		if gvr.Version == "v1" && gvr.Resource == "poddisruptionbudgets" {
			return true
		}
	case "discovery.k8s.io":
		if gvr.Version == "v1" && gvr.Resource == "endpointslices" {
			return true
		}
	case "storage.k8s.io":
		if gvr.Version == "v1" && gvr.Resource == "volumeattachments" {
			return true
		}
	case "coordination.k8s.io":
		if gvr.Version == "v1" && gvr.Resource == "leases" {
			return true
		}
	case "certificates.k8s.io":
		if gvr.Version == "v1" && gvr.Resource == "certificatesigningrequests" {
			return true
		}
	case "admissionregistration.k8s.io":
		if gvr.Version == "v1" {
			switch gvr.Resource {
			case "mutatingwebhookconfigurations",
				"validatingwebhookconfigurations":
				return true
			}
		}
	}
	return false
}

// listPartialViaTyped is the built-in fallback: a bounded switch over
// the resources metadata-only consumers actually census. Typed List
// calls work against the fake clientset every existing unit test
// builds (unlike CoreV1().RESTClient(), which the fake returns as a
// nil *rest.RESTClient). GVRs typedFallbackCovers does not list
// return an error — callers needing those must pass a dynamic or
// metadata client.
func listPartialViaTyped(ctx context.Context, cs kubernetes.Interface,
	gvr schema.GroupVersionResource, namespace string,
	opts metav1.ListOptions) ([]metav1.PartialObjectMetadata, error) {

	if !typedFallbackCovers(gvr) {
		return nil, fmt.Errorf("typed fallback has no client for %s", gvr)
	}
	// The PageFunc constructors take the list scope verbatim —
	// "" (NamespaceAll) is the cluster-wide read for namespaced
	// resources; cluster-scoped resources use the no-arg forms.
	apiVersion := gvr.GroupVersion().String()
	switch {
	case gvr.Group == "":
		switch gvr.Resource {
		case "pods":
			return typedMetaList(ctx, opts, apiVersion,
				Pods(cs, namespace), "Pod",
				func(p *corev1.Pod) *metav1.ObjectMeta { return &p.ObjectMeta })
		case "services":
			return typedMetaList(ctx, opts, apiVersion,
				Services(cs, namespace), "Service",
				func(s *corev1.Service) *metav1.ObjectMeta { return &s.ObjectMeta })
		case "endpoints":
			//nolint:staticcheck // SA1019: see Endpoints — the deprecated kind stays served for endpoints-DCS consumers.
			return typedMetaList(ctx, opts, apiVersion,
				Endpoints(cs, namespace), "Endpoints",
				func(e *corev1.Endpoints) *metav1.ObjectMeta { return &e.ObjectMeta })
		case "configmaps":
			return typedMetaList(ctx, opts, apiVersion,
				ConfigMaps(cs, namespace), "ConfigMap",
				func(c *corev1.ConfigMap) *metav1.ObjectMeta { return &c.ObjectMeta })
		case "secrets":
			return typedMetaList(ctx, opts, apiVersion,
				Secrets(cs, namespace), "Secret",
				func(s *corev1.Secret) *metav1.ObjectMeta { return &s.ObjectMeta })
		case "serviceaccounts":
			return typedMetaList(ctx, opts, apiVersion,
				ServiceAccounts(cs, namespace), "ServiceAccount",
				func(s *corev1.ServiceAccount) *metav1.ObjectMeta { return &s.ObjectMeta })
		case "persistentvolumeclaims":
			return typedMetaList(ctx, opts, apiVersion,
				PersistentVolumeClaims(cs, namespace), "PersistentVolumeClaim",
				func(p *corev1.PersistentVolumeClaim) *metav1.ObjectMeta { return &p.ObjectMeta })
		case "persistentvolumes":
			return typedMetaList(ctx, opts, apiVersion,
				PersistentVolumes(cs), "PersistentVolume",
				func(p *corev1.PersistentVolume) *metav1.ObjectMeta { return &p.ObjectMeta })
		case "namespaces":
			return typedMetaList(ctx, opts, apiVersion,
				Namespaces(cs), "Namespace",
				func(n *corev1.Namespace) *metav1.ObjectMeta { return &n.ObjectMeta })
		case "nodes":
			return typedMetaList(ctx, opts, apiVersion,
				nodes(cs), "Node",
				func(n *corev1.Node) *metav1.ObjectMeta { return &n.ObjectMeta })
		case "events":
			return typedMetaList(ctx, opts, apiVersion,
				Events(cs, namespace), "Event",
				func(e *corev1.Event) *metav1.ObjectMeta { return &e.ObjectMeta })
		case "resourcequotas":
			return typedMetaList(ctx, opts, apiVersion,
				ResourceQuotas(cs, namespace), "ResourceQuota",
				func(r *corev1.ResourceQuota) *metav1.ObjectMeta { return &r.ObjectMeta })
		case "limitranges":
			return typedMetaList(ctx, opts, apiVersion,
				LimitRanges(cs, namespace), "LimitRange",
				func(l *corev1.LimitRange) *metav1.ObjectMeta { return &l.ObjectMeta })
		}
	case gvr.Group == "apps":
		switch gvr.Resource {
		case "deployments":
			return typedMetaList(ctx, opts, apiVersion,
				Deployments(cs, namespace), "Deployment",
				func(d *appsv1.Deployment) *metav1.ObjectMeta { return &d.ObjectMeta })
		case "replicasets":
			return typedMetaList(ctx, opts, apiVersion,
				ReplicaSets(cs, namespace), "ReplicaSet",
				func(r *appsv1.ReplicaSet) *metav1.ObjectMeta { return &r.ObjectMeta })
		case "statefulsets":
			return typedMetaList(ctx, opts, apiVersion,
				StatefulSets(cs, namespace), "StatefulSet",
				func(s *appsv1.StatefulSet) *metav1.ObjectMeta { return &s.ObjectMeta })
		case "daemonsets":
			return typedMetaList(ctx, opts, apiVersion,
				DaemonSets(cs, namespace), "DaemonSet",
				func(d *appsv1.DaemonSet) *metav1.ObjectMeta { return &d.ObjectMeta })
		}
	case gvr.Group == "batch":
		switch gvr.Resource {
		case "jobs":
			return typedMetaList(ctx, opts, apiVersion,
				Jobs(cs, namespace), "Job",
				func(j *batchv1.Job) *metav1.ObjectMeta { return &j.ObjectMeta })
		case "cronjobs":
			return typedMetaList(ctx, opts, apiVersion,
				CronJobs(cs, namespace), "CronJob",
				func(c *batchv1.CronJob) *metav1.ObjectMeta { return &c.ObjectMeta })
		}
	case gvr.Group == "policy":
		return typedMetaList(ctx, opts, apiVersion,
			PodDisruptionBudgets(cs, namespace), "PodDisruptionBudget",
			func(p *policyv1.PodDisruptionBudget) *metav1.ObjectMeta { return &p.ObjectMeta })
	case gvr.Group == "discovery.k8s.io":
		return typedMetaList(ctx, opts, apiVersion,
			EndpointSlices(cs, namespace), "EndpointSlice",
			func(e *discoveryv1.EndpointSlice) *metav1.ObjectMeta { return &e.ObjectMeta })
	case gvr.Group == "storage.k8s.io":
		return typedMetaList(ctx, opts, apiVersion,
			VolumeAttachments(cs), "VolumeAttachment",
			func(v *storagev1.VolumeAttachment) *metav1.ObjectMeta { return &v.ObjectMeta })
	case gvr.Group == "coordination.k8s.io":
		return typedMetaList(ctx, opts, apiVersion,
			Leases(cs, namespace), "Lease",
			func(l *coordinationv1.Lease) *metav1.ObjectMeta { return &l.ObjectMeta })
	case gvr.Group == "certificates.k8s.io":
		return typedMetaList(ctx, opts, apiVersion,
			CertificateSigningRequests(cs), "CertificateSigningRequest",
			func(c *certificatesv1.CertificateSigningRequest) *metav1.ObjectMeta {
				return &c.ObjectMeta
			})
	case gvr.Group == "admissionregistration.k8s.io":
		switch gvr.Resource {
		case "mutatingwebhookconfigurations":
			return typedMetaList(ctx, opts, apiVersion,
				MutatingWebhookConfigurations(cs), "MutatingWebhookConfiguration",
				func(m *admissionv1.MutatingWebhookConfiguration) *metav1.ObjectMeta {
					return &m.ObjectMeta
				})
		case "validatingwebhookconfigurations":
			return typedMetaList(ctx, opts, apiVersion,
				ValidatingWebhookConfigurations(cs), "ValidatingWebhookConfiguration",
				func(v *admissionv1.ValidatingWebhookConfiguration) *metav1.ObjectMeta {
					return &v.ObjectMeta
				})
		}
	}
	return nil, fmt.Errorf("typed fallback does not cover %q", gvr.Resource)
}

// typedMetaList runs one typed paged List and projects each item to
// PartialObjectMetadata — ObjectMeta copied verbatim (the whole
// point of the metadata read), TypeMeta filled from the GVR's own
// group/version plus the resource's kind.
func typedMetaList[T any](ctx context.Context, opts metav1.ListOptions,
	apiVersion string, page PageFunc[T], kind string,
	om func(*T) *metav1.ObjectMeta) ([]metav1.PartialObjectMetadata, error) {

	items, err := ListAll(ctx, opts, page)
	if err != nil {
		return nil, err
	}
	out := make([]metav1.PartialObjectMetadata, 0, len(items))
	for i := range items {
		out = append(out, metav1.PartialObjectMetadata{
			TypeMeta:   metav1.TypeMeta{Kind: kind, APIVersion: apiVersion},
			ObjectMeta: *om(&items[i]),
		})
	}
	return out, nil
}

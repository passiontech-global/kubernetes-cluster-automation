// partial_meta_typed.go — the typed-clientset half of
// ListPartialOrFallback's fallback chain: the built-in GVR table
// (typedFallbackCovers) and the bounded typed List switch
// (listPartialViaTyped) that projects each item to
// PartialObjectMetadata. Split out of partial_meta.go so the
// entry-point file stays under the ~500-LOC bar.
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

type typedMetaLister func(ctx context.Context, cs kubernetes.Interface, ns string,
	opts metav1.ListOptions, apiVersion string) ([]metav1.PartialObjectMetadata, error)

func nsMetaLister[T any](kind string, page func(kubernetes.Interface, string) PageFunc[T],
	om func(*T) *metav1.ObjectMeta) typedMetaLister {
	return func(ctx context.Context, cs kubernetes.Interface, ns string,
		opts metav1.ListOptions, apiVersion string) ([]metav1.PartialObjectMetadata, error) {
		return typedMetaList(ctx, opts, apiVersion, page(cs, ns), kind, om)
	}
}

func clusterMetaLister[T any](kind string, page func(kubernetes.Interface) PageFunc[T],
	om func(*T) *metav1.ObjectMeta) typedMetaLister {
	return func(ctx context.Context, cs kubernetes.Interface, _ string,
		opts metav1.ListOptions, apiVersion string) ([]metav1.PartialObjectMetadata, error) {
		return typedMetaList(ctx, opts, apiVersion, page(cs), kind, om)
	}
}

func coreGVR(resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "", Version: "v1", Resource: resource}
}

func gvrV1(group, resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: group, Version: "v1", Resource: resource}
}

// typedMetaListers is the single source of truth for the built-in GVRs
// ListPartialOrFallback can serve via the typed clientset.
var typedMetaListers = map[schema.GroupVersionResource]typedMetaLister{
	coreGVR("pods"): nsMetaLister("Pod", Pods,
		func(p *corev1.Pod) *metav1.ObjectMeta { return &p.ObjectMeta }),
	coreGVR("services"): nsMetaLister("Service", Services,
		func(s *corev1.Service) *metav1.ObjectMeta { return &s.ObjectMeta }),
	//nolint:staticcheck // SA1019: see Endpoints — the deprecated kind stays served for endpoints-DCS consumers.
	coreGVR("endpoints"): nsMetaLister("Endpoints", Endpoints,
		func(e *corev1.Endpoints) *metav1.ObjectMeta { return &e.ObjectMeta }),
	coreGVR("configmaps"): nsMetaLister("ConfigMap", ConfigMaps,
		func(c *corev1.ConfigMap) *metav1.ObjectMeta { return &c.ObjectMeta }),
	coreGVR("secrets"): nsMetaLister("Secret", Secrets,
		func(s *corev1.Secret) *metav1.ObjectMeta { return &s.ObjectMeta }),
	coreGVR("serviceaccounts"): nsMetaLister("ServiceAccount", ServiceAccounts,
		func(s *corev1.ServiceAccount) *metav1.ObjectMeta { return &s.ObjectMeta }),
	coreGVR("persistentvolumeclaims"): nsMetaLister("PersistentVolumeClaim", PersistentVolumeClaims,
		func(p *corev1.PersistentVolumeClaim) *metav1.ObjectMeta { return &p.ObjectMeta }),
	coreGVR("persistentvolumes"): clusterMetaLister("PersistentVolume", PersistentVolumes,
		func(p *corev1.PersistentVolume) *metav1.ObjectMeta { return &p.ObjectMeta }),
	coreGVR("namespaces"): clusterMetaLister("Namespace", Namespaces,
		func(n *corev1.Namespace) *metav1.ObjectMeta { return &n.ObjectMeta }),
	coreGVR("nodes"): clusterMetaLister("Node", nodes,
		func(n *corev1.Node) *metav1.ObjectMeta { return &n.ObjectMeta }),
	coreGVR("events"): nsMetaLister("Event", Events,
		func(e *corev1.Event) *metav1.ObjectMeta { return &e.ObjectMeta }),
	coreGVR("resourcequotas"): nsMetaLister("ResourceQuota", ResourceQuotas,
		func(r *corev1.ResourceQuota) *metav1.ObjectMeta { return &r.ObjectMeta }),
	coreGVR("limitranges"): nsMetaLister("LimitRange", LimitRanges,
		func(l *corev1.LimitRange) *metav1.ObjectMeta { return &l.ObjectMeta }),

	gvrV1("apps", "deployments"): nsMetaLister("Deployment", Deployments,
		func(d *appsv1.Deployment) *metav1.ObjectMeta { return &d.ObjectMeta }),
	gvrV1("apps", "replicasets"): nsMetaLister("ReplicaSet", ReplicaSets,
		func(r *appsv1.ReplicaSet) *metav1.ObjectMeta { return &r.ObjectMeta }),
	gvrV1("apps", "statefulsets"): nsMetaLister("StatefulSet", StatefulSets,
		func(s *appsv1.StatefulSet) *metav1.ObjectMeta { return &s.ObjectMeta }),
	gvrV1("apps", "daemonsets"): nsMetaLister("DaemonSet", DaemonSets,
		func(d *appsv1.DaemonSet) *metav1.ObjectMeta { return &d.ObjectMeta }),

	gvrV1("batch", "jobs"): nsMetaLister("Job", Jobs,
		func(j *batchv1.Job) *metav1.ObjectMeta { return &j.ObjectMeta }),
	gvrV1("batch", "cronjobs"): nsMetaLister("CronJob", CronJobs,
		func(c *batchv1.CronJob) *metav1.ObjectMeta { return &c.ObjectMeta }),

	gvrV1("policy", "poddisruptionbudgets"): nsMetaLister("PodDisruptionBudget", PodDisruptionBudgets,
		func(p *policyv1.PodDisruptionBudget) *metav1.ObjectMeta { return &p.ObjectMeta }),
	gvrV1("discovery.k8s.io", "endpointslices"): nsMetaLister("EndpointSlice", EndpointSlices,
		func(e *discoveryv1.EndpointSlice) *metav1.ObjectMeta { return &e.ObjectMeta }),
	gvrV1("storage.k8s.io", "volumeattachments"): clusterMetaLister("VolumeAttachment", VolumeAttachments,
		func(v *storagev1.VolumeAttachment) *metav1.ObjectMeta { return &v.ObjectMeta }),
	gvrV1("coordination.k8s.io", "leases"): nsMetaLister("Lease", Leases,
		func(l *coordinationv1.Lease) *metav1.ObjectMeta { return &l.ObjectMeta }),
	gvrV1("certificates.k8s.io", "certificatesigningrequests"): clusterMetaLister("CertificateSigningRequest", CertificateSigningRequests,
		func(c *certificatesv1.CertificateSigningRequest) *metav1.ObjectMeta { return &c.ObjectMeta }),
	gvrV1("admissionregistration.k8s.io", "mutatingwebhookconfigurations"): clusterMetaLister("MutatingWebhookConfiguration", MutatingWebhookConfigurations,
		func(m *admissionv1.MutatingWebhookConfiguration) *metav1.ObjectMeta { return &m.ObjectMeta }),
	gvrV1("admissionregistration.k8s.io", "validatingwebhookconfigurations"): clusterMetaLister("ValidatingWebhookConfiguration", ValidatingWebhookConfigurations,
		func(v *admissionv1.ValidatingWebhookConfiguration) *metav1.ObjectMeta { return &v.ObjectMeta }),
}

// typedFallbackCovers reports whether listPartialViaTyped has a
// typed client path for gvr — the built-in groups the metadata-only
// consumers census.
func typedFallbackCovers(gvr schema.GroupVersionResource) bool {
	_, ok := typedMetaListers[gvr]
	return ok
}

// listPartialViaTyped is the built-in fallback: a table lookup over
// the resources metadata-only consumers actually census. Typed List
// calls work against the fake clientset every existing unit test
// builds (unlike CoreV1().RESTClient(), which the fake returns as a
// nil *rest.RESTClient). GVRs typedFallbackCovers does not list
// return an error — callers needing those must pass a dynamic or
// metadata client.
func listPartialViaTyped(ctx context.Context, cs kubernetes.Interface,
	gvr schema.GroupVersionResource, namespace string,
	opts metav1.ListOptions) ([]metav1.PartialObjectMetadata, error) {

	lister, ok := typedMetaListers[gvr]
	if !ok {
		return nil, fmt.Errorf("typed fallback has no client for %s", gvr)
	}
	return lister(ctx, cs, namespace, opts, gvr.GroupVersion().String())
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

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

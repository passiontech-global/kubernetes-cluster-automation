// list.go — pagination helpers. ~15 modules hand-rolled the same
// `for { List with Limit+Continue; append; break when Continue=="" }`
// loop over BOTH the typed clientset (page.Items / page.Continue) and
// the dynamic client (page.Items / page.GetContinue()). PageFunc is
// the single abstraction both shapes adapt into; ListEach streams
// page-by-page for callers that process inline, ListAll accumulates
// for callers that want the whole result, and the per-resource
// constructors below turn a clientset resource handle into a
// PageFunc so a paged sweep is one call, not a loop.
package kube

import (
	"context"

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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// DefaultListPageSize is the shared page bound ~13 modules redeclare
// as private xListPageSize consts — big enough that any realistic
// resource count fits in one or two pages, small enough that a page
// stays a cheap apiserver read. Pass it as metav1.ListOptions.Limit.
const DefaultListPageSize = 500

// PageFunc fetches ONE page of a paginated List. opts carries the
// caller's selectors (LabelSelector/FieldSelector/Limit) plus
// Continue set to the token of the page to fetch — "" requests the
// first page. It returns the page's items and the continue token for
// the next page ("" = last page). Every typed clientset List and
// dynamic ResourceInterface List adapts into this shape; the helpers
// below do the adapting.
type PageFunc[T any] func(ctx context.Context, opts metav1.ListOptions) (items []T, next string, err error)

// ListEach drives a paginated List to completion, invoking visit once
// per page with that page's items (a page may legitimately be empty —
// visit still runs so per-page side effects stay ordered). The first
// call passes opts verbatim; each subsequent call gets opts with
// Continue set to the previous page's token. A fetch error or a visit
// error stops the walk and is returned — pages already visited are
// NOT rolled back, so visit must be safe to have run partially (the
// same contract the hand-rolled loops had: process-then-continue).
func ListEach[T any](ctx context.Context, opts metav1.ListOptions,
	page PageFunc[T], visit func(items []T) error) error {
	for {
		items, next, err := page(ctx, opts)
		if err != nil {
			return err
		}
		if err := visit(items); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		opts.Continue = next
	}
}

// ListAll is ListEach that accumulates every page's items into one
// slice — the `items = append(items, page.Items...)` shape most
// modules wanted. Returns nil (not an empty slice) when the first
// page errors, matching the hand-rolled loops' `return nil, err`.
func ListAll[T any](ctx context.Context, opts metav1.ListOptions,
	page PageFunc[T]) ([]T, error) {
	var out []T
	err := ListEach(ctx, opts, page, func(items []T) error {
		out = append(out, items...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DynamicPage adapts a dynamic.ResourceInterface's List to a PageFunc
// over unstructured items — covers every dyn.Resource(gvr)...List
// loop (helmrelease-unlocker, velerobackupauditor, cilium-identity-
// auditor, failed-jobs-janitor, cluster-health-probes).
func DynamicPage(ri dynamic.ResourceInterface) PageFunc[unstructured.Unstructured] {
	return func(ctx context.Context, opts metav1.ListOptions) ([]unstructured.Unstructured, string, error) {
		page, err := ri.List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return page.Items, page.GetContinue(), nil
	}
}

// typedPage adapts a typed clientset List method into a PageFunc.
// L is the concrete *XxxList type — it implements
// metav1.ListInterface through the embedded ListMeta, so GetContinue
// supplies the next-page token and items extracts the Items slice.
func typedPage[T any, L metav1.ListInterface](
	list func(ctx context.Context, opts metav1.ListOptions) (L, error),
	items func(L) []T) PageFunc[T] {
	return func(ctx context.Context, opts metav1.ListOptions) ([]T, string, error) {
		page, err := list(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return items(page), page.GetContinue(), nil
	}
}

// ---------------------------------------------------------------------------
// Typed clientset PageFuncs — one constructor per resource the modules
// actually page through. namespace is the list scope
// (metav1.NamespaceAll for cluster-wide); cluster-scoped resources
// take none. Usage:
//
//	pods, err := ListAll(ctx, metav1.ListOptions{
//		FieldSelector: "status.phase=Failed", Limit: 500},
//		Pods(cs, metav1.NamespaceAll))
// ---------------------------------------------------------------------------

// Pods lists Pods in namespace.
func Pods(cs kubernetes.Interface, namespace string) PageFunc[corev1.Pod] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.PodList, error) {
			return cs.CoreV1().Pods(namespace).List(ctx, o)
		},
		func(l *corev1.PodList) []corev1.Pod { return l.Items })
}

// Jobs lists batch Jobs in namespace.
func Jobs(cs kubernetes.Interface, namespace string) PageFunc[batchv1.Job] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*batchv1.JobList, error) {
			return cs.BatchV1().Jobs(namespace).List(ctx, o)
		},
		func(l *batchv1.JobList) []batchv1.Job { return l.Items })
}

// CronJobs lists batch CronJobs in namespace.
func CronJobs(cs kubernetes.Interface, namespace string) PageFunc[batchv1.CronJob] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*batchv1.CronJobList, error) {
			return cs.BatchV1().CronJobs(namespace).List(ctx, o)
		},
		func(l *batchv1.CronJobList) []batchv1.CronJob { return l.Items })
}

// ConfigMaps lists ConfigMaps in namespace.
func ConfigMaps(cs kubernetes.Interface, namespace string) PageFunc[corev1.ConfigMap] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.ConfigMapList, error) {
			return cs.CoreV1().ConfigMaps(namespace).List(ctx, o)
		},
		func(l *corev1.ConfigMapList) []corev1.ConfigMap { return l.Items })
}

// Secrets lists Secrets in namespace.
func Secrets(cs kubernetes.Interface, namespace string) PageFunc[corev1.Secret] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.SecretList, error) {
			return cs.CoreV1().Secrets(namespace).List(ctx, o)
		},
		func(l *corev1.SecretList) []corev1.Secret { return l.Items })
}

// Services lists Services in namespace.
func Services(cs kubernetes.Interface, namespace string) PageFunc[corev1.Service] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.ServiceList, error) {
			return cs.CoreV1().Services(namespace).List(ctx, o)
		},
		func(l *corev1.ServiceList) []corev1.Service { return l.Items })
}

// ServiceAccounts lists core ServiceAccounts in namespace
// (imagepull-secret-auditor).
func ServiceAccounts(cs kubernetes.Interface, namespace string) PageFunc[corev1.ServiceAccount] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.ServiceAccountList, error) {
			return cs.CoreV1().ServiceAccounts(namespace).List(ctx, o)
		},
		func(l *corev1.ServiceAccountList) []corev1.ServiceAccount { return l.Items })
}

// ResourceQuotas lists ResourceQuotas in namespace
// (resource-quota-check).
func ResourceQuotas(cs kubernetes.Interface, namespace string) PageFunc[corev1.ResourceQuota] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.ResourceQuotaList, error) {
			return cs.CoreV1().ResourceQuotas(namespace).List(ctx, o)
		},
		func(l *corev1.ResourceQuotaList) []corev1.ResourceQuota { return l.Items })
}

// EndpointSlices lists discovery EndpointSlices in namespace.
func EndpointSlices(cs kubernetes.Interface, namespace string) PageFunc[discoveryv1.EndpointSlice] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*discoveryv1.EndpointSliceList, error) {
			return cs.DiscoveryV1().EndpointSlices(namespace).List(ctx, o)
		},
		func(l *discoveryv1.EndpointSliceList) []discoveryv1.EndpointSlice { return l.Items })
}

// Namespaces lists cluster-scoped Namespaces.
func Namespaces(cs kubernetes.Interface) PageFunc[corev1.Namespace] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.NamespaceList, error) {
			return cs.CoreV1().Namespaces().List(ctx, o)
		},
		func(l *corev1.NamespaceList) []corev1.Namespace { return l.Items })
}

// nodes lists cluster-scoped Nodes — the backing PageFunc for
// ListNodes in node.go (kept private: node reads must funnel
// through ListNodes, the single place node listing happens).
func nodes(cs kubernetes.Interface) PageFunc[corev1.Node] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.NodeList, error) {
			return cs.CoreV1().Nodes().List(ctx, o)
		},
		func(l *corev1.NodeList) []corev1.Node { return l.Items })
}

// Events lists Events in namespace.
func Events(cs kubernetes.Interface, namespace string) PageFunc[corev1.Event] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.EventList, error) {
			return cs.CoreV1().Events(namespace).List(ctx, o)
		},
		func(l *corev1.EventList) []corev1.Event { return l.Items })
}

// PersistentVolumeClaims lists PersistentVolumeClaims in namespace.
func PersistentVolumeClaims(cs kubernetes.Interface, namespace string) PageFunc[corev1.PersistentVolumeClaim] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.PersistentVolumeClaimList, error) {
			return cs.CoreV1().PersistentVolumeClaims(namespace).List(ctx, o)
		},
		func(l *corev1.PersistentVolumeClaimList) []corev1.PersistentVolumeClaim { return l.Items })
}

// PersistentVolumes lists cluster-scoped PersistentVolumes.
func PersistentVolumes(cs kubernetes.Interface) PageFunc[corev1.PersistentVolume] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*corev1.PersistentVolumeList, error) {
			return cs.CoreV1().PersistentVolumes().List(ctx, o)
		},
		func(l *corev1.PersistentVolumeList) []corev1.PersistentVolume { return l.Items })
}

// StatefulSets lists Apps StatefulSets in namespace.
func StatefulSets(cs kubernetes.Interface, namespace string) PageFunc[appsv1.StatefulSet] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*appsv1.StatefulSetList, error) {
			return cs.AppsV1().StatefulSets(namespace).List(ctx, o)
		},
		func(l *appsv1.StatefulSetList) []appsv1.StatefulSet { return l.Items })
}

// Deployments lists Apps Deployments in namespace.
func Deployments(cs kubernetes.Interface, namespace string) PageFunc[appsv1.Deployment] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*appsv1.DeploymentList, error) {
			return cs.AppsV1().Deployments(namespace).List(ctx, o)
		},
		func(l *appsv1.DeploymentList) []appsv1.Deployment { return l.Items })
}

// ReplicaSets lists Apps ReplicaSets in namespace.
func ReplicaSets(cs kubernetes.Interface, namespace string) PageFunc[appsv1.ReplicaSet] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*appsv1.ReplicaSetList, error) {
			return cs.AppsV1().ReplicaSets(namespace).List(ctx, o)
		},
		func(l *appsv1.ReplicaSetList) []appsv1.ReplicaSet { return l.Items })
}

// DaemonSets lists Apps DaemonSets in namespace.
func DaemonSets(cs kubernetes.Interface, namespace string) PageFunc[appsv1.DaemonSet] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*appsv1.DaemonSetList, error) {
			return cs.AppsV1().DaemonSets(namespace).List(ctx, o)
		},
		func(l *appsv1.DaemonSetList) []appsv1.DaemonSet { return l.Items })
}

// PodDisruptionBudgets lists Policy PodDisruptionBudgets in namespace.
func PodDisruptionBudgets(cs kubernetes.Interface, namespace string) PageFunc[policyv1.PodDisruptionBudget] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*policyv1.PodDisruptionBudgetList, error) {
			return cs.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, o)
		},
		func(l *policyv1.PodDisruptionBudgetList) []policyv1.PodDisruptionBudget { return l.Items })
}

// VolumeAttachments lists cluster-scoped VolumeAttachments.
func VolumeAttachments(cs kubernetes.Interface) PageFunc[storagev1.VolumeAttachment] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*storagev1.VolumeAttachmentList, error) {
			return cs.StorageV1().VolumeAttachments().List(ctx, o)
		},
		func(l *storagev1.VolumeAttachmentList) []storagev1.VolumeAttachment { return l.Items })
}

// Leases lists coordination.k8s.io Leases in namespace — the
// leader-election objects ~40 health checks used to GET one-by-one.
func Leases(cs kubernetes.Interface, namespace string) PageFunc[coordinationv1.Lease] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*coordinationv1.LeaseList, error) {
			return cs.CoordinationV1().Leases(namespace).List(ctx, o)
		},
		func(l *coordinationv1.LeaseList) []coordinationv1.Lease { return l.Items })
}

// CertificateSigningRequests lists cluster-scoped
// CertificateSigningRequests (csr-watcher).
func CertificateSigningRequests(cs kubernetes.Interface) PageFunc[certificatesv1.CertificateSigningRequest] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*certificatesv1.CertificateSigningRequestList, error) {
			return cs.CertificatesV1().CertificateSigningRequests().List(ctx, o)
		},
		func(l *certificatesv1.CertificateSigningRequestList) []certificatesv1.CertificateSigningRequest {
			return l.Items
		})
}

// MutatingWebhookConfigurations lists cluster-scoped
// MutatingWebhookConfigurations (webhookguard snapshot, CA-drift
// audit).
func MutatingWebhookConfigurations(cs kubernetes.Interface) PageFunc[admissionv1.MutatingWebhookConfiguration] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*admissionv1.MutatingWebhookConfigurationList, error) {
			return cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, o)
		},
		func(l *admissionv1.MutatingWebhookConfigurationList) []admissionv1.MutatingWebhookConfiguration {
			return l.Items
		})
}

// ValidatingWebhookConfigurations lists cluster-scoped
// ValidatingWebhookConfigurations (webhookguard snapshot, CA-drift
// audit).
func ValidatingWebhookConfigurations(cs kubernetes.Interface) PageFunc[admissionv1.ValidatingWebhookConfiguration] {
	return typedPage(
		func(ctx context.Context, o metav1.ListOptions) (*admissionv1.ValidatingWebhookConfigurationList, error) {
			return cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, o)
		},
		func(l *admissionv1.ValidatingWebhookConfigurationList) []admissionv1.ValidatingWebhookConfiguration {
			return l.Items
		})
}

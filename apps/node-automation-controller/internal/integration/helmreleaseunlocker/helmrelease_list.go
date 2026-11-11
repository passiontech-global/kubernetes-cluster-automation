// helmrelease-unlocker HelmRelease list + cluster-wide paging helpers,
// plus the helm-controller CrashLoopBackOff health gate the sweep
// consults before touching anything.
// split from helmrelease_unlocker.go (see its header for the module contract).
package helmreleaseunlocker

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// listHelmReleases returns the HR list and the GVR that answered — v2
// first, v2beta2 when the v2 CRDs are absent. The fallback loop and
// its benign/real error split are kube.ListFirstGVR's; HRs are
// unbounded cluster-wide and each item embeds values/crds hooks — a
// single shot List of a large fleet is a heap spike, so the shared
// helper pages at kube.DefaultListPageSize.
func (u *helmReleaseUnlocker) listHelmReleases(ctx context.Context) (*unstructured.UnstructuredList, schema.GroupVersionResource, error) {
	list, gvr, err := kube.ListFirstUnstructured(ctx, u.dyn, helmReleaseGVRs,
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
	if err != nil {
		return nil, schema.GroupVersionResource{},
			fmt.Errorf("list helmreleases (all known GVRs failed): %w", err)
	}
	return list, gvr, nil
}

// listAllPages walks ListOptions.Continue until the apiserver stops
// paging — every cluster-wide dynamic List in this module goes through
// it so no single response hauls the whole resource across the wire.
func (u *helmReleaseUnlocker) listAllPages(ctx context.Context,
	ri dynamic.ResourceInterface) (*unstructured.UnstructuredList, error) {
	return kube.ListAllUnstructured(ctx, ri,
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
}

// helmControllerDown reports whether any helm-controller pod is
// CrashLoopBackOff. A list error is a real error for the caller.
func (u *helmReleaseUnlocker) helmControllerDown(ctx context.Context) (bool, error) {
	pods, err := kube.ListAll(ctx,
		metav1.ListOptions{
			Limit:         kube.DefaultListPageSize,
			LabelSelector: helmControllerSel},
		kube.Pods(u.cs, helmControllerNS))
	if err != nil {
		return false, fmt.Errorf("list helm-controller pods: %w", err)
	}
	for i := range pods {
		statuses := append([]corev1.ContainerStatus{},
			pods[i].Status.InitContainerStatuses...)
		statuses = append(statuses, pods[i].Status.ContainerStatuses...)
		for _, s := range statuses {
			if s.State.Waiting != nil && s.State.Waiting.Reason == "CrashLoopBackOff" {
				logf.FromContext(ctx).Info("helm-controller pod CrashLoopBackOff",
					"pod", helmControllerNS+"/"+pods[i].Name,
					"container", s.Name)
				return true, nil
			}
		}
	}
	return false, nil
}

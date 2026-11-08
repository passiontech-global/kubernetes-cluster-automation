// objects_cached.go — the informer-backed twin of the single-object
// typed Gets, next to nodes_cached.go's ListNodesCached. The manager
// cache already mirrors the types modules watch (buildCacheOptions in
// cmd/manager) — yet every pinned-workload reconcile re-Get its
// object straight from the apiserver on each event. Cached reads are
// watch-fresh (milliseconds behind the apiserver) and free; the
// DESTRUCTIVE paths still confirm on the direct clientset — this
// seam never replaces a confirm-before-act read.
//
// IMPORTANT scope contract: a cached Get only works while the
// manager's informer for that type can actually see the object.
// buildCacheOptions locks some informers to a single object via
// resourceNames field selectors (daemonsets -> konnectivity-agent,
// secrets -> passiontech-pipeline), so a cached Get of any OTHER
// object of that type would come back NotFound-from-cache. Callers
// must pass the reader only for the watched/scoped object — the
// nil-reader fallback (tests, unwatched types) is the direct Get the
// code always did.
package kube

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CachedObjectReader is the minimal Get shape the manager's
// cache-backed client satisfies — client.Reader (mgr.GetClient)
// implements it. A nil reader means "no cache wired" (tests,
// StubManager, literally-built fixtures): the GetXCached helpers
// fall back to the direct clientset Get then, so call sites work
// unchanged outside a running manager.
type CachedObjectReader interface {
	Get(ctx context.Context, key client.ObjectKey, obj client.Object,
		opts ...client.GetOption) error
}

// GetDeploymentCached returns the Deployment from the informer cache
// when r is non-nil, else the direct clientset Get. Cache reads are
// watch-fresh — fine for drift detection; the destructive patch path
// must re-Get on the direct clientset before acting (cache can be
// milliseconds stale right as the k0s stack applier reverts the
// object). NotFound propagates unchanged either way.
func GetDeploymentCached(ctx context.Context, r CachedObjectReader,
	cs kubernetes.Interface, namespace, name string) (*appsv1.Deployment, error) {
	if r == nil {
		return cs.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	}
	d := &appsv1.Deployment{}
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, d)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// GetDaemonSetCached is GetDeploymentCached's DaemonSet counterpart.
// Only valid for the object the manager's DaemonSet informer is
// scoped to (kube-system/konnectivity-agent today) — see the file
// header.
func GetDaemonSetCached(ctx context.Context, r CachedObjectReader,
	cs kubernetes.Interface, namespace, name string) (*appsv1.DaemonSet, error) {
	if r == nil {
		return cs.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
	}
	ds := &appsv1.DaemonSet{}
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, ds)
	if err != nil {
		return nil, err
	}
	return ds, nil
}

// GetSecretCached is GetDeploymentCached's Secret counterpart. Only
// valid for the object the manager's Secret informer is scoped to
// (passiontech-pipeline today) — see the file header.
func GetSecretCached(ctx context.Context, r CachedObjectReader,
	cs kubernetes.Interface, namespace, name string) (*corev1.Secret, error) {
	if r == nil {
		return cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	}
	sec := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, sec)
	if err != nil {
		return nil, err
	}
	return sec, nil
}

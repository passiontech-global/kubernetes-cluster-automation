// snapshot_workloads.go — the workload census readers of the
// per-sweep snapshot: PVCs, StatefulSets, Deployments and
// DaemonSets (split out of snapshot.go — see its header for the
// memoizer contract).
package probefw

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// AllPVCs is the PVC twin — the shared claim census the volume/
// storage checks (resize stalls, stranded localpv pods) read.
func (d *Deps) AllPVCs(ctx context.Context) ([]corev1.PersistentVolumeClaim, error) {
	s := sweepSnap(ctx)
	return s.pvcs.get(func(bool) ([]corev1.PersistentVolumeClaim, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.PersistentVolumeClaims(d.CS, metav1.NamespaceAll))
	})
}

// AllStatefulSets is the statefulset twin.
func (d *Deps) AllStatefulSets(ctx context.Context) ([]appsv1.StatefulSet, error) {
	s := sweepSnap(ctx)
	return s.statefulSets.get(func(bool) ([]appsv1.StatefulSet, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.StatefulSets(d.CS, metav1.NamespaceAll))
	})
}

// AllDeployments is the deployment twin.
func (d *Deps) AllDeployments(ctx context.Context) ([]appsv1.Deployment, error) {
	s := sweepSnap(ctx)
	return s.deployments.get(func(bool) ([]appsv1.Deployment, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Deployments(d.CS, metav1.NamespaceAll))
	})
}

// AllDaemonSets is the daemonset twin.
func (d *Deps) AllDaemonSets(ctx context.Context) ([]appsv1.DaemonSet, error) {
	s := sweepSnap(ctx)
	return s.daemonSets.get(func(bool) ([]appsv1.DaemonSet, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.DaemonSets(d.CS, metav1.NamespaceAll))
	})
}

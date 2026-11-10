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
	s.muPVCs.Lock()
	defer s.muPVCs.Unlock()
	if !s.pvcsSet {
		s.pvcsSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.pvcs, s.pvcsErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.PersistentVolumeClaims(d.CS, metav1.NamespaceAll))
	}
	return s.pvcs, s.pvcsErr
}

// AllStatefulSets is the statefulset twin.
func (d *Deps) AllStatefulSets(ctx context.Context) ([]appsv1.StatefulSet, error) {
	s := sweepSnap(ctx)
	s.muStatefulSets.Lock()
	defer s.muStatefulSets.Unlock()
	if !s.statefulSetsSet {
		s.statefulSetsSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.statefulSets, s.statefulSetsErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.StatefulSets(d.CS, metav1.NamespaceAll))
	}
	return s.statefulSets, s.statefulSetsErr
}

// AllDeployments is the deployment twin.
func (d *Deps) AllDeployments(ctx context.Context) ([]appsv1.Deployment, error) {
	s := sweepSnap(ctx)
	s.muDeployments.Lock()
	defer s.muDeployments.Unlock()
	if !s.deploymentsSet {
		s.deploymentsSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.deployments, s.deploymentsErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Deployments(d.CS, metav1.NamespaceAll))
	}
	return s.deployments, s.deploymentsErr
}

// AllDaemonSets is the daemonset twin.
func (d *Deps) AllDaemonSets(ctx context.Context) ([]appsv1.DaemonSet, error) {
	s := sweepSnap(ctx)
	s.muDaemonSets.Lock()
	defer s.muDaemonSets.Unlock()
	if !s.daemonSetsSet {
		s.daemonSetsSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.daemonSets, s.daemonSetsErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.DaemonSets(d.CS, metav1.NamespaceAll))
	}
	return s.daemonSets, s.daemonSetsErr
}

// snapshot_workloads.go — the workload census readers of the
// per-sweep snapshot: PVCs, StatefulSets, Deployments and
// DaemonSets (split out of snapshot.go — see its header for the
// memoizer contract).
package probefw

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
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
			snapshotListOpts(),
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
			snapshotListOpts(),
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
			snapshotListOpts(),
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
			snapshotListOpts(),
			kube.DaemonSets(d.CS, metav1.NamespaceAll))
	})
}

// AllReplicaSets is the metadata-only ReplicaSet census — the
// ownership joins (pod → RS → Deployment resolution, orphan
// detection) read nothing but ObjectMeta, so the read rides
// ListPartialOrFallback: the metadata client's
// PartialObjectMetadata LIST in production, the typed/dynamic
// fallback under the fake-client tests. Memoized like every census —
// the first check to need it pays the one LIST per sweep.
func (d *Deps) AllReplicaSets(ctx context.Context) ([]metav1.PartialObjectMetadata, error) {
	s := sweepSnap(ctx)
	return s.replicaSets.get(func(bool) ([]metav1.PartialObjectMetadata, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListPartialOrFallback(lctx, d.Meta, d.CS, d.Dyn,
			appsv1.SchemeGroupVersion.WithResource("replicasets"),
			metav1.NamespaceAll,
			snapshotListOpts())
	})
}

// AllCronJobs is the batch/v1 CronJob census — lazy like
// AllReplicaSets: only the checks that suspend/audit CronJobs pay
// the LIST, once per sweep.
func (d *Deps) AllCronJobs(ctx context.Context) ([]batchv1.CronJob, error) {
	s := sweepSnap(ctx)
	return s.cronJobs.get(func(bool) ([]batchv1.CronJob, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.CronJobs(d.CS, metav1.NamespaceAll))
	})
}

// AllJobs is the batch/v1 Job census — lazy like AllCronJobs:
// only the checks that resolve a Job owner (linkerd protocol-stall
// heal, wedged-namespace owner chains) pay the LIST, once per sweep.
func (d *Deps) AllJobs(ctx context.Context) ([]batchv1.Job, error) {
	s := sweepSnap(ctx)
	return s.jobs.get(func(bool) ([]batchv1.Job, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.Jobs(d.CS, metav1.NamespaceAll))
	})
}

// AllPDBs is the policy/v1 PodDisruptionBudget census — the
// eviction-respecting heals (linkerd outlier, protocol-stall)
// resolve a pod's PDB coverage from it instead of a per-pod GET.
func (d *Deps) AllPDBs(ctx context.Context) ([]policyv1.PodDisruptionBudget, error) {
	s := sweepSnap(ctx)
	return s.pdbs.get(func(bool) ([]policyv1.PodDisruptionBudget, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.PodDisruptionBudgets(d.CS, metav1.NamespaceAll))
	})
}

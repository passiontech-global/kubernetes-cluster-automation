// maintenance_snapshot.go — the ctx-carried census provider the
// maintenance-mutex evidence reads prefer over live LISTs/GETs.
//
// Inside a cluster-health sweep the probefw snapshot already memoizes
// the node and daemonset censuses for ~40 checks; the mutex verdict
// (evaluated at most once per Verdict TTL but on EVERY heal gate)
// used to pay its own node LIST + kured DaemonSet GET on top. When a
// provider is installed on ctx, nodeCordonEvidence /
// KuredLockEvidence / maintenanceStampTargets read the shared census
// instead — one census per sweep total, and under kube-apiserver-on-
// Kine that also retires the per-evaluation SQL page reads.
//
// Freshness contract: the census is sweep-scoped, so a cordon or
// kured-lock change made MID-sweep by another actor is invisible to
// the mutex until the next sweep — bounded by the sweep interval,
// and the dedicated cluster-maintenance-stamper runnable (which
// reads live) keeps the L1↔L3 stamp fresh regardless. Callers
// outside a sweep (module heal gates, tests, ad-hoc runs) get nil
// and keep the direct clientset reads — identical semantics.
package kube

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// MaintenanceSnapshotProvider supplies the censuses the maintenance
// evidence functions read. probefw implements it over its per-sweep
// memoized snapshot (AllNodes/AllDaemonSets); platform code only
// names the interface, keeping the leaf layering intact.
type MaintenanceSnapshotProvider interface {
	// Nodes returns the cluster node census.
	Nodes(ctx context.Context) ([]corev1.Node, error)
	// DaemonSets returns the cluster daemonset census — the kured
	// lock lookup scans it for kube-system/kured.
	DaemonSets(ctx context.Context) ([]appsv1.DaemonSet, error)
}

// maintenanceSnapshotKey is the ctx key WithMaintenanceSnapshot
// installs the provider under. Unexported: only probefw's sweep root
// attaches one, so a domain module cannot inject a stale census.
type maintenanceSnapshotKey struct{}

// WithMaintenanceSnapshot installs p on ctx for the maintenance
// evidence readers. Nil p installs nothing (the reads fall back to
// the direct clientset path).
func WithMaintenanceSnapshot(ctx context.Context,
	p MaintenanceSnapshotProvider) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, maintenanceSnapshotKey{}, p)
}

// maintenanceSnapshotFrom returns the ctx-installed provider, or nil
// — the "no sweep census" signal every evidence reader branches on.
func maintenanceSnapshotFrom(ctx context.Context) MaintenanceSnapshotProvider {
	if p, ok := ctx.Value(maintenanceSnapshotKey{}).(MaintenanceSnapshotProvider); ok {
		return p
	}
	return nil
}

// maintenanceNodeList returns the node census for the mutex evidence
// paths — the provider's sweep-memoized read when installed, else the
// direct paged list every non-sweep caller always made.
func maintenanceNodeList(ctx context.Context,
	cs kubernetes.Interface) ([]corev1.Node, error) {
	if p := maintenanceSnapshotFrom(ctx); p != nil {
		return p.Nodes(ctx)
	}
	return ListNodes(ctx, cs)
}

// maintenanceDaemonSet finds one DaemonSet for the kured-lock read —
// a census scan when the provider is installed (the memoized
// AllDaemonSets pays at most one list per sweep), else the direct
// namespaced GET. A census miss is authoritative "absent" for the
// sweep's purposes: kured either is or is not installed, and a DS
// created mid-sweep is picked up next cycle — the same staleness
// bound every other census consumer already accepts.
func maintenanceDaemonSet(ctx context.Context, cs kubernetes.Interface,
	namespace, name string) (*appsv1.DaemonSet, error) {
	if p := maintenanceSnapshotFrom(ctx); p != nil {
		dss, err := p.DaemonSets(ctx)
		if err != nil {
			return nil, err
		}
		for i := range dss {
			if dss[i].Namespace == namespace && dss[i].Name == name {
				return &dss[i], nil
			}
		}
		return nil, nil // absent — same verdict as a NotFound GET
	}
	ds, err := cs.AppsV1().DaemonSets(namespace).Get(ctx, name,
		metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ds, nil
}

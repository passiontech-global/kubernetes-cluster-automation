// snapshot_cluster.go — the cluster-scoped census readers of the
// per-sweep snapshot: EndpointSlices, Services, Namespaces, Events
// and Leases, plus the ns/name → object index joins behind the
// Lease/Service single-object lookups (split out of snapshot.go —
// see its header for the memoizer contract).
package probefw

import (
	"context"
	"slices"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// AllEndpointSlices is the discovery twin — the shared census the
// endpoint-desync checks used to each list on their own.
func (d *Deps) AllEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, error) {
	s := sweepSnap(ctx)
	return s.slices.get(func(bool) ([]discoveryv1.EndpointSlice, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.EndpointSlices(d.CS, metav1.NamespaceAll))
	})
}

// EndpointSlicesForService resolves the EndpointSlices bound to one
// Service — the kubernetes.io/service-name label join behind
// Service(ns).Get → slices lookups, index-backed so repeat resolves
// in one sweep don't rescan the census. Slices without the label
// (and DeletionTimestamp-set ones stay INCLUDED — callers filter
// lifecycle themselves, same as the raw census) never match. The
// returned slice is freshly allocated; elements alias the snapshot's
// slice structs — read-only like AllEndpointSlices.
func (d *Deps) EndpointSlicesForService(ctx context.Context,
	ns, name string) ([]*discoveryv1.EndpointSlice, error) {

	eps, err := d.AllEndpointSlices(ctx)
	if err != nil {
		return nil, err
	}
	byKey := sweepSnap(ctx).sliceSvc.lookup(eps)
	return slices.Clone(byKey[types.NamespacedName{
		Namespace: ns, Name: name}]), nil
}

// AllServices is the service twin.
func (d *Deps) AllServices(ctx context.Context) ([]corev1.Service, error) {
	s := sweepSnap(ctx)
	return s.services.get(func(bool) ([]corev1.Service, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.Services(d.CS, metav1.NamespaceAll))
	})
}

// AllNamespaces is the namespace twin.
func (d *Deps) AllNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	s := sweepSnap(ctx)
	return s.namespaces.get(func(bool) ([]corev1.Namespace, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.Namespaces(d.CS))
	})
}

// AllEvents is the events twin — the cluster-wide event census the
// event-signature checks (scale flapping, restart storms, OOM
// watchers) used to each LIST per check. Events churn constantly and
// are read-only for every check, so the memoized snapshot is both
// safe and the single largest read saving after Pods.
func (d *Deps) AllEvents(ctx context.Context) ([]corev1.Event, error) {
	s := sweepSnap(ctx)
	return s.events.get(func(bool) ([]corev1.Event, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.Events(d.CS, metav1.NamespaceAll))
	})
}

// EventsWithReason filters the shared event census to one reason —
// the client-side equivalent of an Events List with
// FieldSelector "reason=<reason>" (the apiserver cannot field-select
// reasons on most versions anyway, so the checks filtered client-side
// too). Builds on AllEvents: the LIST is paid once per sweep, only
// the filter re-runs. The returned slice is freshly allocated; the
// elements alias the snapshot's event structs — read-only like every
// snapshot payload.
func (d *Deps) EventsWithReason(ctx context.Context, reason string) ([]corev1.Event, error) {
	events, err := d.AllEvents(ctx)
	if err != nil {
		return nil, err
	}
	var out []corev1.Event
	for i := range events {
		if events[i].Reason == reason {
			out = append(out, events[i])
		}
	}
	return out, nil
}

// AllLeases is the coordination.k8s.io census — the leader-election
// objects ~40 health checks used to GET one-by-one per sweep
// (operator-workqueue ~35 GETs, mesh/kcm watchdogs, lease guards,
// percona quorum). One paged cluster LIST per sweep replaces them
// all; callers find their Lease by namespace+name in the result.
func (d *Deps) AllLeases(ctx context.Context) ([]coordinationv1.Lease, error) {
	s := sweepSnap(ctx)
	return s.leases.get(func(bool) ([]coordinationv1.Lease, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		return kube.ListAll(lctx,
			snapshotListOpts(),
			kube.Leases(d.CS, metav1.NamespaceAll))
	})
}

// LeasesFetchedAt reports the wall-clock instant the memoized Lease
// census was fetched — the correct "now" for spec.renewTime staleness
// windows. p.Now() at check-run time lags the fetch by however long
// the worker queue delayed this check, which would overstate lease
// staleness (a lease renewed 9m before the fetch reads 11m-stale to a
// check that ran 2m late and gets bounced for nothing). Outside a
// sweep — or before the census loads — it falls back to d.Now(), the
// pre-snapshot semantics.
func (d *Deps) LeasesFetchedAt(ctx context.Context) time.Time {
	s := sweepSnap(ctx)
	if t := s.leases.fetched(); !t.IsZero() {
		return t
	}
	return d.Now()
}

// Lease finds one Lease in the AllLeases census — the snapshot
// equivalent of `Leases(ns).Get(ctx, name)`: a hit returns the
// listed object, a miss returns nil (callers treat absent the same
// as a NotFound GET). The lookup rides the memoized ns/name index —
// the percona quorum check calls it once per cluster CR and a linear
// census walk per call was ~36 full scans per sweep. List errors
// propagate so callers keep their fail-open/closed semantics.
func (d *Deps) Lease(ctx context.Context, ns, name string) (*coordinationv1.Lease, error) {
	s := sweepSnap(ctx)
	idx, err := s.leaseIndex.get(func(bool) (map[types.NamespacedName]*coordinationv1.Lease, error) {
		leases, err := d.AllLeases(ctx)
		if err != nil {
			return nil, err
		}
		m := make(map[types.NamespacedName]*coordinationv1.Lease, len(leases))
		for i := range leases {
			m[types.NamespacedName{
				Namespace: leases[i].Namespace,
				Name:      leases[i].Name,
			}] = &leases[i]
		}
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return idx[types.NamespacedName{Namespace: ns, Name: name}], nil
}

// Service is the AllServices twin of Lease — the ns/name → object
// lookup over the memoized service index for callers that need one
// Service out of the census (a miss returns nil, list errors
// propagate).
func (d *Deps) Service(ctx context.Context, ns, name string) (*corev1.Service, error) {
	s := sweepSnap(ctx)
	idx, err := s.serviceIndex.get(func(bool) (map[types.NamespacedName]*corev1.Service, error) {
		svcs, err := d.AllServices(ctx)
		if err != nil {
			return nil, err
		}
		m := make(map[types.NamespacedName]*corev1.Service, len(svcs))
		for i := range svcs {
			m[types.NamespacedName{
				Namespace: svcs[i].Namespace,
				Name:      svcs[i].Name,
			}] = &svcs[i]
		}
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return idx[types.NamespacedName{Namespace: ns, Name: name}], nil
}

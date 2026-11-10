// snapshot_cluster.go — the cluster-scoped census readers of the
// per-sweep snapshot: EndpointSlices, Services, Namespaces and
// Events (split out of snapshot.go — see its header for the
// memoizer contract).
package probefw

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// AllEndpointSlices is the discovery twin — the shared census the
// endpoint-desync checks used to each list on their own.
func (d *Deps) AllEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, error) {
	s := sweepSnap(ctx)
	s.muSlices.Lock()
	defer s.muSlices.Unlock()
	if !s.slicesSet {
		s.slicesSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.slices, s.slicesErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.EndpointSlices(d.CS, metav1.NamespaceAll))
	}
	return s.slices, s.slicesErr
}

// AllServices is the service twin.
func (d *Deps) AllServices(ctx context.Context) ([]corev1.Service, error) {
	s := sweepSnap(ctx)
	s.muServices.Lock()
	defer s.muServices.Unlock()
	if !s.servicesSet {
		s.servicesSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.services, s.servicesErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Services(d.CS, metav1.NamespaceAll))
	}
	return s.services, s.servicesErr
}

// AllNamespaces is the namespace twin.
func (d *Deps) AllNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	s := sweepSnap(ctx)
	s.muNamespaces.Lock()
	defer s.muNamespaces.Unlock()
	if !s.namespacesSet {
		s.namespacesSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.namespaces, s.namespacesErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Namespaces(d.CS))
	}
	return s.namespaces, s.namespacesErr
}

// AllEvents is the events twin — the cluster-wide event census the
// event-signature checks (scale flapping, restart storms, OOM
// watchers) used to each LIST per check. Events churn constantly and
// are read-only for every check, so the memoized snapshot is both
// safe and the single largest read saving after Pods.
func (d *Deps) AllEvents(ctx context.Context) ([]corev1.Event, error) {
	s := sweepSnap(ctx)
	s.muEvents.Lock()
	defer s.muEvents.Unlock()
	if !s.eventsSet {
		s.eventsSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		s.events, s.eventsErr = kube.ListAll(lctx,
			metav1.ListOptions{Limit: HealthListPageSize},
			kube.Events(d.CS, metav1.NamespaceAll))
	}
	return s.events, s.eventsErr
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

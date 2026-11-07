// linkerd_endpoint_sync_desync.go — the desync-detection helpers of
// the linkerd-endpoint-sync check (W9-NM2/W10-FIX7): the EndpointSlice
// vs Ready-pod-IP set-divergence test, the controller-owned-slice
// staleness pick, the pod-Ready-since fuse clock, and the
// audited-Service filter.
package nethealth

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// linkerdEndpointSetsDiverge reports whether a Service's
// EndpointSlice view diverged from its pods: a Ready pod IP missing
// from the Ready endpoint addresses (linkerd-destination never learns
// the endpoint exists), or a Ready endpoint address no live selected
// pod owns anymore (a deleted pod's stale IP keeps receiving traffic).
// readyIPs/liveIPs nil-safe: an empty pod set can still flag stale
// endpoint addresses.
func linkerdEndpointSetsDiverge(readyIPs, liveIPs, esReady map[string]bool) bool {
	for ip := range readyIPs {
		if !esReady[ip] {
			return true
		}
	}
	for ip := range esReady {
		if !liveIPs[ip] {
			return true
		}
	}
	return false
}

// linkerdSliceRef is one endpointslice-controller-owned EndpointSlice
// of an audited Service — a delete candidate when it
// provably holds stale endpoint data (W10-FIX7). addrs is the set of
// Ready endpoint addresses (nil Ready counts as ready, same
// convention as the aggregate census).
type linkerdSliceRef struct {
	ns, name string
	uid      types.UID
	addrs    map[string]bool
}

// podReadySince returns the pod's PodReady=True LastTransitionTime —
// the clock for the EndpointSlice heal's missing-IP fuse. ok=false
// when the pod is not Ready (mirrors kube.PodReadyCond, which
// returns on the first PodReady-typed condition).
func podReadySince(pod *corev1.Pod) (since time.Time, ok bool) {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			if c.Status != corev1.ConditionTrue {
				return time.Time{}, false
			}
			return c.LastTransitionTime.Time, true
		}
	}
	return time.Time{}, false
}

// staleLinkerdSlices picks the controller-owned EndpointSlices of a
// desynced Service that provably hold stale endpoint data
// (W10-FIX7):
//
//   - a slice retaining a Ready address no live selected pod owns
//     (a deleted pod's IP still receiving traffic) is stale on its
//     own — only that slice is returned;
//   - a Ready pod IP past linkerdSliceHealMinAge absent from the
//     UNION of all the service's managed slices means the slice SET
//     is incomplete — no single member is identifiable as the stale
//     one, so every managed slice is returned: deleting them forces
//     endpointslice-controller to rebuild the whole set.
//
// readyAged is the service's pod-IP set filtered to pods Ready past
// the fuse; liveIPs is every live selected pod IP. Both nil-safe.
func staleLinkerdSlices(slices []linkerdSliceRef,
	readyAged, liveIPs map[string]bool) []linkerdSliceRef {
	if len(slices) == 0 {
		return nil
	}
	union := map[string]bool{}
	var stale []linkerdSliceRef
	for _, sl := range slices {
		dead := false
		for a := range sl.addrs {
			union[a] = true
			if !liveIPs[a] {
				dead = true
			}
		}
		if dead {
			stale = append(stale, sl)
		}
	}
	for ip := range readyAged {
		if !union[ip] {
			return slices
		}
	}
	return stale
}

// linkerdAuditedService reports whether a Service is in the
// endpoint-sync census: in a linkerd-injected namespace, carrying a
// pod selector (selectorless Services are manually managed — their
// endpoints are user-owned), not ExternalName (a DNS alias has no
// EndpointSlices of its own), and not publishNotReadyAddresses —
// that flag intentionally pins not-ready addresses into the slices,
// so ghost/missing-IP detection cannot tell intent from desync.
// Headless AND ordinary ClusterIP/NodePort/LoadBalancer Services all
// qualify: linkerd-destination builds its endpoint table from
// EndpointSlices for each of them.
func linkerdAuditedService(injected map[string]bool, svc *corev1.Service) bool {
	return injected[svc.Namespace] &&
		len(svc.Spec.Selector) > 0 &&
		svc.Spec.Type != corev1.ServiceTypeExternalName &&
		!svc.Spec.PublishNotReadyAddresses
}

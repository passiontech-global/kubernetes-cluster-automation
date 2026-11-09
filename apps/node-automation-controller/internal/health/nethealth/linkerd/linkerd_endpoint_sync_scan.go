// linkerd_endpoint_sync_scan.go — the census half of the
// linkerd-endpoint-sync sweep: which namespaces are linkerd-
// injected, which Services are audited, the Ready-vs-live pod-IP
// sets per service, the endpointslice-controller-owned slice
// census, and the per-service desync + stale-slice verdicts the
// emit/heal phases consume. Split out of
// linkerd_endpoint_sync.go — see that file for the check.
package linkerd

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// linkerdDesyncScan is one sweep's endpoint-sync census: the
// Services whose EndpointSlice diverged from their Ready pod IPs
// (desynced), the provably-stale managed slices per service
// (staleSlices — the endpoint-sync-heal delete candidates), and
// whether the linkerd control plane is installed (feeds the
// socket-lb-vs-linkerd audit).
type linkerdDesyncScan struct {
	desynced         map[string]*corev1.Service // "ns/name" -> Service
	staleSlices      map[string][]linkerdSliceRef
	linkerdInstalled bool
}

// scanDesync runs the full endpoint-sync census: namespaces opted
// into injection (the only places a desynced EndpointSlice
// actually strands mesh traffic), the audited-Service filter, the
// Ready endpoint addresses per ns/service, and the per-service
// pod-IP divergence test. Converged services clear any persisted
// first-seen stamp so a later desync re-arms the full window —
// a clear failure is a tolerated sub-failure (Warn + continue).
// List failures are Infra — the census cannot be proven.
func (p *linkerdEndpointSyncCheck) scanDesync(ctx context.Context,
	log logr.Logger, now time.Time) (*linkerdDesyncScan, error) {
	nsList, err := p.AllNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	injected := map[string]bool{}
	// linkerdInstalled feeds the socket-lb-vs-linkerd socket-LB audit — the
	// Cilium config only conflicts while the mesh itself is
	// deployed on this cluster.
	linkerdInstalled := false
	for i := range nsList {
		if nsList[i].Labels[kube.LinkerdInjectKey] == "enabled" {
			injected[nsList[i].Name] = true
		}
		if nsList[i].Name == kube.LinkerdNS {
			linkerdInstalled = true
		}
	}

	scan := &linkerdDesyncScan{
		desynced:         map[string]*corev1.Service{},
		staleSlices:      map[string][]linkerdSliceRef{},
		linkerdInstalled: linkerdInstalled,
	}
	if len(injected) == 0 {
		return scan, nil
	}

	svcList, err := p.AllServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	podList, err := p.AllPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	// Audited services — selector + injected ns (+ the
	// ExternalName/publishNotReady exclusions), the same filter
	// the per-service loop applies. Only their controller-owned
	// slices are delete candidates (endpoint-sync-heal).
	audited := map[string]bool{}
	for i := range svcList {
		svc := &svcList[i]
		if linkerdAuditedService(injected, svc) {
			audited[svc.Namespace+"/"+svc.Name] = true
		}
	}
	// Ready endpoint addresses per ns/service — same source and
	// nil-ready-counts-as-ready convention as the masterless
	// census. Paged like every cluster-wide read in this sweep.
	esReady := map[string]map[string]bool{}
	// managedSlices: "ns/svc" → the service's
	// endpointslice-controller-owned EndpointSlices with their
	// Ready address sets — the endpoint-sync-heal delete candidates.
	managedSlices := map[string][]linkerdSliceRef{}
	slices, err := p.AllEndpointSlices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list endpointslices: %w", err)
	}
	for _, s := range slices {
		svc := s.Labels[discoveryv1.LabelServiceName]
		if svc == "" {
			continue
		}
		key := s.Namespace + "/" + svc
		managed := audited[key] &&
			s.Labels[discoveryv1.LabelManagedBy] == linkerdSliceManagedByESC &&
			s.DeletionTimestamp == nil
		var sliceAddrs map[string]bool
		if managed {
			sliceAddrs = map[string]bool{}
		}
		set := esReady[key]
		if set == nil {
			set = map[string]bool{}
			esReady[key] = set
		}
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, a := range ep.Addresses {
				set[a] = true
				if managed {
					sliceAddrs[a] = true
				}
			}
		}
		if managed {
			managedSlices[key] = append(managedSlices[key],
				linkerdSliceRef{ns: s.Namespace, name: s.Name,
					uid: s.UID, addrs: sliceAddrs})
		}
	}

	podsByNS := map[string][]*corev1.Pod{}
	for i := range podList {
		pod := &podList[i]
		podsByNS[pod.Namespace] = append(podsByNS[pod.Namespace], pod)
	}
	for i := range svcList {
		svc := &svcList[i]
		if !linkerdAuditedService(injected, svc) {
			continue
		}
		sel := labels.SelectorFromSet(svc.Spec.Selector)
		readyIPs := map[string]bool{}
		liveIPs := map[string]bool{}
		readyAgedIPs := map[string]bool{}
		for _, pod := range podsByNS[svc.Namespace] {
			if pod.DeletionTimestamp != nil ||
				!sel.Matches(labels.Set(pod.Labels)) ||
				pod.Status.PodIP == "" {
				continue
			}
			liveIPs[pod.Status.PodIP] = true
			// endpoint-sync-heal: kube.PodReadySince fails closed on a
			// zero LastTransitionTime, but the desync read
			// treats a zero stamp as maximally aged — restore
			// the lenient read for Ready pods (zero →
			// since=zero → the age fuse below always trips).
			since, ready := kube.PodReadySince(pod)
			if !ready && kube.PodReadyCond(pod) {
				since, ready = time.Time{}, true
			}
			if ready {
				readyIPs[pod.Status.PodIP] = true
				// endpoint-sync-heal fuse — only a pod Ready past
				// linkerdSliceHealMinAge counts as "missing"
				// from the slices.
				if now.Sub(since) >= linkerdSliceHealMinAge {
					readyAgedIPs[pod.Status.PodIP] = true
				}
			}
		}
		key := svc.Namespace + "/" + svc.Name
		if linkerdEndpointSetsDiverge(readyIPs, liveIPs, esReady[key]) {
			scan.desynced[key] = svc
		} else if err := heal.ClearPersistedFirstSeen(ctx, log,
			&p.linkerdDesyncSince, svc,
			kube.AnnoFirstSeenLinkerdEndpointSync, key,
			p.linkerdSvcPatch(svc)); err != nil {
			// CONVERGED services clear any persisted stamp so a
			// later desync re-arms the full window. Tolerated
			// sub-failure — Warn + continue, never fail the
			// sweep; the stamp retries next sweep.
			log.Info("WARN: persisted first-seen clear failed — "+
				"a stale stamp could fast-trip the next desync",
				"service", key, "error", err)
		}
		if stale := staleLinkerdSlices(
			managedSlices[key], readyAgedIPs, liveIPs); len(stale) > 0 {
			scan.staleSlices[key] = stale
		}
	}
	return scan, nil
}

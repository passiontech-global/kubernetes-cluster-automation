package apiserverendpointguard

import (
	"context"
	"fmt"
	"maps"
	"slices"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func (g *apiServerEndpointGuard) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	preferSlice, verr := g.endpointMode()
	if verr != nil {
		log.Error(verr, "k8s version undetectable — defaulting to corev1 Endpoints")
	}

	epsList, err := g.kubernetesSlices(ctx)
	if err != nil {
		return fmt.Errorf("list endpointslices for %s/%s: %w",
			endpointGuardNS, endpointGuardName, err)
	}
	var primary *discoveryv1.EndpointSlice
	if len(epsList) > 0 {
		primary = epsList[0]
	}

	var ep *unstructured.Unstructured
	if primary == nil || mirrorManagedSlice(primary) || !preferSlice {
		e, getErr := g.dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).
			Get(ctx, endpointGuardName, metav1.GetOptions{})
		gone, err := kube.ConfirmAbsent(getErr)
		if err != nil {
			return fmt.Errorf("get endpoints %s/%s: %w",
				endpointGuardNS, endpointGuardName, err)
		}
		if !gone {
			ep = e
		}
	}

	useSlice := primary != nil &&
		(ep == nil || (preferSlice && !mirrorManagedSlice(primary)))
	if !useSlice && ep == nil {
		return fmt.Errorf("neither endpoints/%s nor a usable endpointslice exists",
			endpointGuardName)
	}

	var activeIPs []string
	var routableIPs map[string]bool
	var quarantinedIPs map[string]bool
	if useSlice {
		activeIPs = slicesIPs(epsList)
		routableIPs = routableSliceIPs(epsList)
		quarantinedIPs = parseQuarantineAnnotation(primary)
	} else {
		activeIPs = endpointIPs(ep)
		routableIPs = routableEndpointIPs(ep)
		quarantinedIPs = parseQuarantineAnnotation(ep)
	}
	if g.peerHighWater == nil {
		g.peerHighWater = map[string]bool{}
	}
	for _, ip := range activeIPs {
		g.peerHighWater[ip] = true
	}
	for ip := range g.memQuarantine {
		quarantinedIPs[ip] = true
	}
	g.memQuarantine = maps.Clone(quarantinedIPs)
	g.quarantineActive = len(quarantinedIPs) > 0
	allIPs := unionIPs(activeIPs, quarantinedIPs)
	if len(allIPs) == 0 {
		log.Info("sweep done: no controller endpoints")
		return nil
	}

	results, toExpire := g.evaluateBackends(ctx, allIPs, activeIPs, quarantinedIPs)

	if len(allIPs) < endpointGuardMinBackends && len(toExpire) == 0 {
		log.Info("sweep done: single-controller cluster — probe only, no edits",
			"backends", allIPs)
		return nil
	}

	reconcilerDriven := primary != nil && !mirrorManagedSlice(primary)
	var peerIPs map[string]bool
	if len(quarantinedIPs) > 0 && !reconcilerDriven {
		peerIPs = g.ssotPeerIPs(ctx)
	}

	toRemove, toAdd, healthyActive := g.decideQuarantine(log, results,
		activeIPs, routableIPs, quarantinedIPs, reconcilerDriven, peerIPs)

	qPost := maps.Clone(quarantinedIPs)
	for _, ip := range toRemove {
		qPost[ip] = true
	}
	for _, ip := range toAdd {
		delete(qPost, ip)
	}
	var sliceCopies []*discoveryv1.EndpointSlice
	var sliceDirty []bool
	if !useSlice {
		sliceCopies, sliceDirty = convergeSlices(epsList, qPost, toAdd)
	}

	if len(toRemove) == 0 && len(toAdd) == 0 && len(toExpire) == 0 &&
		!slices.Contains(sliceDirty, true) {
		log.Info("sweep done", "backends", len(allIPs), "healthyActive", healthyActive,
			"quarantined", len(quarantinedIPs))
		return nil
	}

	if useSlice {
		err = g.applySliceQuarantine(ctx, log, epsList, toRemove, toAdd,
			quarantinedIPs, healthyActive)
	} else {
		err = g.applyEndpointsQuarantine(ctx, log, ep, toRemove, toAdd,
			quarantinedIPs, healthyActive, sliceCopies, sliceDirty)
	}
	if err != nil {
		return err
	}
	g.memQuarantine = maps.Clone(quarantinedIPs)

	log.Info("sweep done", "removed", toRemove, "readded", toAdd,
		"quarantined", slices.Sorted(maps.Keys(quarantinedIPs)))
	return nil
}

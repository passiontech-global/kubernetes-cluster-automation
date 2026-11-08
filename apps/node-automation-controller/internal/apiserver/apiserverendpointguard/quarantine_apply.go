// quarantine_apply.go — the dual-path mutation phase of
// apiserver-endpoint-guard, split out of run() per the
// stateful_masterless_services.go → *_heals.go collector precedent.
// Which branch runs is decided by run()'s SSOT resolution
// (endpoint_ssot.go); the pure Endpoints/EndpointSlice edit helpers
// and the quarantine annotation stamp live in quarantine_mutation.go.
//
// Both appliers mutate the shared quarantinedIPs set IN PLACE as they
// log each action — run() reads the post-mutation set for the
// "sweep done" log line and re-clones it into g.memQuarantine. A
// returned error therefore means partial persistence exactly as
// before the split: the SSOT update failed mid-branch, run() skips
// the memQuarantine sync, and the next cycle re-decides from live
// state.
package apiserverendpointguard

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// applySliceQuarantine is the EndpointSlice-SSOT mutation path (>=1.33
// self-managed clusters): toRemove/toAdd are applied to deep copies of
// every resolved slice, the quarantine annotation is stamped on the
// primary (copies[0]), and each dirty slice is Updated — including the
// primary even when its endpoint set was untouched, because only it
// carries the annotation. The first update failure is returned: the
// periodic loop meters it and the next cycle retries the whole
// decision.
func (g *apiServerEndpointGuard) applySliceQuarantine(ctx context.Context, log logr.Logger,
	epsList []*discoveryv1.EndpointSlice, toRemove, toAdd []string,
	quarantinedIPs map[string]bool, healthyActive int) error {

	copies := deepCopySlices(epsList)
	dirty := make([]bool, len(copies))
	for _, ip := range toRemove {
		quarantinedIPs[ip] = true
		log.Info("QUARANTINE: wedged apiserver pulled from kubernetes EndpointSlice",
			"ip", ip, "remainingHealthy", healthyActive)
		for i := range copies {
			if removeSliceIP(copies[i], ip) {
				dirty[i] = true
			}
		}
	}
	for _, ip := range toAdd {
		if i := sliceIdxForIP(copies, ip); i >= 0 && addSliceIP(copies[i], ip) {
			dirty[i] = true
		}
		delete(quarantinedIPs, ip)
		log.Info("RE-ADD: recovered apiserver back in kubernetes EndpointSlice", "ip", ip)
	}
	// The primary always carries the annotation — persist it even
	// when its endpoint set itself was unchanged this cycle.
	writeQuarantineAnnotation(copies[0], quarantinedIPs)
	for _, err := range g.updateDirtySlices(ctx, copies, dirty, true) {
		if err != nil {
			return err
		}
	}
	return nil
}

// applyEndpointsQuarantine is the corev1 Endpoints-SSOT mutation path
// (hosted planes, <1.33): the unstructured Endpoints object is mutated
// on a deep copy, stamped with the quarantine annotation, and written
// back through the dynamic client — skipped entirely when the
// mutation produced the identical object so a pure slice-repair cycle
// (drift retry) doesn't churn a no-op Endpoints update every sweep.
// The sweep then mirrors the decision onto every drifted EndpointSlice;
// those convergence updates are logged/metered but NOT returned —
// Endpoints already persisted the decision and the next cycle re-applies
// the slice diff.
func (g *apiServerEndpointGuard) applyEndpointsQuarantine(ctx context.Context, log logr.Logger,
	ep *unstructured.Unstructured, toRemove, toAdd []string,
	quarantinedIPs map[string]bool, healthyActive int,
	sliceCopies []*discoveryv1.EndpointSlice, sliceDirty []bool) error {

	mutated := ep.DeepCopy()
	for _, ip := range toRemove {
		removeEndpointIP(mutated, ip)
		quarantinedIPs[ip] = true
		log.Info("QUARANTINE: wedged apiserver pulled from kubernetes endpoints",
			"ip", ip, "remainingHealthy", healthyActive)
	}
	for _, ip := range toAdd {
		addEndpointIP(mutated, ip)
		delete(quarantinedIPs, ip)
		log.Info("RE-ADD: recovered apiserver back in kubernetes endpoints", "ip", ip)
	}
	writeQuarantineAnnotation(mutated, quarantinedIPs)
	// Skip the write when the mutation produced the identical
	// object — a pure slice-repair cycle (drift retry) would
	// otherwise churn a no-op Endpoints update every sweep. A
	// reconciler-wiped annotation still diffs and gets restored.
	if !reflect.DeepEqual(mutated.Object, ep.Object) {
		if _, err := g.dyn.Resource(endpointsGVR).Namespace(endpointGuardNS).
			Update(ctx, mutated, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update endpoints/%s: %w", endpointGuardName, err)
		}
	}

	// EndpointSlices converge to the FULL quarantine set (not just
	// this cycle's removals) so a slice update that failed earlier
	// is retried instead of leaving a wedged IP routable forever.
	// On hosted planes the mirror controller propagates the
	// Endpoints write itself within ~1s — this write just wins the
	// race when propagation lags. The diff itself was computed
	// above against the actual slice contents — reaching this
	// block on drift alone repairs the slice without touching
	// the Endpoints object at all.
	for i, err := range g.updateDirtySlices(ctx, sliceCopies, sliceDirty, false) {
		if err == nil {
			continue
		}
		// Logged/metered, not returned: Endpoints already
		// persisted the decision and the next cycle re-applies
		// the slice diff.
		metrics.IncError(g.queue)
		log.Error(err, "EndpointSlice update failed — retries next cycle",
			"slice", sliceCopies[i].Name)
	}
	return nil
}

// updateDirtySlices Updates every dirty slice copy — plus the primary
// (copies[0]) when updatePrimary, because only the primary carries the
// quarantine annotation even when its endpoint set was untouched. The
// per-slice errors are returned aligned with copies (nil = skipped or
// succeeded): the EndpointSlice-SSOT path STOPS at the first failure —
// a failed primary (annotation-carrier) update must persist nothing,
// so the next cycle retries the whole decision — while the
// Endpoints-mirror convergence path logs and meters each one and
// keeps converging the remaining slices (different error contracts by
// design).
func (g *apiServerEndpointGuard) updateDirtySlices(ctx context.Context,
	copies []*discoveryv1.EndpointSlice, dirty []bool, updatePrimary bool) []error {
	errs := make([]error, len(copies))
	for i, s := range copies {
		if !dirty[i] && !(updatePrimary && i == 0) {
			continue
		}
		if _, err := g.cs.DiscoveryV1().EndpointSlices(endpointGuardNS).
			Update(ctx, s, metav1.UpdateOptions{}); err != nil {
			errs[i] = fmt.Errorf("update endpointslice/%s: %w", s.Name, err)
			if updatePrimary {
				return errs
			}
		}
	}
	return errs
}

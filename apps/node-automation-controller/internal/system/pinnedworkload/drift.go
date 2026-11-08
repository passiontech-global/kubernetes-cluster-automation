// drift.go — the per-field drift predicates the three pinned-workload
// patchers duplicate clause-by-clause (coredns_patcher.go's
// corednsNeedsPatch, metrics_server_patcher.go's
// metricsServerNeedsPatch, konnectivity_patcher.go's
// konnectivityDrifted): replica pin drift, probe timeouts, requests/
// limits, and the cleared-affinity requirement. The patchers keep
// their own wanted values and topology/tolerations/args checks —
// these are the SHARED clauses only, so a semantics change to one
// pinned field cannot fork across the three modules.
package pinnedworkload

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// ReplicaDrifted reports whether the Deployment's spec.replicas
// drifted from the proportional pin. Replica drift only counts when
// the pin is enabled (wantReplicas>0) — a nil .spec.replicas defaults
// to 1 at the API but still means "we never pinned it", so it counts
// as drifted too.
func ReplicaDrifted(d *appsv1.Deployment, wantReplicas int32) bool {
	return wantReplicas > 0 &&
		(d.Spec.Replicas == nil || *d.Spec.Replicas != wantReplicas)
}

// ProbeTimeoutsDrifted reports whether the container's liveness and
// readiness probes are missing or unpinned — both must exist with the
// pinned 5s TimeoutSeconds (the value both Deployment patchers pin).
func ProbeTimeoutsDrifted(c *corev1.Container) bool {
	return c.LivenessProbe == nil || c.LivenessProbe.TimeoutSeconds != 5 ||
		c.ReadinessProbe == nil || c.ReadinessProbe.TimeoutSeconds != 5
}

// ResourcesDrifted reports whether the container's requests/limits
// drifted from the pinned quantities. Each wanted ResourceList is
// compared key-by-key with Quantity.Cmp — a missing key reads as the
// zero quantity, so an absent request is drift against any non-zero
// want (same as the patchers' map-index + Cmp shape). Extra container
// quantities are NOT drift: only the pinned keys are judged. A nil
// wanted list skips that half — konnectivity pins requests only.
func ResourcesDrifted(c *corev1.Container,
	wantReq, wantLim corev1.ResourceList) bool {
	for k, want := range wantReq {
		if q := c.Resources.Requests[k]; q.Cmp(want) != 0 {
			return true
		}
	}
	for k, want := range wantLim {
		if q := c.Resources.Limits[k]; q.Cmp(want) != 0 {
			return true
		}
	}
	return false
}

// AffinitySet reports whether the pod spec carries an affinity —
// drift for the Deployment patchers, which pin affinity to NIL
// (coredns/metrics-server drop the k0s-installed hostname
// anti-affinity that fights the zone spread constraints). The patch
// writes "affinity": null; any set affinity is drift to re-clear.
func AffinitySet(ps corev1.PodSpec) bool {
	return ps.Affinity != nil
}

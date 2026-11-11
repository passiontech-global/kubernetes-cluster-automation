// coredns_patch.go — drift detection and the strategic-merge patch body
// for kube-system/coredns. split from coredns_patcher.go (see its header
// for the module contract).
package corednspatcher

import (
	"encoding/json"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/pinnedworkload"
)

// corednsMinDomainsWanted gates minDomains onto DoNotSchedule only —
// the API rejects minDomains combined with ScheduleAnyway (the cicd
// override therefore runs ScheduleAnyway with minDomains disabled).
func corednsMinDomainsWanted(zoneWhen string, minDomains int) bool {
	return zoneWhen == string(corev1.DoNotSchedule) && minDomains > 0
}

// corednsNeedsPatch reports whether the Deployment lacks any pinned
// field — probe timeouts + liveness failure threshold, requests/
// limits, cleared affinity, the two wanted spread constraints, the
// rollingUpdate.maxUnavailable=1 strategy pin, or (when proportional
// scaling is on, wantReplicas>0) a drifted .spec.replicas. A missing
// coredns container counts as drifted (same as the shell's empty
// jsonpath probe).
func corednsNeedsPatch(d *appsv1.Deployment, zoneWhen string, minDomains int, wantReplicas int32) bool {
	// Replica drift only counts when the pin is enabled — a nil
	// .spec.replicas defaults to 1 at the API but still means "we
	// never pinned it", so it counts as drifted too.
	if pinnedworkload.ReplicaDrifted(d, wantReplicas) {
		return true
	}
	ps := d.Spec.Template.Spec
	for i := range ps.Containers {
		c := &ps.Containers[i]
		if c.Name != "coredns" {
			continue
		}
		if pinnedworkload.ProbeTimeoutsDrifted(c) ||
			corednsLivenessThresholdDrifted(c) ||
			pinnedworkload.ResourcesDrifted(c, corednsWantReq, corednsWantLim) ||
			corednsStrategyDrifted(d) {
			return true
		}
		if pinnedworkload.AffinitySet(ps) {
			return true
		}
		return !corednsTopologyOK(ps.TopologySpreadConstraints, zoneWhen, minDomains)
	}
	return true
}

// corednsLivenessThresholdDrifted requires the pinned
// livenessProbe.failureThreshold=5 — at the default 10s period a
// single slow /ready sync while the apiserver is loaded must not
// restart the pod (5 misses ≈ 50s of tolerance before kubelet acts).
// The readiness probe keeps its default threshold: unready is the
// correct signal there, only liveness needs the wider fuse.
func corednsLivenessThresholdDrifted(c *corev1.Container) bool {
	return c.LivenessProbe == nil || c.LivenessProbe.FailureThreshold != 5
}

// corednsStrategyDrifted requires the pinned
// strategy.rollingUpdate.maxUnavailable=1 — the k8s default 25%
// can take a quarter of a small fleet down in one rollout while the
// apiserver is already degraded (the watch-cache-wedge-gate post-mortem class).
// maxSurge stays unpinned: surge pods are what keep DNS answers
// flowing mid-rollout. A Recreate strategy is drift too — the pin
// only exists under RollingUpdate.
func corednsStrategyDrifted(d *appsv1.Deployment) bool {
	st := d.Spec.Strategy
	if st.Type == appsv1.RecreateDeploymentStrategyType {
		return true
	}
	ru := st.RollingUpdate
	return ru == nil || ru.MaxUnavailable == nil ||
		ru.MaxUnavailable.Type != intstr.Int || ru.MaxUnavailable.IntValue() != 1
}

// corednsTopologyOK requires both wanted constraints: zone per the
// configured whenUnsatisfiable/minDomains and hostname ScheduleAnyway,
// each selector k8s-app=kube-dns with Honor node-inclusion policies.
func corednsTopologyOK(tscs []corev1.TopologySpreadConstraint, zoneWhen string, minDomains int) bool {
	zoneOK, hostOK := false, false
	for _, c := range tscs {
		sel := c.LabelSelector != nil &&
			c.LabelSelector.MatchLabels["k8s-app"] == "kube-dns"
		if c.MaxSkew != 1 {
			continue
		}
		honor := c.NodeTaintsPolicy != nil &&
			*c.NodeTaintsPolicy == corev1.NodeInclusionPolicyHonor &&
			c.NodeAffinityPolicy != nil &&
			*c.NodeAffinityPolicy == corev1.NodeInclusionPolicyHonor
		switch c.TopologyKey {
		case "topology.kubernetes.io/zone":
			if c.WhenUnsatisfiable != corev1.UnsatisfiableConstraintAction(zoneWhen) ||
				!sel || !honor {
				continue
			}
			// minDomains can only exist under DoNotSchedule (API
			// validation), so the not-wanted case means nil.
			if corednsMinDomainsWanted(zoneWhen, minDomains) {
				zoneOK = c.MinDomains != nil && *c.MinDomains == int32(minDomains)
			} else {
				zoneOK = c.MinDomains == nil
			}
		case "kubernetes.io/hostname":
			if c.WhenUnsatisfiable == corev1.ScheduleAnyway && sel && honor {
				hostOK = true
			}
		}
	}
	return zoneOK && hostOK
}

// corednsPatchBody renders the strategic-merge patch — containers
// merge by name (k0s-owned args/labels are untouched), affinity:null
// drops the required hostname anti-affinity, and the constraints list
// merges on topologyKey. minDomains is set to the wanted value, or to
// explicit null when not wanted: the constraints list merges per
// topologyKey, so an omitted minDomains would SURVIVE from a previous
// DoNotSchedule patch — leaving minDomains on a ScheduleAnyway
// constraint that the API then rejects (the cicd shell override sent
// "minDomains": null for the same reason).
//
// spec.replicas is only sent when wantReplicas>0 — an omitted key
// keeps the Deployment's current replica count under strategic
// merge, so disabled scaling never fights an external autoscaler.
func corednsPatchBody(zoneWhen string, minDomains int, wantReplicas int32) ([]byte, error) {
	zone := map[string]any{
		"maxSkew":            1,
		"topologyKey":        "topology.kubernetes.io/zone",
		"whenUnsatisfiable":  zoneWhen,
		"nodeTaintsPolicy":   "Honor",
		"nodeAffinityPolicy": "Honor",
		"labelSelector":      map[string]any{"matchLabels": map[string]any{"k8s-app": "kube-dns"}},
	}
	if corednsMinDomainsWanted(zoneWhen, minDomains) {
		zone["minDomains"] = minDomains
	} else {
		zone["minDomains"] = nil // explicit null — deletes a stale value
	}
	spec := map[string]any{
		// The strategy pin merges field-wise: maxUnavailable=1 lands
		// while an existing maxSurge survives; "type" is pinned so a
		// Recreate drift cannot survive the patch (the drift check
		// treats it as drift, so leaving it would re-patch forever).
		"strategy": map[string]any{
			"type":          "RollingUpdate",
			"rollingUpdate": map[string]any{"maxUnavailable": 1},
		},
		"template": map[string]any{
			"spec": map[string]any{
				"affinity": nil,
				"containers": []any{map[string]any{
					"name": "coredns",
					"livenessProbe": map[string]any{
						"timeoutSeconds": 5, "failureThreshold": 5},
					"readinessProbe": map[string]any{"timeoutSeconds": 5},
					"resources": map[string]any{
						"requests": map[string]any{"cpu": "25m", "memory": "64Mi"},
						"limits":   map[string]any{"cpu": "1000m", "memory": "256Mi"},
					},
				}},
				"topologySpreadConstraints": []any{
					zone,
					map[string]any{
						"maxSkew":            1,
						"topologyKey":        "kubernetes.io/hostname",
						"whenUnsatisfiable":  "ScheduleAnyway",
						"nodeTaintsPolicy":   "Honor",
						"nodeAffinityPolicy": "Honor",
						"labelSelector":      map[string]any{"matchLabels": map[string]any{"k8s-app": "kube-dns"}},
					},
				},
			},
		},
	}
	if wantReplicas > 0 {
		spec["replicas"] = wantReplicas
	}
	return json.Marshal(map[string]any{"spec": spec})
}

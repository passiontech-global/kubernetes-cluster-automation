// descheduler_storm_watch.go — the Node watch wiring of the
// descheduler-storm-gate: the sweep mapfunc, the change predicate,
// and the jqFilter-equivalent node projections the predicate reads.
// Split from descheduler_storm_gate.go (see its header for the
// module contract).
package deschedulerstormgate

import (
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// The watch wiring below installs these package-level units
// verbatim — tests exercise the exact predicate/mapfunc the
// controller runs instead of introspecting controller-runtime
// internals.

// nodeSweepRequests collapses every Node event onto the single fixed
// sweep key (see shared.SweepRequests).
var nodeSweepRequests = shared.SweepRequests("descheduler-storm-gate-sweep")

// stormSignalChanges is the Node watch predicate — fire only when the
// fields the verdict reads actually changed (bash jqFilter
// equivalent: {conds: type=status, taints: keys}). Comparing raw
// Status.Conditions would fire on every kubelet heartbeat —
// lastHeartbeatTime/Reason/Message churn constantly.
var stormSignalChanges = shared.NodeUpdatePredicate(true, func(oldN, newN *corev1.Node) bool {
	return oldN.Spec.Unschedulable != newN.Spec.Unschedulable ||
		!maps.Equal(condStatusMap(oldN), condStatusMap(newN)) ||
		!slices.Equal(taintKeys(oldN), taintKeys(newN))
})

// condStatusMap is the jqFilter projection: condition type -> status,
// dropping churny fields (lastHeartbeatTime, reason, message).
func condStatusMap(n *corev1.Node) map[corev1.NodeConditionType]corev1.ConditionStatus {
	m := make(map[corev1.NodeConditionType]corev1.ConditionStatus, len(n.Status.Conditions))
	for _, c := range n.Status.Conditions {
		m[c.Type] = c.Status
	}
	return m
}

// taintKeys is the jqFilter projection: taint keys in order.
func taintKeys(n *corev1.Node) []string {
	keys := make([]string, 0, len(n.Spec.Taints))
	for _, t := range n.Spec.Taints {
		keys = append(keys, t.Key)
	}
	return keys
}

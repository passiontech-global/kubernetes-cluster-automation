// nodecond_ssot_test.go — the SSOT drift guard between the agent's
// conditionDefs and the controller's zombie-condition sweeper. Every
// NodeCondition nodereporter emits must be in
// nodecond.HeartbeatSweptNames — the set the node-condition-sweeper
// (controller side) reconciles when a frozen heartbeat says the
// reporter died. A def missing from the swept set is a zombie
// condition nothing will ever clear: the 2026-11-09 InodePressure
// W18-1 ownership flip left exactly this gap between the two apps'
// lists and one stale test on the far side never noticed.
package nodereporter

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// deliberatelyUnswept records condition types a def may carry that
// are intentionally OUTSIDE HeartbeatSweptNames, each with its
// reason — the escape hatch must be explicit, never silent.
var deliberatelyUnswept = map[corev1.NodeConditionType]string{}

// TestConditionDefsCoveredByHeartbeatSweep pins the cross-app
// contract: every condition the reporter owns is swept by the
// controller when its heartbeat freezes, so no latched condition can
// outlive its writer.
func TestConditionDefsCoveredByHeartbeatSweep(t *testing.T) {
	var missing []corev1.NodeConditionType
	for _, def := range conditionDefs {
		if slices.Contains(nodecond.HeartbeatSweptNames, string(def.typ)) {
			continue
		}
		if _, deliberate := deliberatelyUnswept[def.typ]; deliberate {
			continue
		}
		missing = append(missing, def.typ)
	}
	if len(missing) > 0 {
		t.Fatalf("conditionDefs absent from nodecond.HeartbeatSweptNames — the controller sweeper can never clear them (add to the swept set in libs/hostkit/nodecond, or record a deliberate exclusion here with its reason): %v", missing)
	}
}

// TestConditionOrderCoversCondDefs pins the projection contract:
// conditionOrder must name every latchdefs.CondDefs key exactly once
// (a CondDef missing from the order renders no condition; a duplicate
// renders it twice), and every non-empty order entry must resolve a
// CondDef (the "" entry is WatchdogStale's freshness probe).
func TestConditionOrderCoversCondDefs(t *testing.T) {
	seen := map[string]int{}
	for _, latch := range conditionOrder {
		seen[latch]++
		if latch == "" {
			continue
		}
		if _, ok := latchdefs.CondDefs[latch]; !ok {
			t.Errorf("conditionOrder entry %q has no latchdefs.CondDefs row", latch)
		}
	}
	for latch := range latchdefs.CondDefs {
		if seen[latch] != 1 {
			t.Errorf("latchdefs.CondDefs[%q] appears %d times in conditionOrder, want exactly 1", latch, seen[latch])
		}
	}
	if seen[""] != 1 {
		t.Errorf("WatchdogStale probe entry appears %d times in conditionOrder, want exactly 1", seen[""])
	}
}

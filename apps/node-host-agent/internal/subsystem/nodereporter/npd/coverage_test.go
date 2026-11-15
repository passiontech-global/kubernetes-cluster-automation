package npd

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestSeedConditions(t *testing.T) {
	m := &Monitor{}
	m.SeedConditions([]corev1.NodeCondition{
		{Type: condKernelDeadlock, Status: corev1.ConditionTrue, Message: "hung task"},
		{Type: condReadonlyFS, Status: corev1.ConditionTrue, Message: "ro mount"},
	})
	if !m.seeded || !m.kernelDeadlock || m.kernelDeadlockMsg != "hung task" || !m.kernelDeadlockEventSent {
		t.Fatalf("unexpected deadlock state after SeedConditions: %+v", m)
	}
	if !m.readonlyFS || m.readonlyFSMsg != "ro mount" {
		t.Fatalf("unexpected readonlyFS state after SeedConditions: %+v", m)
	}

	// Second call is a no-op because m.seeded is true.
	m.kernelDeadlock = false
	m.SeedConditions([]corev1.NodeCondition{
		{Type: condKernelDeadlock, Status: corev1.ConditionTrue, Message: "second"},
	})
	if m.kernelDeadlock {
		t.Fatal("expected second SeedConditions call to be ignored")
	}
}

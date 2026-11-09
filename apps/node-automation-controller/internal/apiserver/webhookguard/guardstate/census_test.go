// census_test.go — coverage for the endpoint-census node-health discount:
// nodeUnhealthyForEndpoints flags every node whose pod network is
// presumed dead for admission.
package guardstate

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// gsReadyNode builds a Ready Node carrying the given taints.
func gsReadyNode(name string, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionTrue,
		}}},
	}
}

func TestNodeUnhealthyForEndpoints(t *testing.T) {
	notReady := gsReadyNode("n-notready")
	notReady.Status.Conditions[0].Status = corev1.ConditionFalse
	partCond := gsReadyNode("n-partcond")
	partCond.Status.Conditions = append(partCond.Status.Conditions,
		corev1.NodeCondition{Type: "NetworkPartitioned", Status: corev1.ConditionTrue})

	for _, tc := range []struct {
		name string
		node *corev1.Node
		want bool
	}{
		{"not ready", notReady, true},
		{"ready clean", gsReadyNode("n-ok"), false},
		{"network-partitioned taint", gsReadyNode("n1",
			corev1.Taint{Key: "passiontech.dev/network-partitioned", Effect: corev1.TaintEffectNoSchedule}), true},
		{"kubelet-unresponsive taint", gsReadyNode("n2",
			corev1.Taint{Key: "passiontech.dev/kubelet-unresponsive", Effect: corev1.TaintEffectNoSchedule}), true},
		{"unreachable taint", gsReadyNode("n3",
			corev1.Taint{Key: "node.kubernetes.io/unreachable", Effect: corev1.TaintEffectNoSchedule}), true},
		{"not-ready taint", gsReadyNode("n4",
			corev1.Taint{Key: "node.kubernetes.io/not-ready", Effect: corev1.TaintEffectNoSchedule}), true},
		{"out-of-service taint", gsReadyNode("n5",
			corev1.Taint{Key: "node.kubernetes.io/out-of-service", Effect: corev1.TaintEffectNoSchedule}), true},
		{"NetworkPartitioned condition", partCond, true},
		{"unrelated taint", gsReadyNode("n6",
			corev1.Taint{Key: "node.cilium.io/agent-not-ready", Effect: corev1.TaintEffectNoSchedule}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeUnhealthyForEndpoints(tc.node); got != tc.want {
				t.Fatalf("nodeUnhealthyForEndpoints = %v, want %v", got, tc.want)
			}
		})
	}
}

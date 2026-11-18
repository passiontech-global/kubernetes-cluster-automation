// konnectivity_heal_labels_internal_test.go — the virtual-worker
// census must key on the real Kubernetes instance-type label; a bare
// "instance-type" key never appears on node objects, so external
// capacity used to be counted as a worker that could dial the tunnel.
package apiserver

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestIsVirtualWorkerNodeLabelsStableInstanceType(t *testing.T) {
	// The canonical label with the external-capacity value marks a
	// shadow node — it cannot run a konnectivity-agent.
	if !isVirtualWorkerNodeLabels(map[string]string{
		corev1.LabelInstanceTypeStable: "external",
	}) {
		t.Fatal("external-capacity node counted as a Ready worker")
	}
	// Real workers also carry the label; an ordinary instance type
	// must NOT exclude them from the census.
	if isVirtualWorkerNodeLabels(map[string]string{
		corev1.LabelInstanceTypeStable: "m5.large",
	}) {
		t.Fatal("real worker excluded by its instance-type label")
	}
	// The legacy virtual shapes keep their presence-based filtering.
	for _, labels := range []map[string]string{
		{"liqo.io/type": "virtual-node"},
		{"virtual-kubelet.io/provider": "azure"},
		{"type": "virtual-kubelet"},
	} {
		if !isVirtualWorkerNodeLabels(labels) {
			t.Fatalf("virtual node %v counted as a Ready worker", labels)
		}
	}
	if isVirtualWorkerNodeLabels(map[string]string{"kubernetes.io/hostname": "w1"}) {
		t.Fatal("ordinary worker node filtered out")
	}
}

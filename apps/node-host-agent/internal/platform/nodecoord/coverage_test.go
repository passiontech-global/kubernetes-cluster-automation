package nodecoord

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewKube(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "node-1",
			Annotations: map[string]string{"k": "v"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "pod-1",
		},
	}
	cs := fake.NewSimpleClientset(node, pod)
	c := NewKube("node-1", cs)

	annos, err := c.GetAnnos(context.Background())
	if err != nil || annos["k"] != "v" {
		t.Fatalf("GetAnnos = (%v,%v)", annos, err)
	}
	if err := c.PatchNodeStatus(context.Background(), StatusCondition{
		Type:    "TestCond",
		Status:  "False",
		Reason:  "OK",
		Message: "healthy",
	}); err != nil {
		t.Fatalf("PatchNodeStatus: %v", err)
	}
	if err := c.PatchPodAnno(context.Background(), "default", "pod-1", map[string]string{"a": "b"}); err != nil {
		t.Fatalf("PatchPodAnno: %v", err)
	}
}

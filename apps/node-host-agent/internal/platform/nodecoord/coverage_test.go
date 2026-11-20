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

func TestNewKubeKuredRebootTaint(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{{
				Key:    "weave.works/kured-node-reboot",
				Effect: corev1.TaintEffectNoSchedule,
			}},
		},
	}
	cs := fake.NewSimpleClientset(node)
	c := NewKube("node-1", cs)

	v, err := c.Maintenance(context.Background())
	if err != nil || !v.KuredLocked || !v.Active {
		t.Fatalf("Maintenance with reboot taint = (%+v,%v), want KuredLocked+Active", v, err)
	}
	if !c.HoldEmergencyHeal(context.Background()) {
		t.Fatal("HoldEmergencyHeal must hold when kured reboot taint is present")
	}

	// Removing the taint and expiring cache clears KuredLocked.
	node.Spec.Taints = nil
	if _, err := cs.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.cachedAt = c.cachedAt.Add(-2 * CacheTTL)
	c.mu.Unlock()

	v, err = c.Maintenance(context.Background())
	if err != nil || v.KuredLocked || v.Active {
		t.Fatalf("Maintenance after taint removal = (%+v,%v), want clear", v, err)
	}
}

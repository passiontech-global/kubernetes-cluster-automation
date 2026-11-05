package partitionevictor

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestPartitionEvictor(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	old := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	partitioned := testutil.Node("p1", corev1.ConditionTrue, nil)
	partitioned.Status.Conditions = append(partitioned.Status.Conditions,
		corev1.NodeCondition{
			Type:               "HostNetworkProblems",
			Status:             corev1.ConditionTrue,
			LastTransitionTime: old,
		})
	healthy := testutil.Node("h1", corev1.ConditionTrue, nil)
	others := []*corev1.Node{
		testutil.Node("h2", corev1.ConditionTrue, nil),
		testutil.Node("h3", corev1.ConditionTrue, nil),
	}
	podOnP1 := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "src-ctrl", Namespace: "flux-system"},
		Spec: corev1.PodSpec{NodeName: "p1"}}

	objs := []runtime.Object{partitioned, healthy, podOnP1}
	for _, n := range others {
		objs = append(objs, n)
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}

	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, "node.ops/network-partitioned") {
		t.Fatal("partitioned node not tainted")
	}
	_, err := cs.CoreV1().Pods("flux-system").Get(ctx, "src-ctrl", metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatal("flux-system pod not evicted off partitioned node")
	}

	// Recovery: condition cleared -> taint removed on next sweep.
	p1 := testutil.GetNode(t, cs, "p1")
	p1.Status.Conditions[1].Status = corev1.ConditionFalse
	if _, err := cs.CoreV1().Nodes().UpdateStatus(ctx, p1, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, "node.ops/network-partitioned") {
		t.Fatal("taint not removed after recovery")
	}
}

func TestPartitionEvictorAbortsOnMajorityPartition(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	var objs []runtime.Object
	for _, name := range []string{"a", "b"} {
		n := testutil.Node(name, corev1.ConditionTrue, nil)
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
			Type:               "ClusterNetworkProblems",
			Status:             corev1.ConditionTrue,
			LastTransitionTime: old,
		})
		objs = append(objs, n)
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, "node.ops/network-partitioned") {
			t.Fatalf("node %s tainted during a majority partition — guard failed", name)
		}
	}
}

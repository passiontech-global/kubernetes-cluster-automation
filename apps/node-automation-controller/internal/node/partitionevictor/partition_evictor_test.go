package partitionevictor

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders (pe-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

// pePartitionedNode builds a node whose given NWPD condition has been
// True for `age` (already exceeds partitionMinAge when age > 10m),
// carrying a fresh lastHeartbeatTime — the agent re-stamps it every
// ~2m while alive, so a sustained latch on a live agent always does
// (the zombie variants override it).
func pePartitionedNode(name string, condType corev1.NodeConditionType, age time.Duration, taints ...corev1.Taint) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil, taints...)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               condType,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
		LastHeartbeatTime:  metav1.NewTime(time.Now()),
	})
	return n
}

func pePod(ns, nodeName, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{NodeName: nodeName},
	}
}

// peHealthyNodes returns n plain Ready nodes named prefix-0..prefix-(n-1).
func peHealthyNodes(prefix string, n int) []runtime.Object {
	objs := make([]runtime.Object, 0, n)
	for i := range n {
		objs = append(objs, testutil.Node(fmt.Sprintf("%s-%d", prefix, i), corev1.ConditionTrue, nil))
	}
	return objs
}

func peCountTaintsWithKey(taints []corev1.Taint, key string) int {
	n := 0
	for _, t := range taints {
		if t.Key == key {
			n++
		}
	}
	return n
}

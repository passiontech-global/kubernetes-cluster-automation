// node_hang_precordon_meshwide_test.go — coverage for the mesh-wide
// NebulaIsolated abort guard in node-hang-precordon.
package nodehealth

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// Single-worker NebulaIsolated (1/3) is a real isolated node — still cordons.
func TestNodeHangSingleNebulaIsolatedStillCordons(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", nodecond.NebulaIsolated, 5*time.Minute, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		probetest.ReadyWorkerNode("w3", "", 0, false),
	)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("single NebulaIsolated worker must fail check")
	}
	n1, _ := cs.CoreV1().Nodes().Get(ctx, "w1", metav1.GetOptions{})
	if !n1.Spec.Unschedulable {
		t.Fatal("single NebulaIsolated worker was not cordoned")
	}
}

// Mesh-wide NebulaIsolated (3/3) ignores NebulaIsolated for cordoning AND
// auto-uncordons a worker previously precordoned solely for NebulaIsolated.
func TestNodeHangMeshWideNebulaIsolatedUncordonsAndSkipsCordon(t *testing.T) {
	w1 := probetest.ReadyWorkerNode("w1", nodecond.NebulaIsolated, 10*time.Minute, true)
	w1.Annotations = map[string]string{nodeHangPreCordonAnno: nodeHangPreCordonValue}
	w2 := probetest.ReadyWorkerNode("w2", nodecond.NebulaIsolated, 10*time.Minute, false)
	w3 := probetest.ReadyWorkerNode("w3", nodecond.NebulaIsolated, 10*time.Minute, false)

	cs := fake.NewSimpleClientset(w1, w2, w3)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("mesh-wide NebulaIsolated with no other hang latch must pass: %+v", res)
	}
	for _, name := range []string{"w1", "w2", "w3"} {
		n, _ := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if n.Spec.Unschedulable {
			t.Fatalf("worker %s stayed unschedulable under mesh-wide NebulaIsolated", name)
		}
	}
}

// Under mesh-wide NebulaIsolated, a worker ALSO carrying a real local hang
// latch (e.g. KubeletPLEGUnhealthy) is still cordoned normally.
func TestNodeHangMeshWideNebulaIsolatedStillCordonsOtherLatch(t *testing.T) {
	w1 := probetest.ReadyWorkerNode("w1", nodecond.NebulaIsolated, 10*time.Minute, false)
	now := time.Now()
	w1.Status.Conditions = append(w1.Status.Conditions, corev1.NodeCondition{
		Type:               corev1.NodeConditionType(nodecond.KubeletPLEGUnhealthy),
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(now.Add(-5 * time.Minute)),
		LastHeartbeatTime:  metav1.NewTime(now),
	})
	w2 := probetest.ReadyWorkerNode("w2", nodecond.NebulaIsolated, 10*time.Minute, false)
	w3 := probetest.ReadyWorkerNode("w3", nodecond.NebulaIsolated, 10*time.Minute, false)

	cs := fake.NewSimpleClientset(w1, w2, w3)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("worker with KubeletPLEGUnhealthy must fail even under mesh-wide NebulaIsolated")
	}
	n1, _ := cs.CoreV1().Nodes().Get(ctx, "w1", metav1.GetOptions{})
	if !n1.Spec.Unschedulable {
		t.Fatal("worker with KubeletPLEGUnhealthy was not cordoned")
	}
}

// cpu_steal_taint_sync_test.go — coverage for the
// cpu-steal-taint-sync check: taint on sustained pressure with
// headroom, headroom guard, untaint after the clear window.
package nodehealth

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// stealNode builds a Ready worker node carrying a CPUStealPressure
// condition of the given status transitioned `age` ago.
func stealNode(name string, status corev1.ConditionStatus, age time.Duration) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               cpuStealCond,
		Status:             status,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
	})
	return n
}

func TestCPUStealTaintsPressuredWorkerWithHeadroom(t *testing.T) {
	w1 := stealNode("w1", corev1.ConditionTrue, 10*time.Minute)
	w2 := testutil.Node("w2", corev1.ConditionTrue, nil)
	w3 := testutil.Node("w3", corev1.ConditionTrue, nil)
	cs := fake.NewSimpleClientset(w1, w2, w3)
	p := testProber(cs)
	res := probetest.MustCheck[*cpuStealTaintSyncCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("sustained steal pressure must fail: %+v", res)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kube.TaintCPUSteal) {
		t.Fatal("pressured worker not tainted")
	}
	for _, n := range []string{"w2", "w3"} {
		if kube.HasTaint(testutil.GetNode(t, cs, n).Spec.Taints, kube.TaintCPUSteal) {
			t.Fatalf("healthy worker %s must not be tainted", n)
		}
	}
}

func TestCPUStealSkipsTaintWithoutHeadroom(t *testing.T) {
	w1 := stealNode("w1", corev1.ConditionTrue, 10*time.Minute)
	w2 := stealNode("w2", corev1.ConditionTrue, 20*time.Minute)
	cs := fake.NewSimpleClientset(w1, w2)
	p := testProber(cs)
	res := probetest.MustCheck[*cpuStealTaintSyncCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("sustained steal pressure must fail: %+v", res)
	}
	// Zero healthy others — tainting anything would strand scheduling.
	for _, n := range []string{"w1", "w2"} {
		if kube.HasTaint(testutil.GetNode(t, cs, n).Spec.Taints, kube.TaintCPUSteal) {
			t.Fatalf("worker %s tainted with no healthy headroom", n)
		}
	}
}

func TestCPUStealUntaintsAfterClearWindow(t *testing.T) {
	w1 := stealNode("w1", corev1.ConditionTrue, 10*time.Minute)
	w2 := testutil.Node("w2", corev1.ConditionTrue, nil)
	w3 := testutil.Node("w3", corev1.ConditionTrue, nil)
	cs := fake.NewSimpleClientset(w1, w2, w3)
	p := testProber(cs)
	chk := probetest.MustCheck[*cpuStealTaintSyncCheck](t, p)
	base := time.Now()
	p.Now = func() time.Time { return base }
	if res := chk.Run(ctx); res.Pass {
		t.Fatalf("sustained steal pressure must fail: %+v", res)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kube.TaintCPUSteal) {
		t.Fatal("pressured worker not tainted")
	}
	// Pressure clears — the 10m clear window must elapse before the
	// taint lifts.
	w1n := testutil.GetNode(t, cs, "w1")
	for i, c := range w1n.Status.Conditions {
		if c.Type == cpuStealCond {
			w1n.Status.Conditions[i].Status = corev1.ConditionFalse
		}
	}
	if _, err := cs.CoreV1().Nodes().UpdateStatus(ctx, w1n, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update node status: %v", err)
	}
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("cleared pressure should pass: %+v", res)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kube.TaintCPUSteal) {
		t.Fatal("taint lifted inside the clear window")
	}
	base = base.Add(11 * time.Minute)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("cleared pressure should pass: %+v", res)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kube.TaintCPUSteal) {
		t.Fatal("taint survived the clear window")
	}
}

// The persisted twin of the clear window: the operator restarted
// mid-window (empty ledger), but the Node carries the first-seen
// stamp proving the pressure cleared >10m ago — the first
// post-restart sweep must honor it, untaint, and drop the stamp so
// the next taint cycle re-arms a full window.
func TestCPUStealUntaintRestartResume(t *testing.T) {
	w1 := stealNode("w1", corev1.ConditionFalse, 20*time.Minute)
	w1.Spec.Taints = append(w1.Spec.Taints, corev1.Taint{
		Key:    kube.TaintCPUSteal,
		Value:  cpuStealTaintValue,
		Effect: corev1.TaintEffectPreferNoSchedule,
	})
	w1.Annotations = map[string]string{
		kube.AnnoFirstSeenCPUStealClear: `{"w1":"` +
			time.Now().Add(-(cpuStealClearMinAge + time.Minute)).
				UTC().Format(time.RFC3339) + `"}`}
	cs := fake.NewSimpleClientset(w1)
	res := probetest.MustCheck[*cpuStealTaintSyncCheck](t, testProber(cs)).Run(ctx)
	if !res.Pass {
		t.Fatalf("cleared pressure should pass: %+v", res)
	}
	got := testutil.GetNode(t, cs, "w1")
	if kube.HasTaint(got.Spec.Taints, kube.TaintCPUSteal) {
		t.Fatal("persisted clear window did not resume — taint survived the first sweep")
	}
	if _, ok := got.Annotations[kube.AnnoFirstSeenCPUStealClear]; ok {
		t.Fatal("resolved clear stamp lingered on the node")
	}
}

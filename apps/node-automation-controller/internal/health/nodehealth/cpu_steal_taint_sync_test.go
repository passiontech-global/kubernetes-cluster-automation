// cpu_steal_taint_sync_test.go — coverage for the
// cpu-steal-taint-sync check: taint on sustained pressure with
// headroom, headroom guard, untaint after the clear window.
package nodehealth

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// stealNode builds a Ready worker node carrying a CPUStealPressure
// condition of the given status transitioned `age` ago, with a fresh
// heartbeat — nodereporter re-stamps it every ~2m while alive.
func stealNode(name string, status corev1.ConditionStatus, age time.Duration) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               cpuStealCond,
		Status:             status,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
		LastHeartbeatTime:  metav1.NewTime(time.Now()),
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

// A CPUStealPressure True whose heartbeat froze is a zombie from a
// wedged reporter: no taint, and the latch stops counting as live
// pressure. The same latch with a fresh heartbeat taints — proving
// the difference is the heartbeat gate, not the headroom guard.
func TestCPUStealZombieHeartbeatDoesNotTaint(t *testing.T) {
	w1 := stealNode("w1", corev1.ConditionTrue, 10*time.Minute)
	w1.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeHangCondHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(w1,
		testutil.Node("w2", corev1.ConditionTrue, nil),
		testutil.Node("w3", corev1.ConditionTrue, nil),
		testutil.Node("w4", corev1.ConditionTrue, nil))
	p := testProber(cs)
	res := probetest.MustCheck[*cpuStealTaintSyncCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("zombie steal latch must not fail the check: %+v", res)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kube.TaintCPUSteal) {
		t.Fatal("zombie CPUStealPressure tainted the worker")
	}

	// A fresh heartbeat on the same latch (same fleet, ample
	// headroom) taints as usual.
	w1.Status.Conditions[1].LastHeartbeatTime = metav1.NewTime(time.Now())
	if _, err := cs.CoreV1().Nodes().UpdateStatus(ctx, w1, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if res := probetest.MustCheck[*cpuStealTaintSyncCheck](t, p).Run(ctx); res.Pass {
		t.Fatalf("fresh steal latch must fail the check: %+v", res)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kube.TaintCPUSteal) {
		t.Fatal("fresh CPUStealPressure did not taint the worker")
	}
}

// stealHealthyWorkers — the headroom counter on a zero-value check —
// counts only Ready+schedulable+steal-untainted workers outside the
// exclude set and the control plane; a live CPUStealPressure is not
// headroom but a frozen-heartbeat zombie is, and a node already
// bearing the steal taint never counts (its taint was earned).
func TestStealHealthyWorkersCountsHeadroom(t *testing.T) {
	now := time.Now()

	live := stealNode("live", corev1.ConditionTrue, 10*time.Minute) // pressured, live heartbeat → excluded
	// Same pressure but a frozen heartbeat — zombie, counts as headroom.
	zombie := stealNode("zombie", corev1.ConditionTrue, 10*time.Minute)
	for i, c := range zombie.Status.Conditions {
		if c.Type == cpuStealCond {
			zombie.Status.Conditions[i].LastHeartbeatTime =
				metav1.NewTime(now.Add(-nodeHangCondHeartbeatMaxAge - time.Minute))
		}
	}
	// A false-pressure condition also counts.
	falseCond := stealNode("falsecond", corev1.ConditionFalse, time.Minute)

	alreadyTainted := testutil.Node("tainted", corev1.ConditionTrue, nil,
		corev1.Taint{Key: kube.TaintCPUSteal, Effect: corev1.TaintEffectNoSchedule})
	unschedulable := testutil.Node("cordoned", corev1.ConditionTrue, nil)
	unschedulable.Spec.Unschedulable = true
	notReady := testutil.Node("notready", corev1.ConditionFalse, nil)
	cp := testutil.Node("cp", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/control-plane": ""})

	nodes := []corev1.Node{*live, *zombie, *falseCond, *alreadyTainted,
		*unschedulable, *notReady, *cp}

	// Zero-value receiver: only pure helpers, no Deps needed.
	p := &cpuStealTaintSyncCheck{}
	if got := p.stealHealthyWorkers(nodes, "", now); got != 2 {
		t.Fatalf("stealHealthyWorkers = %d, want 2 (zombie+falsecond)", got)
	}
	if got := p.stealHealthyWorkers(nodes, "zombie", now); got != 1 {
		t.Fatalf("exclude=zombie: got %d, want 1", got)
	}
	if got := p.stealHealthyWorkers(nodes, "falsecond", now); got != 1 {
		t.Fatalf("exclude=falsecond: got %d, want 1", got)
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

// A worker whose breaker already opened defers its taint: the check
// still FAILs (the pressure is present and that stays visible), but
// no taint lands this sweep — and never an error.
func TestCPUStealTaintDefersUnderOpenCircuit(t *testing.T) {
	w1 := stealNode("w1", corev1.ConditionTrue, 10*time.Minute)
	w2 := testutil.Node("w2", corev1.ConditionTrue, nil)
	w3 := testutil.Node("w3", corev1.ConditionTrue, nil)
	cs := fake.NewSimpleClientset(w1, w2, w3)
	now := time.Now()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	for range 3 {
		heal.TryAcquireTarget(CheckNameCPUStealTaintSync, "w1", now)
	}
	res := probetest.MustCheck[*cpuStealTaintSyncCheck](t, testProber(cs)).Run(ctx)
	if res.Pass {
		t.Fatalf("sustained steal pressure must still fail: %+v", res)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kube.TaintCPUSteal) {
		t.Fatal("taint applied while the target circuit is open")
	}
}

// Both taint patches must invalidate ONLY the node census: a
// sweep-wide InvalidateSweep here wiped the pod/... caches a node
// taint cannot stale, re-listing the whole snapshot for every later
// check — and the armed direct-CS re-read must carry the patch.
func TestCPUStealPatchInvalidatesNodesOnly(t *testing.T) {
	t.Run("taint", func(t *testing.T) {
		w1 := stealNode("w1", corev1.ConditionTrue, 10*time.Minute)
		w2 := testutil.Node("w2", corev1.ConditionTrue, nil)
		w3 := testutil.Node("w3", corev1.ConditionTrue, nil)
		cs := fake.NewSimpleClientset(w1, w2, w3,
			probetest.PendingUnscheduledPod("apps", "witness", time.Minute, true))
		var podLists, nodeLists int
		cs.PrependReactor("list", "pods",
			func(ktesting.Action) (bool, runtime.Object, error) {
				podLists++
				return false, nil, nil
			})
		cs.PrependReactor("list", "nodes",
			func(ktesting.Action) (bool, runtime.Object, error) {
				nodeLists++
				return false, nil, nil
			})
		p := testProber(cs)
		chk := probetest.MustCheck[*cpuStealTaintSyncCheck](t, p)
		sweepCtx := probefw.WithSweepSnapshot(ctx)
		if _, err := chk.AllPods(sweepCtx); err != nil {
			t.Fatal(err)
		}
		if _, err := chk.AllNodes(sweepCtx); err != nil {
			t.Fatal(err)
		}
		if podLists != 1 || nodeLists != 1 {
			t.Fatalf("warm-up lists pods=%d nodes=%d, want 1/1", podLists, nodeLists)
		}
		if res := chk.Run(sweepCtx); res.Pass {
			t.Fatalf("sustained steal pressure must fail: %+v", res)
		}
		// The taint landed; re-reading the pod census must hit the
		// memoized snapshot — a sweep-wide wipe would re-LIST here.
		if _, err := chk.AllPods(sweepCtx); err != nil {
			t.Fatal(err)
		}
		if podLists != 1 {
			t.Fatalf("taint re-listed pods %d time(s) — sweep-wide wipe, want 0", podLists-1)
		}
		fresh, err := chk.AllNodes(sweepCtx)
		if err != nil {
			t.Fatal(err)
		}
		if nodeLists != 2 {
			t.Fatalf("node census reads=%d, want 2 (memo + one armed re-read)", nodeLists)
		}
		for i := range fresh {
			if fresh[i].Name == "w1" && !kube.HasTaint(fresh[i].Spec.Taints, kube.TaintCPUSteal) {
				t.Fatal("post-patch census carries the pre-taint copy")
			}
		}
	})
	t.Run("untaint", func(t *testing.T) {
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
		cs := fake.NewSimpleClientset(w1,
			probetest.PendingUnscheduledPod("apps", "witness", time.Minute, true))
		var podLists, nodeLists int
		cs.PrependReactor("list", "pods",
			func(ktesting.Action) (bool, runtime.Object, error) {
				podLists++
				return false, nil, nil
			})
		cs.PrependReactor("list", "nodes",
			func(ktesting.Action) (bool, runtime.Object, error) {
				nodeLists++
				return false, nil, nil
			})
		p := testProber(cs)
		chk := probetest.MustCheck[*cpuStealTaintSyncCheck](t, p)
		sweepCtx := probefw.WithSweepSnapshot(ctx)
		if _, err := chk.AllPods(sweepCtx); err != nil {
			t.Fatal(err)
		}
		if _, err := chk.AllNodes(sweepCtx); err != nil {
			t.Fatal(err)
		}
		if podLists != 1 || nodeLists != 1 {
			t.Fatalf("warm-up lists pods=%d nodes=%d, want 1/1", podLists, nodeLists)
		}
		if res := chk.Run(sweepCtx); !res.Pass {
			t.Fatalf("cleared pressure should pass: %+v", res)
		}
		// The untaint landed; re-reading the pod census must hit the
		// memoized snapshot — a sweep-wide wipe would re-LIST here.
		if _, err := chk.AllPods(sweepCtx); err != nil {
			t.Fatal(err)
		}
		if podLists != 1 {
			t.Fatalf("untaint re-listed pods %d time(s) — sweep-wide wipe, want 0", podLists-1)
		}
		fresh, err := chk.AllNodes(sweepCtx)
		if err != nil {
			t.Fatal(err)
		}
		if nodeLists != 2 {
			t.Fatalf("node census reads=%d, want 2 (memo + one armed re-read)", nodeLists)
		}
		for i := range fresh {
			if fresh[i].Name == "w1" && kube.HasTaint(fresh[i].Spec.Taints, kube.TaintCPUSteal) {
				t.Fatal("post-patch census carries the pre-untaint copy")
			}
		}
	})
}

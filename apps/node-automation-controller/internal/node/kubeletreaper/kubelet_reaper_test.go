package kubeletreaper

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// kubeletDeadTaint is the NoSchedule taint the reaper applies.
var kubeletDeadTaint = corev1.Taint{
	Key:    kubeletReaperTaint,
	Value:  "true",
	Effect: corev1.TaintEffectNoSchedule,
}

// kubeletWorker builds a Ready worker node whose Ready-condition
// heartbeat is hbAge old. hbAge < 0 leaves the zero timestamp, which
// the sweep treats as stale (time.Since(zero) >> HB_STALE_S).
func kubeletWorker(name string, hbAge time.Duration, taints ...corev1.Taint) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil, taints...)
	if hbAge >= 0 {
		n.Status.Conditions[0].LastHeartbeatTime = metav1.NewTime(time.Now().Add(-hbAge))
	}
	return n
}

// ---------------------------------------------------------------------------
// sweep() — pure per-node taint decision (no probe needed)
// ---------------------------------------------------------------------------

func TestKubeletReaperSweep(t *testing.T) {
	t.Run("probe ok clears existing taint", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 0, kubeletDeadTaint))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0, kubeletDeadTaint), true); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("taint kept though kubelet :10250 answers")
		}
	})

	t.Run("probe ok without taint is a no-op", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 0))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), true); err != nil {
			t.Fatal(err)
		}
		if len(testutil.GetNode(t, cs, "w1").Spec.Taints) != 0 {
			t.Fatal("unexpected taint on a healthy node")
		}
	})

	t.Run("probe fail + stale heartbeat taints", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 300*time.Second))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("dead kubelet (heartbeat 300s old) not tainted")
		}
	})

	t.Run("probe fail + missing heartbeat timestamp taints", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", -1)) // zero LastHeartbeatTime
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("missing heartbeat timestamp not tainted")
		}
	})

	t.Run("probe fail + no Ready condition taints", func(t *testing.T) {
		n := kubeletWorker("w1", 0)
		n.Status.Conditions = nil
		cs := fake.NewSimpleClientset(n)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("absent Ready condition not tainted")
		}
	})

	t.Run("probe fail + fresh heartbeat keeps untainted", func(t *testing.T) {
		// Fresh heartbeat + dead :10250 = broken proxy path, not a
		// dead kubelet — tainting here caused a mass-eviction once.
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 10*time.Second))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("tainted despite fresh heartbeat")
		}
	})

	t.Run("probe fail + future-dated heartbeat keeps untainted", func(t *testing.T) {
		// Clock skew: a heartbeat timestamped in the FUTURE (age < 0)
		// is still proof the kubelet posted status — never stale.
		future := kubeletWorker("w1", 0)
		future.Status.Conditions[0].LastHeartbeatTime =
			metav1.NewTime(time.Now().Add(time.Hour))
		cs := fake.NewSimpleClientset(future)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("tainted on a future-dated (skewed) heartbeat — clock skew is not staleness")
		}
	})

	t.Run("probe fail + future-dated heartbeat clears taint", func(t *testing.T) {
		// Same skew while already tainted: the fresh path removes it.
		future := kubeletWorker("w1", 0, kubeletDeadTaint)
		future.Status.Conditions[0].LastHeartbeatTime =
			metav1.NewTime(time.Now().Add(time.Hour))
		cs := fake.NewSimpleClientset(future)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("taint kept though the skewed heartbeat is fresh")
		}
	})

	t.Run("probe fail + fresh heartbeat clears taint", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 10*time.Second, kubeletDeadTaint))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("taint kept though heartbeat is fresh")
		}
	})

	t.Run("probe fail + already tainted + stale heartbeat keeps taint", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 300*time.Second, kubeletDeadTaint))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("taint dropped though kubelet is still dead")
		}
	})

	t.Run("sweep on a missing node errors", func(t *testing.T) {
		r := &kubeletReaper{cs: fake.NewSimpleClientset()}
		// Probe-failed path: the fresh Get is where a vanished node
		// is noticed (the ok+untainted fast path never touches the
		// API — the listed object WAS the read).
		if err := r.sweep(ctx, kubeletWorker("ghost", 0), false); err == nil {
			t.Fatal("expected error for a missing node")
		}
	})
}

// ---------------------------------------------------------------------------
// sweep() — API-call discipline: the listed object is the only read a
// healthy untainted node ever needs; the fresh Get is probe-fail only.
// ---------------------------------------------------------------------------

// nodeGetCount returns a reactor (and its reader) that counts get/nodes
// calls while letting them fall through to the object tracker.
func nodeGetCount(cs *fake.Clientset) func() int {
	var n int32
	cs.PrependReactor("get", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			atomic.AddInt32(&n, 1)
			return false, nil, nil
		})
	return func() int { return int(atomic.LoadInt32(&n)) }
}

func TestKubeletReaperSweepGetCalls(t *testing.T) {
	t.Run("probe ok + no listed taint touches the API zero times", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 0))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), true); err != nil {
			t.Fatal(err)
		}
		if actions := cs.Actions(); len(actions) != 0 {
			t.Fatalf("healthy untainted sweep made %d API calls, want 0: %v",
				len(actions), actions)
		}
	})

	t.Run("probe ok + listed taint untaints via ONE get inside kube.UntaintNode", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 0, kubeletDeadTaint))
		gets := nodeGetCount(cs)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0, kubeletDeadTaint), true); err != nil {
			t.Fatal(err)
		}
		// Read the count before testutil.GetNode() below — the assertion
		// helper's own Get would inflate it.
		if gets() != 1 {
			t.Fatalf("node gets = %d, want exactly 1 (kube.UntaintNode's own re-read)", gets())
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("listed taint not removed on a healthy probe")
		}
	})

	t.Run("probe ok + stale listed taint on a clean node is a safe no-op", func(t *testing.T) {
		// The listed snapshot still shows our taint but the stored
		// node lost it — kube.UntaintNode's internal re-Get must see the
		// fresh truth and patch nothing.
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 0))
		var patches int32
		cs.PrependReactor("patch", "nodes",
			func(ktesting.Action) (bool, runtime.Object, error) {
				atomic.AddInt32(&patches, 1)
				return false, nil, nil
			})
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0, kubeletDeadTaint), true); err != nil {
			t.Fatal(err)
		}
		if n := atomic.LoadInt32(&patches); n != 0 {
			t.Fatalf("stale listed taint produced %d patches, want 0", n)
		}
	})

	t.Run("probe fail ALWAYS re-gets — listed freshness is not trusted", func(t *testing.T) {
		// Listed shows a fresh heartbeat; the stored (fresher-read)
		// node is stale — only the re-Get can produce the taint.
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 300*time.Second))
		gets := nodeGetCount(cs)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err != nil {
			t.Fatal(err)
		}
		if gets() == 0 {
			t.Fatal("probe-failed sweep decided without a fresh node read")
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("stale stored heartbeat not tainted — listed copy won?")
		}
	})
}

// ---------------------------------------------------------------------------
// run() — probe fan-out, broken-probe-path abort, control-plane skip
// ---------------------------------------------------------------------------

func TestKubeletReaperRun(t *testing.T) {
	t.Run("all probes fail -> aborts without touching taints", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			kubeletWorker("w1", 300*time.Second),
			kubeletWorker("w2", -1))
		r := &kubeletReaper{
			cs:      cs,
			probeFn: func(context.Context, string) bool { return false },
		}
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
		// Zero successes means the probe path itself is broken —
		// no decision may be applied even though both heartbeats
		// look stale.
		for _, name := range []string{"w1", "w2"} {
			if kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, kubeletReaperTaint) {
				t.Fatalf("node %s tainted during probe-path abort", name)
			}
		}
	})

	t.Run("mixed results taint only the dead node", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			kubeletWorker("w1", 300*time.Second), // stale hb but probe ok
			kubeletWorker("w2", 300*time.Second)) // probe fail + stale hb
		r := &kubeletReaper{
			cs: cs,
			probeFn: func(_ context.Context, name string) bool {
				return name == "w1"
			},
		}
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("w1 tainted though its probe passed")
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w2").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("w2 not tainted — probe failed with a stale heartbeat")
		}
	})

	t.Run("control plane is never probed nor tainted", func(t *testing.T) {
		cp := kubeletWorker("cp1", -1)
		cp.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
		cs := fake.NewSimpleClientset(cp, kubeletWorker("w1", 10*time.Second))

		// probeFn would fail for cp1 — k0s control planes run no
		// kubelet — so it must never be called for it.
		var mu sync.Mutex
		probed := map[string]bool{}
		r := &kubeletReaper{
			cs: cs,
			probeFn: func(_ context.Context, name string) bool {
				mu.Lock()
				probed[name] = true
				mu.Unlock()
				return name == "w1"
			},
		}
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
		if probed["cp1"] {
			t.Fatal("control-plane node was probed")
		}
		if !probed["w1"] {
			t.Fatal("worker node was not probed")
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "cp1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("control-plane node tainted")
		}
	})

	t.Run("recovered node gets untainted in the same pass", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			kubeletWorker("w1", 10*time.Second, kubeletDeadTaint),
			kubeletWorker("w2", 10*time.Second))
		r := &kubeletReaper{
			cs:      cs,
			probeFn: func(context.Context, string) bool { return true },
		}
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("recovered node still tainted")
		}
	})

	t.Run("node list error aborts the run", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("list", "nodes",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("api down")
			})
		r := &kubeletReaper{
			cs:      cs,
			probeFn: func(context.Context, string) bool { return true },
		}
		if err := r.run(ctx); err == nil {
			t.Fatal("expected error when the node list fails")
		}
	})

	t.Run("per-node sweep failure is logged, not fatal", func(t *testing.T) {
		// w1 is listed (and probe-FAILED, so sweep re-Gets) but
		// vanishes before the fresh read — the bash loop continued
		// to the next node on any per-node failure, so run must
		// return nil. w2's probe succeeds so the all-fail abort
		// guard stays out of the way.
		cs := fake.NewSimpleClientset(
			kubeletWorker("w1", 10*time.Second),
			kubeletWorker("w2", 10*time.Second))
		cs.PrependReactor("get", "nodes",
			func(a ktesting.Action) (bool, runtime.Object, error) {
				if a.(ktesting.GetAction).GetName() == "w1" {
					return true, nil, errors.New("node vanished")
				}
				return false, nil, nil
			})
		r := &kubeletReaper{
			cs:      cs,
			queue:   "kubelet-liveness-reaper",
			probeFn: func(_ context.Context, name string) bool { return name == "w2" },
		}
		before := testutil.QueueErrorCount(t, "kubelet-liveness-reaper")
		if err := r.run(ctx); err != nil {
			t.Fatalf("per-node sweep failure must not fail the run: %v", err)
		}
		// The failure was absorbed (nil return) but must still be
		// metered — an uncounted skip is invisible to alerting.
		if got := testutil.QueueErrorCount(t, "kubelet-liveness-reaper") - before; got != 1 {
			t.Fatalf("absorbed sweep failure not IncError'd, delta %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// sweep() — patch-failure paths through kube.UntaintNode/kube.TaintNode
// ---------------------------------------------------------------------------

func TestKubeletReaperSweepPatchErrors(t *testing.T) {
	failPatch := func(cs *fake.Clientset) {
		cs.PrependReactor("patch", "nodes",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("patch rejected")
			})
	}

	t.Run("probe ok + untaint patch fails", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 0, kubeletDeadTaint))
		failPatch(cs)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0, kubeletDeadTaint), true); err == nil {
			t.Fatal("expected error when the untaint patch fails")
		}
	})

	t.Run("stale heartbeat + taint patch fails", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 300*time.Second))
		failPatch(cs)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err == nil {
			t.Fatal("expected error when the taint patch fails")
		}
	})

	t.Run("fresh heartbeat + untaint patch fails", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 10*time.Second, kubeletDeadTaint))
		failPatch(cs)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, kubeletWorker("w1", 0), false); err == nil {
			t.Fatal("expected error when the recovery untaint fails")
		}
	})
}

package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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
	n := node(name, corev1.ConditionTrue, nil, taints...)
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
		if err := r.sweep(ctx, "w1", true); err != nil {
			t.Fatal(err)
		}
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("taint kept though kubelet :10250 answers")
		}
	})

	t.Run("probe ok without taint is a no-op", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 0))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, "w1", true); err != nil {
			t.Fatal(err)
		}
		if len(getNode(t, cs, "w1").Spec.Taints) != 0 {
			t.Fatal("unexpected taint on a healthy node")
		}
	})

	t.Run("probe fail + stale heartbeat taints", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 300*time.Second))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, "w1", false); err != nil {
			t.Fatal(err)
		}
		if !hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("dead kubelet (heartbeat 300s old) not tainted")
		}
	})

	t.Run("probe fail + missing heartbeat timestamp taints", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", -1)) // zero LastHeartbeatTime
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, "w1", false); err != nil {
			t.Fatal(err)
		}
		if !hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("missing heartbeat timestamp not tainted")
		}
	})

	t.Run("probe fail + no Ready condition taints", func(t *testing.T) {
		n := kubeletWorker("w1", 0)
		n.Status.Conditions = nil
		cs := fake.NewSimpleClientset(n)
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, "w1", false); err != nil {
			t.Fatal(err)
		}
		if !hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("absent Ready condition not tainted")
		}
	})

	t.Run("probe fail + fresh heartbeat keeps untainted", func(t *testing.T) {
		// Fresh heartbeat + dead :10250 = broken proxy path, not a
		// dead kubelet — tainting here caused a mass-eviction once.
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 10*time.Second))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, "w1", false); err != nil {
			t.Fatal(err)
		}
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("tainted despite fresh heartbeat")
		}
	})

	t.Run("probe fail + fresh heartbeat clears taint", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 10*time.Second, kubeletDeadTaint))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, "w1", false); err != nil {
			t.Fatal(err)
		}
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("taint kept though heartbeat is fresh")
		}
	})

	t.Run("probe fail + already tainted + stale heartbeat keeps taint", func(t *testing.T) {
		cs := fake.NewSimpleClientset(kubeletWorker("w1", 300*time.Second, kubeletDeadTaint))
		r := &kubeletReaper{cs: cs}
		if err := r.sweep(ctx, "w1", false); err != nil {
			t.Fatal(err)
		}
		if !hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("taint dropped though kubelet is still dead")
		}
	})

	t.Run("sweep on a missing node errors", func(t *testing.T) {
		r := &kubeletReaper{cs: fake.NewSimpleClientset()}
		if err := r.sweep(ctx, "ghost", true); err == nil {
			t.Fatal("expected error for a missing node")
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
			if hasTaint(getNode(t, cs, name).Spec.Taints, kubeletReaperTaint) {
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
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("w1 tainted though its probe passed")
		}
		if !hasTaint(getNode(t, cs, "w2").Spec.Taints, kubeletReaperTaint) {
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
		if hasTaint(getNode(t, cs, "cp1").Spec.Taints, kubeletReaperTaint) {
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
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
			t.Fatal("recovered node still tainted")
		}
	})
}

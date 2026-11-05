// node_hang_precordon_test.go — coverage for the
// node-hang-precordon check (W8-ST2/W9-CP3/W10-KR6): cordon
// stamping, auto-uncordon, foreign-cordon safety, clock-skew fuse,
// and the expanded latch set.
package clusterhealthprobes

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// W8-ST2 — a hung worker gets spec.unschedulable patched; an already-
// cordoned worker is left alone.
func TestCheckNodeHangPreCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		readyWorkerNode("w-hang", "KernelHungTasks", 5*time.Minute, false),
		readyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*nodeHangCheck](t, p).run(ctx); res.pass {
		t.Fatal("hung node did not fail the check")
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, "w-hang", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Spec.Unschedulable {
		t.Fatal("hung node not cordoned")
	}
	n2, err := cs.CoreV1().Nodes().Get(ctx, "w-ok", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n2.Spec.Unschedulable {
		t.Fatal("healthy node cordoned")
	}
}

// W8-ST2 — a latch that is too fresh does not trigger the cordon.
func TestCheckNodeHangPreCordonTooFresh(t *testing.T) {
	cs := fake.NewSimpleClientset(
		readyWorkerNode("w1", "FilesystemReadOnly", time.Minute, false),
		readyWorkerNode("w2", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*nodeHangCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("fresh latch failed the check: %+v", res)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "w1", metav1.GetOptions{})
	if n.Spec.Unschedulable {
		t.Fatal("fresh-latch node cordoned too early")
	}
}

// ---------------------------------------------------------------------------
// W8-ST2 — pre-cordon annotation + auto-uncordon (W9 additions)
// ---------------------------------------------------------------------------

// A sustained hang latch cordons AND stamps the node so the
// auto-uncordon path can tell our cordon from a deliberate one.
func TestCheckNodeHangPreCordonStampsAnnotation(t *testing.T) {
	cs := fake.NewSimpleClientset(
		readyWorkerNode("w-hang", "KernelHungTasks", 5*time.Minute, false),
		readyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*nodeHangCheck](t, p).run(ctx); res.pass {
		t.Fatal("hung node did not fail the check")
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, "w-hang", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Spec.Unschedulable {
		t.Fatal("hung node not cordoned")
	}
	if got := n.Annotations[nodeHangPreCordonAnno]; got != nodeHangPreCordonValue {
		t.Fatalf("pre-cordon stamp = %q, want %q", got, nodeHangPreCordonValue)
	}
}

// A stamped cordon lifts itself once every latch cleared — the
// transient-recovery / post-SNR-reboot shape.
func TestCheckNodeHangAutoUncordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		precordonedWorkerNode("w-recover", true),
		readyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*nodeHangCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("cleared node must pass: %+v", res)
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, "w-recover", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n.Spec.Unschedulable {
		t.Fatal("cleared node still cordoned")
	}
	if _, ok := n.Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("pre-cordon stamp not removed on uncordon")
	}
	m := findMetric(t, "node_automation_node_hang_uncordons_total",
		map[string]string{"node": "w-recover"})
	if m == nil || m.GetCounter().GetValue() != 1 {
		t.Fatalf("uncordons_total=%v, want 1", m)
	}
}

// An unstamped cordon is never ours — kubectl cordon / NHC fencing
// must survive the sweep untouched.
func TestCheckNodeHangLeavesForeignCordon(t *testing.T) {
	foreign := readyWorkerNode("w-manual", "", 0, true) // unschedulable, no stamp
	cs := fake.NewSimpleClientset(foreign, readyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*nodeHangCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("no latch must pass: %+v", res)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "w-manual", metav1.GetOptions{})
	if !n.Spec.Unschedulable {
		t.Fatal("foreign cordon lifted by the auto-uncordon")
	}
}

// A latch that is True but still inside its cordon fuse keeps the
// pre-cordon — "active" for the uncordon guard is status, not age.
func TestCheckNodeHangUncordonBlockedByFreshLatch(t *testing.T) {
	n := readyWorkerNode("w-fresh", "FilesystemReadOnly", 30*time.Second, true)
	n.Annotations = map[string]string{
		nodeHangPreCordonAnno: nodeHangPreCordonValue,
	}
	cs := fake.NewSimpleClientset(n, readyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*nodeHangCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("fresh latch must not fail the check: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-fresh", metav1.GetOptions{})
	if !got.Spec.Unschedulable {
		t.Fatal("node uncordoned while a latch is still True")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; !ok {
		t.Fatal("pre-cordon stamp removed while latch active")
	}
}

// A stamp left on a schedulable node (manual `kubectl uncordon`) is
// cleaned so a later deliberate cordon cannot inherit the
// auto-uncordon.
func TestCheckNodeHangStaleStampCleanup(t *testing.T) {
	n := precordonedWorkerNode("w-stale", false) // schedulable but still stamped
	cs := fake.NewSimpleClientset(n, readyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*nodeHangCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("stale stamp must pass: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-stale", metav1.GetOptions{})
	if got.Spec.Unschedulable {
		t.Fatal("schedulable node cordoned by stamp cleanup")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("stale pre-cordon stamp not removed")
	}
}

// ---------------------------------------------------------------------------
// W9-CP3 — ClockUnsynchronized pre-cordon
// ---------------------------------------------------------------------------

// ClockUnsynchronized past the 10m fuse cordons with the same stamp;
// inside the fuse the NTP daemon gets its resync window.
func TestCheckNodeHangClockSkewCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		readyWorkerNode("w-skew", nodeClockSkewCond, 15*time.Minute, false),
		readyWorkerNode("w-skew-fresh", nodeClockSkewCond, 5*time.Minute, false),
		readyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*nodeHangCheck](t, p).run(ctx); res.pass {
		t.Fatal("sustained clock skew did not fail the check")
	}
	old, _ := cs.CoreV1().Nodes().Get(ctx, "w-skew", metav1.GetOptions{})
	if !old.Spec.Unschedulable ||
		old.Annotations[nodeHangPreCordonAnno] != nodeHangPreCordonValue {
		t.Fatal("sustained ClockUnsynchronized not cordoned+stamped")
	}
	fresh, _ := cs.CoreV1().Nodes().Get(ctx, "w-skew-fresh", metav1.GetOptions{})
	if fresh.Spec.Unschedulable {
		t.Fatal("fresh ClockUnsynchronized cordoned inside the NTP resync window")
	}
}

// ---------------------------------------------------------------------------
// W10-KR6 — nodeHangConds expansion
// ---------------------------------------------------------------------------

// Every Wave-10 latch in nodeHangConds cordons a worker once True for
// >= nodeHangCondMinAge — same fuse as the original two.
func TestNodeHangPreCordonNewLatches(t *testing.T) {
	for i, cond := range []corev1.NodeConditionType{
		"KubeletRuntimeStall", "KubeletWatchWedge",
		"PodTeardownWedged", "InodePressure",
	} {
		name := "w-" + string(rune('a'+i))
		cs := fake.NewSimpleClientset(
			readyWorkerNode(name, cond, 5*time.Minute, false),
			readyWorkerNode("w-ok-"+string(rune('a'+i)), "", 0, false))
		p := testProberDyn(cs, shOpDyn())
		if res := mustCheck[*nodeHangCheck](t, p).run(ctx); res.pass {
			t.Fatalf("%s latch did not fail the check", cond)
		}
		n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !n.Spec.Unschedulable {
			t.Fatalf("%s node not cordoned", cond)
		}
		if got := n.Annotations[nodeHangPreCordonAnno]; got != nodeHangPreCordonValue {
			t.Fatalf("%s cordon missing pre-cordon stamp: %q", cond, got)
		}
	}
}

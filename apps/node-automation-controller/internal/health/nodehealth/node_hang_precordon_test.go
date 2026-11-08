// node_hang_precordon_test.go — coverage for the
// node-hang-precordon check (W8-ST2/W9-CP3/W10-KR6): cordon
// stamping, auto-uncordon, foreign-cordon safety, clock-skew fuse,
// and the expanded latch set.
package nodehealth

import (
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// W8-ST2 — a hung worker gets spec.unschedulable patched; an already-
// cordoned worker is left alone.
func TestCheckNodeHangPreCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-hang", "KernelHungTasks", 5*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
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
		probetest.ReadyWorkerNode("w1", "FilesystemReadOnly", time.Minute, false),
		probetest.ReadyWorkerNode("w2", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
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
		probetest.ReadyWorkerNode("w-hang", "KernelHungTasks", 5*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
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
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
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
	m := probetest.FindMetric(t, "node_automation_node_hang_uncordons_total",
		map[string]string{"node": "w-recover"})
	if m == nil || m.GetCounter().GetValue() != 1 {
		t.Fatalf("uncordons_total=%v, want 1", m)
	}
}

// An unstamped cordon is never ours — kubectl cordon / NHC fencing
// must survive the sweep untouched.
func TestCheckNodeHangLeavesForeignCordon(t *testing.T) {
	foreign := probetest.ReadyWorkerNode("w-manual", "", 0, true) // unschedulable, no stamp
	cs := fake.NewSimpleClientset(foreign, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
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
	n := probetest.ReadyWorkerNode("w-fresh", "FilesystemReadOnly", 30*time.Second, true)
	n.Annotations = map[string]string{
		nodeHangPreCordonAnno: nodeHangPreCordonValue,
	}
	cs := fake.NewSimpleClientset(n, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
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
	cs := fake.NewSimpleClientset(n, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
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
		probetest.ReadyWorkerNode("w-skew", "ClockUnsynchronized", 15*time.Minute, false),
		probetest.ReadyWorkerNode("w-skew-fresh", "ClockUnsynchronized", 5*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
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

// W12-1.4 — ClockSkewDetected (chrony synced but >2s offset) rides
// the same 10m clock fuse as ClockUnsynchronized.
func TestCheckNodeHangClockSkewDetectedCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-skew2", "ClockSkewDetected", 15*time.Minute, false),
		probetest.ReadyWorkerNode("w-skew2-fresh", "ClockSkewDetected", 5*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("sustained ClockSkewDetected did not fail the check")
	}
	old, _ := cs.CoreV1().Nodes().Get(ctx, "w-skew2", metav1.GetOptions{})
	if !old.Spec.Unschedulable ||
		old.Annotations[nodeHangPreCordonAnno] != nodeHangPreCordonValue {
		t.Fatal("sustained ClockSkewDetected not cordoned+stamped")
	}
	fresh, _ := cs.CoreV1().Nodes().Get(ctx, "w-skew2-fresh", metav1.GetOptions{})
	if fresh.Spec.Unschedulable {
		t.Fatal("fresh ClockSkewDetected cordoned inside the resync window")
	}
}

// ---------------------------------------------------------------------------
// nodeHangConds coverage
// ---------------------------------------------------------------------------

// Every latch in nodeHangConds cordons a worker once True for
// >= nodeHangCondMinAge — same fuse as the original two.
func TestNodeHangPreCordonNewLatches(t *testing.T) {
	for i, cond := range nodeHangConds {
		name := "w-" + string(rune('a'+i))
		cs := fake.NewSimpleClientset(
			probetest.ReadyWorkerNode(name, cond, 5*time.Minute, false),
			probetest.ReadyWorkerNode("w-ok-"+string(rune('a'+i)), "", 0, false))
		p := testProberDyn(cs, probetest.OpDyn())
		if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
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

// ---------------------------------------------------------------------------
// InodePressure split (plan Component 2)
// ---------------------------------------------------------------------------

// InodePressure is kubelet-native but stays in the precordon set
// (nodecond.HangPreCordonNames) — a sustained inode storm starves the
// node like any other latch. The condition-SWEEPER is the one gate
// that must never touch it: kubelet conditions are outside
// nodecond.HeartbeatSweptNames (see node_condition_sweeper_test.go).
func TestNodeHangPreCordonInodePressureNotSwept(t *testing.T) {
	found := false
	for _, c := range nodeHangConds {
		if c == "InodePressure" {
			found = true
		}
	}
	if !found {
		t.Fatal("InodePressure left the precordon set")
	}
	for _, c := range nodeCondSweptConds {
		if c == "InodePressure" {
			t.Fatal("InodePressure must not be swept — kubelet-owned")
		}
	}
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-inode", "InodePressure", 5*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("sustained InodePressure did not fail the check")
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, "w-inode", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Spec.Unschedulable ||
		n.Annotations[nodeHangPreCordonAnno] != nodeHangPreCordonValue {
		t.Fatal("sustained InodePressure not cordoned+stamped")
	}
}

// ---------------------------------------------------------------------------
// Stale-heartbeat gate (2026-11-06 zombie-latch outage)
// ---------------------------------------------------------------------------

// A fused latch whose lastHeartbeatTime froze — the reporter may be
// dead and the True value a zombie — is NOT cordon evidence. This is
// the 2026-11-06 fleet shape: wedged node-host-agents left a
// ~70m-old KubeletPLEGUnhealthy latch live and precordoned half the
// workers.
func TestCheckNodeHangIgnoresStaleHeartbeat(t *testing.T) {
	stale := probetest.ReadyWorkerNode("w-zombie", "KubeletPLEGUnhealthy", 30*time.Minute, false)
	stale.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeHangCondHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(stale, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("stale-heartbeat latch must not fail the check: %+v", res)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "w-zombie", metav1.GetOptions{})
	if n.Spec.Unschedulable {
		t.Fatal("zombie latch cordoned the node")
	}
}

// A latch with NO heartbeat at all is equally unproven — refused.
func TestCheckNodeHangIgnoresMissingHeartbeat(t *testing.T) {
	noHB := probetest.ReadyWorkerNode("w-nohb", "KernelHungTasks", 5*time.Minute, false)
	noHB.Status.Conditions[1].LastHeartbeatTime = metav1.Time{}
	cs := fake.NewSimpleClientset(noHB, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("heartbeat-less latch must not fail the check: %+v", res)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "w-nohb", metav1.GetOptions{})
	if n.Spec.Unschedulable {
		t.Fatal("heartbeat-less latch cordoned the node")
	}
}

// A stale latch on a second condition does not shield a live one —
// the fresh latch still cordons.
func TestCheckNodeHangStaleLatchDoesNotShieldLiveLatch(t *testing.T) {
	n := probetest.ReadyWorkerNode("w-mixed", "KernelHungTasks", 30*time.Minute, false)
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeHangCondHeartbeatMaxAge - time.Minute))
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               "FilesystemReadOnly",
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-5 * time.Minute)),
		LastHeartbeatTime:  metav1.NewTime(time.Now()),
	})
	cs := fake.NewSimpleClientset(n, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("a live latch beside a stale one must still fail the check")
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-mixed", metav1.GetOptions{})
	if !got.Spec.Unschedulable {
		t.Fatal("live latch not cordoned beside a stale one")
	}
}

// A stamped cordon stays cordoned while the latch is still True —
// even a frozen heartbeat: a dead reporter can't prove recovery, so
// the stale gate must not accidentally auto-uncordon.
func TestCheckNodeHangStaleLatchHoldsPreCordon(t *testing.T) {
	n := precordonedWorkerNode("w-held", true)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               "KubeletPLEGUnhealthy",
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
		LastHeartbeatTime:  metav1.NewTime(time.Now().Add(-nodeHangCondHeartbeatMaxAge - time.Minute)),
	})
	cs := fake.NewSimpleClientset(n, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("stale latch is a warning, not a check failure: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-held", metav1.GetOptions{})
	if !got.Spec.Unschedulable {
		t.Fatal("stale latch auto-uncordoned a possibly-hung node")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; !ok {
		t.Fatal("pre-cordon stamp removed while latch still True")
	}
}

// ---------------------------------------------------------------------------
// Counter-series churn guard
// ---------------------------------------------------------------------------

// The cordon/uncordon counters must not leak {node} series on node
// churn (pool rotation): a node leaving the sweep census keeps its
// series for one sweep — a single missed list must not erase
// evidence — and loses both series on the second consecutive
// absence. Returning re-arms the absence streak.
func TestNodeHangCounterSeriesPrunedOnNodeGone(t *testing.T) {
	testutil.CleanupMetric(t, nodeHangCordonsTotal, "w-churn")
	testutil.CleanupMetric(t, nodeHangUncordonsTotal, "w-churn")

	// Sweep 1 — the sustained latch cordons w-churn: both Inc paths
	// book the node into the check's carry-forward ledger.
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-churn", "KernelHungTasks", 5*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	check := probetest.MustCheck[*nodeHangCheck](t, p)
	if res := check.Run(ctx); res.Pass {
		t.Fatal("hung node did not fail the check")
	}
	if got := ptestutil.ToFloat64(nodeHangCordonsTotal.WithLabelValues("w-churn")); got != 1 {
		t.Fatalf("cordons_total = %v, want 1", got)
	}

	// Sweep 2 — the node left the cluster: first absence, series kept.
	if err := cs.CoreV1().Nodes().Delete(ctx, "w-churn", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if res := check.Run(ctx); !res.Pass {
		t.Fatalf("node-less roster must pass: %+v", res)
	}
	if got := ptestutil.ToFloat64(nodeHangCordonsTotal.WithLabelValues("w-churn")); got != 1 {
		t.Fatalf("first absence pruned the cordon series: %v", got)
	}

	// Sweep 3 — the node object is back in its post-reboot shape
	// (stamped cordon, latch cleared): the auto-uncordon Inc's the
	// uncordon series and the sighting re-arms the streak.
	if _, err := cs.CoreV1().Nodes().Create(ctx,
		precordonedWorkerNode("w-churn", true), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if res := check.Run(ctx); !res.Pass {
		t.Fatalf("auto-uncordon sweep must pass: %+v", res)
	}
	if got := ptestutil.ToFloat64(nodeHangUncordonsTotal.WithLabelValues("w-churn")); got != 1 {
		t.Fatalf("uncordons_total = %v, want 1", got)
	}

	// Sweep 4 — gone again: first absence carries BOTH series.
	if err := cs.CoreV1().Nodes().Delete(ctx, "w-churn", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if res := check.Run(ctx); !res.Pass {
		t.Fatalf("node-less roster must pass: %+v", res)
	}
	if got := ptestutil.ToFloat64(nodeHangCordonsTotal.WithLabelValues("w-churn")); got != 1 {
		t.Fatalf("cordon series pruned on first absence: %v", got)
	}
	if got := ptestutil.ToFloat64(nodeHangUncordonsTotal.WithLabelValues("w-churn")); got != 1 {
		t.Fatalf("uncordon series pruned on first absence: %v", got)
	}

	// Sweep 5 — second consecutive absence: both series deleted. The
	// DeleteLabelValues bool is the absence proof (WithLabelValues
	// would silently re-create the series at 0); label-scoped on
	// w-churn because sibling tests share the registered vecs.
	if res := check.Run(ctx); !res.Pass {
		t.Fatalf("node-less roster must pass: %+v", res)
	}
	if nodeHangCordonsTotal.DeleteLabelValues("w-churn") {
		t.Fatal("cordon series survived two consecutive absences")
	}
	if nodeHangUncordonsTotal.DeleteLabelValues("w-churn") {
		t.Fatal("uncordon series survived two consecutive absences")
	}
}

// precordonedWorkerNode builds a worker node carrying our pre-cordon stamp —
// unschedulable with passiontech.dev/precordoned-by=node-hang-precordon and
// no active latch (the auto-uncordon shape).
func precordonedWorkerNode(name string, unschedulable bool) *corev1.Node {
	n := probetest.ReadyWorkerNode(name, "", 0, unschedulable)
	n.Annotations = map[string]string{
		nodeHangPreCordonAnno: nodeHangPreCordonValue,
	}
	return n
}

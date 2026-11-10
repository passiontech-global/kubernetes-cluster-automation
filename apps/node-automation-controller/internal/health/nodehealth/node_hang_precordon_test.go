// node_hang_precordon_test.go — coverage for the
// node-hang-precordon check (node-hang-precordon/clock-skew-precordon/kubelet-watch-wedge): cordon
// stamping, auto-uncordon, foreign-cordon safety, clock-skew fuse,
// and the expanded latch set.
package nodehealth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// node-hang-precordon — a hung worker gets spec.unschedulable patched; an already-
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

// node-hang-precordon — a latch that is too fresh does not trigger the cordon.
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
// node-hang-precordon — pre-cordon annotation + auto-uncordon (clock-skew additions)
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
// clock-skew-precordon — ClockUnsynchronized pre-cordon
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

// node-hang-extra-conds — ClockSkewDetected (chrony synced but >2s offset) rides
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

// InodePressure is agent-latched since inode-pressure (hostmetrics
// state-inode-pressure) and lives in both precordon sets — a
// sustained inode storm starves the node like any other latch
// (nodecond.HangPreCordonNames, gated on LastTransitionTime) and a
// frozen heartbeat on it is a dead reporter's zombie the
// condition-SWEEPER must reconcile (nodecond.HeartbeatSweptNames,
// see node_condition_sweeper_test.go).
func TestNodeHangPreCordonInodePressure(t *testing.T) {
	found := false
	for _, c := range nodeHangConds {
		if c == "InodePressure" {
			found = true
		}
	}
	if !found {
		t.Fatal("InodePressure left the precordon set")
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

// ---------------------------------------------------------------------------
// 35% cap — off-by-one fix (clocksource-unstable) + first-cordon exception
// ---------------------------------------------------------------------------

// Two-worker cluster: floor(0.35*2)=0, so the ratio math alone would
// block every precordon there. The FIRST cordon (cordoned == 0) is
// exempt — a hung 2-node fleet must still be precordonable — and the
// SECOND hung worker must then be capped (invariant: at most
// max(1, floor(0.35*workers)) = 1 worker cordoned after the sweep).
func TestCheckNodeHangPreCordonTwoWorkerFirstCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-a", "KernelHungTasks", 5*time.Minute, false),
		probetest.ReadyWorkerNode("w-b", "KernelHungTasks", 5*time.Minute, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("hung workers did not fail the check")
	}
	a, err := cs.CoreV1().Nodes().Get(ctx, "w-a", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Spec.Unschedulable {
		t.Fatal("first cordon in a 2-worker cluster was blocked by the ratio cap")
	}
	b, err := cs.CoreV1().Nodes().Get(ctx, "w-b", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Spec.Unschedulable {
		t.Fatal("second cordon in a 2-worker cluster exceeded the cap invariant (max 1)")
	}
}

// The off-by-one: at exactly the cap (3/10 workers already cordoned)
// the old pre-increment test (3/10 >= 0.35 is false) let a FOURTH
// cordon through, leaving 4/10 = 40% cordoned. The post-increment
// test blocks it. One below the cap (2/10) still cordons a third —
// landing exactly on max(1, floor(0.35*10)) = 3.
func TestCheckNodeHangPreCordonCapBoundary(t *testing.T) {
	// alreadyCordoned = foreign-cordoned workers; hungCordoned says
	// whether the hung worker may be precordoned: at the cap
	// (3/10) the old pre-increment test (3/10 >= 0.35 is false)
	// let a FOURTH cordon through, leaving 4/10 = 40% cordoned —
	// the post-increment test blocks it. One below the cap (2/10)
	// still cordons a third, landing exactly on
	// max(1, floor(0.35*10)) = 3.
	cases := []struct {
		alreadyCordoned int
		hungCordoned    bool
	}{
		{alreadyCordoned: 3, hungCordoned: false},
		{alreadyCordoned: 2, hungCordoned: true},
	}
	for _, tc := range cases {
		nodes := []corev1.Node{*probetest.ReadyWorkerNode("w-hang", "KernelHungTasks", 5*time.Minute, false)}
		for i := range tc.alreadyCordoned {
			nodes = append(nodes, *probetest.ReadyWorkerNode(fmt.Sprintf("w-manual-%d", i), "", 0, true))
		}
		for i := tc.alreadyCordoned + 1; len(nodes) < 10; i++ {
			nodes = append(nodes, *probetest.ReadyWorkerNode(fmt.Sprintf("w-ok-%d", i), "", 0, false))
		}
		objs := make([]runtime.Object, len(nodes))
		for i := range nodes {
			objs[i] = &nodes[i]
		}
		cs := fake.NewSimpleClientset(objs...)
		p := testProberDyn(cs, probetest.OpDyn())
		if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
			t.Fatalf("alreadyCordoned=%d: hung node did not fail the check", tc.alreadyCordoned)
		}
		n, err := cs.CoreV1().Nodes().Get(ctx, "w-hang", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if n.Spec.Unschedulable != tc.hungCordoned {
			t.Fatalf("alreadyCordoned=%d: unschedulable = %v, want %v",
				tc.alreadyCordoned, n.Spec.Unschedulable, tc.hungCordoned)
		}
		testutil.CleanupMetric(t, nodeHangCordonsTotal, "w-hang")
	}
}

// All three patch paths — uncordon, stale-stamp clear, cordon — must
// invalidate ONLY the node census: a sweep-wide InvalidateSweep here
// wiped the pod/... caches a node spec/annotation patch cannot stale,
// re-listing the whole snapshot for every later check.
func TestNodeHangPatchInvalidatesNodesOnly(t *testing.T) {
	held := precordonedWorkerNode("w-held", true)                                        // stamped + cordon, latch cleared → uncordon
	stamp := precordonedWorkerNode("w-stamp", false)                                     // stamped + schedulable → stale-stamp clear
	hung := probetest.ReadyWorkerNode("w-hang", "KernelHungTasks", 5*time.Minute, false) // live latch → cordon
	cs := fake.NewSimpleClientset(held, stamp, hung,
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
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*nodeHangCheck](t, p)
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
		t.Fatalf("sustained hang latch did not fail the check: %+v", res)
	}
	// Three node patches landed; re-reading the pod census must hit
	// the memoized snapshot — a sweep-wide wipe would re-LIST here.
	if _, err := chk.AllPods(sweepCtx); err != nil {
		t.Fatal(err)
	}
	if podLists != 1 {
		t.Fatalf("node patches re-listed pods %d time(s) — sweep-wide wipe, want 0", podLists-1)
	}
	// The next node census is the armed direct-CS re-read carrying
	// every patch: uncordon, stamp clears, and the fresh cordon.
	fresh, err := chk.AllNodes(sweepCtx)
	if err != nil {
		t.Fatal(err)
	}
	if nodeLists != 2 {
		t.Fatalf("node census reads=%d, want 2 (memo + one armed re-read)", nodeLists)
	}
	got := map[string]*corev1.Node{}
	for i := range fresh {
		got[fresh[i].Name] = &fresh[i]
	}
	if got["w-held"].Spec.Unschedulable {
		t.Fatal("post-patch census still carries the held cordon")
	}
	if _, ok := got["w-held"].Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("post-patch census still carries the lifted stamp")
	}
	if _, ok := got["w-stamp"].Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("post-patch census still carries the stale stamp")
	}
	if !got["w-hang"].Spec.Unschedulable {
		t.Fatal("post-patch census misses the fresh cordon")
	}
}

// ---------------------------------------------------------------------------
// Remaining Run branches — control-plane skip, clock-skew heartbeat
// gate, latch-active clock fuse, patch failures, already-cordoned skip
// ---------------------------------------------------------------------------

// Control-plane nodes are excluded from BOTH the worker count and the
// latch scan — a cp node carrying a sustained latch is never a
// precordon candidate (it runs no kubelet workload anyway).
func TestCheckNodeHangControlPlaneSkipped(t *testing.T) {
	cp := probetest.ReadyWorkerNode("w-cp", "KernelHungTasks", 5*time.Minute, false)
	cp.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
	cs := fake.NewSimpleClientset(cp,
		probetest.ReadyWorkerNode("w-hang", "KernelHungTasks", 5*time.Minute, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("hung worker did not fail the check")
	}
	got, err := cs.CoreV1().Nodes().Get(ctx, "w-cp", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Unschedulable {
		t.Fatal("control-plane node cordoned — it is not a worker")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("control-plane node stamped")
	}
}

// A fused clock-skew latch with a frozen heartbeat is the same zombie
// shape as the hang latches — warn, don't cordon. This exercises the
// clock-skew half of nodeHangLatch's stale reporting.
func TestCheckNodeHangClockSkewStaleHeartbeat(t *testing.T) {
	skew := probetest.ReadyWorkerNode("w-cpskew", "ClockUnsynchronized", 15*time.Minute, false)
	skew.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeHangCondHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(skew, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("stale-heartbeat clock latch must not fail the check: %+v", res)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "w-cpskew", metav1.GetOptions{})
	if n.Spec.Unschedulable {
		t.Fatal("zombie clock latch cordoned the node")
	}
}

// nodeHangLatchActive's clock-skew half: a stamped cordon stays while
// ANY clock latch is True — here ClockSkewDetected is the only active
// condition and it is still inside its 10m fuse (not cordon evidence,
// but it IS uncordon evidence).
func TestCheckNodeHangClockLatchHoldsPreCordon(t *testing.T) {
	n := precordonedWorkerNode("w-clockheld", true)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               "ClockSkewDetected",
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-30 * time.Second)),
		LastHeartbeatTime:  metav1.NewTime(time.Now()),
	})
	cs := fake.NewSimpleClientset(n, probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("fresh clock latch must not fail the check: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-clockheld", metav1.GetOptions{})
	if !got.Spec.Unschedulable {
		t.Fatal("uncordoned while a clock latch is still True")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; !ok {
		t.Fatal("pre-cordon stamp removed while clock latch active")
	}
}

// A failed node List is an Infra result — the check cannot tell
// "no hang" from "never looked".
func TestCheckNodeHangInfraError(t *testing.T) {
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w-ok", "", 0, false))
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx)
	if res.Infra == nil {
		t.Fatalf("node list failure must surface as Infra, got %+v", res)
	}
}

// Patch failures are tolerated per-node: the uncordon patch error
// leaves the node cordoned+stamped and IncErrors once — the next
// sweep retries.
func TestCheckNodeHangUncordonPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		precordonedWorkerNode("w-held", true),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	before := testutil.QueueErrorCount(t, "cluster-health-probes")
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("a failed uncordon must not fabricate a finding: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-held", metav1.GetOptions{})
	if !got.Spec.Unschedulable {
		t.Fatal("uncordon reported delivered on a rejected patch")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; !ok {
		t.Fatal("stamp removed although the uncordon patch failed")
	}
	if d := testutil.QueueErrorCount(t, "cluster-health-probes") - before; d != 1 {
		t.Fatalf("uncordon patch failure IncError delta = %v, want 1", d)
	}
}

// Same tolerance on the stale-stamp clear: the patch error keeps the
// stamp (a later sweep retries the cleanup) and IncErrors once.
func TestCheckNodeHangStaleStampPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		precordonedWorkerNode("w-stale", false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	before := testutil.QueueErrorCount(t, "cluster-health-probes")
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("a failed stamp clear must not fabricate a finding: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-stale", metav1.GetOptions{})
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; !ok {
		t.Fatal("stale stamp removed although the patch failed")
	}
	if d := testutil.QueueErrorCount(t, "cluster-health-probes") - before; d != 1 {
		t.Fatalf("stale-stamp patch failure IncError delta = %v, want 1", d)
	}
}

// The cordon patch itself failing leaves the node schedulable — the
// finding still reports (the latch IS live) and the error is metered.
func TestCheckNodeHangCordonPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-hang", "KernelHungTasks", 5*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	before := testutil.QueueErrorCount(t, "cluster-health-probes")
	res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("live latch must still fail the check on a patch error")
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-hang", metav1.GetOptions{})
	if got.Spec.Unschedulable {
		t.Fatal("node cordoned although the patch was rejected")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("pre-cordon stamp written although the patch was rejected")
	}
	if d := testutil.QueueErrorCount(t, "cluster-health-probes") - before; d != 1 {
		t.Fatalf("cordon patch failure IncError delta = %v, want 1", d)
	}
}

// A manually cordoned node carrying a live latch emits the finding
// but is NOT re-patched — spec.unschedulable is already true, so the
// sweep must not stack our stamp onto somebody else's cordon.
func TestCheckNodeHangSkipsAlreadyCordoned(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-manual-hang", "KernelHungTasks", 5*time.Minute, true),
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("live latch on a cordoned node must still fail the check")
	}
	if !strings.Contains(res.Why, "w-manual-hang") {
		t.Fatalf("why missing the latched node: %q", res.Why)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-manual-hang", metav1.GetOptions{})
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("pre-cordon stamp stacked onto a foreign cordon")
	}
}

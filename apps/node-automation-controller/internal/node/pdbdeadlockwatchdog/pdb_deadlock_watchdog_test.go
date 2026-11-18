package pdbdeadlockwatchdog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders (pdw-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

// pdwBlockedPDB builds a PDB pinned at the drain-blocking signature:
// pods exist (expectedPods>0) but the eviction API allows zero
// voluntary disruptions.
func pdwBlockedPDB(ns, name string, expected, desired, current int32) *policyv1.PodDisruptionBudget {
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		// A real selector — policy/v1 nil selects NOTHING, and the
		// cordoned-node check lists pods through it.
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"pdw": "protected"},
			},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			ExpectedPods:       expected,
			DesiredHealthy:     desired,
			CurrentHealthy:     current,
			DisruptionsAllowed: 0,
		},
	}
}

// pdwPod is a Running pod carrying the pdw=protected label the test
// PDBs select, pinned to nodeName — the cordoned-node check only
// counts pods that actually sit on a cordoned node.
func pdwPod(ns, name, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Labels: map[string]string{"pdw": "protected"},
		},
		Spec:   corev1.PodSpec{NodeName: nodeName},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// pdwCordonedNode is a Ready node under drain: spec.unschedulable is
// what kubectl drain/kured set, independent of the Ready condition.
func pdwCordonedNode(name string) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil)
	n.Spec.Unschedulable = true
	return n
}

// newPDWWatchdog returns a watchdog whose clock the test controls:
// mutate *clock between run() calls to age sightings without
// sleeping.
func newPDWWatchdog(cs *fake.Clientset, clock *time.Time) *pdbDeadlockWatchdog {
	return &pdbDeadlockWatchdog{
		cs:  cs,
		now: func() time.Time { return *clock },
	}
}

// pdbTrackedCount reports how many keys a FirstSeenLedger holds —
// the ledger exposes no Len, so a keep-all Prune does the counting.
func pdbTrackedCount(l *state.FirstSeenLedger) int {
	n := 0
	l.Prune(func(string) bool { n++; return true })
	return n
}

// pdwDrainBlocked reads the node_automation_pdb_drain_blocked series
// for (ns, name, reason) off the controller-runtime registry:
// (value, true) when the series exists. The watchdog prunes resolved
// series outright (DeleteLabelValues — same hygiene as
// ForgetAPIBackend), so "absent" means resolved/never-fired rather
// than a lingering 0.
func pdwDrainBlocked(t *testing.T, ns, name, reason string) (float64, bool) {
	t.Helper()
	fams, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != "node_automation_pdb_drain_blocked" {
			continue
		}
		for _, m := range f.GetMetric() {
			lbl := map[string]string{}
			for _, l := range m.GetLabel() {
				lbl[l.GetName()] = l.GetValue()
			}
			if lbl["namespace"] == ns && lbl["pdb"] == name && lbl["reason"] == reason {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

// pdwClearMetrics removes every series the test could have created —
// the GaugeVec is process-global, so leaked series would poison
// sibling tests sharing the registry.
func pdwClearMetrics(t *testing.T, entries ...[2]string) {
	t.Helper()
	for _, e := range entries {
		for _, r := range []string{
			pdbReasonImpossiblePolicy, pdbReasonCordonedNode, pdbReasonProlonged,
		} {
			metrics.PDBDrainBlocked.DeleteLabelValues(e[0], e[1], r)
		}
	}
}

// pdwSetStatus patches the listed status fields of a PDB through the
// fake — the same read-modify-write a test performs to flip the
// blocked signature on or off.
func pdwSetStatus(t *testing.T, cs *fake.Clientset, ns, name string,
	mutate func(*policyv1.PodDisruptionBudgetStatus)) {
	t.Helper()
	p, err := cs.PolicyV1().PodDisruptionBudgets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mutate(&p.Status)
	if _, err := cs.PolicyV1().PodDisruptionBudgets(ns).
		UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// A first sighting only OPENS the continuity window — the gauge must
// stay unset until the reason's threshold passes with no gap. An
// impossible PDB (desiredHealthy >= expectedPods) with no cordon
// opens exactly two windows: impossible_policy and the generic
// prolonged catch-all.
func TestPDBWatchdogFirstSightingNotReported(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-a", "impossible"}) })
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		pdwBlockedPDB("pdw-a", "impossible", 2, 2, 2))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{pdbReasonImpossiblePolicy, pdbReasonProlonged} {
		if _, ok := pdwDrainBlocked(t, "pdw-a", "impossible", r); ok {
			t.Fatalf("series %s set on first sighting", r)
		}
		if _, ok := w.firstSeen.Seen("pdw-a/impossible/"+r, time.Now()); !ok {
			t.Fatalf("first-seen window for %s not opened", r)
		}
	}
	if _, ok := w.firstSeen.Seen("pdw-a/impossible/"+pdbReasonCordonedNode, time.Now()); ok {
		t.Fatal("cordoned window opened without a cordoned node")
	}
}

// impossible_policy fires once desiredHealthy >= expectedPods has
// held for >= 10m — and ONLY that reason (no cordon, and 11m is
// inside the prolonged window's 30m threshold).
func TestPDBWatchdogImpossiblePolicy(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-b", "min-equals-replicas"}) })
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		pdwBlockedPDB("pdw-b", "min-equals-replicas", 2, 2, 2))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := pdwDrainBlocked(t, "pdw-b", "min-equals-replicas",
		pdbReasonImpossiblePolicy); !ok || v != 1 {
		t.Fatalf("impossible_policy = %v (ok=%v), want 1", v, ok)
	}
	for _, r := range []string{pdbReasonCordonedNode, pdbReasonProlonged} {
		if _, ok := pdwDrainBlocked(t, "pdw-b", "min-equals-replicas", r); ok {
			t.Fatalf("reason %s fired before its own threshold", r)
		}
	}
}

// cordoned_node_blocked needs BOTH a spec.unschedulable node and zero
// disruptions for >= 15m. A PDB whose desiredHealthy < expectedPods
// (a satisfiable policy) isolates the cordon reason from
// impossible_policy.
func TestPDBWatchdogCordonedNodeBlocked(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-c", "drain-wedged"}) })
	cs := fake.NewSimpleClientset(
		pdwCordonedNode("n1"),
		pdwPod("pdw-c", "w1", "n1"),
		pdwPod("pdw-c", "w2", "n1"),
		pdwBlockedPDB("pdw-c", "drain-wedged", 3, 1, 1))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	// Inside the window — nothing reported yet.
	now = now.Add(14 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := pdwDrainBlocked(t, "pdw-c", "drain-wedged", pdbReasonCordonedNode); ok {
		t.Fatal("cordoned_node_blocked fired before 15m")
	}
	// Past the window — cordon reason fires; impossible stays off
	// (policy is satisfiable), prolonged is still under 30m.
	now = now.Add(2 * time.Minute) // 16m continuous
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := pdwDrainBlocked(t, "pdw-c", "drain-wedged",
		pdbReasonCordonedNode); !ok || v != 1 {
		t.Fatalf("cordoned_node_blocked = %v (ok=%v), want 1", v, ok)
	}
	if _, ok := pdwDrainBlocked(t, "pdw-c", "drain-wedged", pdbReasonImpossiblePolicy); ok {
		t.Fatal("impossible_policy fired although desiredHealthy < expectedPods")
	}
	if _, ok := pdwDrainBlocked(t, "pdw-c", "drain-wedged", pdbReasonProlonged); ok {
		t.Fatal("prolonged fired before 30m")
	}
}

// pinned-volume-guard — a statically-cordoned node (spec.unschedulable held past
// the cordon-active window, companion taint older than 45m) is
// deliberate state, not a drain in flight: cordoned_node_blocked must
// not open its continuity window for it.
func TestPDBWatchdogStaleCordonIgnored(t *testing.T) {
	now := time.Now()
	stale := pdwCordonedNode("n-stale")
	stale.Spec.Taints = []corev1.Taint{{
		Key:       kube.UnschedulableTaintKey,
		TimeAdded: &metav1.Time{Time: now.Add(-time.Hour)},
	}}
	cs := fake.NewSimpleClientset(
		stale,
		pdwBlockedPDB("pdw-e", "stale-cordon", 3, 1, 1))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.firstSeen.Seen("pdw-e/stale-cordon/"+pdbReasonCordonedNode, time.Now()); ok {
		t.Fatal("cordoned window opened for a stale (>45m) cordon")
	}
	if _, ok := pdwDrainBlocked(t, "pdw-e", "stale-cordon", pdbReasonCordonedNode); ok {
		t.Fatal("cordoned_node_blocked fired on a static cordon")
	}
}

// Without a cordon the cordon reason can never hold — the window
// must not even open (continuity keyed to the precondition, not the
// base signal).
func TestPDBWatchdogNoCordonNoWindow(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		pdwBlockedPDB("pdw-d", "no-cordon", 3, 1, 1))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.firstSeen.Seen("pdw-d/no-cordon/"+pdbReasonCordonedNode, time.Now()); ok {
		t.Fatal("cordoned window opened although no node is unschedulable")
	}
}

// prolonged_zero_disruptions is the generic catch-all: any blocked
// PDB at >= 30m, regardless of root cause.
func TestPDBWatchdogProlongedZeroDisruptions(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-e", "stuck-controller"}) })
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		pdwBlockedPDB("pdw-e", "stuck-controller", 3, 1, 1))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(29 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := pdwDrainBlocked(t, "pdw-e", "stuck-controller", pdbReasonProlonged); ok {
		t.Fatal("prolonged fired before 30m")
	}
	now = now.Add(2 * time.Minute) // 31m continuous
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := pdwDrainBlocked(t, "pdw-e", "stuck-controller",
		pdbReasonProlonged); !ok || v != 1 {
		t.Fatalf("prolonged_zero_disruptions = %v (ok=%v), want 1", v, ok)
	}
}

// The reasons are independent series, not a winner-takes-all verdict:
// an impossible PDB on a cluster with a cordoned node reports all
// three once the longest window elapses.
func TestPDBWatchdogMultipleReasonsCoexist(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-f", "triple"}) })
	cs := fake.NewSimpleClientset(
		pdwCordonedNode("n1"),
		pdwPod("pdw-f", "t1", "n1"),
		pdwPod("pdw-f", "t2", "n1"),
		pdwBlockedPDB("pdw-f", "triple", 2, 2, 2))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{
		pdbReasonImpossiblePolicy, pdbReasonCordonedNode, pdbReasonProlonged,
	} {
		if v, ok := pdwDrainBlocked(t, "pdw-f", "triple", r); !ok || v != 1 {
			t.Fatalf("reason %s = %v (ok=%v), want 1", r, v, ok)
		}
	}
}

// Recovery clears the series AND the first-seen entry: a PDB whose
// disruptionsAllowed opens back up must not keep reporting (or
// resume a stale window on the next flap).
func TestPDBWatchdogRecoveryClearsSeries(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-g", "recovers"}) })
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		pdwBlockedPDB("pdw-g", "recovers", 2, 2, 2))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := pdwDrainBlocked(t, "pdw-g", "recovers", pdbReasonImpossiblePolicy); !ok {
		t.Fatal("series never set — test cannot observe the clear")
	}
	pdwSetStatus(t, cs, "pdw-g", "recovers",
		func(s *policyv1.PodDisruptionBudgetStatus) { s.DisruptionsAllowed = 1 })
	now = now.Add(time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{pdbReasonImpossiblePolicy, pdbReasonProlonged} {
		if _, ok := pdwDrainBlocked(t, "pdw-g", "recovers", r); ok {
			t.Fatalf("series %s survived recovery", r)
		}
	}
	if pdbTrackedCount(&w.firstSeen) != 0 {
		t.Fatalf("first-seen entries leaked after recovery: %v", w.firstSeen)
	}
}

// A deleted PDB must drop every window and series — the prune pass
// has to work for objects that no longer exist (no per-PDB cleanup
// runs for them).
func TestPDBWatchdogDeletedPDBPrunesSeries(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-h", "ephemeral"}) })
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		pdwBlockedPDB("pdw-h", "ephemeral", 2, 2, 2))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := pdwDrainBlocked(t, "pdw-h", "ephemeral", pdbReasonProlonged); !ok {
		t.Fatal("series never set — test cannot observe the prune")
	}
	if err := cs.PolicyV1().PodDisruptionBudgets("pdw-h").
		Delete(ctx, "ephemeral", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{
		pdbReasonImpossiblePolicy, pdbReasonCordonedNode, pdbReasonProlonged,
	} {
		if _, ok := pdwDrainBlocked(t, "pdw-h", "ephemeral", r); ok {
			t.Fatalf("series %s outlived its PDB", r)
		}
	}
	if pdbTrackedCount(&w.firstSeen) != 0 {
		t.Fatalf("first-seen entries leaked for deleted PDB: %v", w.firstSeen)
	}
}

// "Continuously" is a gap-free window: a one-cycle break in the
// precondition restarts the timer rather than accumulating.
func TestPDBWatchdogContinuityResetsOnGap(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-i", "flappy"}) })
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		pdwBlockedPDB("pdw-i", "flappy", 2, 2, 2))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	// 5m in: the block clears for one cycle — the window dies.
	pdwSetStatus(t, cs, "pdw-i", "flappy",
		func(s *policyv1.PodDisruptionBudgetStatus) { s.DisruptionsAllowed = 1 })
	now = now.Add(5 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if pdbTrackedCount(&w.firstSeen) != 0 {
		t.Fatal("first-seen entry survived a gap in the precondition")
	}
	// The block returns — a NEW window opens at t+6m, not a resume
	// of the t+0 one.
	pdwSetStatus(t, cs, "pdw-i", "flappy",
		func(s *policyv1.PodDisruptionBudgetStatus) { s.DisruptionsAllowed = 0 })
	now = now.Add(time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	// t+15m wall-clock but only 9m of continuity — must not fire.
	now = now.Add(9 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := pdwDrainBlocked(t, "pdw-i", "flappy", pdbReasonImpossiblePolicy); ok {
		t.Fatal("fired on cumulative age — gap did not reset the window")
	}
	// t+17m wall-clock = 11m of continuity — now it fires.
	now = now.Add(2 * time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok := pdwDrainBlocked(t, "pdw-i", "flappy",
		pdbReasonImpossiblePolicy); !ok || v != 1 {
		t.Fatalf("impossible_policy = %v (ok=%v) after continuous window, want 1", v, ok)
	}
}

// Reasons age independently: when impossible_policy's precondition
// drops (desiredHealthy falls below expectedPods) its series is
// pruned while a still-holding cordon reason keeps both its window
// and its gauge.
func TestPDBWatchdogReasonsResolveIndependently(t *testing.T) {
	now := time.Now()
	t.Cleanup(func() { pdwClearMetrics(t, [2]string{"pdw-j", "mixed"}) })
	cs := fake.NewSimpleClientset(
		pdwCordonedNode("n1"),
		pdwPod("pdw-j", "m1", "n1"),
		pdwPod("pdw-j", "m2", "n1"),
		pdwBlockedPDB("pdw-j", "mixed", 2, 2, 2))
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(16 * time.Minute) // impossible + cordoned both set
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{pdbReasonImpossiblePolicy, pdbReasonCordonedNode} {
		if _, ok := pdwDrainBlocked(t, "pdw-j", "mixed", r); !ok {
			t.Fatalf("series %s never set — test cannot observe resolution", r)
		}
	}
	// Policy becomes satisfiable (desired < expected) but the PDB
	// still blocks and the node stays cordoned.
	pdwSetStatus(t, cs, "pdw-j", "mixed",
		func(s *policyv1.PodDisruptionBudgetStatus) { s.DesiredHealthy = 1 })
	now = now.Add(time.Minute)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := pdwDrainBlocked(t, "pdw-j", "mixed", pdbReasonImpossiblePolicy); ok {
		t.Fatal("impossible_policy series survived its precondition")
	}
	if _, ok := w.firstSeen.Seen("pdw-j/mixed/"+pdbReasonImpossiblePolicy, time.Now()); ok {
		t.Fatal("impossible_policy window kept although precondition dropped")
	}
	if v, ok := pdwDrainBlocked(t, "pdw-j", "mixed",
		pdbReasonCordonedNode); !ok || v != 1 {
		t.Fatalf("cordoned series = %v (ok=%v) after sibling reason resolved, want 1", v, ok)
	}
}

// PDBs that are not blocking — no expected pods (selector drifted
// off everything) or disruptions still allowed — open no windows and
// produce no series.
func TestPDBWatchdogIgnoresNonBlockingPDBs(t *testing.T) {
	now := time.Now()
	drifted := pdwBlockedPDB("pdw-k", "no-pods", 0, 0, 0) // expectedPods == 0
	healthy := pdwBlockedPDB("pdw-k", "normal", 3, 2, 3)
	healthy.Status.DisruptionsAllowed = 1
	cs := fake.NewSimpleClientset(
		pdwCordonedNode("n1"), // even a cordon can't unblock nothing
		drifted, healthy)
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if pdbTrackedCount(&w.firstSeen) != 0 {
		t.Fatalf("non-blocking PDBs opened %d windows: %v", pdbTrackedCount(&w.firstSeen), w.firstSeen)
	}
	for _, name := range []string{"no-pods", "normal"} {
		for _, r := range []string{
			pdbReasonImpossiblePolicy, pdbReasonCordonedNode, pdbReasonProlonged,
		} {
			if _, ok := pdwDrainBlocked(t, "pdw-k", name, r); ok {
				t.Fatalf("series for non-blocking PDB %s reason %s exists", name, r)
			}
		}
	}
}

// A node list failure aborts the whole sweep — misreading the cordon
// signal would silently clear cordoned_node_blocked series or mis-age
// windows.
func TestPDBWatchdogNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pdwBlockedPDB("pdw-l", "any", 2, 2, 2))
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	now := time.Now()
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A PDB list failure is likewise fatal to the run — an empty snapshot
// would look like "everything recovered" and prune live series.
func TestPDBWatchdogPDBListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil))
	cs.PrependReactor("list", "poddisruptionbudgets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	now := time.Now()
	w := newPDWWatchdog(cs, &now)
	if err := w.run(ctx); err == nil {
		t.Fatal("expected error when the PDB list fails")
	}
}

// Package-wide test context shared by this package's _test files.
var ctx = context.Background()

// ---------------------------------------------------------------------------
// cordoned-block relief (P2-#10)
// ---------------------------------------------------------------------------

// pdwReliefWatchdog builds a watchdog wired for the relief paths:
// dyn stub for the maintenance verdict, both knobs on.
func pdwReliefWatchdog(cs *fake.Clientset, clock *time.Time) *pdbDeadlockWatchdog {
	return &pdbDeadlockWatchdog{
		cs:  cs,
		dyn: testutil.NewDynamicClientWithCRDs(),
		cfg: pdbConfig{unhealthyEvictionPolicyPatch: true, cordonedUnhealthyRelief: true},
		now: func() time.Time { return *clock },
	}
}

// pdwUnreadyPod builds a pod matching the pdw=protected selector,
// pinned to nodeName, Ready=False for unreadyFor with a container
// waiting in waitReason.
func pdwUnreadyPod(ns, name, nodeName string, unreadyFor time.Duration,
	waitReason string) *corev1.Pod {

	pod := pdwPod(ns, name, nodeName)
	pod.Status.Conditions = []corev1.PodCondition{{
		Type:               corev1.PodReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-unreadyFor)),
	}}
	if waitReason != "" {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "c",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
				Reason: waitReason,
			}},
		}}
	}
	return pod
}

// pdwStaticCordonedNode is a node whose cordon is older than the
// 45m active window — NodeActivelyCordoned reads false so the
// maintenance mutex stays clear while the test drives the relief
// with an artificial cordoned set.
func pdwStaticCordonedNode(name string) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil)
	n.Spec.Unschedulable = true
	ta := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	n.Spec.Taints = []corev1.Taint{{
		Key:       "node.kubernetes.io/unschedulable",
		Effect:    corev1.TaintEffectNoSchedule,
		TimeAdded: &ta,
	}}
	return n
}

// The patch path: a blocked PDB with unset unhealthyPodEvictionPolicy
// plus a wedged pod on a cordoned node gets the AlwaysAllow merge
// patch, the counter increments, and the cooldown stamps.
func TestPDBReliefPatchesUnhealthyEvictionPolicy(t *testing.T) {
	clock := time.Now()
	pdb := pdwBlockedPDB("app", "web-pdb", 3, 2, 1)
	pod := pdwUnreadyPod("app", "web-0", "node-cordoned", 10*time.Minute, "CrashLoopBackOff")
	cs := fake.NewSimpleClientset(pdb, pod, pdwStaticCordonedNode("node-cordoned"))
	w := pdwReliefWatchdog(cs, &clock)

	w.relieveCordonedBlock(context.Background(), logr.Discard(), clock,
		pdb, map[string]bool{"node-cordoned": true})

	got, err := cs.PolicyV1().PodDisruptionBudgets("app").Get(context.Background(), "web-pdb", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pdb: %v", err)
	}
	if got.Spec.UnhealthyPodEvictionPolicy == nil ||
		*got.Spec.UnhealthyPodEvictionPolicy != policyv1.AlwaysAllow {
		t.Fatalf("unhealthyPodEvictionPolicy = %v, want AlwaysAllow",
			got.Spec.UnhealthyPodEvictionPolicy)
	}
	if _, err := cs.CoreV1().Pods("app").Get(context.Background(), "web-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("patch path must not delete the pod: %v", err)
	}
	// Cooldown stamped — an immediate second call is a no-op.
	before := pdbUnhealthyPolicyPatchedTotalValue(t)
	w.relieveCordonedBlock(context.Background(), logr.Discard(), clock,
		pdb, map[string]bool{"node-cordoned": true})
	if after := pdbUnhealthyPolicyPatchedTotalValue(t); after != before {
		t.Fatalf("cooldown violated: counter moved %v → %v", before, after)
	}
}

// The delete fallback: policy already AlwaysAllow (patch path moot)
// and the pod unready >30m with no DB quorum label → the pod is
// deleted so it reschedules onto a schedulable node.
func TestPDBReliefDeletesWedgedPodFallback(t *testing.T) {
	clock := time.Now()
	pdb := pdwBlockedPDB("app", "web-pdb", 3, 2, 1)
	always := policyv1.AlwaysAllow
	pdb.Spec.UnhealthyPodEvictionPolicy = &always
	pod := pdwUnreadyPod("app", "web-0", "node-cordoned", 45*time.Minute, "ImagePullBackOff")
	cs := fake.NewSimpleClientset(pdb, pod, pdwStaticCordonedNode("node-cordoned"))
	w := pdwReliefWatchdog(cs, &clock)

	w.relieveCordonedBlock(context.Background(), logr.Discard(), clock,
		pdb, map[string]bool{"node-cordoned": true})

	if _, err := cs.CoreV1().Pods("app").Get(context.Background(), "web-0", metav1.GetOptions{}); err == nil {
		t.Fatal("wedged pod was not deleted by the fallback")
	}
}

// The production bug this fix targets: the relief exists to finish
// an ACTIVE cordon drain (<45m), but the classic maintenance mutex
// holds on exactly that signal — under AllowedV the patch AND the
// pod-delete fallback were dead code for the whole cordon window.
// With the cluster-wide-only / upgrade-only gates both paths must
// proceed while the cordon is fresh.
func TestPDBReliefProceedsDuringActiveCordon(t *testing.T) {
	clock := time.Now()
	// Fresh cordon taint (5m) — NodeActivelyCordoned=true, so the
	// maintenance verdict carries a NODE-scoped hold. That hold must
	// NOT defer either relief path.
	activeNode := testutil.Node("node-cordoned", corev1.ConditionTrue, nil)
	activeNode.Spec.Unschedulable = true
	ta := metav1.NewTime(clock.Add(-5 * time.Minute))
	activeNode.Spec.Taints = []corev1.Taint{{
		Key:       "node.kubernetes.io/unschedulable",
		Effect:    corev1.TaintEffectNoSchedule,
		TimeAdded: &ta,
	}}

	// Patch path under the active cordon.
	pdb := pdwBlockedPDB("app", "web-pdb", 3, 2, 1)
	pod := pdwUnreadyPod("app", "web-0", "node-cordoned", 10*time.Minute, "CrashLoopBackOff")
	cs := fake.NewSimpleClientset(pdb, pod, activeNode)
	w := pdwReliefWatchdog(cs, &clock)

	w.relieveCordonedBlock(context.Background(), logr.Discard(), clock,
		pdb, map[string]bool{"node-cordoned": true})

	got, err := cs.PolicyV1().PodDisruptionBudgets("app").Get(context.Background(), "web-pdb", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pdb: %v", err)
	}
	if got.Spec.UnhealthyPodEvictionPolicy == nil ||
		*got.Spec.UnhealthyPodEvictionPolicy != policyv1.AlwaysAllow {
		t.Fatalf("patch deferred by active cordon: policy=%v",
			got.Spec.UnhealthyPodEvictionPolicy)
	}

	// Delete fallback under the active cordon — AlwaysAllow policy
	// makes the patch path moot, the wedged pod must still die.
	pdb2 := pdwBlockedPDB("app", "web-pdb2", 3, 2, 1)
	always := policyv1.AlwaysAllow
	pdb2.Spec.UnhealthyPodEvictionPolicy = &always
	pod2 := pdwUnreadyPod("app", "web-1", "node-cordoned", 45*time.Minute, "ImagePullBackOff")
	cs2 := fake.NewSimpleClientset(pdb2, pod2, activeNode)
	w2 := pdwReliefWatchdog(cs2, &clock)

	w2.relieveCordonedBlock(context.Background(), logr.Discard(), clock,
		pdb2, map[string]bool{"node-cordoned": true})

	if _, err := cs2.CoreV1().Pods("app").Get(context.Background(), "web-1", metav1.GetOptions{}); err == nil {
		t.Fatal("pod-delete fallback deferred by active cordon")
	}
}

// A DB quorum member is never deleted — deleting it trades a drain
// stall for a data-store outage. Every operator label in the quorum
// set (including the Percona PXC/PSMDB pair) must shield the pod.
func TestPDBReliefSkipsDBQuorumPod(t *testing.T) {
	for _, label := range pdbDBQuorumLabels {
		t.Run(label, func(t *testing.T) {
			clock := time.Now()
			pdb := pdwBlockedPDB("app", "db-pdb", 3, 2, 1)
			always := policyv1.AlwaysAllow
			pdb.Spec.UnhealthyPodEvictionPolicy = &always
			pod := pdwUnreadyPod("app", "pg-0", "node-cordoned", 45*time.Minute, "CrashLoopBackOff")
			pod.Labels[label] = "cluster"
			cs := fake.NewSimpleClientset(pdb, pod, pdwStaticCordonedNode("node-cordoned"))
			w := pdwReliefWatchdog(cs, &clock)

			w.relieveCordonedBlock(context.Background(), logr.Discard(), clock,
				pdb, map[string]bool{"node-cordoned": true})

			if _, err := cs.CoreV1().Pods("app").Get(context.Background(), "pg-0", metav1.GetOptions{}); err != nil {
				t.Fatalf("DB quorum pod deleted: %v", err)
			}
		})
	}
}

// Negative: a pod unready only 10m does not reach the 30m delete
// fuse, and a pod without a container-error state is not wedge
// evidence at all.
func TestPDBReliefRespectsFuses(t *testing.T) {
	clock := time.Now()
	pdb := pdwBlockedPDB("app", "web-pdb", 3, 2, 1)
	always := policyv1.AlwaysAllow
	pdb.Spec.UnhealthyPodEvictionPolicy = &always
	// 10m unready — under the 30m delete fuse (but over the 5m
	// patch-evidence fuse; the patch path is moot here since the
	// policy is already AlwaysAllow).
	pod := pdwUnreadyPod("app", "web-0", "node-cordoned", 10*time.Minute, "CrashLoopBackOff")
	// A Ready pod on the same cordoned node — not wedge evidence.
	ready := pdwPod("app", "web-1", "node-cordoned")
	ready.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodReady, Status: corev1.ConditionTrue,
	}}
	cs := fake.NewSimpleClientset(pdb, pod, ready, pdwStaticCordonedNode("node-cordoned"))
	w := pdwReliefWatchdog(cs, &clock)

	w.relieveCordonedBlock(context.Background(), logr.Discard(), clock,
		pdb, map[string]bool{"node-cordoned": true})

	for _, n := range []string{"web-0", "web-1"} {
		if _, err := cs.CoreV1().Pods("app").Get(context.Background(), n, metav1.GetOptions{}); err != nil {
			t.Fatalf("pod %s deleted inside fuse: %v", n, err)
		}
	}
}

// Knobs off: both relief paths disabled → nothing happens even with
// a perfect wedge fixture.
func TestPDBReliefKnobsOff(t *testing.T) {
	clock := time.Now()
	pdb := pdwBlockedPDB("app", "web-pdb", 3, 2, 1)
	pod := pdwUnreadyPod("app", "web-0", "node-cordoned", 45*time.Minute, "CrashLoopBackOff")
	cs := fake.NewSimpleClientset(pdb, pod, pdwStaticCordonedNode("node-cordoned"))
	w := &pdbDeadlockWatchdog{
		cs:  cs,
		dyn: testutil.NewDynamicClientWithCRDs(),
		cfg: pdbConfig{}, // both knobs false
		now: func() time.Time { return clock },
	}

	w.relieveCordonedBlock(context.Background(), logr.Discard(), clock,
		pdb, map[string]bool{"node-cordoned": true})

	got, _ := cs.PolicyV1().PodDisruptionBudgets("app").Get(context.Background(), "web-pdb", metav1.GetOptions{})
	if got.Spec.UnhealthyPodEvictionPolicy != nil {
		t.Fatal("patch landed with knob off")
	}
	if _, err := cs.CoreV1().Pods("app").Get(context.Background(), "web-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted with knob off: %v", err)
	}
}

// pdbUnhealthyPolicyPatchedTotalValue reads the relief counter for
// cooldown assertions.
func pdbUnhealthyPolicyPatchedTotalValue(t *testing.T) float64 {
	t.Helper()
	mfs, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "node_automation_pdb_unhealthy_policy_patched_total" {
			continue
		}
		var v float64
		for _, m := range mf.GetMetric() {
			v += m.GetCounter().GetValue()
		}
		return v
	}
	return 0
}

// node_condition_sweeper_test.go — coverage for the
// node-condition-sweeper check: stale-heartbeat zombie True
// conditions get patched False, live-heartbeat conditions and
// non-managed types are never touched.
package nodehealth

import (
	"errors"
	"strings"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// A True managed condition whose heartbeat froze is reconciled to
// False — the 2026-11-07 zombie left by a wedged reporter.
func TestNodeCondSweeperClearsZombie(t *testing.T) {
	n := probetest.ReadyWorkerNode("w-zombie", "KubeletPLEGUnhealthy",
		nodeCondSweepHeartbeatMaxAge+time.Minute, false)
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeCondSweepHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(n,
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("zombie condition did not fail the check")
	}
	got, err := cs.CoreV1().Nodes().Get(ctx, "w-zombie", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := kube.NodeCondition(got, "KubeletPLEGUnhealthy")
	if c == nil || c.Status != corev1.ConditionFalse {
		t.Fatalf("zombie condition = %+v, want Status=False", c)
	}
	if c.Reason != "StaleConditionCleared" {
		t.Fatalf("cleared reason = %q, want StaleConditionCleared", c.Reason)
	}
}

// A True managed condition with a FRESH heartbeat is a live latch —
// the sweeper must not second-guess its writer.
func TestNodeCondSweeperKeepsLiveLatch(t *testing.T) {
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-live", "KernelHungTasks", 5*time.Minute, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("live latch failed the check: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-live", metav1.GetOptions{})
	c := kube.NodeCondition(got, "KernelHungTasks")
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("live latch = %+v, want Status=True untouched", c)
	}
}

// A fresh True with NO heartbeat stamp is left alone — a foreign
// writer that just set it may not stamp heartbeats at all.
func TestNodeCondSweeperKeepsFreshNoHeartbeat(t *testing.T) {
	n := probetest.ReadyWorkerNode("w-fresh", "NebulaIsolated", time.Minute, false)
	n.Status.Conditions[1].LastHeartbeatTime = metav1.Time{}
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("fresh no-heartbeat latch failed the check: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-fresh", metav1.GetOptions{})
	c := kube.NodeCondition(got, "NebulaIsolated")
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("fresh latch = %+v, want Status=True untouched", c)
	}
}

// Non-managed condition types (kubelet-owned, foreign writers) are
// never patched even with a frozen heartbeat.
func TestNodeCondSweeperIgnoresForeignConditions(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-2 * nodeCondSweepHeartbeatMaxAge))
	n := probetest.ReadyWorkerNode("w-foreign", "", 0, false)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               "ForeignCondition",
		Status:             corev1.ConditionTrue,
		Reason:             "ForeignWriter",
		LastHeartbeatTime:  old,
		LastTransitionTime: old,
	})
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("foreign condition failed the check: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-foreign", metav1.GetOptions{})
	c := kube.NodeCondition(got, "ForeignCondition")
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("foreign condition = %+v, want Status=True untouched", c)
	}
}

// End-to-end with precordon: a stamped cordon under a zombie latch
// lifts once the sweeper clears the condition — the manual sequence
// run on 2026-11-07.
func TestNodeCondSweeperThenAutoUncordon(t *testing.T) {
	n := precordonedWorkerNode("w-held", true)
	old := metav1.NewTime(time.Now().Add(-nodeCondSweepHeartbeatMaxAge - time.Minute))
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               "KubeletPLEGUnhealthy",
		Status:             corev1.ConditionTrue,
		Reason:             "KubeletPLEGUnhealthyDetected",
		LastHeartbeatTime:  old,
		LastTransitionTime: old,
	})
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("zombie condition did not fail the check")
	}
	// The precordon's own sweep now sees no active latch → auto-uncordon.
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("precordon sweep after clear failed: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-held", metav1.GetOptions{})
	if got.Spec.Unschedulable {
		t.Fatal("stamped cordon did not lift after zombie clear")
	}
}

// InodePressure is agent-latched since inode-pressure (hostmetrics
// state-inode-pressure) and kubelet never emits a condition of this
// type — a frozen heartbeat on it can only be a dead reporter's
// zombie, so the sweeper clears it like any other HeartbeatSweptNames
// member. The remaining split (KernelDeadlock permanent, kubelet
// condition types untouched) is pinned by nodecond.
func TestNodeCondSweeperSweepsFrozenInodePressure(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-2 * nodeCondSweepHeartbeatMaxAge))
	n := probetest.ReadyWorkerNode("w-inode", "", 0, false)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               "InodePressure",
		Status:             corev1.ConditionTrue,
		Reason:             "FilesystemInodesExhausted",
		LastHeartbeatTime:  old,
		LastTransitionTime: old,
	})
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("frozen InodePressure zombie did not fail the check")
	}
	got, err := cs.CoreV1().Nodes().Get(ctx, "w-inode", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := kube.NodeCondition(got, "InodePressure")
	if c == nil || c.Status != corev1.ConditionFalse {
		t.Fatalf("InodePressure = %+v, want Status=False swept", c)
	}
}

// The HeartbeatSweptNames superset: nodereporter-owned conditions
// outside the old precordon-hang + clock-skew lists (here the
// WatchdogStale probe latch) are swept too — nodecond is the
// allowlist's single source of truth.
func TestNodeCondSweeperCoversHeartbeatSweptSuperset(t *testing.T) {
	found := false
	for _, c := range nodeCondSweptConds {
		if c == "WatchdogStale" {
			found = true
		}
	}
	if !found {
		t.Fatal("WatchdogStale missing from the sweeper allowlist")
	}
	n := probetest.ReadyWorkerNode("w-watchdog", "WatchdogStale",
		nodeCondSweepHeartbeatMaxAge+time.Minute, false)
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeCondSweepHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("zombie WatchdogStale did not fail the check")
	}
	got, err := cs.CoreV1().Nodes().Get(ctx, "w-watchdog", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := kube.NodeCondition(got, "WatchdogStale")
	if c == nil || c.Status != corev1.ConditionFalse {
		t.Fatalf("WatchdogStale zombie = %+v, want Status=False cleared", c)
	}
}

// TestNodeCondSweeperSweepsEveryAgentEmittedCondition proves the
// allowlist covers EVERY condition nodereporter emits and re-stamps:
// each nodecond.HeartbeatSweptNames entry — including the 20 that
// joined as agent-added conditions (NodeOverloaded, WatchdogStale, DnsFallbackActive,
// DnsResolvStale, JournaldUnreadable, NebulaDegraded,
// CiliumIPAMExhausted, CiliumBPFMapPressure, SpegelMirrorDegraded,
// CalicoVethLeak, Fail2banDown, ConntrackPressure,
// KernelKeysPressure, ControlPlaneCertReloadStale,
// NebulaPMTUBlackhole,
// KubeconfigCertExpiring, CPUStealPressure, SystemdSessionBloat,
// KernelNetShimDegraded, ClocksourceUnstable) — must be cleared when
// it sits True with a frozen heartbeat. nodecond pins the list
// against the agent's own emitter (libs/hostkit
// TestHeartbeatSweptCoversLatchBackedExactly + the agent's
// kernel_latch_conditions_test cross-check); this test pins the
// CONSUMER side: a name in HeartbeatSweptNames that the sweeper
// skipped would be a zombie the reporter can never reconcile.
func TestNodeCondSweeperSweepsEveryAgentEmittedCondition(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-2 * nodeCondSweepHeartbeatMaxAge))
	for _, name := range nodecond.HeartbeatSweptNames {
		n := probetest.ReadyWorkerNode("w-sweep-"+name, corev1.NodeConditionType(name),
			nodeCondSweepHeartbeatMaxAge+time.Minute, false)
		n.Status.Conditions[1].LastHeartbeatTime = old
		cs := fake.NewSimpleClientset(n)
		p := testProberDyn(cs, probetest.OpDyn())
		if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
			t.Errorf("%s: zombie True did not fail the check", name)
			continue
		}
		got, err := cs.CoreV1().Nodes().Get(ctx, "w-sweep-"+name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c := kube.NodeCondition(got, corev1.NodeConditionType(name))
		if c == nil || c.Status != corev1.ConditionFalse {
			t.Errorf("%s: zombie condition = %+v, want Status=False swept", name, c)
		}
	}
	// And nothing outside the allowlist: the agent-carried-but-
	// permanent KernelDeadlock latch must NOT appear in the swept
	// set (InodePressure is in since inode-pressure — pinned by the sweep
	// loop above).
	for _, c := range nodeCondSweptConds {
		if c == "KernelDeadlock" {
			t.Error("KernelDeadlock must not be swept — permanent latch")
		}
	}
}

// The post-patch invalidation must be node-scoped: the cleared zombie
// drops the NODE census (and arms the next AllNodes to re-read d.CS
// past the informer cache) but must NOT wipe the rest of the sweep
// snapshot — a node status patch cannot stale pods, and a sweep-wide
// InvalidateSweep here forced every later check to re-LIST the whole
// census for nothing.
func TestNodeCondSweeperPatchInvalidatesNodesOnly(t *testing.T) {
	n := probetest.ReadyWorkerNode("w-zombie", "KubeletPLEGUnhealthy",
		nodeCondSweepHeartbeatMaxAge+time.Minute, false)
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeCondSweepHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(n,
		probetest.ReadyWorkerNode("w-ok", "", 0, false),
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
	chk := probetest.MustCheck[*nodeCondSweepCheck](t, p)
	sweepCtx := probefw.WithSweepSnapshot(ctx)
	// Warm the snapshot: one pod census, one node census.
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
		t.Fatal("zombie condition did not fail the check")
	}
	// The patch landed; re-reading the pod census must hit the
	// memoized snapshot — a sweep-wide wipe would re-LIST here.
	if _, err := chk.AllPods(sweepCtx); err != nil {
		t.Fatal(err)
	}
	if podLists != 1 {
		t.Fatalf("node patch re-listed pods %d time(s) — sweep-wide wipe, want 0", podLists-1)
	}
	// The next node census is the armed direct-CS re-read — it must
	// carry the PATCHED node, not a lagging informer copy.
	fresh, err := chk.AllNodes(sweepCtx)
	if err != nil {
		t.Fatal(err)
	}
	if nodeLists != 2 {
		t.Fatalf("node census reads=%d, want 2 (memo + one armed re-read)", nodeLists)
	}
	for i := range fresh {
		if fresh[i].Name != "w-zombie" {
			continue
		}
		if c := kube.NodeCondition(&fresh[i], "KubeletPLEGUnhealthy"); c == nil || c.Status != corev1.ConditionFalse {
			t.Fatalf("post-patch census carries the stale pre-patch copy: %+v", c)
		}
	}
}

// A NotReady node is mid-rescue — NHC/SNR/FAR own its conditions
// now, so the sweeper must not erase the evidence the remediation
// path reads. The zombie True survives untouched and the check
// stays quiet.
func TestNodeCondSweeperSkipsNotReadyNode(t *testing.T) {
	n := probetest.ReadyWorkerNode("w-notready", "KubeletPLEGUnhealthy",
		nodeCondSweepHeartbeatMaxAge+time.Minute, false)
	// Flip Ready to False — kubelet is down, the rescue path owns
	// this node's conditions now.
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == corev1.NodeReady {
			n.Status.Conditions[i].Status = corev1.ConditionFalse
		}
	}
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeCondSweepHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(n,
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("NotReady node's zombie must be left for the rescue path: %+v", res)
	}
	got, err := cs.CoreV1().Nodes().Get(ctx, "w-notready", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := kube.NodeCondition(got, "KubeletPLEGUnhealthy")
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("NotReady zombie condition = %+v, want Status=True untouched", c)
	}
}

// The zombie TTL is 25m — a condition whose heartbeat froze 20m ago
// is still inside the NHC remediation window (WatchdogStale allows
// 1200s) and must NOT be swept yet; only past 25m does the sweeper
// call the writer dead.
func TestNodeCondSweeperTTLBoundary(t *testing.T) {
	// 20m-frozen heartbeat: inside the window → untouched.
	n := probetest.ReadyWorkerNode("w-mid", "KubeletPLEGUnhealthy",
		nodeCondSweepHeartbeatMaxAge, false)
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-20 * time.Minute))
	n.Status.Conditions[1].LastTransitionTime =
		metav1.NewTime(time.Now().Add(-20 * time.Minute))
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("20m-frozen condition must survive inside the TTL: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-mid", metav1.GetOptions{})
	if c := kube.NodeCondition(got, "KubeletPLEGUnhealthy"); c == nil ||
		c.Status != corev1.ConditionTrue {
		t.Fatalf("20m zombie = %+v, want Status=True untouched", c)
	}
}

// ---------------------------------------------------------------------------
// The action-heartbeat group: LocalRemediationInProgress is stamped
// True by node-host-agent per remediation ACTION — its frozen
// heartbeat is the NORMAL episode end (consumers already ignore it
// past the 3m lease), so the sweeper garbage-collects the stale
// True on its own shorter TTL instead of waiting for a reporter
// that never re-stamps it.
// ---------------------------------------------------------------------------

// remediationNode builds a Ready worker carrying a
// LocalRemediationInProgress condition with the given heartbeat and
// transition ages.
func remediationNode(name string, hbAge, transAge time.Duration) *corev1.Node {
	n := probetest.ReadyWorkerNode("w-"+name, "",
		0, false)
	old := metav1.NewTime(time.Now().Add(-transAge))
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               corev1.NodeConditionType(nodecond.CondLocalRemediation),
		Status:             corev1.ConditionTrue,
		Reason:             "L1SelfHeal",
		LastHeartbeatTime:  metav1.NewTime(time.Now().Add(-hbAge)),
		LastTransitionTime: old,
	})
	return n
}

// An episode whose heartbeat froze past the 10m remediation TTL is
// garbage-collected to False — the stale True no longer reads as
// in-progress on kubectl describe.
func TestNodeCondSweeperClearsExpiredRemediation(t *testing.T) {
	n := remediationNode("expired",
		nodeCondRemediationSweepMaxAge+time.Minute,
		nodeCondRemediationSweepMaxAge+time.Minute)
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	before := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues("w-expired", nodecond.CondLocalRemediation))
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("expired remediation cleanup must not fail the check: %+v", res)
	}
	if delta := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues("w-expired", nodecond.CondLocalRemediation)) - before; delta != 1 {
		t.Fatalf("sweeps_total delta = %v, want 1", delta)
	}
	got, err := cs.CoreV1().Nodes().Get(ctx, "w-expired", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := kube.NodeCondition(got, nodecond.CondLocalRemediation)
	if c == nil || c.Status != corev1.ConditionFalse {
		t.Fatalf("expired remediation = %+v, want Status=False", c)
	}
	if c.Reason != "StaleConditionCleared" {
		t.Fatalf("cleared reason = %q, want StaleConditionCleared", c.Reason)
	}
}

// A LIVE episode — heartbeat inside the 10m TTL — is never
// second-guessed: the agent may stamp again at any moment.
func TestNodeCondSweeperKeepsLiveRemediation(t *testing.T) {
	n := remediationNode("live", time.Minute, time.Hour)
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("live remediation failed the check: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-live", metav1.GetOptions{})
	c := kube.NodeCondition(got, nodecond.CondLocalRemediation)
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("live remediation = %+v, want Status=True untouched", c)
	}
}

// Between the 3m consumer lease and the 10m sweep TTL the sweeper
// still holds its fire — consumers ignore the expired condition on
// their own, but the object keeps its True until the episode TTL
// proves no writer will ever stamp again.
func TestNodeCondSweeperKeepsRecentRemediationExpiry(t *testing.T) {
	n := remediationNode("recent",
		5*time.Minute, 5*time.Minute)
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("5m-expired remediation must survive inside the sweep TTL: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-recent", metav1.GetOptions{})
	c := kube.NodeCondition(got, nodecond.CondLocalRemediation)
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("5m-expired remediation = %+v, want Status=True untouched", c)
	}
}

// The remediation group is deliberately separate from
// HeartbeatSweptNames — nodereporter does not own or re-stamp this
// condition, so it must never appear in the reporter-owned allowlist
// (whose 25m TTL and AgentHeartbeatManaged semantics assume a
// per-cycle heartbeat writer).
func TestNodeCondSweeperRemediationGroupIsSeparate(t *testing.T) {
	for _, c := range nodeCondSweptConds {
		if c == corev1.NodeConditionType(nodecond.CondLocalRemediation) {
			t.Fatal("LocalRemediationInProgress must not join HeartbeatSweptNames — nodereporter does not own it")
		}
	}
	found := false
	for _, c := range nodeCondRemediationConds {
		if c == corev1.NodeConditionType(nodecond.CondLocalRemediation) {
			found = true
		}
	}
	if !found {
		t.Fatal("LocalRemediationInProgress missing from the remediation sweep group")
	}
}

func TestNodeCondSweeperMixedZombieAndExpiredRemediation(t *testing.T) {
	n := probetest.ReadyWorkerNode("w-mixed", "KubeletPLEGUnhealthy",
		nodeCondSweepHeartbeatMaxAge+time.Minute, false)
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeCondSweepHeartbeatMaxAge - time.Minute))
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               corev1.NodeConditionType(nodecond.CondLocalRemediation),
		Status:             corev1.ConditionTrue,
		Reason:             "L1SelfHeal",
		LastHeartbeatTime:  metav1.NewTime(time.Now().Add(-nodeCondRemediationSweepMaxAge - time.Minute)),
		LastTransitionTime: metav1.NewTime(time.Now().Add(-nodeCondRemediationSweepMaxAge - time.Minute)),
	})
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("mixed zombie KubeletPLEGUnhealthy + expired remediation must FAIL")
	}
	if !strings.Contains(res.Why, "KubeletPLEGUnhealthy") {
		t.Fatalf("res.Why missing zombie condition KubeletPLEGUnhealthy: %q", res.Why)
	}
	if strings.Contains(res.Why, nodecond.CondLocalRemediation) {
		t.Fatalf("res.Why must not blame normal expired %s: %q", nodecond.CondLocalRemediation, res.Why)
	}
	got, err := cs.CoreV1().Nodes().Get(ctx, "w-mixed", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, condType := range []corev1.NodeConditionType{"KubeletPLEGUnhealthy", corev1.NodeConditionType(nodecond.CondLocalRemediation)} {
		c := kube.NodeCondition(got, condType)
		if c == nil || c.Status != corev1.ConditionFalse {
			t.Fatalf("%s not cleared to False: %+v", condType, c)
		}
	}
}

// ---------------------------------------------------------------------------
// Stale kured-reboot-in-progress annotation cleanup: kured stamps an
// RFC3339 timestamp when starting a reboot drain; if kured crashes or
// aborts mid-drain, the annotation remains stranded indefinitely.
// ---------------------------------------------------------------------------

func kuredNode(name string, ready bool, annos map[string]string, taints ...corev1.Taint) *corev1.Node {
	n := probetest.ReadyWorkerNode(name, "", 0, false)
	if !ready {
		for i := range n.Status.Conditions {
			if n.Status.Conditions[i].Type == corev1.NodeReady {
				n.Status.Conditions[i].Status = corev1.ConditionFalse
			}
		}
	}
	n.Annotations = annos
	n.Spec.Taints = taints
	return n
}

func kuredDS(annos map[string]string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        kuredDaemonSetName,
			Namespace:   kuredDaemonSetNS,
			Annotations: annos,
		},
	}
}

func TestNodeCondSweeperClearsStaleKuredAnnotation(t *testing.T) {
	staleStamp := time.Now().Add(-kuredRebootInProgressMaxAge - 5*time.Minute).UTC().Format(time.RFC3339)
	cases := []struct {
		name string
		ds   *appsv1.DaemonSet
	}{
		{name: "no kured DaemonSet", ds: nil},
		{name: "kured DaemonSet without lock", ds: kuredDS(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodeName := "w-kured-stale-" + strings.ReplaceAll(tc.name, " ", "-")
			n := kuredNode(nodeName, true, map[string]string{
				nodecond.KuredRebootInProgressAnno: staleStamp,
				"keep.example.com/other":           "preserved",
			})
			objs := []runtime.Object{n}
			if tc.ds != nil {
				objs = append(objs, tc.ds)
			}
			cs := fake.NewSimpleClientset(objs...)
			p := testProberDyn(cs, probetest.OpDyn())
			sweepCtx := probetest.SweepCtx(ctx, p.Deps)
			before := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues(nodeName, "kured-reboot-in-progress"))
			if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(sweepCtx); !res.Pass {
				t.Fatalf("stale kured annotation cleanup must pass silently, got: %+v", res)
			}
			if delta := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues(nodeName, "kured-reboot-in-progress")) - before; delta != 1 {
				t.Fatalf("sweeps_total delta = %v, want 1", delta)
			}
			got, err := cs.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := got.Annotations[nodecond.KuredRebootInProgressAnno]; ok {
				t.Fatalf("stale %s annotation still present: %v",
					nodecond.KuredRebootInProgressAnno, got.Annotations)
			}
			if got.Annotations["keep.example.com/other"] != "preserved" {
				t.Fatalf("unrelated annotation lost: %v", got.Annotations)
			}
			if eff := kube.EffectiveAnno(sweepCtx, n, nodecond.KuredRebootInProgressAnno); eff != "" {
				t.Fatalf("sweep overlay EffectiveAnno = %q, want empty after patch", eff)
			}
		})
	}
}

func TestNodeCondSweeperKeepsFreshOrUnparseableKuredAnnotation(t *testing.T) {
	freshStamp := time.Now().Add(-kuredRebootInProgressMaxAge + 10*time.Minute).UTC().Format(time.RFC3339)
	cases := []struct {
		name  string
		stamp string
	}{
		{name: "fresh under 2h", stamp: freshStamp},
		{name: "unparseable", stamp: "not-a-timestamp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodeName := "w-kured-" + strings.ReplaceAll(tc.name, " ", "-")
			n := kuredNode(nodeName, true, map[string]string{
				nodecond.KuredRebootInProgressAnno: tc.stamp,
			})
			cs := fake.NewSimpleClientset(n)
			var dsGets int
			cs.PrependReactor("get", "daemonsets", func(ktesting.Action) (bool, runtime.Object, error) {
				dsGets++
				return false, nil, nil
			})
			p := testProberDyn(cs, probetest.OpDyn())
			before := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues(nodeName, "kured-reboot-in-progress"))
			if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
				t.Fatalf("unexpected failure: %+v", res)
			}
			if dsGets != 0 {
				t.Fatalf("kured DaemonSet fetched %d times with no candidate nodes, want 0", dsGets)
			}
			if delta := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues(nodeName, "kured-reboot-in-progress")) - before; delta != 0 {
				t.Fatalf("sweeps_total delta = %v, want 0", delta)
			}
			got, _ := cs.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if got.Annotations[nodecond.KuredRebootInProgressAnno] != tc.stamp {
				t.Fatalf("annotation changed = %q, want %q untouched",
					got.Annotations[nodecond.KuredRebootInProgressAnno], tc.stamp)
			}
		})
	}
}

func TestNodeCondSweeperSkipsNotReadyNodeKuredAnnotation(t *testing.T) {
	staleStamp := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	n := kuredNode("w-kured-notready", false, map[string]string{
		nodecond.KuredRebootInProgressAnno: staleStamp,
	})
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	before := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues("w-kured-notready", "kured-reboot-in-progress"))
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("unexpected failure: %+v", res)
	}
	if delta := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues("w-kured-notready", "kured-reboot-in-progress")) - before; delta != 0 {
		t.Fatalf("sweeps_total delta = %v, want 0", delta)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-kured-notready", metav1.GetOptions{})
	if got.Annotations[nodecond.KuredRebootInProgressAnno] != staleStamp {
		t.Fatalf("NotReady node annotation modified: %v", got.Annotations)
	}
}

func TestNodeCondSweeperSkipsKuredAnnotationWhenNodeLockedOrTainted(t *testing.T) {
	staleStamp := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	nLock := kuredNode("w-node-lock", true, map[string]string{
		nodecond.KuredRebootInProgressAnno: staleStamp,
		nodecond.KuredLockAnno:             `{"nodeID":"w-node-lock"}`,
	})
	nTaint := kuredNode("w-node-taint", true, map[string]string{
		nodecond.KuredRebootInProgressAnno: staleStamp,
	}, corev1.Taint{Key: nodecond.KuredRebootTaintKey, Effect: corev1.TaintEffectNoSchedule})

	cs := fake.NewSimpleClientset(nLock, nTaint)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("unexpected failure: %+v", res)
	}
	for _, name := range []string{"w-node-lock", "w-node-taint"} {
		got, _ := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if got.Annotations[nodecond.KuredRebootInProgressAnno] != staleStamp {
			t.Fatalf("%s annotation cleared despite node-level lock/taint", name)
		}
	}
}

func TestNodeCondSweeperRespectsKuredDaemonSetLockScope(t *testing.T) {
	staleStamp := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)

	// DS holds lock for w-locked: w-locked is skipped, w-other is cleaned,
	// and the DS lookup happens at most once per sweep.
	nLocked := kuredNode("w-locked", true, map[string]string{
		nodecond.KuredRebootInProgressAnno: staleStamp,
	})
	nOther := kuredNode("w-other", true, map[string]string{
		nodecond.KuredRebootInProgressAnno: staleStamp,
	})
	ds := kuredDS(map[string]string{
		nodecond.KuredLockAnno: `{"nodeID":"w-locked"}`,
	})
	cs := fake.NewSimpleClientset(nLocked, nOther, ds)
	var dsGets int
	cs.PrependReactor("get", "daemonsets", func(ktesting.Action) (bool, runtime.Object, error) {
		dsGets++
		return false, nil, nil
	})
	p := testProberDyn(cs, probetest.OpDyn())
	beforeLocked := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues("w-locked", "kured-reboot-in-progress"))
	beforeOther := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues("w-other", "kured-reboot-in-progress"))
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("unexpected failure: %+v", res)
	}
	if dsGets != 1 {
		t.Fatalf("kured DaemonSet fetched %d times, want 1", dsGets)
	}
	if delta := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues("w-locked", "kured-reboot-in-progress")) - beforeLocked; delta != 0 {
		t.Fatalf("w-locked sweeps_total delta = %v, want 0", delta)
	}
	if delta := ptestutil.ToFloat64(nodeCondSweepsTotal.WithLabelValues("w-other", "kured-reboot-in-progress")) - beforeOther; delta != 1 {
		t.Fatalf("w-other sweeps_total delta = %v, want 1", delta)
	}
	gotLocked, _ := cs.CoreV1().Nodes().Get(ctx, "w-locked", metav1.GetOptions{})
	if gotLocked.Annotations[nodecond.KuredRebootInProgressAnno] != staleStamp {
		t.Fatalf("w-locked annotation cleared while DS holds its lock: %v", gotLocked.Annotations)
	}
	gotOther, _ := cs.CoreV1().Nodes().Get(ctx, "w-other", metav1.GetOptions{})
	if _, ok := gotOther.Annotations[nodecond.KuredRebootInProgressAnno]; ok {
		t.Fatalf("w-other annotation not cleared while DS lock targets w-locked: %v", gotOther.Annotations)
	}
}

func TestNodeCondSweeperFailsClosedOnUnparseableLockOrDSError(t *testing.T) {
	staleStamp := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)

	t.Run("unparseable DS lock", func(t *testing.T) {
		n := kuredNode("w-unparseable", true, map[string]string{
			nodecond.KuredRebootInProgressAnno: staleStamp,
		})
		ds := kuredDS(map[string]string{
			nodecond.KuredLockAnno: `{not-valid-json`,
		})
		cs := fake.NewSimpleClientset(n, ds)
		p := testProberDyn(cs, probetest.OpDyn())
		if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
			t.Fatalf("unexpected failure: %+v", res)
		}
		got, _ := cs.CoreV1().Nodes().Get(ctx, "w-unparseable", metav1.GetOptions{})
		if got.Annotations[nodecond.KuredRebootInProgressAnno] != staleStamp {
			t.Fatalf("annotation cleared despite unparseable DS lock")
		}
	})

	t.Run("unscoped JSON DS lock", func(t *testing.T) {
		n := kuredNode("w-unscoped", true, map[string]string{
			nodecond.KuredRebootInProgressAnno: staleStamp,
		})
		ds := kuredDS(map[string]string{
			nodecond.KuredLockAnno: `{}`,
		})
		cs := fake.NewSimpleClientset(n, ds)
		p := testProberDyn(cs, probetest.OpDyn())
		if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
			t.Fatalf("unexpected failure: %+v", res)
		}
		got, _ := cs.CoreV1().Nodes().Get(ctx, "w-unscoped", metav1.GetOptions{})
		if got.Annotations[nodecond.KuredRebootInProgressAnno] != staleStamp {
			t.Fatalf("annotation cleared despite unscoped DS lock")
		}
	})

	t.Run("DS Get API error", func(t *testing.T) {
		n := kuredNode("w-ds-err", true, map[string]string{
			nodecond.KuredRebootInProgressAnno: staleStamp,
		})
		cs := fake.NewSimpleClientset(n)
		cs.PrependReactor("get", "daemonsets", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("apiserver timeout"))
		})
		p := testProberDyn(cs, probetest.OpDyn())
		if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
			t.Fatalf("unexpected failure: %+v", res)
		}
		got, _ := cs.CoreV1().Nodes().Get(ctx, "w-ds-err", metav1.GetOptions{})
		if got.Annotations[nodecond.KuredRebootInProgressAnno] != staleStamp {
			t.Fatalf("annotation cleared despite DS Get error")
		}
		// Ensure error does not panic and no patch was issued.
		for _, act := range cs.Actions() {
			if act.GetVerb() == "patch" && act.GetResource().Resource == "nodes" {
				t.Fatalf("unexpected node patch on DS Get error: %+v", act)
			}
		}
	})
}

// node_condition_sweeper_test.go — coverage for the
// node-condition-sweeper check: stale-heartbeat zombie True
// conditions get patched False, live-heartbeat conditions and
// non-managed types are never touched.
package nodehealth

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// A True managed condition whose heartbeat froze is reconciled to
// False — the 2026-11-07 zombie left by a wedged reporter.
func TestNodeCondSweeperClearsZombie(t *testing.T) {
	n := probetest.ReadyWorkerNode("w-zombie", "KubeletPLEGUnhealthy",
		nodeHangCondHeartbeatMaxAge+time.Minute, false)
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeHangCondHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(n,
		probetest.ReadyWorkerNode("w-ok", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(ctx); res.Pass {
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
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(ctx); !res.Pass {
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
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(ctx); !res.Pass {
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
	old := metav1.NewTime(time.Now().Add(-2 * nodeHangCondHeartbeatMaxAge))
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
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(ctx); !res.Pass {
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
	old := metav1.NewTime(time.Now().Add(-nodeHangCondHeartbeatMaxAge - time.Minute))
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               "KubeletPLEGUnhealthy",
		Status:             corev1.ConditionTrue,
		Reason:             "KubeletPLEGUnhealthyDetected",
		LastHeartbeatTime:  old,
		LastTransitionTime: old,
	})
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("zombie condition did not fail the check")
	}
	// The precordon's own sweep now sees no active latch → auto-uncordon.
	if res := probetest.MustCheck[*nodeHangCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("precordon sweep after clear failed: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-held", metav1.GetOptions{})
	if got.Spec.Unschedulable {
		t.Fatal("stamped cordon did not lift after zombie clear")
	}
}

// InodePressure is agent-latched since W18-1 (hostmetrics
// state-inode-pressure) and kubelet never emits a condition of this
// type — a frozen heartbeat on it can only be a dead reporter's
// zombie, so the sweeper clears it like any other HeartbeatSweptNames
// member. The remaining split (KernelDeadlock permanent, kubelet
// condition types untouched) is pinned by nodecond.
func TestNodeCondSweeperSweepsFrozenInodePressure(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-2 * nodeHangCondHeartbeatMaxAge))
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
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(ctx); res.Pass {
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
		nodeHangCondHeartbeatMaxAge+time.Minute, false)
	n.Status.Conditions[1].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-nodeHangCondHeartbeatMaxAge - time.Minute))
	cs := fake.NewSimpleClientset(n)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(ctx); res.Pass {
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
// joined in W18 (NodeOverloaded, WatchdogStale, DnsFallbackActive,
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
	old := metav1.NewTime(time.Now().Add(-2 * nodeHangCondHeartbeatMaxAge))
	for _, name := range nodecond.HeartbeatSweptNames {
		n := probetest.ReadyWorkerNode("w-sweep-"+name, corev1.NodeConditionType(name),
			nodeHangCondHeartbeatMaxAge+time.Minute, false)
		n.Status.Conditions[1].LastHeartbeatTime = old
		cs := fake.NewSimpleClientset(n)
		p := testProberDyn(cs, probetest.OpDyn())
		if res := probetest.MustCheck[*nodeCondSweepCheck](t, p).Run(ctx); res.Pass {
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
	// And nothing outside the allowlist: kubelet-native InodePressure
	// (pinned above) plus the agent-carried-but-permanent
	// KernelDeadlock latch must NOT appear in the swept set.
	for _, c := range nodeCondSweptConds {
		if c == "KernelDeadlock" {
			t.Error("KernelDeadlock must not be swept — permanent latch")
		}
	}
}

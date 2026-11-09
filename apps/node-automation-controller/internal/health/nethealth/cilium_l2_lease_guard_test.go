// cilium_l2_lease_guard_test.go — coverage for the
// cilium-l2-lease-guard check (cilium-l2-lease-guard): the stale-holder predicate
// matrix (every reason), the healthy-holder pass, the two-cycle
// cilium-agent not-Ready streak, and the heal-gated Lease delete.
package nethealth

import (
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// l2Lease builds a cilium-l2announce Lease held by holder.
func l2Lease(name, holder string) *coordinationv1.Lease {
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: name,
			UID: types.UID("lease-uid-" + name),
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(holder)},
	}
}

// l2Node builds a node with the given shapes flipped on.
func l2Node(name string, notReady, netUnavail, unsched, controlPlane bool) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name,
		Labels: map[string]string{}}}
	ready := corev1.NodeCondition{Type: corev1.NodeReady,
		Status: corev1.ConditionTrue}
	if notReady {
		ready.Status = corev1.ConditionFalse
	}
	n.Status.Conditions = append(n.Status.Conditions, ready)
	if netUnavail {
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
			Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionTrue})
	}
	n.Spec.Unschedulable = unsched
	if controlPlane {
		n.Labels[l2ControlPlaneRoleLabel] = ""
	}
	return n
}

// TestCiliumL2StaleHolderReasons — the predicate matrix: each
// stale-holder reason fires alone; a fully healthy holder reads
// empty.
func TestCiliumL2StaleHolderReasons(t *testing.T) {
	lease := l2Lease("cilium-l2announce-web_apps", "node-a")

	cases := []struct {
		name         string
		node         *corev1.Node
		agentNotRedy bool
		want         []string
	}{
		{"node gone", nil, false,
			[]string{l2ReasonNodeMissing}},
		{"not ready", l2Node("a", true, false, false, false), false,
			[]string{l2ReasonNodeNotReady}},
		{"network unavailable", l2Node("a", false, true, false, false), false,
			[]string{l2ReasonNetUnavail}},
		{"unschedulable", l2Node("a", false, false, true, false), false,
			[]string{l2ReasonUnschedulable}},
		{"control plane", l2Node("a", false, false, false, true), false,
			[]string{l2ReasonControlPlane}},
		{"agent not ready", l2Node("a", false, false, false, false), true,
			[]string{l2ReasonAgentNotReady}},
		{"healthy holder", l2Node("a", false, false, false, false), false,
			nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ciliumL2StaleHolderReasons(lease, tc.node,
				tc.agentNotRedy)
			if len(got) != len(tc.want) {
				t.Fatalf("reasons = %v, want %v", got, tc.want)
			}
			for i, r := range tc.want {
				if got[i] != r {
					t.Fatalf("reasons = %v, want %v", got, tc.want)
				}
			}
		})
	}
	// An empty holderIdentity is the node_missing class too.
	if got := ciliumL2StaleHolderReasons(
		l2Lease("cilium-l2announce-x_y", ""), nil, false); len(got) != 1 ||
		got[0] != l2ReasonNodeMissing {
		t.Fatalf("empty holder reasons = %v, want [node_missing]", got)
	}
	// Multiple reasons fire together on one holder.
	node := l2Node("a", true, false, true, true)
	got := ciliumL2StaleHolderReasons(lease, node, false)
	if len(got) != 3 {
		t.Fatalf("compound reasons = %v, want 3", got)
	}
}

// TestCiliumL2LeaseGuardFlagsAndDeletes — a lease held by a gone
// node flags node_missing and is deleted under the heal gate; a
// healthy holder passes clean.
func TestCiliumL2LeaseGuardFlagsAndDeletes(t *testing.T) {
	healthy := l2Node("w-ok", false, false, false, false)
	cs := fake.NewSimpleClientset(
		l2Lease("cilium-l2announce-web_dead", "w-gone"),
		l2Lease("cilium-l2announce-web_ok", "w-ok"),
		healthy)
	p := testProber(cs)
	chk := probetest.MustCheck[*ciliumL2LeaseGuardCheck](t, p)

	res := chk.Run(ctx)
	if res.Pass {
		t.Fatalf("stale holder must fail the check: %+v", res)
	}
	if !ciliumL2StaleLeaseGauge.DeleteLabelValues(
		"cilium-l2announce-web_dead", "w-gone", l2ReasonNodeMissing) {
		t.Fatal("missing node_missing series for the stale lease")
	}
	if ciliumL2StaleLeaseGauge.DeleteLabelValues(
		"cilium-l2announce-web_ok", "w-ok", "") {
		t.Fatal("healthy holder flagged")
	}
	// The heal gate ran: the stale lease is gone, the healthy one
	// survives, and the delivered delete stamped the cooldown.
	if _, err := cs.CoordinationV1().Leases("kube-system").
		Get(ctx, "cilium-l2announce-web_dead", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("stale lease should be deleted, err=%v", err)
	}
	if _, err := cs.CoordinationV1().Leases("kube-system").
		Get(ctx, "cilium-l2announce-web_ok", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy lease must survive: %v", err)
	}
	if !p.Heals.CooledDown("selfheal/"+CheckNameCiliumL2LeaseGuard+
		"/lease/cilium-l2announce-web_dead",
		ciliumL2LeaseHealCool-time.Minute, time.Now()) {
		t.Fatal("delivered delete did not stamp the heal cooldown")
	}
	// The ledger reconciled: after the heal the flagged tuple no
	// longer re-asserts, so a second sweep passes (lease gone).
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("post-heal sweep must pass: %+v", res)
	}
	ciliumL2StaleLeaseGauge.DeleteLabelValues("cilium-l2announce-web_dead",
		"w-gone", l2ReasonNodeMissing)
}

// TestCiliumL2LeaseGuardAgentStreak — the cilium_agent_not_ready
// reason fires only after the holder's cilium-agent pod reads
// not-Ready for >= 2 consecutive sweep cycles; a Ready sweep resets.
func TestCiliumL2LeaseGuardAgentStreak(t *testing.T) {
	node := l2Node("w-ag", false, false, false, false)
	agent := probetest.PodWithPhase("kube-system", "cilium-w-ag",
		corev1.PodRunning, false, time.Hour)
	agent.Labels = map[string]string{"k8s-app": "cilium"}
	agent.Spec.NodeName = "w-ag"
	cs := fake.NewSimpleClientset(
		l2Lease("cilium-l2announce-web_apps", "w-ag"), node, agent)
	p := testProber(cs)
	chk := probetest.MustCheck[*ciliumL2LeaseGuardCheck](t, p)

	for cycle := 1; cycle <= 3; cycle++ {
		res := chk.Run(ctx)
		flagged := ciliumL2StaleLeaseGauge.DeleteLabelValues(
			"cilium-l2announce-web_apps", "w-ag", l2ReasonAgentNotReady)
		if cycle == 1 && flagged {
			t.Fatal("cycle 1: one not-Ready sweep must not flag yet")
		}
		if cycle == 1 && !res.Pass {
			t.Fatalf("cycle 1 must pass: %+v", res)
		}
		if cycle == 2 && !flagged {
			t.Fatal("cycle 2: two consecutive not-Ready sweeps must flag")
		}
		// Cycle 3: heal the agent pod — the Ready sweep resets the
		// streak, and the following lone not-Ready cycle must NOT
		// flag again (streak re-armed at 1).
		if cycle == 2 {
			agent.Status.Conditions = []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue}}
			if _, err := cs.CoreV1().Pods("kube-system").
				UpdateStatus(ctx, agent, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if res := chk.Run(ctx); !res.Pass {
				t.Fatalf("ready agent sweep must pass: %+v", res)
			}
			agent.Status.Conditions = nil
			if _, err := cs.CoreV1().Pods("kube-system").
				UpdateStatus(ctx, agent, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			res := chk.Run(ctx)
			if flagged := ciliumL2StaleLeaseGauge.DeleteLabelValues(
				"cilium-l2announce-web_apps", "w-ag", l2ReasonAgentNotReady); flagged || !res.Pass {
				t.Fatalf("reset streak: one not-Ready cycle must not flag (res=%+v)", res)
			}
			return
		}
	}
}

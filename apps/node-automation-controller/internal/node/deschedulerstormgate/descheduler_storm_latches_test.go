package deschedulerstormgate

import (
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// Every latch in stormConds gates the descheduler exactly like the
// original storm conditions — the node-host-agent overlay, kernel,
// kubelet and CNI latches included, now spelled the way nodecond (the
// agent shared source of truth) spells them: SystemdSessionBloat,
// ConntrackPressure, JournaldUnreadable, ControlPlaneCertReloadStale
// and the new CiliumBPFMapPressure among them.
func TestStormGateScalesDownOnLatchConditions(t *testing.T) {
	for _, cond := range stormConds {
		cs := fake.NewSimpleClientset(
			withStormCond(testutil.Node("n1", corev1.ConditionTrue, nil), cond),
			deschedulerDeploy(1, nil))
		r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		if got := getDeschedulerReplicas(t, cs); got != 0 {
			t.Fatalf("condition %s must gate the descheduler, replicas=%d", cond, got)
		}
	}
}

// The agent's renamed spellings are the storm-gate contract now: a
// node carrying SystemdSessionBloat True (the agent's name for the
// legacy SystemdSessionLeak latch — plus the other renames and the
// new CiliumBPFMapPressure) storms, and the legacy spellings are gone
// from the list so the gate can never wait on a name the agent
// stopped emitting.
func TestStormGateDetectsRenamedConditions(t *testing.T) {
	for _, legacy := range []string{
		"SystemdSessionLeak", "ConntrackExhausted",
		"JournaldWedged", "ControlPlaneFrozen",
	} {
		if slices.Contains(stormConds, corev1.NodeConditionType(legacy)) {
			t.Fatalf("legacy spelling %s still in stormConds — nodecond is the source of truth", legacy)
		}
	}
	for _, renamed := range []corev1.NodeConditionType{
		nodecond.SystemdSessionBloat, nodecond.ConntrackPressure,
		nodecond.JournaldUnreadable, nodecond.ControlPlaneCertReloadStale,
		nodecond.CiliumBPFMapPressure,
	} {
		cs := fake.NewSimpleClientset(
			withStormCond(testutil.Node("n1", corev1.ConditionTrue, nil), renamed),
			deschedulerDeploy(1, nil))
		r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		if got := getDeschedulerReplicas(t, cs); got != 0 {
			t.Fatalf("renamed condition %s must storm, replicas=%d", renamed, got)
		}
	}
}

// A nodereporter-owned storm latch whose lastHeartbeatTime froze is a
// zombie — the wedged reporter cannot vouch for it, so it must NOT
// gate the descheduler; the same latch with a fresh heartbeat does.
func TestStormGateZombieHeartbeatDoesNotGate(t *testing.T) {
	node := testutil.Node("n1", corev1.ConditionTrue, nil)
	node.Status.Conditions = append(node.Status.Conditions, corev1.NodeCondition{
		Type:               nodecond.SystemdSessionBloat,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Hour)),
		LastHeartbeatTime: metav1.NewTime(time.Now().Add(
			-2 * stormCondHeartbeatMaxAge)),
	})
	cs := fake.NewSimpleClientset(node, deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("zombie storm latch held the descheduler at %d, want 1", got)
	}

	// A fresh heartbeat proves the writer alive — the latch gates.
	n1, err := cs.CoreV1().Nodes().Get(ctx, "n1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n1.Status.Conditions {
		if n1.Status.Conditions[i].Type == nodecond.SystemdSessionBloat {
			n1.Status.Conditions[i].LastHeartbeatTime = metav1.NewTime(time.Now())
		}
	}
	if _, err := cs.CoreV1().Nodes().UpdateStatus(ctx, n1, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("fresh-heartbeat storm latch did not gate, replicas=%d", got)
	}
}

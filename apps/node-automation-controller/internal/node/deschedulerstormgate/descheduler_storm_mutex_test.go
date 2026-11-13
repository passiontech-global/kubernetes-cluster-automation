package deschedulerstormgate

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// ---------------------------------------------------------------------------
// 2.7 — Cluster Maintenance Mutex
// ---------------------------------------------------------------------------

// Signal (a): a cordoned node is deliberate maintenance — the
// descheduler must stay at 0.
func TestStormGateScalesDownOnUnschedulableNode(t *testing.T) {
	n := testutil.Node("w1", corev1.ConditionTrue, nil)
	n.Spec.Unschedulable = true
	cs := fake.NewSimpleClientset(n, deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 while a node is cordoned, got %d", got)
	}
}

// Signal (b): kured holding its node-lock annotation means a reboot
// drain is in progress — the descheduler stays at 0.
func TestStormGateScalesDownOnKuredLock(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
		kuredDaemonSet(map[string]string{nodecond.KuredLockAnno: "w1"}))
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 while kured holds the lock, got %d", got)
	}
}

// Signal (c): an autopilot Plan outside its terminal states means a
// k0s upgrade is in flight — the descheduler stays at 0.
func TestStormGateScalesDownOnActivePlan(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	dyn := stormGateDynFake(autopilotPlan("autopilot", "InProgress"))
	r := &deschedulerStormGate{cs: cs, dyn: dyn}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 while an autopilot plan runs, got %d", got)
	}
}

// Terminal plan states are NOT maintenance — Schedulable/Completed
// plans must not gate the descheduler.
func TestStormGateTerminalPlansAreClear(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
		kuredDaemonSet(nil)) // kured present but holding no lock
	dyn := stormGateDynFake(
		autopilotPlan("old", "Completed"),
		autopilotPlan("idle", "Schedulable"))
	r := &deschedulerStormGate{cs: cs, dyn: dyn}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("terminal plan states must not scale, replicas=%d", got)
	}
}

// A plan with no status.state yet is not provably terminal — fail
// closed, it gates like an active upgrade.
func TestStormGateStatelessPlanIsStorm(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	dyn := stormGateDynFake(autopilotPlan("autopilot", ""))
	r := &deschedulerStormGate{cs: cs, dyn: dyn}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("a status-less plan must fail closed to storm, got %d", got)
	}
}

// A maintenance-check failure errors the reconcile — never a "clear"
// verdict on blind data.
func TestStormGateMaintenanceCheckError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("get", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the kured get fails")
	}
}

// ---------------------------------------------------------------------------
// maintenance-mutex memo — one mutex evaluation per verdict TTL.
// ---------------------------------------------------------------------------

// The maintenance-mutex evidence is memoized on the reconciler (the
// kube.Verdict pattern): the second reconcile inside the ~1m TTL
// window performs no dynamic API reads at all — every node
// storm-signal flip fans a full sweep into this single-key queue,
// and without the memo each node-event reconcile re-paid the mutex's
// autopilot Plan + medik8s remediation lists. (The NHC pause probe
// is deliberately excluded from the count: it is not memoized and
// runs per sweep.)
func TestStormGateMaintenanceEvidenceMemoized(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	dyn := stormGateDynFake()
	mutexLists := 0
	dyn.PrependReactor("list", "*",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetResource().Resource != kube.GVRNodeHealthCheck.Resource {
				mutexLists++
			}
			return false, nil, nil
		})
	r := &deschedulerStormGate{cs: cs, dyn: dyn,
		maintVerdict: &maintenance.Verdict{}}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if mutexLists == 0 {
		t.Fatal("cold reconcile paid no mutex dynamic reads")
	}
	first := mutexLists
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := mutexLists - first; got != 0 {
		t.Fatalf("second reconcile inside the TTL made %d dynamic reads — memo not consulted", got)
	}
}

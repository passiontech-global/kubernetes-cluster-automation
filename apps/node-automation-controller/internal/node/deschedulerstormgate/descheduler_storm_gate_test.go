package deschedulerstormgate

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// stormGateDynFake returns a dynamic fake that knows the PlanList
// kind for the maintenance-mutex autopilot check (the autopilot Plan
// CRD is in testutil.NewDynamicClient's baked-in table).
func stormGateDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
}

// autopilotPlan builds a Plan CR in `state` — "" renders no status at
// all (a brand-new Plan before the controller writes one).
func autopilotPlan(name, state string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "autopilot.k0sproject.io/v1beta2",
		"kind":       "Plan",
		"metadata":   map[string]any{"name": name},
	}}
	if state != "" {
		u.Object["status"] = map[string]any{"state": state}
	}
	return u
}

func kuredDaemonSet(annos map[string]string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "kured", Annotations: annos}}
}

func getDescheduler(t *testing.T, cs *fake.Clientset) *appsv1.Deployment {
	t.Helper()
	d, err := cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get descheduler: %v", err)
	}
	return d
}

// withStormCond returns a Ready node additionally carrying a latched
// storm condition (NPD/kubelet pressure style).
func withStormCond(n *corev1.Node, cond corev1.NodeConditionType) *corev1.Node {
	n.Status.Conditions = append(n.Status.Conditions,
		corev1.NodeCondition{Type: cond, Status: corev1.ConditionTrue})
	return n
}

func TestStormGateScalesDownOnStormCondition(t *testing.T) {
	// Ready=True is not enough — a latched True storm condition
	// (MemoryPressure here, one of stormConds) gates the descheduler.
	cs := fake.NewSimpleClientset(
		withStormCond(testutil.Node("n1", corev1.ConditionTrue, nil),
			corev1.NodeMemoryPressure),
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 on storm condition, got %d", got)
	}
}

func TestStormGateScalesDownOnStormTaint(t *testing.T) {
	// A stormTaints key (passiontech.dev/kubelet-unresponsive — set by the
	// reaper) on an otherwise healthy node also forces the verdict.
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, corev1.Taint{
			Key:    "passiontech.dev/kubelet-unresponsive",
			Effect: corev1.TaintEffectNoSchedule,
		}),
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 on storm taint, got %d", got)
	}
}

func TestStormGateIgnoresNonStormSignals(t *testing.T) {
	// A True condition outside stormConds (PIDPressure) plus an
	// unrelated taint must not gate anything.
	n := testutil.Node("n1", corev1.ConditionTrue, nil, corev1.Taint{
		Key:    "dedicated=special",
		Effect: corev1.TaintEffectNoSchedule,
	})
	n.Status.Conditions = append(n.Status.Conditions,
		corev1.NodeCondition{Type: corev1.NodePIDPressure, Status: corev1.ConditionTrue})
	cs := fake.NewSimpleClientset(n, deschedulerDeploy(1, nil))

	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("non-storm signals must not scale, replicas=%d", got)
	}
}

func TestStormGateDecisionAnnotatedOnce(t *testing.T) {
	// All clear + replicas already correct: the decision annotation
	// must still be written the first time (audit trail), but must
	// never be rewritten afterwards — no annotation churn.
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]; got == "" {
		t.Fatal("decision annotation not written on first clear verdict")
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas churned on a no-op verdict: %d", got)
	}

	// Second pass: a present annotation is left untouched. Write a
	// sentinel through the API and verify the reconciler does not
	// overwrite it.
	d := getDescheduler(t, cs)
	d.Annotations[stormGateDecisionAnno] = "sentinel"
	if _, err := cs.AppsV1().Deployments("kube-system").
		Update(ctx, d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]; got != "sentinel" {
		t.Fatalf("decision annotation churned: %q", got)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas changed on steady state: %d", got)
	}
}

func TestStormGateHoldOnlyWhenTrue(t *testing.T) {
	// passiontech.dev/storm-gate-hold=<anything-but-"true"> is not a
	// hold — scaling still happens during a storm.
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionFalse, nil),
		deschedulerDeploy(1, map[string]string{stormGateHoldAnno: "false"}))
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("hold=false must not block scaling, replicas=%d", got)
	}
}

func TestStormGateNoDeschedulerDeployment(t *testing.T) {
	// Cluster without descheduler — the reconcile is a clean no-op.
	// The IsNotFound skip runs BEFORE the maintenance mutex: a nil
	// dyn client AND a failing kured get prove neither ran — both
	// would have errored the reconcile on the old order.
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionFalse, nil))
	cs.PrependReactor("get", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("kured get must not run")
		})
	r := &deschedulerStormGate{cs: cs} // dyn nil — must not be consulted either
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("expected 5m requeue, got %s", res.RequeueAfter)
	}
}

// condStatusMap keeps only type->status — kubelet heartbeat churn
// (lastHeartbeatTime/reason/message) must not change the projection,
// or every node update would enqueue a full verdict.
func TestCondStatusMapIgnoresChurn(t *testing.T) {
	a := testutil.Node("n1", corev1.ConditionTrue, nil)
	a.Status.Conditions[0].LastHeartbeatTime = metav1.NewTime(time.Now())
	a.Status.Conditions[0].Reason = "KubeletReady"
	a.Status.Conditions[0].Message = "kubelet is posting ready"

	b := testutil.Node("n1", corev1.ConditionTrue, nil)
	b.Status.Conditions[0].LastHeartbeatTime = metav1.NewTime(time.Now().Add(time.Hour))
	b.Status.Conditions[0].Reason = "OtherReason"
	b.Status.Conditions[0].Message = "different message"

	if !reflect.DeepEqual(condStatusMap(a), condStatusMap(b)) {
		t.Fatal("condStatusMap must drop heartbeat churn fields")
	}

	// A real status change DOES change the projection.
	b.Status.Conditions[0].Status = corev1.ConditionFalse
	if reflect.DeepEqual(condStatusMap(a), condStatusMap(b)) {
		t.Fatal("condStatusMap missed a status flip")
	}
}

// taintKeys is the jqFilter projection — keys only, in order.
func TestTaintKeys(t *testing.T) {
	n := testutil.Node("n1", corev1.ConditionTrue, nil,
		corev1.Taint{Key: "a", Value: "1", Effect: corev1.TaintEffectNoSchedule},
		corev1.Taint{Key: "b", Effect: corev1.TaintEffectNoExecute})
	got := taintKeys(n)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("taintKeys = %v, want [a b]", got)
	}
	if got := taintKeys(testutil.Node("n2", corev1.ConditionTrue, nil)); len(got) != 0 {
		t.Fatalf("taintKeys on untainted node = %v", got)
	}
}

// An empty-but-successful node list is an apiserver/RBAC flap, not a
// healthy cluster — the reconcile errors instead of scaling the
// descheduler up on blind data.
func TestStormGateEmptyNodeList(t *testing.T) {
	cs := fake.NewSimpleClientset(deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error on an empty node list")
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas changed on blind data: %d", got)
	}
}

// A nil dynamic client makes the autopilot check unverifiable —
// fail closed like any other check error, never "no signal".
func TestStormGateNilDynFailsClosed(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs} // dyn nil — wiring bug
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas changed on an unverifiable mutex check: %d", got)
	}
}

// An API failure aborts the reconcile — never a "clear" verdict on
// empty data.
func TestStormGateNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset(deschedulerDeploy(1, nil))
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A failed replicas merge-patch errors the reconcile — the verdict
// must not be swallowed.
func TestStormGateScalePatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionFalse, nil), // storm -> want 0
		deschedulerDeploy(1, nil))
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if strings.Contains(
				string(a.(ktesting.PatchAction).GetPatch()), "replicas") {
				return true, nil, errors.New("patch rejected")
			}
			return false, nil, nil
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the replicas patch fails")
	}
}

// Scaling writes a spec.replicas merge patch — never a full-object
// Update that would clobber concurrent spec edits or fail on
// resourceVersion.
func TestStormGateScalesViaMergePatch(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionFalse, nil), // storm -> want 0
		deschedulerDeploy(1, nil))
	cs.PrependReactor("update", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("full-object update must not be used")
		})
	var patches [][]byte
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			patches = append(patches, a.(ktesting.PatchAction).GetPatch())
			return false, nil, nil
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// The scale write is ONE merge patch carrying spec.replicas plus
	// the decision annotation (the two used to be back-to-back
	// patches on the same Deployment).
	var doc map[string]any
	if len(patches) != 1 || json.Unmarshal(patches[0], &doc) != nil {
		t.Fatalf("scale patches = %s, want one merged patch", patches)
	}
	if got := doc["spec"].(map[string]any)["replicas"]; got != float64(0) {
		t.Fatalf("merged patch replicas = %v, want 0", got)
	}
	annos := doc["metadata"].(map[string]any)["annotations"].(map[string]any)
	if _, ok := annos[stormGateDecisionAnno]; !ok {
		t.Fatalf("merged patch missing %s: %s", stormGateDecisionAnno, patches[0])
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("merge patch did not scale to 0, replicas=%d", got)
	}
}

// A failed decision-annotation patch errors the reconcile — the audit
// trail is part of the verdict.
func TestStormGateDecisionPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionFalse, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if strings.Contains(
				string(a.(ktesting.PatchAction).GetPatch()),
				stormGateDecisionAnno) {
				return true, nil, errors.New("patch rejected")
			}
			return false, nil, nil
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the decision annotation patch fails")
	}
}

// A deployment GET failure that is NOT NotFound is a real reconcile
// error — only a missing descheduler is the benign skip.
func TestStormGateDeployGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("get", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the deployment get fails")
	}
}

// Replicas already correct but no decision annotation recorded yet:
// the elif still annotates, and a patch failure there errors the
// reconcile just like the scale path.
func TestStormGateAnnotateErrorOnSteadyReplicas(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil), // clear verdict, want=1
		deschedulerDeploy(1, nil))                      // cur=1 -> elif branch
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the elif annotation patch fails")
	}
}

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
		kuredDaemonSet(map[string]string{kube.KuredLockAnno: "w1"}))
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

// W9-CP3 — the node-host-agent overlay/kernel latches added to
// stormConds gate the descheduler exactly like the existing storm
// conditions.
func TestStormGateScalesDownOnLatchConditions(t *testing.T) {
	for _, cond := range []corev1.NodeConditionType{
		"NebulaPMTUBlackhole", "KernelSlabLeak", "ClockUnsynchronized",
	} {
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

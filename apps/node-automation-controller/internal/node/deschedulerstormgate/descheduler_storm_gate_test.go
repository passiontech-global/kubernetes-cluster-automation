package deschedulerstormgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
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
	u := testutil.Unstructured(
		kube.AutopilotPlanGVR.GroupVersion().WithKind("Plan"), "", name, nil)
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
// storm condition (NPD/kubelet pressure style) with a fresh
// lastHeartbeatTime — nodereporter re-stamps it every ~2m while
// alive, so a live latch always carries one.
func withStormCond(n *corev1.Node, cond corev1.NodeConditionType) *corev1.Node {
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:              cond,
		Status:            corev1.ConditionTrue,
		LastHeartbeatTime: metav1.NewTime(time.Now()),
	})
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

// ---------------------------------------------------------------------------
// W12-SC1 — PriorityClass preemption cascade
// ---------------------------------------------------------------------------

// preemptedEvent builds a recent reason=Preempted corev1.Event.
func preemptedEvent(name string, age time.Duration) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "apps",
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Reason:        "Preempted",
		LastTimestamp: metav1.NewTime(time.Now().Add(-age)),
	}
}

// Signal (d): a Preempted-event burst past the ceiling is a domino
// eviction storm — the descheduler's own evictions would amplify it,
// so it scales to 0.
func TestStormGateScalesDownOnPreemptionStorm(t *testing.T) {
	objs := []runtime.Object{
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
	}
	for i := 0; i < stormPreemptionMax+1; i++ {
		objs = append(objs, preemptedEvent(
			fmt.Sprintf("ev-%d", i), time.Minute))
	}
	cs := fake.NewSimpleClientset(objs...)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("preemption storm must gate the descheduler, replicas=%d", got)
	}
	// The audit trail records the storm signal too.
	decision := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]
	if !strings.Contains(decision, "preempted=") ||
		!strings.Contains(decision, "verdict=storm") {
		t.Fatalf("decision missing the preempted signal: %q", decision)
	}
}

// At-or-under the ceiling plus stale events is ordinary churn — the
// descheduler keeps running.
func TestStormGatePreemptionChurnIsClear(t *testing.T) {
	objs := []runtime.Object{
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
	}
	for i := 0; i < stormPreemptionMax; i++ {
		objs = append(objs, preemptedEvent(
			fmt.Sprintf("fresh-%d", i), time.Minute))
	}
	for i := 0; i < 5; i++ {
		objs = append(objs, preemptedEvent(
			fmt.Sprintf("stale-%d", i), 30*time.Minute))
	}
	cs := fake.NewSimpleClientset(objs...)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("under-ceiling churn must not gate, replicas=%d", got)
	}
}

// An events-list failure aborts the reconcile — never a "clear"
// verdict on blind data (same posture as the node-list failure).
func TestStormGatePreemptionListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("list", "events",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the events list fails")
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas changed on blind data: %d", got)
	}
}

// ---------------------------------------------------------------------------
// W18-8 — image-pull storm (storm signal (e))
// ---------------------------------------------------------------------------

// stalledPod builds a pod whose app container is currently waiting
// in `reason` (ImagePullBackOff / ErrImagePull / "" for healthy).
func stalledPod(ns, name, reason string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	if reason != "" {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "app",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
				Reason:  reason,
				Message: "back-off pulling image"}},
		}}
	}
	return p
}

// Signal (e): stormImagePullMinPods stuck pods gate the descheduler
// exactly like a node storm — rescheduling pods whose images cannot
// land just spreads unrunnable pods across more nodes — and the
// decision annotation records the image-pull-stall reason.
func TestStormGateImagePullStormGates(t *testing.T) {
	objs := []runtime.Object{
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
		stalledPod("apps", "a", "ImagePullBackOff"),
		stalledPod("apps", "b", "ImagePullBackOff"),
		stalledPod("apps", "c", "ErrImagePull"),
	}
	cs := fake.NewSimpleClientset(objs...)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("image-pull storm must gate the descheduler, replicas=%d", got)
	}
	decision := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]
	if !strings.Contains(decision, "image-pull-stall") ||
		!strings.Contains(decision, "verdict=storm") ||
		!strings.Contains(decision, "imagepull=[") {
		t.Fatalf("decision missing the image-pull-stall signal: %q", decision)
	}
}

// Under the thresholds — 2 stuck pods in ONE namespace — is an
// ordinary broken Deployment, not a storm: the descheduler keeps
// running.
func TestStormGateImagePullUnderThresholdIsClear(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
		stalledPod("apps", "a", "ImagePullBackOff"),
		stalledPod("apps", "b", "ErrImagePull"),
	)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("under-threshold pull stalls must not gate, replicas=%d", got)
	}
	if decision := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]; strings.Contains(decision, "image-pull-stall") {
		t.Fatalf("under-threshold verdict recorded a storm signal: %q", decision)
	}
}

// The namespace half of the threshold: stuck pods in TWO namespaces
// gate even below stormImagePullMinPods — two unrelated workloads
// failing to pull points at the cluster (registry/network), not one
// bad Deployment.
func TestStormGateImagePullTwoNamespacesGate(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
		stalledPod("apps", "a", "ImagePullBackOff"),
		stalledPod("db", "b", "ErrImagePull"),
	)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("pull stalls in 2 namespaces must gate, replicas=%d", got)
	}
}

// A pod-list failure aborts the reconcile — never a "clear" verdict
// on blind data (same posture as the node/events list failures).
func TestStormGateImagePullListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the pod census list fails")
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas changed on blind data: %d", got)
	}
}

// ---------------------------------------------------------------------------
// W18-9 — forgotten maintenance holds (MaintenanceHoldStale)
// ---------------------------------------------------------------------------

// drainMaintenanceHoldStale counts the recorder's queued
// MaintenanceHoldStale events — NewFakeRecorder delivers synchronously,
// so the count is deterministic right after Reconcile returns.
func drainMaintenanceHoldStale(rec *record.FakeRecorder) int {
	n := 0
	for {
		select {
		case e := <-rec.Events:
			if strings.Contains(e, maintenanceHoldStaleReason) {
				n++
			}
		default:
			return n
		}
	}
}

// holdAnnos builds the descheduler Deployment annotations for a hold
// whose first-seen stamp says it has been "true" for `age` ("" age =
// no stamp — a hold the controller just started tracking).
func holdAnnos(age time.Duration) map[string]string {
	annos := map[string]string{stormGateHoldAnno: "true"}
	if age != 0 {
		annos[kube.AnnoFirstSeenStormGateHold] = fmt.Sprintf(
			`{"%s":"%s"}`, stormHoldLedgerKey,
			time.Now().Add(-age).UTC().Format(time.RFC3339))
	}
	return annos
}

// A hold kept "true" past the stale window fires exactly ONE
// MaintenanceHoldStale Warning — repeat reconciles must not spam.
func TestStormGateStaleHoldWarnsOnce(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, holdAnnos(3*time.Hour)))
	rec := record.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(), recorder: rec}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 1 {
		t.Fatalf("stale hold warnings = %d, want 1", got)
	}
	// The hold path still skips scaling.
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("hold must skip scaling, replicas=%d", got)
	}
	// Repeat reconciles of the SAME stale hold must stay silent.
	for range 2 {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("repeated reconciles spammed %d extra warnings", got)
	}
}

// A hold inside the stale window (fresh stamp, or none yet) warns
// nothing — the annotation has to HOLD past 2h first.
func TestStormGateFreshHoldDoesNotWarn(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, holdAnnos(time.Hour)))
	rec := record.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(), recorder: rec}
	for range 2 {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("fresh hold warned %d times, want 0", got)
	}
}

// Releasing the hold clears the persisted stamp and re-arms: a NEW
// hold starts a fresh 2h window instead of inheriting the old one.
func TestStormGateHoldReleaseReArms(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, holdAnnos(3*time.Hour)))
	rec := record.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(), recorder: rec}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 1 {
		t.Fatalf("stale hold warnings = %d, want 1", got)
	}

	// Release the hold: the next sweep must clear the stamp...
	d := getDescheduler(t, cs)
	d.Annotations[stormGateHoldAnno] = "false"
	if _, err := cs.AppsV1().Deployments("kube-system").
		Update(ctx, d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDescheduler(t, cs).Annotations[kube.AnnoFirstSeenStormGateHold]; got != "" {
		t.Fatalf("released hold left first-seen stamp behind: %q", got)
	}

	// ...and a NEW hold starts fresh: stamped at now, no warning.
	d = getDescheduler(t, cs)
	d.Annotations[stormGateHoldAnno] = "true"
	if _, err := cs.AppsV1().Deployments("kube-system").
		Update(ctx, d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("re-armed hold warned %d times, want 0", got)
	}
	if got := getDescheduler(t, cs).Annotations[kube.AnnoFirstSeenStormGateHold]; got == "" {
		t.Fatal("new hold was not stamped with a fresh first-seen")
	}
}

// nhcCR builds a NodeHealthCheck fixture — pauseRequests nil renders
// no spec at all (a healthy, unpaused NHC). The slice is []any: the
// dynamic fake deep-copies fixture JSON, which chokes on typed
// slices.
func nhcCR(name string, pauseRequests []string) *unstructured.Unstructured {
	fields := map[string]any{}
	if pauseRequests != nil {
		reqs := make([]any, len(pauseRequests))
		for i, r := range pauseRequests {
			reqs[i] = r
		}
		fields["spec"] = map[string]any{"pauseRequests": reqs}
	}
	return testutil.Unstructured(
		kube.GVRNodeHealthCheck.GroupVersion().WithKind("NodeHealthCheck"),
		"", name, fields)
}

func nhcPauseAnno(name string, age time.Duration) map[string]string {
	return map[string]string{
		kube.AnnoFirstSeenNHCPause: fmt.Sprintf(
			`{"%s":"%s"}`, name,
			time.Now().Add(-age).UTC().Format(time.RFC3339)),
	}
}

// A NodeHealthCheck paused via spec.pauseRequests past the stale
// window fires exactly ONE MaintenanceHoldStale Warning on the NHC —
// repeat sweeps must not spam.
func TestStormGateNHCPauseStaleWarnsOnce(t *testing.T) {
	nhc := nhcCR("nhc", []string{"runbook pause"})
	nhc.SetAnnotations(nhcPauseAnno("nhc", 3*time.Hour))
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	rec := record.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(nhc), recorder: rec}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 1 {
		t.Fatalf("stale NHC pause warnings = %d, want 1", got)
	}
	for range 2 {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("repeated sweeps spammed %d extra warnings", got)
	}
}

// A fresh (or untracked) pause warns nothing until the window holds.
func TestStormGateNHCPauseFreshDoesNotWarn(t *testing.T) {
	nhc := nhcCR("nhc", []string{"runbook pause"})
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	rec := record.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(nhc), recorder: rec}
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("fresh pause warned %d times, want 0", got)
	}
}

// Releasing the pause clears the persisted stamp on the NHC and
// re-arms the window; re-pausing warns nothing until it holds again.
func TestStormGateNHCPauseReleaseClearsStamp(t *testing.T) {
	nhc := nhcCR("nhc", []string{"runbook pause"})
	nhc.SetAnnotations(nhcPauseAnno("nhc", 3*time.Hour))
	dyn := stormGateDynFake(nhc)
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	rec := record.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: dyn, recorder: rec}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 1 {
		t.Fatalf("stale NHC pause warnings = %d, want 1", got)
	}

	// Release the pause — the next sweep clears the stamp.
	if _, err := dyn.Resource(kube.GVRNodeHealthCheck).
		Update(ctx, nhcCR("nhc", nil), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	obj, err := dyn.Resource(kube.GVRNodeHealthCheck).
		Get(ctx, "nhc", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := obj.GetAnnotations()[kube.AnnoFirstSeenNHCPause]; got != "" {
		t.Fatalf("released pause left first-seen stamp behind: %q", got)
	}

	// A NEW pause starts fresh — no immediate warning.
	if _, err := dyn.Resource(kube.GVRNodeHealthCheck).
		Update(ctx, nhcCR("nhc", []string{"again"}), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("re-armed pause warned %d times, want 0", got)
	}
}

// A cluster without the medik8s CRD is an empty scan — the probe
// must not error the reconcile (same posture as the mutex's absent
// autopilot/medik8s CRDs). The fake needs the list kind REGISTERED
// (an unregistered List panics before reactors run), so the absent
// CRD is simulated with the error a real absent CRD produces.
func TestStormGateNHCCRDAbsentIsClear(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		kube.GVRNodeHealthCheck: "NodeHealthCheckList",
		// The reconcile continues into the maintenance mutex after
		// the probe — the fake needs every GVR that later List
		// touches registered or it panics before any reactor runs.
		kube.AutopilotPlanGVR:          "PlanList",
		kube.GVRSelfNodeRemediation:    "SelfNodeRemediationList",
		kube.GVRFenceAgentsRemediation: "FenceAgentsRemediationList",
		kube.GVRNodeMaintenance:        "NodeMaintenanceList",
	})
	dyn.PrependReactor("list", "nodehealthchecks",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, &meta.NoKindMatchError{
				GroupKind: schema.GroupKind{
					Group: kube.GVRNodeHealthCheck.Group, Kind: "NodeHealthCheck"},
			}
		})
	rec := record.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: dyn, recorder: rec}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("absent NHC CRD must not error the reconcile: %v", err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("absent CRD warned %d times, want 0", got)
	}
}

// A real NHC list failure errors the reconcile — never a silent
// "nothing paused".
func TestStormGateNHCListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	dyn := stormGateDynFake()
	dyn.PrependReactor("list", "nodehealthchecks",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: dyn}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the NHC list fails")
	}
}

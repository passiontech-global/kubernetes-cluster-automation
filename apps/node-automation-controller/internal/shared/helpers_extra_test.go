package shared

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ---------------------------------------------------------------------------
// PatchNodeLabels — kubectl label --overwrite merge semantics.
// ---------------------------------------------------------------------------

func TestPatchNodeLabelsMerge(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue,
		map[string]string{"keep": "me", "old": "value"}))

	if err := PatchNodeLabels(ctx, cs, "n1",
		map[string]string{"old": "new", "added": "yes"}); err != nil {
		t.Fatalf("PatchNodeLabels: %v", err)
	}

	got := getNode(t, cs, "n1").Labels
	want := map[string]string{"keep": "me", "old": "new", "added": "yes"}
	if len(got) != len(want) {
		t.Fatalf("labels = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("label %q = %q, want %q (all labels %v)", k, got[k], v, got)
		}
	}
}

func TestPatchNodeLabelsNilMap(t *testing.T) {
	// A node that never had labels — the merge patch must create the
	// labels map rather than fail.
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil))
	if err := PatchNodeLabels(ctx, cs, "n1",
		map[string]string{"first": "label"}); err != nil {
		t.Fatalf("PatchNodeLabels: %v", err)
	}
	if got := getNode(t, cs, "n1").Labels["first"]; got != "label" {
		t.Fatalf("label not created on bare node, labels=%v",
			getNode(t, cs, "n1").Labels)
	}
}

// ---------------------------------------------------------------------------
// NodeReady / IsControlPlane edge cases.
// ---------------------------------------------------------------------------

func TestNodeReadyNoConditions(t *testing.T) {
	// kubelet has never posted a status — no conditions at all.
	bare := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "bare"}}
	if NodeReady(bare) {
		t.Fatal("node with no conditions reported ready")
	}
	if c := NodeCondition(bare, corev1.NodeReady); c != nil {
		t.Fatal("NodeCondition should be nil on a condition-less node")
	}
}

func TestIsControlPlaneMasterLabel(t *testing.T) {
	// The legacy master-role label variant must count too.
	m := node("cp", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/master": ""})
	if !IsControlPlane(m) {
		t.Fatal("master-role label not recognized as control plane")
	}
}

// ---------------------------------------------------------------------------
// PatchNodeTaints / TaintNode / UntaintNode edge cases.
// ---------------------------------------------------------------------------

func TestPatchNodeTaintsNilWritesEmptyArray(t *testing.T) {
	// nil marshals as "taints":null — the helper must normalize to []
	// so the merge patch clears the key instead of writing null.
	tainted := node("n1", corev1.ConditionTrue, nil,
		corev1.Taint{Key: "a", Effect: corev1.TaintEffectNoSchedule})
	cs := fake.NewSimpleClientset(tainted)
	if err := PatchNodeTaints(ctx, cs, "n1", nil); err != nil {
		t.Fatalf("PatchNodeTaints(nil): %v", err)
	}
	got := getNode(t, cs, "n1").Spec.Taints
	if got == nil {
		t.Fatal("spec.taints marshaled as null, want empty array")
	}
	if len(got) != 0 {
		t.Fatalf("taints not cleared: %+v", got)
	}
}

func TestPatchNodeTaintsPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	if err := PatchNodeTaints(ctx, cs, "n1",
		[]corev1.Taint{{Key: "a", Effect: corev1.TaintEffectNoSchedule}}); err == nil {
		t.Fatal("expected error when the node patch fails")
	}
}

func TestTaintNodeGetError(t *testing.T) {
	// Node absent -> the get inside TaintNode fails (NotFound).
	cs := fake.NewSimpleClientset()
	if err := TaintNode(ctx, cs, "ghost", "k", "v",
		corev1.TaintEffectNoSchedule); err == nil {
		t.Fatal("expected error when the node does not exist")
	}
}

func TestUntaintNodeGetErrorAndNoop(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil))
	if err := UntaintNode(ctx, cs, "ghost", "k"); err == nil {
		t.Fatal("expected error when the node does not exist")
	}
	// Node exists but carries no matching taint -> clean no-op.
	if err := UntaintNode(ctx, cs, "n1", "never-was-there"); err != nil {
		t.Fatalf("untaint of an absent key must be a no-op: %v", err)
	}
}

func TestListNodesError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	if _, err := ListNodes(ctx, cs); err == nil {
		t.Fatal("expected error when the node list fails")
	}
	if _, err := CountNotReadyNodes(ctx, cs); err == nil {
		t.Fatal("expected CountNotReadyNodes to propagate the list error")
	}
}

func TestPatchNodeLabelsPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	if err := PatchNodeLabels(ctx, cs, "n1",
		map[string]string{"k": "v"}); err == nil {
		t.Fatal("expected error when the node patch fails")
	}
}

// ---------------------------------------------------------------------------
// DaemonSetSettled — every lagging field must veto "settled".
// ---------------------------------------------------------------------------

func TestDaemonSetSettledFields(t *testing.T) {
	t.Run("settled", func(t *testing.T) {
		if !DaemonSetSettled(settledDaemonSet()) {
			t.Fatal("fully caught-up DaemonSet not settled")
		}
	})
	t.Run("observedGeneration lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.ObservedGeneration = 2 // controller hasn't seen gen 3
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite stale observedGeneration")
		}
	})
	t.Run("updatedNumberScheduled lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.UpdatedNumberScheduled = 3 // old pod template on one node
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite pods still on the old revision")
		}
	})
	t.Run("numberReady lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.NumberReady = 3 // updated but not ready yet
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite unready pod")
		}
	})
}

// ---------------------------------------------------------------------------
// periodic — the cron-replacement loop.
// ---------------------------------------------------------------------------

func TestPeriodicRunsUntilCancelled(t *testing.T) {
	var calls atomic.Int32
	ran := make(chan struct{})
	p := &Periodic{
		Name:     "test-periodic",
		Interval: 10 * time.Millisecond,
		Fn: func(context.Context) error {
			if calls.Add(1) == 1 {
				close(ran)
			}
			return nil
		},
		Log: logr.Discard(),
	}

	pctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- p.Start(pctx) }()

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("fn never ran")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
	if calls.Load() < 1 {
		t.Fatal("fn was never invoked")
	}
}

// A ctx cancelled before Start must return promptly — the random
// phase offset must never delay shutdown by up to a full interval.
func TestPeriodicCancelledBeforeStart(t *testing.T) {
	pctx, cancel := context.WithCancel(ctx)
	cancel()
	p := &Periodic{
		Name:     "test-periodic-cancelled",
		Interval: time.Hour,
		Fn: func(context.Context) error {
			t.Error("fn ran on an already-cancelled ctx")
			return nil
		},
		Log: logr.Discard(),
	}
	done := make(chan error, 1)
	go func() { done <- p.Start(pctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return promptly on a cancelled ctx")
	}
}

// Cancelling mid-jitter (the uniform [0,interval) phase-offset wait
// before the ticker starts) must abort Start immediately — not when
// the offset would have elapsed.
func TestPeriodicCancelDuringJitter(t *testing.T) {
	p := &Periodic{
		Name:     "test-periodic-jitter-cancel",
		Interval: time.Hour, // offset + first tick are both far out
		Fn: func(context.Context) error {
			t.Error("fn ran")
			return nil
		},
		Log: logr.Discard(),
	}
	pctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- p.Start(pctx) }()
	time.Sleep(50 * time.Millisecond) // Start is in the offset wait
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel during the jitter wait did not return promptly")
	}
}

func TestPeriodicErrorIncrementsErrorMetric(t *testing.T) {
	var calls atomic.Int32
	second := make(chan struct{})
	p := &Periodic{
		Name:     "test-periodic-err",
		Interval: 10 * time.Millisecond,
		Fn: func(context.Context) error {
			if calls.Add(1) == 1 {
				return errors.New("boom") // first run fails
			}
			// Second invocation can only happen after the loop
			// consumed the error and called IncError — closing this
			// channel is a happens-after witness for the increment.
			select {
			case <-second:
			default:
				close(second)
			}
			return nil
		},
		Log: logr.Discard(),
	}

	before := reconcileErrorCount(t, "test-periodic-err")

	pctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- p.Start(pctx) }()

	select {
	case <-second:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("loop did not continue after a failed run")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("periodic start: %v", err)
	}

	if got := reconcileErrorCount(t, "test-periodic-err"); got != before+1 {
		t.Fatalf("error counter = %v, want %v", got, before+1)
	}
}

// A non-positive Interval used to panic in rand.N / time.NewTicker —
// Start must now return it as a plain error instead (the manager
// turns a runnable error into a clean exit, not a crash loop).
func TestPeriodicNonPositiveInterval(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Minute} {
		p := &Periodic{
			Name:     "test-periodic-bad-interval",
			Interval: d,
			Fn: func(context.Context) error {
				t.Error("fn ran on a non-positive interval")
				return nil
			},
			Log: logr.Discard(),
		}
		if err := p.Start(ctx); err == nil {
			t.Fatalf("Start(Interval=%s) returned nil, want error", d)
		}
	}
}

// AddPeriodic must reject a non-positive interval BEFORE mgr.Add —
// the returned error is what setupModules propagates to abort boot
// (e.g. an env-derived *_INTERVAL knob set to "0s"). A nil manager
// proves the guard fires before any manager interaction.
func TestAddPeriodicRejectsNonPositiveInterval(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		err := AddPeriodic(nil, "bad-interval", d,
			func(context.Context) error { return nil })
		if err == nil {
			t.Fatalf("AddPeriodic(interval=%s) returned nil, want error", d)
		}
	}
}

// A parsed-but-tiny interval ("1ns" through an env knob) is just as
// bad as <=0 — it would hot-loop the sweep on every tick. AddPeriodic
// floors the interval at 1s for the same reason.
func TestAddPeriodicRejectsSubSecondInterval(t *testing.T) {
	for _, d := range []time.Duration{time.Nanosecond, 500 * time.Millisecond, time.Second - 1} {
		err := AddPeriodic(nil, "bad-interval", d,
			func(context.Context) error { return nil })
		if err == nil {
			t.Fatalf("AddPeriodic(interval=%s) returned nil, want error", d)
		}
	}
}

// ---------------------------------------------------------------------------
// SweepRequests / fixedSweepRequest — fixed-key watch fan-in.
// ---------------------------------------------------------------------------

// Every object an informer could deliver must collapse to exactly one
// request carrying the fixed key — byte-identical NamespacedNames are
// what lets the workqueue set dedup an informer burst into one sweep.
func TestSweepRequestsFixedKey(t *testing.T) {
	fn := SweepRequests("test-sweep")
	want := types.NamespacedName{Name: "test-sweep"}
	for _, obj := range []client.Object{
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "cilium-x", Namespace: "kube-system"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "passiontech-pipeline", Namespace: "fluent-system"}},
	} {
		reqs := fn(ctx, obj)
		if len(reqs) != 1 {
			t.Fatalf("%T %s/%s mapped to %d requests, want 1",
				obj, obj.GetNamespace(), obj.GetName(), len(reqs))
		}
		if reqs[0].NamespacedName != want {
			t.Fatalf("%T %s/%s mapped to %+v, want fixed key %q",
				obj, obj.GetNamespace(), obj.GetName(),
				reqs[0].NamespacedName, want)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers.go — taint/condition sweeps (carved out of the old monolith
// controller_test.go).
// ---------------------------------------------------------------------------

func TestTaintHelpers(t *testing.T) {
	n := node("n1", corev1.ConditionTrue, nil)
	cs := fake.NewSimpleClientset(n)

	if err := TaintNode(ctx, cs, "n1", "node.ops/test", "true", corev1.TaintEffectNoSchedule); err != nil {
		t.Fatalf("TaintNode: %v", err)
	}
	got := getNode(t, cs, "n1")
	if !HasTaint(got.Spec.Taints, "node.ops/test") {
		t.Fatal("taint not applied")
	}
	if len(got.Spec.Taints) != 1 {
		t.Fatalf("expected 1 taint, got %d", len(got.Spec.Taints))
	}

	// Idempotent: same key is not duplicated.
	if err := TaintNode(ctx, cs, "n1", "node.ops/test", "true", corev1.TaintEffectNoSchedule); err != nil {
		t.Fatalf("TaintNode idempotent: %v", err)
	}
	if l := len(getNode(t, cs, "n1").Spec.Taints); l != 1 {
		t.Fatalf("expected still 1 taint, got %d", l)
	}

	if err := UntaintNode(ctx, cs, "n1", "node.ops/test"); err != nil {
		t.Fatalf("UntaintNode: %v", err)
	}
	if HasTaint(getNode(t, cs, "n1").Spec.Taints, "node.ops/test") {
		t.Fatal("taint not removed")
	}
}

func TestDropTaintsByKey(t *testing.T) {
	in := []corev1.Taint{
		{Key: "a", Effect: corev1.TaintEffectNoSchedule},
		{Key: "a", Effect: corev1.TaintEffectNoExecute},
		{Key: "b", Effect: corev1.TaintEffectNoSchedule},
	}
	out := DropTaintsByKey(in, "a")
	if len(out) != 1 || out[0].Key != "b" {
		t.Fatalf("expected only taint b, got %+v", out)
	}
	// In-place contract: the result aliases the input's backing
	// array — the surviving taint moved into slot 0 — and the stale
	// tail past len(out) is zeroed so the dropped entries (and their
	// strings) become collectable.
	if in[0].Key != "b" {
		t.Fatalf("result does not alias the input array: in[0]=%+v", in[0])
	}
	for i, stale := range in[len(out):] {
		if stale != (corev1.Taint{}) {
			t.Fatalf("stale tail slot %d not cleared: %+v", len(out)+i, stale)
		}
	}
}

func TestNodeConditionHelpers(t *testing.T) {
	ready := node("w", corev1.ConditionTrue, nil)
	notReady := node("w2", corev1.ConditionFalse, nil)
	cp := node("cp", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/control-plane": ""})

	if !NodeReady(ready) || NodeReady(notReady) {
		t.Fatal("NodeReady wrong")
	}
	if !IsControlPlane(cp) || IsControlPlane(ready) {
		t.Fatal("IsControlPlane wrong")
	}
}

func TestCountNotReadyNodes(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("a", corev1.ConditionTrue, nil),
		node("b", corev1.ConditionFalse, nil),
		node("c", corev1.ConditionTrue, nil))
	n, err := CountNotReadyNodes(ctx, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 NotReady, got %d", n)
	}
}

func TestDaemonSetSettled(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     3,
			DesiredNumberScheduled: 4,
			UpdatedNumberScheduled: 4,
			NumberReady:            4,
		},
	}
	if !DaemonSetSettled(ds) {
		t.Fatal("expected settled")
	}
	ds.Status.NumberReady = 3
	if DaemonSetSettled(ds) {
		t.Fatal("expected not settled when a replica is not ready")
	}
}

// PodReadyCond mirrors the bash Ready=True probe: absent condition and
// Ready=False both count as not ready.
func TestPodReadyCond(t *testing.T) {
	p := &corev1.Pod{}
	if PodReadyCond(p) {
		t.Fatal("pod with no conditions reported ready")
	}
	p.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionFalse},
	}
	if PodReadyCond(p) {
		t.Fatal("Ready=False pod reported ready")
	}
	p.Status.Conditions[0].Status = corev1.ConditionTrue
	if !PodReadyCond(p) {
		t.Fatal("Ready=True pod reported not ready")
	}
}

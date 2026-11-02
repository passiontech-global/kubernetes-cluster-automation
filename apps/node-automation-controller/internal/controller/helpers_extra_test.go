package controller

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
	"k8s.io/client-go/kubernetes/fake"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// ---------------------------------------------------------------------------
// patchNodeLabels — kubectl label --overwrite merge semantics.
// ---------------------------------------------------------------------------

func TestPatchNodeLabelsMerge(t *testing.T) {
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue,
		map[string]string{"keep": "me", "old": "value"}))

	if err := patchNodeLabels(ctx, cs, "n1",
		map[string]string{"old": "new", "added": "yes"}); err != nil {
		t.Fatalf("patchNodeLabels: %v", err)
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
	if err := patchNodeLabels(ctx, cs, "n1",
		map[string]string{"first": "label"}); err != nil {
		t.Fatalf("patchNodeLabels: %v", err)
	}
	if got := getNode(t, cs, "n1").Labels["first"]; got != "label" {
		t.Fatalf("label not created on bare node, labels=%v",
			getNode(t, cs, "n1").Labels)
	}
}

// ---------------------------------------------------------------------------
// nodeReady / isControlPlane edge cases.
// ---------------------------------------------------------------------------

func TestNodeReadyNoConditions(t *testing.T) {
	// kubelet has never posted a status — no conditions at all.
	bare := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "bare"}}
	if nodeReady(bare) {
		t.Fatal("node with no conditions reported ready")
	}
	if c := nodeCondition(bare, corev1.NodeReady); c != nil {
		t.Fatal("nodeCondition should be nil on a condition-less node")
	}
}

func TestIsControlPlaneMasterLabel(t *testing.T) {
	// The legacy master-role label variant must count too.
	m := node("cp", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/master": ""})
	if !isControlPlane(m) {
		t.Fatal("master-role label not recognized as control plane")
	}
}

// ---------------------------------------------------------------------------
// daemonSetSettled — every lagging field must veto "settled".
// ---------------------------------------------------------------------------

func settledDaemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     3,
			DesiredNumberScheduled: 4,
			UpdatedNumberScheduled: 4,
			NumberReady:            4,
		},
	}
}

func TestDaemonSetSettledFields(t *testing.T) {
	t.Run("settled", func(t *testing.T) {
		if !daemonSetSettled(settledDaemonSet()) {
			t.Fatal("fully caught-up DaemonSet not settled")
		}
	})
	t.Run("observedGeneration lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.ObservedGeneration = 2 // controller hasn't seen gen 3
		if daemonSetSettled(ds) {
			t.Fatal("settled despite stale observedGeneration")
		}
	})
	t.Run("updatedNumberScheduled lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.UpdatedNumberScheduled = 3 // old pod template on one node
		if daemonSetSettled(ds) {
			t.Fatal("settled despite pods still on the old revision")
		}
	})
	t.Run("numberReady lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.NumberReady = 3 // updated but not ready yet
		if daemonSetSettled(ds) {
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
	p := &periodic{
		name:     "test-periodic",
		interval: 10 * time.Millisecond,
		fn: func(context.Context) error {
			if calls.Add(1) == 1 {
				close(ran)
			}
			return nil
		},
		log: logr.Discard(),
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

// reconcileErrorCount reads the native error counter for module `name`
// off the controller-runtime registry (the one metrics.init registers
// into) — end-to-end proof the periodic loop calls IncError.
func reconcileErrorCount(t *testing.T, name string) float64 {
	t.Helper()
	mfs, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather registry: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "node_automation_reconcile_errors_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "controller" && lp.GetValue() == name {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestPeriodicErrorIncrementsErrorMetric(t *testing.T) {
	var calls atomic.Int32
	second := make(chan struct{})
	p := &periodic{
		name:     "test-periodic-err",
		interval: 10 * time.Millisecond,
		fn: func(context.Context) error {
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
		log: logr.Discard(),
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
	<-done

	if got := reconcileErrorCount(t, "test-periodic-err"); got != before+1 {
		t.Fatalf("error counter = %v, want %v", got, before+1)
	}
}

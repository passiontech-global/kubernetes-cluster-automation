package shared

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var ctx = context.Background()

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

// A panicking Fn must not escape Start: controller-runtime does not
// recover Runnable panics, so an unrecovered panic would crash the
// whole 32-module binary. runOnce converts it into a run error —
// IncError counts it exactly like a returned error and the ticker
// keeps going (the second invocation is the happens-after witness,
// same as the plain-error test above).
func TestPeriodicPanicIsCountedAndLoopContinues(t *testing.T) {
	var calls atomic.Int32
	second := make(chan struct{})
	p := &Periodic{
		Name:     "test-periodic-panic",
		Interval: 10 * time.Millisecond,
		Fn: func(context.Context) error {
			if calls.Add(1) == 1 {
				panic("boom")
			}
			select {
			case <-second:
			default:
				close(second)
			}
			return nil
		},
		Log: logr.Discard(),
	}

	before := reconcileErrorCount(t, "test-periodic-panic")

	pctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- p.Start(pctx) }()

	select {
	case <-second:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("loop did not survive a panicking fn")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("periodic start: %v", err)
	}

	if got := reconcileErrorCount(t, "test-periodic-panic"); got != before+1 {
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

// reconcileErrorCount reads the native error counter for module `name`
// off the controller-runtime registry (the one metrics.init registers
// into) — end-to-end proof the periodic loop calls IncError. Kept
// local (not testutil) because shared must stay a leaf: testutil
// already imports shared.
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

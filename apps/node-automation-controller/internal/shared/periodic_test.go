package shared

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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

func TestNodeUpdatePredicateAndRequeueAfter(t *testing.T) {
	p := NodeUpdatePredicate(true, func(oldNode, newNode *corev1.Node) bool {
		return oldNode.Name != newNode.Name
	})
	if !p.Create(event.CreateEvent{}) || !p.Delete(event.DeleteEvent{}) || !p.Generic(event.GenericEvent{}) {
		t.Fatal("Create/Delete/Generic must always return true")
	}
	if !p.Update(event.UpdateEvent{}) {
		t.Fatal("missing objects should return fallbackOnMissing=true")
	}
	n1 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "a"}}
	n2 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "b"}}
	if p.Update(event.UpdateEvent{ObjectOld: n1, ObjectNew: n1}) {
		t.Fatal("equal nodes should return false")
	}
	if !p.Update(event.UpdateEvent{ObjectOld: n1, ObjectNew: n2}) {
		t.Fatal("different nodes should return true")
	}

	if got := RequeueAfter(0); got != 0 {
		t.Fatalf("RequeueAfter(0) = %v, want 0", got)
	}
	if got := RequeueAfter(-time.Second); got != -time.Second {
		t.Fatalf("RequeueAfter(-1s) = %v, want -1s", got)
	}
	base := 10 * time.Second
	for range 10 {
		got := RequeueAfter(base)
		if got < 9*time.Second || got >= 11*time.Second {
			t.Fatalf("RequeueAfter(10s) = %v outside [9s, 11s)", got)
		}
	}
}

type captureLogSink struct {
	mu      sync.Mutex
	entries []capturedLog
}

type capturedLog struct {
	msg string
	err error
	kvs map[string]any
}

func (s *captureLogSink) Init(logr.RuntimeInfo)    {}
func (s *captureLogSink) Enabled(int) bool         { return true }
func (s *captureLogSink) Info(int, string, ...any) {}
func (s *captureLogSink) Error(err error, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kvs := make(map[string]any, len(keysAndValues)/2)
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		if k, ok := keysAndValues[i].(string); ok {
			kvs[k] = keysAndValues[i+1]
		}
	}
	s.entries = append(s.entries, capturedLog{msg: msg, err: err, kvs: kvs})
}
func (s *captureLogSink) WithValues(...any) logr.LogSink { return s }
func (s *captureLogSink) WithName(string) logr.LogSink   { return s }

func TestPeriodicPanicLogsStack(t *testing.T) {
	sink := &captureLogSink{}
	log := logr.New(sink)
	p := &Periodic{
		Name:     "test-panic-stack",
		Interval: 10 * time.Millisecond,
		Fn: func(context.Context) error {
			panic("boom")
		},
		Log: log,
	}

	p.invokeOnce(t.Context(), log)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(sink.entries))
	}
	entry := sink.entries[0]
	if entry.msg != "periodic run failed" {
		t.Fatalf("msg = %q, want periodic run failed", entry.msg)
	}
	if entry.err == nil || entry.err.Error() != "panic in periodic run: boom" {
		t.Fatalf("err = %v, want panic in periodic run: boom", entry.err)
	}
	stack, ok := entry.kvs["stack"].(string)
	if !ok || !strings.Contains(stack, "TestPeriodicPanicLogsStack") {
		t.Fatalf("stack = %q, want stack trace containing panicking frame", stack)
	}
}

type fakePeriodicMgr struct {
	manager.Manager
	added []manager.Runnable
}

func (m *fakePeriodicMgr) Add(r manager.Runnable) error {
	m.added = append(m.added, r)
	return nil
}

func (m *fakePeriodicMgr) GetLogger() logr.Logger {
	return logr.Discard()
}

func TestAddPeriodicWithTimeout(t *testing.T) {
	mgr := &fakePeriodicMgr{}
	if err := AddPeriodic(mgr, "default-p", time.Minute, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("AddPeriodic err: %v", err)
	}
	if err := AddPeriodicWithTimeout(mgr, "custom-p", 5*time.Minute, 25*time.Minute, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("AddPeriodicWithTimeout err: %v", err)
	}
	if len(mgr.added) != 2 {
		t.Fatalf("added = %d, want 2", len(mgr.added))
	}
	p0 := mgr.added[0].(*Periodic)
	p1 := mgr.added[1].(*Periodic)
	if p0.RunTimeout != 0 {
		t.Fatalf("AddPeriodic RunTimeout = %v, want 0", p0.RunTimeout)
	}
	if p1.RunTimeout != 25*time.Minute || p1.Interval != 5*time.Minute || p1.Name != "custom-p" {
		t.Fatalf("AddPeriodicWithTimeout stored %+v", p1)
	}

	// Verify runOnce honors RunTimeout shorter than 2*Interval.
	var deadline time.Time
	var hasDeadline bool
	pShort := &Periodic{
		Name:       "short-timeout",
		Interval:   time.Hour,
		RunTimeout: 50 * time.Millisecond,
		Fn: func(c context.Context) error {
			deadline, hasDeadline = c.Deadline()
			<-c.Done()
			return c.Err()
		},
		Log: logr.Discard(),
	}
	start := time.Now()
	err := pShort.runOnce(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runOnce err = %v, want DeadlineExceeded", err)
	}
	if !hasDeadline || deadline.Sub(start) > time.Second {
		t.Fatalf("runOnce deadline = %v (has=%v), want ~50ms", deadline.Sub(start), hasDeadline)
	}
}

func TestPeriodicLiveness(t *testing.T) {
	t.Run("empty liveness returns nil", func(t *testing.T) {
		l := NewLiveness()
		if err := l.Check(nil); err != nil {
			t.Fatalf("empty Liveness.Check = %v, want nil", err)
		}
		if err := (*Liveness)(nil).Check(nil); err != nil {
			t.Fatalf("nil Liveness.Check = %v, want nil", err)
		}
	})

	t.Run("active loop healthy across ticks, errors, panics, and unregisters on cancel", func(t *testing.T) {
		l := NewLiveness()
		l.Floor = 500 * time.Millisecond
		var count atomic.Int32
		third := make(chan struct{})
		p := &Periodic{
			Name:       "healthy-loop",
			Interval:   10 * time.Millisecond,
			RunTimeout: 50 * time.Millisecond,
			Fn: func(context.Context) error {
				switch count.Add(1) {
				case 1:
					return errors.New("transient")
				case 2:
					panic("transient panic")
				case 3:
					close(third)
				}
				return nil
			},
			Log: logr.Discard(),
		}

		pctx, cancel := context.WithCancel(WithLiveness(t.Context(), l))
		done := make(chan error, 1)
		go func() { done <- p.Start(pctx) }()

		select {
		case <-third:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("loop did not reach 3rd tick")
		}
		if err := l.Check(nil); err != nil {
			cancel()
			t.Fatalf("healthy loop Check = %v, want nil", err)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Start err = %v", err)
		}
		// Unregistered on exit: loops list must be empty and Check nil.
		l.mu.Lock()
		remaining := len(l.loops)
		l.mu.Unlock()
		if remaining != 0 {
			t.Fatalf("loops remaining after Start exit = %d, want 0", remaining)
		}
		if err := l.Check(nil); err != nil {
			t.Fatalf("post-exit Check = %v, want nil", err)
		}
	})

	t.Run("hung Fn trips Check with loop name", func(t *testing.T) {
		var fakeNow atomic.Int64
		fakeNow.Store(int64(time.Second))
		l := &Liveness{
			Floor: 100 * time.Millisecond,
			nowFn: func() time.Duration { return time.Duration(fakeNow.Load()) },
		}
		entered := make(chan struct{})
		release := make(chan struct{})
		p := &Periodic{
			Name:       "wedged-loop",
			Interval:   10 * time.Millisecond,
			RunTimeout: 20 * time.Millisecond,
			Liveness:   l,
			Fn: func(context.Context) error {
				select {
				case <-entered:
				default:
					close(entered)
				}
				<-release
				return nil
			},
			Log: logr.Discard(),
		}

		pctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- p.Start(pctx) }()

		<-entered
		if err := l.Check(nil); err != nil {
			close(release)
			cancel()
			t.Fatalf("Check before budget exceeded = %v, want nil", err)
		}
		// Advance monotonic clock past budget (max(2*1s+20ms, 100ms) if clamped, else 100ms).
		fakeNow.Add(int64(5 * time.Second))
		err := l.Check(nil)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%q", "wedged-loop")) {
			close(release)
			cancel()
			t.Fatalf("Check after budget exceeded = %v, want error naming wedged-loop", err)
		}
		close(release)
		cancel()
		<-done
	})

	t.Run("NextInterval updates beat.staleAfter when interval grows", func(t *testing.T) {
		l := NewLiveness()
		l.Floor = 50 * time.Millisecond
		var fakeNow atomic.Int64
		fakeNow.Store(int64(time.Second))
		l.nowFn = func() time.Duration { return time.Duration(fakeNow.Load()) }

		nextStarted := make(chan struct{})
		p := &Periodic{
			Name:       "adaptive-loop",
			Interval:   10 * time.Millisecond,
			RunTimeout: 20 * time.Millisecond,
			Liveness:   l,
			NextInterval: func(time.Duration) time.Duration {
				select {
				case <-nextStarted:
				default:
					close(nextStarted)
				}
				return 5 * time.Second
			},
			Fn:  func(context.Context) error { return nil },
			Log: logr.Discard(),
		}

		pctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- p.Start(pctx) }()

		<-nextStarted
		// Give Start a moment to store the updated staleAfter before waitTimer.
		time.Sleep(15 * time.Millisecond)
		// Advance past original 100ms floor, still inside 2*5s+20ms budget.
		fakeNow.Add(int64(2 * time.Second))
		if err := l.Check(nil); err != nil {
			cancel()
			t.Fatalf("adaptive loop Check = %v, want nil with grown staleAfter", err)
		}
		cancel()
		<-done
	})
}

func TestPeriodicSkipInitialJitter(t *testing.T) {
	ran := make(chan struct{})
	p := &Periodic{
		Name:              "skip-jitter",
		Interval:          time.Hour,
		SkipInitialJitter: true,
		Fn: func(context.Context) error {
			close(ran)
			return nil
		},
		Log: logr.Discard(),
	}
	pctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.Start(pctx) }()
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("SkipInitialJitter did not invoke Fn immediately")
	}
	cancel()
	<-done

	t.Setenv(skipInitialJitterEnv, "true")
	mgr := &fakePeriodicMgr{}
	if err := AddPeriodic(mgr, "env-skip", time.Hour, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("AddPeriodic err: %v", err)
	}
	got := mgr.added[0].(*Periodic)
	if !got.SkipInitialJitter {
		t.Fatal("AddPeriodic did not honor NODE_AUTOMATION_TEST_NO_INITIAL_JITTER=true")
	}
}

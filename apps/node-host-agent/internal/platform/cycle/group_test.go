// group_test.go — RunAll fan-out semantics (concurrent loops, park
// until ctx, wait-for-children teardown, all-dead early return) and
// the EverySafe per-tick recover + onPanic hook.
package cycle

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunAllRunsEveryLoop: each looper starts on its own goroutine
// and RunAll returns only after ctx cancel, with the children
// actually unwound (Every runners exit on ctx.Done).
func TestRunAllRunsEveryLoop(t *testing.T) {
	var a, b atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunAll(ctx,
			Every("a", time.Hour, func(context.Context) { a.Add(1) }),
			Every("b", time.Hour, func(context.Context) { b.Add(1) }),
		)
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for a.Load() != 1 || b.Load() != 1 {
		select {
		case <-deadline:
			t.Fatalf("loops never ran: a=%d b=%d", a.Load(), b.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("RunAll did not return after cancel")
	}
}

// TestRunAllSurvivesChildPanic: Spawn recovers a panicking child — a
// dead loop must neither kill the group nor its sibling.
func TestRunAllSurvivesChildPanic(t *testing.T) {
	var ok atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunAll(ctx,
			Every("panics", time.Hour, func(context.Context) { panic("boom") }),
			Every("lives", time.Hour, func(context.Context) { ok.Add(1) }),
		)
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for ok.Load() != 1 {
		select {
		case <-deadline:
			t.Fatal("sibling loop did not run")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	// One child is dead but the group must keep parking on ctx —
	// Run must not return while ctx is live (supervisor contract).
	select {
	case <-done:
		t.Fatal("RunAll returned while ctx live with a loop running")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("RunAll did not return after cancel")
	}
}

// exitLoop is a Looper that returns from Run immediately — the
// clean-early-exit half of the RunAll contract.
type exitLoop struct{ name string }

func (e exitLoop) Name() string        { return e.name }
func (e exitLoop) Run(context.Context) {}

// TestRunAllReturnsWhenAllChildrenExit: a fully-dead group has
// nothing left to park for — RunAll returns so the supervisor's
// restart path applies instead of the subsystem staying silently
// dead.
func TestRunAllReturnsWhenAllChildrenExit(t *testing.T) {
	done := make(chan struct{})
	go func() {
		RunAll(context.Background(), exitLoop{"one"}, exitLoop{"two"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunAll did not return after every loop exited")
	}
}

// TestRunAllParksWhileOneLoopLives: one clean-exiting loop is logged
// and left dead, but the group still blocks on ctx for the survivor.
func TestRunAllParksWhileOneLoopLives(t *testing.T) {
	var alive atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunAll(ctx,
			exitLoop{"quits"},
			Every("alive", time.Hour, func(context.Context) { alive.Add(1) }),
		)
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for alive.Load() != 1 {
		select {
		case <-deadline:
			t.Fatal("surviving loop never ran")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	select {
	case <-done:
		t.Fatal("RunAll returned while a loop still lived")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("RunAll did not return after cancel")
	}
}

// TestEverySafeRecoversTickPanic: a panicking fn counts the hook and
// the loop keeps ticking — the safeCycle semantics.
func TestEverySafeRecoversTickPanic(t *testing.T) {
	var calls, panics atomic.Int64
	r := EverySafe("safe", 10*time.Millisecond, func(context.Context) {
		if calls.Add(1) == 1 {
			panic("first tick only")
		}
	}, func(name string, _ any) {
		if name != "safe" {
			t.Errorf("onPanic name=%q want %q", name, "safe")
		}
		panics.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after cancel")
		}
	}()

	deadline := time.After(5 * time.Second)
	for calls.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("loop died after tick panic: calls=%d", calls.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if panics.Load() != 1 {
		t.Fatalf("onPanic fired %d times, want 1", panics.Load())
	}
}

// spawn_test.go — Spawn contract: derived child ctx, in-goroutine
// panic recovery, stop() = cancel-then-wait on every exit path.
package cycle

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestSpawnRunsImmediatelyAndStopWaits: the child is already running
// when Spawn returns, and stop() blocks until the goroutine exits —
// not merely until the child ctx is cancelled (the child may unwind
// past ctx.Done before returning).
func TestSpawnRunsImmediatelyAndStopWaits(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var exited atomic.Bool
	stop := Spawn(context.Background(), "waits", func(ctx context.Context) {
		defer exited.Store(true)
		close(started)
		<-ctx.Done() // observe the cancel
		<-release    // unwind takes a beat — stop must wait for it
	})

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("fn did not start before Spawn returned")
	}

	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()

	// ctx cancelled but the child still unwinds — stop must not
	// return yet.
	select {
	case <-stopped:
		t.Fatal("stop returned before the goroutine exited")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return after goroutine exit")
	}
	if !exited.Load() {
		t.Fatal("stop returned before fn fully unwound")
	}
}

// TestSpawnChildCtxDerivesFromParent: the child observes parent
// cancellation AND its own stop — a stopped child's ctx is dead
// while the parent's stays live.
func TestSpawnChildCtxDerivesFromParent(t *testing.T) {
	var childErr atomic.Value
	stop := Spawn(context.Background(), "derived", func(ctx context.Context) {
		<-ctx.Done()
		childErr.Store(ctx.Err())
	})
	stop()
	if err, _ := childErr.Load().(error); err == nil {
		t.Fatal("child ctx not cancelled by stop")
	}

	ctx, cancel := context.WithCancel(context.Background())
	seen := make(chan struct{})
	Spawn(ctx, "parent-propagates", func(cctx context.Context) {
		<-cctx.Done()
		close(seen)
	})
	cancel()
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("child ctx not cancelled by parent")
	}
}

// TestSpawnRecoversPanic: a panicking fn must not crash the process
// (the agent's recover only wraps Run) — the goroutine exits and
// stop() still returns.
func TestSpawnRecoversPanic(t *testing.T) {
	stop := Spawn(context.Background(), "panics", func(context.Context) {
		panic("boom")
	})
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return after recovered panic")
	}
}

// TestSpawnStopIdempotent: repeated/concurrent stop calls are safe —
// a caller may defer stop() and also invoke it on a fast path.
func TestSpawnStopIdempotent(t *testing.T) {
	stop := Spawn(context.Background(), "idempotent", func(ctx context.Context) {
		<-ctx.Done()
	})
	stop()
	stop()
	go stop()
}

// TestSpawnStopWithoutCancel: stop alone (parent still live) kills
// the child — the derived ctx is what makes bounded teardown work
// when the parent stays alive.
func TestSpawnStopWithoutCancel(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	var exited atomic.Bool
	stop := Spawn(parent, "solo-stop", func(ctx context.Context) {
		<-ctx.Done()
		exited.Store(true)
	})
	stop()
	if !exited.Load() {
		t.Fatal("child did not exit on stop")
	}
	if parent.Err() != nil {
		t.Fatal("stop cancelled the parent ctx")
	}
}

package cycle

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestName(t *testing.T) {
	r := Every("probe", time.Minute, func(context.Context) {})
	if got := r.Name(); got != "probe" {
		t.Fatalf("Name()=%q want %q", got, "probe")
	}
}

func TestEveryRunsImmediately(t *testing.T) {
	var calls atomic.Int64
	r := Every("immediate", time.Hour, func(context.Context) {
		calls.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Interval is an hour — only the up-front call can have run.
	deadline := time.After(5 * time.Second)
	for calls.Load() != 1 {
		select {
		case <-deadline:
			t.Fatal("fn never ran")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("Run did not return after cancel")
	}
}

func TestEveryTicksAtInterval(t *testing.T) {
	var calls atomic.Int64
	r := Every("ticks", 20*time.Millisecond, func(context.Context) {
		calls.Add(1)
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

	// Immediate call + at least two ticks (~40ms) — generous deadline
	// for slow CI.
	deadline := time.After(5 * time.Second)
	for calls.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("fn ran %d times, want >=3 (immediate + ticks)",
				calls.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestEveryStopsTickingAfterCancel(t *testing.T) {
	var calls atomic.Int64
	r := Every("stop", 10*time.Millisecond, func(context.Context) {
		calls.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	deadline := time.After(5 * time.Second)
	for calls.Load() < 1 {
		select {
		case <-deadline:
			t.Fatal("fn never ran")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("Run did not return after cancel")
	}
	// Give any in-flight tick a moment, then confirm no more calls.
	time.Sleep(30 * time.Millisecond)
	got := calls.Load()
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != got {
		t.Fatalf("fn kept running after cancel: %d → %d", got, calls.Load())
	}
}

func TestIdleBlocksUntilCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Idle(ctx); close(done) }()

	select {
	case <-done:
		t.Fatal("Idle returned before ctx cancel")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Idle did not return after cancel")
	}
}

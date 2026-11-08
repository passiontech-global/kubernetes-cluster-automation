// poll_test.go — the bounded fixed-cadence poll behind the wait
// loops that used to hand-roll "try N times, sleep between, bail on
// ctx". The injected sleep seam keeps every path sleep-free.

package cycle

import (
	"context"
	"testing"
	"time"
)

// TestPollSuccessOnNthAttempt: check first, then ctx, then sleep —
// a success short-circuits WITHOUT a trailing sleep.
func TestPollSuccessOnNthAttempt(t *testing.T) {
	attempts, sleeps := 0, 0
	ok := Poll(context.Background(), 5, time.Hour,
		func() bool {
			attempts++
			return attempts == 3
		},
		func(time.Duration) { sleeps++ })
	if !ok {
		t.Fatal("Poll must report the 3rd-attempt success")
	}
	if attempts != 3 || sleeps != 2 {
		t.Fatalf("attempts=%d sleeps=%d want 3/2", attempts, sleeps)
	}
}

// TestPollExhaustsTries: every failed attempt sleeps — including the
// LAST one, matching the original loops that slept before returning
// their timeout error.
func TestPollExhaustsTries(t *testing.T) {
	attempts, sleeps := 0, 0
	ok := Poll(context.Background(), 3, time.Hour,
		func() bool {
			attempts++
			return false
		},
		func(time.Duration) { sleeps++ })
	if ok {
		t.Fatal("exhausted tries must report false")
	}
	if attempts != 3 || sleeps != 3 {
		t.Fatalf("attempts=%d sleeps=%d want 3/3", attempts, sleeps)
	}
}

// TestPollCancelledCtxStops: a cancelled ctx fails the poll without
// the final sleep — check, then the ctx gate, then sleep.
func TestPollCancelledCtxStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts, sleeps := 0, 0
	ok := Poll(ctx, 10, time.Hour,
		func() bool {
			attempts++
			if attempts == 2 {
				cancel()
			}
			return false
		},
		func(time.Duration) { sleeps++ })
	if ok {
		t.Fatal("cancelled ctx must report false")
	}
	if attempts != 2 || sleeps != 1 {
		t.Fatalf("attempts=%d sleeps=%d want 2/1 — cancel must stop before attempt 3", attempts, sleeps)
	}
}

// TestPollNilSleepDefaultsToTimeSleep: nil sleep → time.Sleep (the
// etcdmaint seam's default); a real short interval keeps the test
// bounded.
func TestPollNilSleepDefaultsToTimeSleep(t *testing.T) {
	attempts := 0
	ok := Poll(context.Background(), 3, time.Millisecond,
		func() bool {
			attempts++
			return attempts == 2
		}, nil)
	if !ok || attempts != 2 {
		t.Fatalf("ok=%v attempts=%d want true/2", ok, attempts)
	}
}

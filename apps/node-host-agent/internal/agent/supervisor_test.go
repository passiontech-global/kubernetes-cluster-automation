// supervisor_test.go — the restart-backoff reset policy. The loop
// itself (panic recovery, metrics, jitter) is covered in
// agent_test.go; this file pins the superviseHealthyRun rule that
// decides when the exponential ladder resets: only a run healthy
// enough in ABSOLUTE terms (twice the current backoff, or 5 minutes
// flat) may reset — the original "outlived the current backoff" rule
// let a 5.1s crash-loop reset the ladder every round and stay pinned
// at a 5s restart cadence forever.
package agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSuperviseHealthyRun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		elapsed, backof time.Duration
		want            bool
	}{
		// Instant death — never healthy, ladder keeps climbing.
		{"instant death", 0, superviseBackoffInitial, false},
		{"short crash", time.Second, superviseBackoffInitial, false},
		// The bug this pins: a run dying just past the current
		// backoff resets the OLD rule and keeps the 5s loop alive
		// forever — under the new rule the ladder still climbs.
		{"crash just past current backoff", 5100 * time.Millisecond, 5 * time.Second, false},
		{"crash just past doubled backoff", 11 * time.Second, 10 * time.Second, false},
		// Healthy runs: twice the current backoff resets.
		{"survived double the backoff", 10 * time.Second, 5 * time.Second, true},
		{"survived double a mid-ladder backoff", 80 * time.Second, 40 * time.Second, true},
		// The absolute floor: any run of 5 minutes or more is
		// healthy, whatever the ladder says (backoff*2 at the cap
		// would be 10m — the floor keeps the reset reachable).
		{"absolute five minute floor", superviseBackoffMax, superviseBackoffMax, true},
		{"just under the floor", superviseBackoffMax - time.Second, superviseBackoffMax, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := superviseHealthyRun(tc.elapsed, tc.backof); got != tc.want {
				t.Fatalf("superviseHealthyRun(%v, %v) = %v, want %v",
					tc.elapsed, tc.backof, got, tc.want)
			}
		})
	}
}

// TestRestartTimerDrainsStaleTick: a bare timer.Reset on a timer
// whose tick is still queued in timer.C — the case every Run that
// outlives the armed backoff produces (the timer fires 5s into the
// run) — hands the STALE tick to the select: the restart happens
// with ZERO wait and the whole 5s→5m ladder is skipped. restartTimer
// must stop+drain before Reset, so the re-armed fire lands no
// earlier than the new delay.
func TestRestartTimerDrainsStaleTick(t *testing.T) {
	t.Parallel()
	timer := time.NewTimer(5 * time.Millisecond)
	time.Sleep(15 * time.Millisecond) // tick fired, NOT consumed
	restartTimer(timer, 200*time.Millisecond)
	select {
	case <-timer.C:
		t.Fatal("stale tick consumed — restart skipped the backoff")
	case <-time.After(100 * time.Millisecond):
	}
	// The re-armed fire still lands after the full new delay.
	select {
	case <-timer.C:
	case <-time.After(2 * time.Second):
		t.Fatal("re-armed timer never fired")
	}
}

// ladderSubsystem: the first Run outlives the armed 5s backoff timer
// (fires mid-run), the second blocks until ctx is cancelled.
type ladderSubsystem struct {
	calls     atomic.Int32
	firstDone chan struct{}
}

func (s *ladderSubsystem) Name() string { return "ladder" }

func (s *ladderSubsystem) Run(ctx context.Context) {
	if s.calls.Add(1) == 1 {
		time.Sleep(superviseBackoffInitial + 300*time.Millisecond)
		close(s.firstDone)
		return
	}
	<-ctx.Done()
}

// TestSuperviseWaitsFullBackoffAfterRunOutlivingBackoff: the armed
// timer fires INSIDE any Run that outlives the current backoff —
// the normal healthy case. The queued stale tick must not skip the
// wait: the restart after such a run still waits the full jittered
// backoff (≥ backoff − 15%).
func TestSuperviseWaitsFullBackoffAfterRunOutlivingBackoff(t *testing.T) {
	a := New(Config{})
	sub := &ladderSubsystem{firstDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.superviseSubsystem(ctx, sub)

	<-sub.firstDone // the first Run outlived the armed timer
	ended := time.Now()

	// The second Run must start — but no earlier than the shortest
	// jittered wait (backoff ±15% → ≥ backoff*17/20). The 20ms poll
	// granularity is noise against a 4.25s floor.
	var restartedAt time.Time
	for deadline := ended.Add(10 * time.Second); time.Now().Before(deadline); {
		if sub.calls.Load() >= 2 {
			restartedAt = time.Now()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if restartedAt.IsZero() {
		t.Fatal("supervisor never restarted the subsystem")
	}
	if gap := restartedAt.Sub(ended); gap < superviseBackoffInitial*17/20 {
		t.Fatalf("second Run started %v after the first ended — the stale "+
			"timer tick skipped the %v backoff", gap, superviseBackoffInitial)
	}
}

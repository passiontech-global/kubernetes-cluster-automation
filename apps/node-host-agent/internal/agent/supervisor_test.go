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

// ladderSubsystem: the first Run outlives the armed 5s backoff timer
// (fires mid-run), the second blocks until ctx is cancelled.
type ladderSubsystem struct {
	calls     atomic.Int32
	firstDone chan struct{}
	// restarted signals the SECOND Run's entry (cap 1, non-blocking
	// send — later entries are irrelevant to the single waiter).
	restarted chan struct{}
}

func (s *ladderSubsystem) Name() string { return "ladder" }

func (s *ladderSubsystem) Run(ctx context.Context) {
	if s.calls.Add(1) == 1 {
		// Load-bearing real-time scenario: the run must outlive the
		// supervisor's initial backoff for superviseHealthyRun to
		// keep the ladder where it is — there is no fake clock for
		// the supervisor's production timers.
		time.Sleep(superviseBackoffInitial + 300*time.Millisecond)
		close(s.firstDone)
		return
	}
	select {
	case s.restarted <- struct{}{}:
	default:
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
	sub := &ladderSubsystem{
		firstDone: make(chan struct{}),
		restarted: make(chan struct{}, 1),
	}
	ctx := t.Context()
	go a.superviseSubsystem(ctx, sub)

	<-sub.firstDone // the first Run outlived the armed timer
	ended := time.Now()

	// The second Run must start — but no earlier than the shortest
	// jittered wait (backoff ±15% → ≥ backoff*17/20). Waiting on the
	// subsystem's own restarted signal instead of polling: the 10s
	// guard is only the give-up bound.
	var restartedAt time.Time
	select {
	case <-sub.restarted:
		restartedAt = time.Now()
	case <-time.After(10 * time.Second):
	}
	if restartedAt.IsZero() {
		t.Fatal("supervisor never restarted the subsystem")
	}
	if gap := restartedAt.Sub(ended); gap < superviseBackoffInitial*17/20 {
		t.Fatalf("second Run started %v after the first ended — the stale "+
			"timer tick skipped the %v backoff", gap, superviseBackoffInitial)
	}
}

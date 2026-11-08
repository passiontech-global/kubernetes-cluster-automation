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

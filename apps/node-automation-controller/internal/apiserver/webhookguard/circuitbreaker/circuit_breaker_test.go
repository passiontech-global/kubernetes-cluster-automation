// circuit_breaker_test.go — unit coverage for the breaker's
// test-seam threshold selection; the sweep-level coverage lives in
// the facade's webhook_guard_test.go, which drives run() end to end.
package circuitbreaker

import (
	"testing"
	"time"
)

// tripThreshold picks the faster partition window only when raw
// Ready endpoints remain (all of them stranded on bad nodes); a truly
// empty backend keeps the full dead threshold. Field overrides win
// over the package defaults.
func TestTripThresholdSelection(t *testing.T) {
	b := &Breaker{}
	if got := b.tripThreshold(0); got != DeadThreshold {
		t.Fatalf("raw=0 threshold = %s, want %s", got, DeadThreshold)
	}
	if got := b.tripThreshold(3); got != PartitionedThreshold {
		t.Fatalf("raw>0 threshold = %s, want %s", got, PartitionedThreshold)
	}
	b = &Breaker{
		zeroThreshold:          7 * time.Minute,
		partitionZeroThreshold: 42 * time.Second}
	if got := b.tripThreshold(0); got != 7*time.Minute {
		t.Fatalf("zeroThreshold override ignored: %s", got)
	}
	if got := b.tripThreshold(1); got != 42*time.Second {
		t.Fatalf("partitionZeroThreshold override ignored: %s", got)
	}
}

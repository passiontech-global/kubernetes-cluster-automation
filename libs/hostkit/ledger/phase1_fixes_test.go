// phase1_fixes_test.go — regression coverage for FirstSeenLedger future-skew self-healing.
package ledger

import (
	"testing"
	"time"
)

func TestFirstSeenLedgerFutureSkewSelfHeals(t *testing.T) {
	var fs FirstSeenLedger
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	fs.Seed("k1", now.Add(10*time.Minute))

	if age, ok := fs.Seen("k1", now); !ok || age != 0 {
		t.Fatalf("Seen on future stamp = (%v, %v), want (0, true)", age, ok)
	}
	first, seen := fs.Observe("k1", now)
	if seen || !first.Equal(now) {
		t.Fatalf("Observe on future stamp = (%v, %v), want (%v, false)", first, seen, now)
	}
	later := now.Add(5 * time.Minute)
	if age, ok := fs.Seen("k1", later); !ok || age != 5*time.Minute {
		t.Fatalf("Seen after self-heal = (%v, %v), want (5m, true)", age, ok)
	}
}

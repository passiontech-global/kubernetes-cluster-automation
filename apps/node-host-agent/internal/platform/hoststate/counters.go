// counters.go — the consecutive-* on-disk fail counters
// (controllerhygiene): read, locked increment, reset. They ride the
// same epoch-file format as the budgets but are a separate concern
// — a streak counter, not a cooldown.

package hoststate

import (
	"os"
	"path/filepath"
)

// --- consecutive-* counters (controllerhygiene) ---

// Counter reads <Dir>/<name> as an int — absent/garbage → 0.
func (s *Store) Counter(name string) int {
	return int(s.Epoch(filepath.Join(s.Dir, name)))
}

// Incr mirrors lib.sh ctr_inc: read + increment + write + return.
// Garbage → 1. A failed write returns 0 (the streak is lost, never
// invented). The read-modify-write runs under the same mutex as
// RateTrySpend: counters are shared with the feeder goroutine
// (consecutive-journal-unreadable is incremented by BOTH
// controllerhygiene's cycle and its feeder-side journal reads), so
// an unlocked check-then-write can drop a concurrent increment.
func (s *Store) Incr(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.Counter(name) + 1
	if !s.WriteEpochFile(filepath.Join(s.Dir, name), int64(n)) {
		return 0
	}
	return n
}

// ResetCounter removes a consecutive-* file.
func (s *Store) ResetCounter(name string) {
	_ = os.Remove(filepath.Join(s.Dir, name))
}

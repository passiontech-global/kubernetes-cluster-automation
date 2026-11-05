// streak.go — StreakLedger: the consecutive-sweep counter several
// modules hand-roll as map[string]int plus a prune loop —
// orphanendpointslicecleaner's absentStreak (an EndpointSlice must
// be seen without its Service N sweeps in a row before the
// re-confirm + delete unlocks; UID in the key so a recreate never
// inherits another object's streak), corednswatchdog's streak map
// (consecutive probe failures per pod, saturating at
// corednsStreakMax), deadnodesweeper's stuck counters. The shared
// shape: Hit where the condition holds this sweep, Reset where a
// live re-check disproved it (stale snapshot — a fresh occurrence
// must not ride an old streak), Prune the keys whose object
// vanished so the map cannot grow on churn-prone names.
//
// Like the ledgers in cooldown.go/seen.go the zero value is ready
// to use (lazy arm on first Hit/Set) and nothing locks — sweeps
// are single-goroutine or the caller serializes.
package shared

// StreakLedger counts, per key, how many consecutive sweeps the
// tracked condition held.
type StreakLedger struct {
	streaks map[string]int
}

// Hit increments key's streak and returns the new count, creating
// the ledger lazily — callers compare the return against their
// threshold ("act once this reaches N") without a separate read.
func (s *StreakLedger) Hit(key string) int {
	if s.streaks == nil {
		s.streaks = map[string]int{}
	}
	s.streaks[key]++
	return s.streaks[key]
}

// Set forces key's streak to n — e.g. pinning an already-flagged
// key at its threshold so it stays acted-on instead of counting
// up forever (corednswatchdog's `streak[name] = corednsStreakMax`).
func (s *StreakLedger) Set(key string, n int) {
	if s.streaks == nil {
		s.streaks = map[string]int{}
	}
	s.streaks[key] = n
}

// Count reports key's current streak — 0 for an untracked key.
func (s *StreakLedger) Count(key string) int {
	return s.streaks[key]
}

// Reset drops key — the next Hit restarts at 1. Call where a live
// re-confirm disproved the condition (the snapshot was stale) so
// the next genuine occurrence re-arms from zero instead of
// inheriting the streak.
func (s *StreakLedger) Reset(key string) {
	delete(s.streaks, key)
}

// Prune deletes every tracked key for which keep returns false and
// returns the drop count. Call once per sweep with the set of keys
// whose object still exists so entries for vanished objects
// re-arm. The same skip-on-incomplete-sweep contract as
// FirstSeenLedger.Prune applies: the ledger cannot tell "condition
// resolved" from "object never evaluated", so on a failed or
// short-circuited sweep an empty keep set would wipe still-valid
// streaks — callers skip Prune then.
func (s *StreakLedger) Prune(keep func(key string) bool) int {
	pruned := 0
	for k := range s.streaks {
		if !keep(k) {
			delete(s.streaks, k)
			pruned++
		}
	}
	return pruned
}

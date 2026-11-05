// seen.go — SeenSet: the "warn/report once per key" bookkeeping
// modules hand-roll as map[string]struct{} plus a prune loop.
// csr-watcher's warned/reported sets are the canonical shape: mark a
// key the first time it is acted on, suppress repeats on later
// sweeps, and drop entries whose object vanished so the set cannot
// grow forever on churn-prone names.
//
// Like the ledgers in cooldown.go/ledger.go the zero value is ready
// to use (lazy arm on first Add) and nothing locks — sweeps are
// single-goroutine or the caller serializes.
package shared

// SeenSet tracks which keys have already been noted.
type SeenSet struct {
	set map[string]struct{}
}

// Add records key, reporting whether it was new — callers fire the
// once-action (warn log, IncError) only on a true return.
func (s *SeenSet) Add(key string) bool {
	if s.set == nil {
		s.set = map[string]struct{}{}
	}
	if _, ok := s.set[key]; ok {
		return false
	}
	s.set[key] = struct{}{}
	return true
}

// Has reports whether key was previously Added.
func (s *SeenSet) Has(key string) bool {
	_, ok := s.set[key]
	return ok
}

// Forget drops key — a re-added key reads as new again.
func (s *SeenSet) Forget(key string) {
	delete(s.set, key)
}

// Prune deletes every key for which live returns false and returns
// the drop count. Call once per sweep with the set of still-existing
// objects so entries for vanished objects re-arm (the same lifecycle
// as FirstSeenLedger.Prune — skip it on incomplete sweeps, when an
// empty live set would wipe still-live keys).
func (s *SeenSet) Prune(live func(key string) bool) int {
	pruned := 0
	for k := range s.set {
		if !live(k) {
			delete(s.set, k)
			pruned++
		}
	}
	return pruned
}

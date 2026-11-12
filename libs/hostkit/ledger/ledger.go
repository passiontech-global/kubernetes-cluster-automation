// Package ledger holds the time-keyed and count-keyed bookkeeping
// ledgers more than one app hand-rolls as map[string]time.Time /
// map[string]int: CooldownSet ("acted on at T; suppress repeats
// inside the window"), FirstSeenLedger ("first seen at T; a
// condition counts as persistent only once now-first exceeds the
// window") and StreakLedger ("consecutive sweeps the condition
// held"). Ported verbatim from
// node-automation-controller's internal/platform/state — the state
// package keeps type aliases so its ~95 call sites compile
// unchanged, while node-host-agent consumes the types directly.
//
// Like GaugeLedger (which stays app-side: it is typed on
// *prometheus.GaugeVec) the zero value is ready to use (lazy arm on
// first write). CooldownSet locks: the controller's Deps.Heals is
// one ledger shared by every check in the sweep, and the
// cluster-health-probes run loop drives checks through a bounded
// worker pool, so two checks may stamp the same ledger
// concurrently. FirstSeenLedger and StreakLedger stay lock-free —
// they are per-check instance state, one goroutine touches a given
// check per sweep. The maps are deliberately unbounded: keys live
// only as long as the condition they track, and Prune/Forget is the
// caller's hygiene hook for resolved ones.
package ledger

import (
	"maps"
	"sync"
	"time"
)

// CooldownSet tracks the last action stamp per key.
type CooldownSet struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// CooledDown reports whether key was stamped inside cooldown of now.
// An unstamped key is never cooled down.
func (c *CooldownSet) CooledDown(key string, cooldown time.Duration, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	last, ok := c.last[key]
	return ok && now.Sub(last) < cooldown
}

// Stamp records now as key's last-action time, creating the ledger
// lazily. Stamp the SUCCESSFUL action only — a failed attempt must
// not start the cooldown or one transient error would suppress the
// remediation for the whole window.
func (c *CooldownSet) Stamp(key string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		c.last = map[string]time.Time{}
	}
	c.last[key] = now
}

// Forget drops key's stamp — the next CooledDown reads uncooled.
// Use when the healed condition is verified resolved so a brand-new
// failure on the same key is not suppressed by the old stamp.
func (c *CooldownSet) Forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.last, key)
}

// Prune deletes every tracked key for which keep returns false and
// returns how many were dropped — the same ledger-hygiene contract
// as FirstSeenLedger.Prune: call only after a complete sweep (a
// partial keep set would wipe live cooldowns). keep receives the
// key AND its last-action stamp so age-based retention ("drop
// stamps older than the longest cooldown") needs no second lookup.
func (c *CooldownSet) Prune(keep func(key string, last time.Time) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	pruned := 0
	for k, last := range c.last {
		if !keep(k, last) {
			delete(c.last, k)
			pruned++
		}
	}
	return pruned
}

// Entries returns a COPY of the key→last-stamp map — callers that
// must inspect ages without stamping (prune-by-age, "when did this
// last fire" diagnostics) read it instead of reaching into
// internals. Mutating the returned map does not affect the ledger;
// write through Stamp/Forget.
func (c *CooldownSet) Entries() map[string]time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.last)
}

// PruneExpired evicts every stamp older than maxAge and returns the
// evicted count — the leak bound for ledgers keyed by EPHEMERAL
// names (pod/Job/CertificateRequest names with rotating suffixes):
// a stamp whose window has long passed can never suppress an action
// again, so holding it only grows the map one dead name per heal
// forever. Call once per sweep with the LONGEST cooldown the ledger
// serves — a shorter bound would drop still-binding stamps (when a
// keyspace mixes cooldowns, the widest window wins). Unlike Prune
// this needs no complete-sweep precondition: expiry is computed per
// entry, not voted by a keep set.
func (c *CooldownSet) PruneExpired(now time.Time, maxAge time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	pruned := 0
	for k, last := range c.last {
		if now.Sub(last) > maxAge {
			delete(c.last, k)
			pruned++
		}
	}
	return pruned
}

// Last returns key's last-action stamp without copying the ledger —
// the single-key read for "when did this one fire" diagnostics;
// Entries() is for bulk inspection only (it copies the whole map).
func (c *CooldownSet) Last(key string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.last[key]
	return t, ok
}

// FirstSeenLedger tracks when each key was first observed — the
// persistence window behind "condition held for >Nm" signatures.
type FirstSeenLedger struct {
	seen map[string]time.Time
}

// Observe returns key's first-seen time, stamping now on first
// observation. seen=false on the first sighting — callers treat it
// as "inside the window", so a flapping signature that resolves and
// recurs re-arms instead of instantly reading as persistent.
func (l *FirstSeenLedger) Observe(key string, now time.Time) (first time.Time, seen bool) {
	if l.seen == nil {
		l.seen = map[string]time.Time{}
	}
	if t, ok := l.seen[key]; ok {
		return t, true
	}
	l.seen[key] = now
	return now, false
}

// Seed records first as key's first-seen when key is untracked OR
// first predates the current stamp — the persisted-annotation
// restore path: a stamp recovered off the target object must win
// the ledger's first sighting so the window keeps counting from the
// original observation instead of re-arming at the post-restart
// sweep. Seeds only ever move the stamp EARLIER (the wider window
// wins, matching the wider-of-two-clocks persisted-cooldown
// contract); a later seed never rejuvenates the window.
func (l *FirstSeenLedger) Seed(key string, first time.Time) {
	if l.seen == nil {
		l.seen = map[string]time.Time{}
	}
	if t, ok := l.seen[key]; !ok || first.Before(t) {
		l.seen[key] = first
	}
}

// Seen reports how long key has been tracked — (age, true) for a
// tracked key, (0, false) otherwise. Unlike Observe it never stamps,
// so it suits read-only checks that must not create ledger entries.
func (l *FirstSeenLedger) Seen(key string, now time.Time) (time.Duration, bool) {
	t, ok := l.seen[key]
	if !ok {
		return 0, false
	}
	return now.Sub(t), true
}

// Forget drops key's entry — the next Observe re-arms the window.
func (l *FirstSeenLedger) Forget(key string) {
	delete(l.seen, key)
}

// Prune deletes every tracked key for which keep returns false and
// returns how many were dropped. Call once per sweep with the set of
// still-live signatures so resolved conditions re-arm; an empty keep
// set after a failed/short-circuited sweep would wipe the ledger —
// callers skip Prune on incomplete sweeps for exactly that reason
// (same contract as GaugeLedger.Prune).
func (l *FirstSeenLedger) Prune(keep func(key string) bool) int {
	pruned := 0
	for k := range l.seen {
		if !keep(k) {
			delete(l.seen, k)
			pruned++
		}
	}
	return pruned
}

// SeenSet tracks which keys have already been noted — the
// "warn/report once per key" bookkeeping modules hand-roll as
// map[string]struct{} plus a prune loop.
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

// StreakLedger counts, per key, how many consecutive sweeps the
// tracked condition held — the shared shape behind every
// absentStreak/stuck-counter map[string]int: Hit where the condition
// holds this sweep, Reset where a live re-check disproved it (stale
// snapshot — a fresh occurrence must not ride an old streak), Prune
// the keys whose object vanished so the map cannot grow on
// churn-prone names.
//
// Like the other ledgers the zero value is ready to use (lazy arm on
// first Hit/Set) and nothing locks — sweeps are single-goroutine or
// the caller serializes.
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

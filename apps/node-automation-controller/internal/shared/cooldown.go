// cooldown.go — the two time-keyed bookkeeping ledgers nearly every
// sweep module hand-rolls as map[string]time.Time:
//
//   - CooldownSet: "key was acted on at T; suppress repeats inside
//     the cooldown window" — heal/guard actions that must not
//     re-fire every sweep (leader-pod deletes, restart stamps).
//   - FirstSeenLedger: "key first appeared at T; a condition counts
//     as persistent only once now-first exceeds the window" — the
//     first-seen streak bookkeeping behind every "stuck for >Nm"
//     signature, pruned when the signature resolves so a later
//     recurrence re-arms the window.
//
// Like GaugeLedger the zero value is ready to use (lazy arm on first
// write) and neither type locks — sweeps are single-goroutine or the
// caller already serializes under its own mutex (clusterhealthprobes'
// deps.mu). The maps are deliberately unbounded: keys live only as
// long as the condition they track, and Prune/Forget is the caller's
// hygiene hook for resolved ones.
package shared

import "time"

// CooldownSet tracks the last action stamp per key.
type CooldownSet struct {
	last map[string]time.Time
}

// CooledDown reports whether key was stamped inside cooldown of now.
// An unstamped key is never cooled down.
func (c *CooldownSet) CooledDown(key string, cooldown time.Duration, now time.Time) bool {
	last, ok := c.last[key]
	return ok && now.Sub(last) < cooldown
}

// Stamp records now as key's last-action time, creating the ledger
// lazily. Stamp the SUCCESSFUL action only — a failed attempt must
// not start the cooldown or one transient error would suppress the
// remediation for the whole window.
func (c *CooldownSet) Stamp(key string, now time.Time) {
	if c.last == nil {
		c.last = map[string]time.Time{}
	}
	c.last[key] = now
}

// Forget drops key's stamp — the next CooledDown reads uncooled.
// Use when the healed condition is verified resolved so a brand-new
// failure on the same key is not suppressed by the old stamp.
func (c *CooldownSet) Forget(key string) {
	delete(c.last, key)
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

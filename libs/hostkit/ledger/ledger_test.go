package ledger

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCooldownSetZeroValue(t *testing.T) {
	// A literally-constructed consumer (no setup) must work:
	// zero-value ledger reads uncooled, Forget/Prune are no-ops,
	// Entries is empty.
	var c CooldownSet
	now := time.Now()
	if c.CooledDown("k", time.Minute, now) {
		t.Fatal("zero-value CooldownSet reported a cooldown")
	}
	c.Forget("k")
	if n := c.Prune(func(string, time.Time) bool { return false }); n != 0 {
		t.Fatalf("zero-value Prune = %d, want 0", n)
	}
	if got := c.Entries(); len(got) != 0 {
		t.Fatalf("zero-value Entries = %v", got)
	}
}

func TestCooldownSetStampAndCooledDown(t *testing.T) {
	var c CooldownSet
	now := time.Now()
	c.Stamp("a", now.Add(-time.Minute))

	// Inside the window.
	if !c.CooledDown("a", 5*time.Minute, now) {
		t.Fatal("stamp 1m old read uncooled inside a 5m window")
	}
	// Past the window.
	if c.CooledDown("a", 30*time.Second, now) {
		t.Fatal("stamp 1m old read cooled inside a 30s window")
	}
	// Unstamped keys never read cooled.
	if c.CooledDown("b", time.Hour, now) {
		t.Fatal("unstamped key reported a cooldown")
	}
}

func TestCooldownSetForget(t *testing.T) {
	var c CooldownSet
	now := time.Now()
	c.Stamp("a", now)
	c.Forget("a")
	if c.CooledDown("a", time.Hour, now) {
		t.Fatal("Forget did not drop the stamp")
	}
	// Forgetting an untracked key is a no-op, not a panic.
	c.Forget("never-stamped")
}

func TestCooldownSetPrune(t *testing.T) {
	var c CooldownSet
	now := time.Now()
	c.Stamp("live", now)
	c.Stamp("stale", now.Add(-time.Hour))

	// Age-based retention through the keep callback's stamp argument:
	// keep whatever fired within the last 30m.
	n := c.Prune(func(_ string, last time.Time) bool {
		return now.Sub(last) < 30*time.Minute
	})
	if n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	if c.CooledDown("stale", 24*time.Hour, now) {
		t.Fatal("pruned key still tracked")
	}
	if !c.CooledDown("live", time.Minute, now) {
		t.Fatal("kept key lost its stamp")
	}
}

func TestCooldownSetEntries(t *testing.T) {
	var c CooldownSet
	t1 := time.Now().Add(-time.Minute)
	t2 := time.Now()
	c.Stamp("a", t1)
	c.Stamp("b", t2)

	got := c.Entries()
	if len(got) != 2 || !got["a"].Equal(t1) || !got["b"].Equal(t2) {
		t.Fatalf("Entries = %v", got)
	}
	// The copy is read-only: mutating it must not corrupt the ledger.
	got["a"] = time.Now().Add(time.Hour)
	delete(got, "b")
	if !c.CooledDown("a", 5*time.Minute, time.Now()) {
		t.Fatal("Entries mutation reached into the ledger")
	}
	if _, ok := c.Entries()["b"]; !ok {
		t.Fatal("Entries delete removed a ledger entry")
	}
}

// Seed only ever moves a first-seen stamp EARLIER: it restores a
// persisted window into an empty ledger and wins against a fresher
// in-RAM stamp, but a later seed must never rejuvenate the window.
func TestFirstSeenLedgerSeed(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Hour)
	later := now.Add(-time.Minute)

	var l FirstSeenLedger
	l.Seed("k", older)
	if got, _ := l.Observe("k", now); !got.Equal(older) {
		t.Fatalf("Seed then Observe = %v, want %v", got, older)
	}

	// A fresher seed does not overwrite an older stamp.
	l.Seed("k", later)
	if got, _ := l.Observe("k", now); !got.Equal(older) {
		t.Fatalf("Seed(later) overwrote the older stamp: %v", got)
	}

	// An older seed DOES overwrite a fresher stamp — the restore
	// path after Observe already stamped now this sweep.
	l.Seed("k2", now)
	l.Seed("k2", older)
	if got, _ := l.Observe("k2", now); !got.Equal(older) {
		t.Fatalf("Seed(older) did not move the stamp back: %v", got)
	}
}

// PruneExpired is the leak bound for ephemeral-key ledgers: stamps
// past the retention bound are evicted, live ones are kept, and the
// zero-value ledger is a safe no-op.
func TestCooldownSetPruneExpired(t *testing.T) {
	var c CooldownSet
	now := time.Now()
	c.Stamp("live", now.Add(-time.Minute))
	c.Stamp("dead-pod-abc12", now.Add(-time.Hour))
	c.Stamp("dead-pod-def34", now.Add(-2*time.Hour))

	if n := c.PruneExpired(now, 30*time.Minute); n != 2 {
		t.Fatalf("PruneExpired = %d, want 2", n)
	}
	if !c.CooledDown("live", 5*time.Minute, now) {
		t.Fatal("live stamp was evicted")
	}
	if _, ok := c.Last("dead-pod-abc12"); ok {
		t.Fatal("expired stamp survived PruneExpired")
	}
	// A zero-value ledger must not panic.
	var empty CooldownSet
	if n := empty.PruneExpired(now, time.Minute); n != 0 {
		t.Fatalf("zero-value PruneExpired = %d, want 0", n)
	}
}

// Last is the single-key read for "when did this one fire": it
// reports the exact stamp without copying the ledger, ok=false on an
// unstamped key (and on the zero-value ledger), and it must observe
// Forget — the delivered-delete diagnostics read the stamp
// before/after a heal through it.
func TestCooldownSetLast(t *testing.T) {
	var c CooldownSet
	now := time.Now()

	if _, ok := c.Last("k"); ok {
		t.Fatal("zero-value Last reported a stamp")
	}
	stamp := now.Add(-time.Minute)
	c.Stamp("k", stamp)
	got, ok := c.Last("k")
	if !ok || !got.Equal(stamp) {
		t.Fatalf("Last = (%v,%v), want (%v,true)", got, ok, stamp)
	}
	// Entries copies; Last must keep reading the live map — stamping
	// another key must not disturb k's read.
	c.Stamp("other", now)
	if got, ok = c.Last("k"); !ok || !got.Equal(stamp) {
		t.Fatalf("Last after second stamp = (%v,%v), want (%v,true)",
			got, ok, stamp)
	}
	c.Forget("k")
	if _, ok = c.Last("k"); ok {
		t.Fatal("Last still reports a forgotten stamp")
	}
}

func TestFirstSeenLedgerObserveAndSeenForgetPrune(t *testing.T) {
	t0 := time.Unix(1000, 0)
	l := &FirstSeenLedger{}
	if _, seen := l.Observe("k", t0); seen {
		t.Fatal("first observe reported seen")
	}
	first, seen := l.Observe("k", t0.Add(30*time.Second))
	if !seen || !first.Equal(t0) {
		t.Fatalf("repeat observe got (%v, %v), want (%v, true)", first, seen, t0)
	}
	age, ok := l.Seen("k", t0.Add(time.Minute))
	if !ok || age != time.Minute {
		t.Fatalf("Seen got (%v, %v), want (1m, true)", age, ok)
	}
	if _, ok := l.Seen("absent", t0); ok {
		t.Fatalf("untracked key reported tracked: ok=%v", ok)
	}
	l.Forget("k")
	if _, ok := l.Seen("k", t0); ok {
		t.Fatal("forgotten key still tracked")
	}
	if _, seen := l.Observe("k", t0.Add(2*time.Minute)); seen {
		t.Fatal("forgotten key did not re-arm")
	}
	l.Seed("a", t0)
	l.Seed("b", t0)
	dropped := l.Prune(func(key string) bool { return key == "a" })
	if dropped != 2 {
		t.Fatalf("Prune dropped %d, want 2 (a kept; b and re-armed k dropped)", dropped)
	}
	if _, ok := l.Seen("a", t0); !ok {
		t.Fatal("kept key pruned")
	}
	if _, ok := l.Seen("b", t0); ok {
		t.Fatal("dropped key retained")
	}
}

func TestSeenSetAddOnce(t *testing.T) {
	var s SeenSet
	if !s.Add("a") {
		t.Fatal("first Add should report new")
	}
	if s.Add("a") {
		t.Fatal("second Add of the same key should not report new")
	}
	if !s.Has("a") {
		t.Fatal("Has should see the added key")
	}
	if s.Has("b") {
		t.Fatal("Has should not see an unknown key")
	}
}

func TestSeenSetPrune(t *testing.T) {
	var s SeenSet
	s.Add("a")
	s.Add("b")
	s.Add("c")
	if n := s.Prune(func(k string) bool { return k != "b" }); n != 1 {
		t.Fatalf("Prune dropped %d keys, want 1", n)
	}
	if s.Has("b") || !s.Has("a") || !s.Has("c") {
		t.Fatal("Prune kept the wrong keys")
	}
	// A re-added pruned key reads as new again (re-arms the once-action).
	if !s.Add("b") {
		t.Fatal("re-Add of a pruned key should report new")
	}
}

func TestSeenSetForget(t *testing.T) {
	s := &SeenSet{}
	s.Add("a")
	s.Forget("a")
	if s.Has("a") {
		t.Fatal("forgotten key still present")
	}
	if !s.Add("a") {
		t.Fatal("forgotten key did not re-arm")
	}
	s.Forget("never-added") // no-op on untracked key
	if !s.Has("a") {
		t.Fatal("Forget on an untracked key disturbed a live entry")
	}
}

func TestStreakLedgerHitIncrements(t *testing.T) {
	var s StreakLedger // zero value — lazy arm on first Hit
	if n := s.Hit("a"); n != 1 {
		t.Fatalf("first Hit = %d, want 1", n)
	}
	if n := s.Hit("a"); n != 2 {
		t.Fatalf("second Hit = %d, want 2", n)
	}
	if n := s.Hit("b"); n != 1 {
		t.Fatalf("Hit on a second key = %d, want 1", n)
	}
	if s.Count("a") != 2 {
		t.Fatalf("Count(a) = %d, want 2", s.Count("a"))
	}
}

func TestStreakLedgerCountUntracked(t *testing.T) {
	var s StreakLedger
	if s.Count("missing") != 0 {
		t.Fatal("untracked key should count 0")
	}
}

func TestStreakLedgerResetReArms(t *testing.T) {
	var s StreakLedger
	s.Hit("a")
	s.Hit("a")
	s.Reset("a")
	if s.Count("a") != 0 {
		t.Fatal("Reset key should count 0")
	}
	if n := s.Hit("a"); n != 1 {
		t.Fatalf("Hit after Reset = %d, want 1 — streak re-arms", n)
	}
	// Reset on an untracked key is a no-op.
	s.Reset("never-seen")
}

func TestStreakLedgerSetForces(t *testing.T) {
	var s StreakLedger // Set also lazy-arms
	s.Set("a", 5)
	if s.Count("a") != 5 {
		t.Fatalf("Count after Set = %d, want 5", s.Count("a"))
	}
	if n := s.Hit("a"); n != 6 {
		t.Fatalf("Hit after Set = %d, want 6", n)
	}
	s.Set("b", 0)
	if s.Count("b") != 0 {
		t.Fatal("Set to 0 should count 0")
	}
}

func TestStreakLedgerPrune(t *testing.T) {
	var s StreakLedger
	s.Hit("a")
	s.Hit("b")
	s.Hit("c")
	if n := s.Prune(func(k string) bool { return k != "b" }); n != 1 {
		t.Fatalf("Prune dropped %d keys, want 1", n)
	}
	if s.Count("b") != 0 || s.Count("a") != 1 || s.Count("c") != 1 {
		t.Fatal("Prune kept the wrong keys")
	}
	// A pruned key re-arms from zero on its next Hit.
	if n := s.Hit("b"); n != 1 {
		t.Fatalf("Hit on a pruned key = %d, want 1", n)
	}
}

// TestCooldownSetConcurrentAccess pins the ledger's locking contract:
// a CooldownSet shared across a worker pool must be safe — run under
// -race this fails on any unsynchronized map access.
func TestCooldownSetConcurrentAccess(t *testing.T) {
	var c CooldownSet
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		key := fmt.Sprintf("heal/%d", i)
		wg.Add(4)
		go func() { defer wg.Done(); c.Stamp(key, now) }()
		go func() { defer wg.Done(); c.CooledDown(key, time.Minute, now) }()
		go func() { defer wg.Done(); _ = c.Entries() }()
		go func() { defer wg.Done(); c.PruneExpired(now, time.Minute) }()
	}
	wg.Wait()
	if got := len(c.Entries()); got == 0 {
		t.Fatal("concurrent stamps left the ledger empty")
	}
}

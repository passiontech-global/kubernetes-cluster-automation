package state

import (
	"testing"
	"time"
)

func TestCooldownSetZeroValue(t *testing.T) {
	// A literally-constructed module (no Setup) must work: zero-value
	// ledger reads uncooled, Forget/Prune are no-ops, Entries is empty.
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

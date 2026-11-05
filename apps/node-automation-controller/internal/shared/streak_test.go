package shared

import "testing"

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

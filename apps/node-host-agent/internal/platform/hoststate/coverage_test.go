package hoststate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfirmMarkerAndPruneMarkers(t *testing.T) {
	s, clk, _ := newTestStore(t)
	dir := s.Dir

	// First sight creates marker and returns (true, false).
	first, confirmed := s.ConfirmMarker("seen-pod-a", time.Hour)
	if !first || confirmed {
		t.Fatalf("first ConfirmMarker = (%v,%v), want (true,false)", first, confirmed)
	}
	// Second sight within minAge returns (false, false).
	first, confirmed = s.ConfirmMarker("seen-pod-a", time.Hour)
	if first || confirmed {
		t.Fatalf("within minAge ConfirmMarker = (%v,%v), want (false,false)", first, confirmed)
	}
	// Advance past minAge -> confirms on subsequent cycle.
	clk.now = clk.now.Add(2 * time.Hour)
	first, confirmed = s.ConfirmMarker("seen-pod-a", time.Hour)
	if first || !confirmed {
		t.Fatalf("elapsed ConfirmMarker = (%v,%v), want (false,true)", first, confirmed)
	}

	// PruneMarkers keeps "pod-a" and drops "pod-b".
	s.RateSpend("seen-pod-b")
	s.PruneMarkers("seen-", func(id string) bool { return id == "pod-a" })
	if _, err := os.Stat(filepath.Join(dir, "seen-pod-a")); err != nil {
		t.Fatalf("kept marker missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "seen-pod-b")); !os.IsNotExist(err) {
		t.Fatalf("pruned marker still exists: %v", err)
	}
}

func TestReapStaleLatch(t *testing.T) {
	s, _, _ := newTestStore(t)
	s.EnterFrom("shared-x", "owner-1", "entering")
	if !s.Exists("shared-x") {
		t.Fatal("expected latch to exist")
	}
	if !s.ReapStaleLatch("shared-x") {
		t.Fatal("expected ReapStaleLatch to return true")
	}
	if s.Exists("shared-x") {
		t.Fatal("expected latch to be removed after ReapStaleLatch")
	}
	if s.ReapStaleLatch("shared-x") {
		t.Fatal("expected second ReapStaleLatch to return false")
	}
}

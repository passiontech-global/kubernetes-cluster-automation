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

func TestPruneMarkersPrunesRAMOnlyEntries(t *testing.T) {
	s, _, _ := newTestStore(t)
	cleanDir := filepath.Clean(s.Dir)
	siblingDir := filepath.Clean(t.TempDir())

	// Populate:
	// - disk + lastSpent marker ("keep-disk")
	// - RAM-only lastSpent + ramEpochs ("drop-ram" and "keep-ram")
	// - lastSpent-only with no disk file ("drop-spent-only")
	// - sibling dir entries that must stay untouched
	s.RateSpend("seen-keep-disk")

	s.shared.mu.Lock()
	if s.shared.lastSpent == nil {
		s.shared.lastSpent = map[string]int64{}
	}
	s.shared.lastSpent[rateSpendKey(cleanDir, "seen-drop-ram")] = 1700000001
	s.shared.lastSpent[rateSpendKey(cleanDir, "seen-keep-ram")] = 1700000002
	s.shared.lastSpent[rateSpendKey(cleanDir, "seen-drop-spent-only")] = 1700000003
	s.shared.lastSpent[rateSpendKey(siblingDir, "seen-drop-ram")] = 1700000004
	s.shared.mu.Unlock()

	s.shared.ramMu.Lock()
	if s.shared.ramEpochs == nil {
		s.shared.ramEpochs = map[string]int64{}
	}
	s.shared.ramEpochs[filepath.Join(cleanDir, "seen-drop-ram")] = 1700000001
	s.shared.ramEpochs[filepath.Join(cleanDir, "seen-keep-ram")] = 1700000002
	s.shared.ramEpochs[filepath.Join(siblingDir, "seen-drop-ram")] = 1700000004
	s.shared.ramMu.Unlock()

	keepCalls := map[string]int{}
	s.PruneMarkers("seen-", func(id string) bool {
		keepCalls[id]++
		// Calling back into Store inside keep must not deadlock.
		_ = s.Exists("unrelated")
		return id == "keep-disk" || id == "keep-ram"
	})

	for _, id := range []string{"keep-disk", "keep-ram", "drop-ram", "drop-spent-only"} {
		if keepCalls[id] != 1 {
			t.Fatalf("keep(%q) called %d times, want 1", id, keepCalls[id])
		}
	}

	// Kept markers remain; dropped RAM-only markers are gone from both maps.
	if _, err := os.Stat(filepath.Join(cleanDir, "seen-keep-disk")); err != nil {
		t.Fatalf("kept disk marker missing: %v", err)
	}
	if s.Epoch(filepath.Join(cleanDir, "seen-keep-ram")) == 0 {
		t.Fatal("kept RAM marker was unexpectedly cleared")
	}
	if s.Epoch(filepath.Join(cleanDir, "seen-drop-ram")) != 0 {
		t.Fatal("dropped RAM marker still present in Epoch/ramEpochs")
	}
	s.shared.mu.Lock()
	_, hasDropRAM := s.shared.lastSpent[rateSpendKey(cleanDir, "seen-drop-ram")]
	_, hasDropSpent := s.shared.lastSpent[rateSpendKey(cleanDir, "seen-drop-spent-only")]
	_, hasKeepRAM := s.shared.lastSpent[rateSpendKey(cleanDir, "seen-keep-ram")]
	_, hasSiblingSpent := s.shared.lastSpent[rateSpendKey(siblingDir, "seen-drop-ram")]
	s.shared.mu.Unlock()
	if hasDropRAM || hasDropSpent {
		t.Fatalf("dropped entries remain in lastSpent: dropRam=%v dropSpent=%v", hasDropRAM, hasDropSpent)
	}
	if !hasKeepRAM || !hasSiblingSpent {
		t.Fatalf("kept/sibling entries missing from lastSpent: keepRam=%v sibling=%v", hasKeepRAM, hasSiblingSpent)
	}
	s.shared.ramMu.RLock()
	_, hasSiblingRAM := s.shared.ramEpochs[filepath.Join(siblingDir, "seen-drop-ram")]
	s.shared.ramMu.RUnlock()
	if !hasSiblingRAM {
		t.Fatal("sibling dir ramEpochs entry was unexpectedly removed")
	}
}

func TestPruneMarkersGlobMetacharacters(t *testing.T) {
	t.Run("bracket_charclass_in_prefix", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		keepFile := filepath.Join(s.Dir, "last-suspect-foo[1]-podA")
		dropFile := filepath.Join(s.Dir, "last-suspect-foo[1]-podB")
		unrelatedFile := filepath.Join(s.Dir, "last-suspect-foo1-keep")
		for _, p := range []string{keepFile, dropFile, unrelatedFile} {
			if err := os.WriteFile(p, []byte("1700000000\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		s.PruneMarkers("last-suspect-foo[1]-", func(id string) bool { return id == "podA" })
		if _, err := os.Stat(keepFile); err != nil {
			t.Fatalf("kept bracket marker missing: %v", err)
		}
		if _, err := os.Stat(dropFile); !os.IsNotExist(err) {
			t.Fatalf("stale bracket marker survived PruneMarkers: err=%v", err)
		}
		if _, err := os.Stat(unrelatedFile); err != nil {
			t.Fatalf("unrelated marker matching glob charclass was deleted: %v", err)
		}
	})

	t.Run("unclosed_bracket_in_prefix", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		dropFile := filepath.Join(s.Dir, "last-suspect-foo[-podB")
		if err := os.WriteFile(dropFile, []byte("1700000000\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.PruneMarkers("last-suspect-foo[-", nil)
		if _, err := os.Stat(dropFile); !os.IsNotExist(err) {
			t.Fatalf("unclosed-bracket marker survived PruneMarkers: err=%v", err)
		}
	})

	t.Run("question_and_star_wildcards_in_prefix_do_not_delete_unrelated", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		dropQ := filepath.Join(s.Dir, "last-suspect-?-drop")
		keepQ := filepath.Join(s.Dir, "last-suspect-x-keepme")
		dropStar := filepath.Join(s.Dir, "last-suspect-*-drop")
		keepStar := filepath.Join(s.Dir, "last-suspect-abc-keepme")
		for _, p := range []string{dropQ, keepQ, dropStar, keepStar} {
			if err := os.WriteFile(p, []byte("1700000000\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		s.PruneMarkers("last-suspect-?-", nil)
		if _, err := os.Stat(dropQ); !os.IsNotExist(err) {
			t.Fatalf("literal '?' marker not deleted: err=%v", err)
		}
		if _, err := os.Stat(keepQ); err != nil {
			t.Fatalf("unrelated marker deleted by '?' prefix: %v", err)
		}
		s.PruneMarkers("last-suspect-*-", nil)
		if _, err := os.Stat(dropStar); !os.IsNotExist(err) {
			t.Fatalf("literal '*' marker not deleted: err=%v", err)
		}
		if _, err := os.Stat(keepStar); err != nil {
			t.Fatalf("unrelated marker deleted by '*' prefix: %v", err)
		}
	})

	t.Run("glob_metachar_in_store_dir", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "state[0]")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		s := New(dir, filepath.Join(dir, "watchdog.log"), nil, nil)
		keepFile := filepath.Join(dir, "last-suspect-podA")
		dropFile := filepath.Join(dir, "last-suspect-podB")
		for _, p := range []string{keepFile, dropFile} {
			if err := os.WriteFile(p, []byte("1700000000\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		s.PruneMarkers("last-suspect-", func(id string) bool { return id == "podA" })
		if _, err := os.Stat(keepFile); err != nil {
			t.Fatalf("kept marker missing in metachar dir: %v", err)
		}
		if _, err := os.Stat(dropFile); !os.IsNotExist(err) {
			t.Fatalf("stale marker survived in metachar dir: err=%v", err)
		}
	})

	t.Run("missing_dir_still_prunes_ram_markers", func(t *testing.T) {
		missingDir := filepath.Join(t.TempDir(), "does-not-exist")
		s := New(missingDir, filepath.Join(missingDir, "watchdog.log"), nil, nil)
		s.shared.mu.Lock()
		s.shared.lastSpent = map[string]int64{
			rateSpendKey(missingDir, "seen-drop"): 1700000000,
		}
		s.shared.mu.Unlock()
		s.PruneMarkers("seen-", nil)
		s.shared.mu.Lock()
		_, stillPresent := s.shared.lastSpent[rateSpendKey(missingDir, "seen-drop")]
		s.shared.mu.Unlock()
		if stillPresent {
			t.Fatal("RAM marker not pruned when s.Dir does not exist")
		}
	})
}

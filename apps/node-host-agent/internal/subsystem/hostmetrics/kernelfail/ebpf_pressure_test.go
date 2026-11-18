package kernelfail

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

func TestEBPFDefaultCeilings(t *testing.T) {
	if DefaultEBPFProgsMax != 8192 || DefaultEBPFMapsMax != 16384 {
		t.Fatalf("defaults = %d/%d, want 8192/16384",
			DefaultEBPFProgsMax, DefaultEBPFMapsMax)
	}
	f := kfixture(t)
	r := New(f.deps)
	if r.deps.EBPFProgsMax != DefaultEBPFProgsMax ||
		r.deps.EBPFMapsMax != DefaultEBPFMapsMax {
		t.Fatalf("New defaults = %d/%d, want %d/%d",
			r.deps.EBPFProgsMax, r.deps.EBPFMapsMax,
			DefaultEBPFProgsMax, DefaultEBPFMapsMax)
	}
}

func TestEBPFPressureLatchAndHysteresis(t *testing.T) {
	f := kfixture(t)
	progs, maps, scanned := DefaultEBPFProgsMax, 500, true
	scanAt := time.Unix(1000, 0)
	f.deps.EBPFSnapshot = func() (int, int, bool, time.Time) {
		return progs, maps, scanned, scanAt
	}
	r := New(f.deps)
	latchFile := filepath.Join(f.deps.StateDir, latchdefs.LatchFilePrefix+latchdefs.LatchEBPFPressure)

	// Tick 1 and 2: not yet latched (needs 3 consecutive fresh scans).
	r.updateEBPFPressure()
	scanAt = scanAt.Add(time.Minute)
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); !os.IsNotExist(err) {
		t.Fatal("latched before 3 consecutive fresh scans")
	}

	// Tick 3 (new stamp): enters LatchEBPFPressure.
	scanAt = scanAt.Add(time.Minute)
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); err != nil {
		t.Fatalf("expected latch file after 3 fresh scans: %v", err)
	}

	// Drop inside the hysteresis band (6144 < 8192, >= 6144 clear is
	// exclusive on the low side): latch remains held.
	progs = DefaultEBPFProgsMax * 3 / 4
	scanAt = scanAt.Add(time.Minute)
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); err != nil {
		t.Fatalf("latch cleared inside hysteresis band: %v", err)
	}

	// Unscanned tick: inconclusive, latch remains held.
	scanned = false
	progs = 0
	scanAt = scanAt.Add(time.Minute)
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); err != nil {
		t.Fatalf("latch cleared on unscanned tick: %v", err)
	}

	// Scanned and below clear threshold (< 6144 and < 12288): latch exits.
	scanned = true
	progs = DefaultEBPFProgsMax*3/4 - 1
	maps = DefaultEBPFMapsMax*3/4 - 1
	scanAt = scanAt.Add(time.Minute)
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); !os.IsNotExist(err) {
		t.Fatal("expected latch to exit below hysteresis clear threshold")
	}
}

// TestEBPFPressureCachedReadDoesNotAdvanceStreak pins the Wave-5 fix:
// a 30s latch ticker re-reading the same 60s sweep cache used to latch
// after 3 ticks (90s) even though only one real scan had happened.
func TestEBPFPressureCachedReadDoesNotAdvanceStreak(t *testing.T) {
	f := kfixture(t)
	progs := DefaultEBPFProgsMax
	scanAt := time.Unix(2000, 0)
	f.deps.EBPFSnapshot = func() (int, int, bool, time.Time) {
		return progs, 0, true, scanAt
	}
	r := New(f.deps)
	latchFile := filepath.Join(f.deps.StateDir, latchdefs.LatchFilePrefix+latchdefs.LatchEBPFPressure)

	// Four re-reads of an unchanged stamp (the ticker outruns the cache).
	for i := 0; i < 4; i++ {
		r.updateEBPFPressure()
	}
	if _, err := os.Stat(latchFile); !os.IsNotExist(err) {
		t.Fatal("latched from repeated reads of one cached snapshot")
	}

	// Three genuinely new scans reach the confirmation threshold.
	for i := 0; i < ebpfConfirmTicks; i++ {
		scanAt = scanAt.Add(time.Minute)
		r.updateEBPFPressure()
	}
	if _, err := os.Stat(latchFile); err != nil {
		t.Fatalf("expected latch after %d fresh scans: %v", ebpfConfirmTicks, err)
	}
}

package kernelfail

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

func TestEBPFPressureLatchAndHysteresis(t *testing.T) {
	f := kfixture(t)
	progs, maps, scanned := 2048, 500, true
	f.deps.EBPFSnapshot = func() (int, int, bool) {
		return progs, maps, scanned
	}
	r := New(f.deps)
	latchFile := filepath.Join(f.deps.StateDir, latchdefs.LatchFilePrefix+latchdefs.LatchEBPFPressure)

	// Tick 1 and 2: not yet latched (needs 3 consecutive ticks).
	r.updateEBPFPressure()
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); !os.IsNotExist(err) {
		t.Fatal("latched before 3 consecutive ticks")
	}

	// Tick 3: enters LatchEBPFPressure.
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); err != nil {
		t.Fatalf("expected latch file after 3 ticks: %v", err)
	}

	// Drop into hysteresis band (1800 < 2048, >= 1536): latch remains held.
	progs = 1800
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); err != nil {
		t.Fatalf("latch cleared inside hysteresis band: %v", err)
	}

	// Unscanned tick: inconclusive, latch remains held.
	scanned = false
	progs = 0
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); err != nil {
		t.Fatalf("latch cleared on unscanned tick: %v", err)
	}

	// Scanned and below clear threshold (< 1536 and < 3072): latch exits.
	scanned = true
	progs = 1535
	maps = 3071
	r.updateEBPFPressure()
	if _, err := os.Stat(latchFile); !os.IsNotExist(err) {
		t.Fatal("expected latch to exit below hysteresis clear threshold")
	}
}

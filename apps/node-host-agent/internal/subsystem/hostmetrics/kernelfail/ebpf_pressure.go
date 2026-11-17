// ebpf_pressure.go — Wave-3 #10: kernel eBPF prog/map/bpffs-pin leak latch.
//
// Consumes the Collector's cached ebpfSnapshot closure (0 extra I/O),
// enters LatchEBPFPressure after 3 consecutive ticks >= EBPFProgsMax (2048)
// or EBPFMapsMax (4096), and clears only once both drop below the 75%
// hysteresis band (1536 / 3072).
package kernelfail

import (
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

const (
	// DefaultEBPFProgsMax / DefaultEBPFMapsMax are the eBPF leak ceilings.
	// Hysteresis clear sits at 3/4 (1536 progs / 3072 maps).
	DefaultEBPFProgsMax = 2048
	DefaultEBPFMapsMax  = 4096
	ebpfConfirmTicks    = 3
)

func (r *Runner) updateEBPFPressure() {
	if r.deps.EBPFSnapshot == nil {
		return
	}
	progs, maps, scanned := r.deps.EBPFSnapshot()
	if !scanned {
		return
	}
	progsMax := r.deps.EBPFProgsMax
	if progsMax <= 0 {
		progsMax = DefaultEBPFProgsMax
	}
	mapsMax := r.deps.EBPFMapsMax
	if mapsMax <= 0 {
		mapsMax = DefaultEBPFMapsMax
	}
	progsClear := progsMax * 3 / 4
	mapsClear := mapsMax * 3 / 4

	latchName := latchdefs.LatchFilePrefix + latchdefs.LatchEBPFPressure
	latchPath := r.statePath(latchName)

	switch {
	case progs >= progsMax || maps >= mapsMax:
		r.ebpfStreak++
		if r.ebpfStreak >= ebpfConfirmTicks {
			r.ensureStateLatch(latchPath, latchName, fmt.Sprintf(
				"progs=%d/%d maps=%d/%d", progs, progsMax, maps, mapsMax))
		}
	case progs < progsClear && maps < mapsClear:
		r.ebpfStreak = 0
		if r.deps.Store != nil {
			r.deps.Store.Exit(latchdefs.LatchEBPFPressure, nil)
		}
	default:
		// Inside the hysteresis band [clear, max): keep held latch if any,
		// but reset the entry streak so a noisy edge cannot accumulate.
		r.ebpfStreak = 0
	}
}

// ebpf_pressure.go — Wave-3 #10: kernel eBPF prog/map/bpffs-pin leak latch.
//
// Consumes the Collector's cached ebpfSnapshotAt closure (0 extra I/O),
// enters LatchEBPFPressure after 3 consecutive FRESH SCANS >=
// DefaultEBPFProgsMax (8192) or DefaultEBPFMapsMax (16384), and clears
// only once both drop below the 75% hysteresis band (6144 / 12288).
//
// Wave-5 P0: the latch ticker is 30s while the fd-link cache is 60s,
// so a naive streak counted each re-read of the same snapshot as new
// evidence — 3 ticks (90s) latched a healthy Cilium worker. The cache
// stamp is now the freshness token; re-reads are ignored entirely.
// EBPFResourcePressure is a storm-gate/heartbeat condition only (it is
// NOT in nodecond.HangPreCordonNames): cordon never shrinks BPF maps,
// so the old 2m hang fuse started a cluster-wide cordon domino.
package kernelfail

import (
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

const (
	// DefaultEBPFProgsMax / DefaultEBPFMapsMax are the eBPF leak ceilings.
	// Raised from 2048/4096 to 8192/16384: a normal Cilium datapath
	// already carries thousands of progs/pins, and the maps figure
	// intentionally double-counts an object that is both fd-open and
	// pinned (the node_host_agent_ebpf_maps_count contract). Hysteresis
	// clear sits at 3/4 (6144 progs / 12288 maps).
	DefaultEBPFProgsMax = 8192
	DefaultEBPFMapsMax  = 16384
	ebpfConfirmTicks    = 3
)

func (r *Runner) updateEBPFPressure() {
	if r.deps.EBPFSnapshot == nil {
		return
	}
	progs, maps, scanned, scanAt := r.deps.EBPFSnapshot()
	if !scanned {
		return
	}
	// A zero stamp is only emitted by hand-built test seams — treat it
	// as always fresh so those seams keep their old semantics. The real
	// collector always stamps the sweep, and a tick that merely re-reads
	// the same cached sweep must not advance the confirmation streak.
	if !scanAt.IsZero() && !scanAt.After(r.ebpfLastScanAt) {
		return
	}
	r.ebpfLastScanAt = scanAt

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

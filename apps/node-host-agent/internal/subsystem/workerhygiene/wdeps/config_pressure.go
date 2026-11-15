// config_pressure.go — the leak/pressure-guard knobs:
// PressureConfig, its defaults and its
// NODE_HOST_AGENT_DSTATE_STORM_THRESHOLD env row (the d-state-storm D-state
// storm + A2 zombie storm thresholds and the psi-memory-thrash PSI memory-thrash
// guard all read this group).
package wdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// PressureConfig groups the leak/pressure guard knobs: the d-state-storm
// D-state storm + A2 zombie storm thresholds and the psi-memory-thrash PSI
// memory-thrash guard — latch when /proc/pressure/memory `full
// avg60` exceeds PSIFullAvg60 (percent) AND MemAvailable/MemTotal
// drops under MemFreeMinRatio for ConsecNeeded cycles.
type PressureConfig struct {
	DStateStormThreshold int     // total D-state procs → storm latch (5)
	ZombieStormThreshold int     // defunct children of one parent → storm
	PSIFullAvg60         float64 // PSI memory full avg60 percent (25)
	MemFreeMinRatio      float64 // free-mem ratio floor (0.08)
	// Inotify* knobs for the inotify-pressure-hygiene check: the
	// hard sysctl ceilings the auto-bump respects (watches
	// additionally cap at the ~1KiB/watch RAM budget the check
	// computes from MemTotal) and the runaway-pod evict switch.
	// InotifyEvictRunawayPod is NOT defaulted in applyDefaults —
	// the env knob owns the true default (the Feeder.Enabled
	// precedent); a direct-New caller leaves it false.
	InotifyMaxInstancesCeiling int64
	InotifyMaxWatchesCeiling   int64
	InotifyEvictRunawayPod     bool
}

func (p *PressureConfig) applyDefaults() {
	if p.DStateStormThreshold <= 0 {
		p.DStateStormThreshold = defaultDStateStormThreshold
	}
	if p.ZombieStormThreshold <= 0 {
		p.ZombieStormThreshold = zombieStormThreshold
	}
	if p.PSIFullAvg60 <= 0 {
		p.PSIFullAvg60 = defaultPSIFullAvg60
	}
	if p.MemFreeMinRatio <= 0 {
		p.MemFreeMinRatio = defaultMemFreeMinRatio
	}
	if p.InotifyMaxInstancesCeiling <= 0 {
		p.InotifyMaxInstancesCeiling = defaultInotifyMaxInstancesCeiling
	}
	if p.InotifyMaxWatchesCeiling <= 0 {
		p.InotifyMaxWatchesCeiling = defaultInotifyMaxWatchesCeiling
	}
}

// envKnobs returns the pressure domain's env rows — the D-state
// storm threshold (empty env → in-package default) plus the
// inotify-pressure-hygiene ceilings and evict switch.
func (p *PressureConfig) envKnobs() []envx.Knob {
	return []envx.Knob{
		envx.IntKnob(envnames.EnvDstateStormThreshold, &p.DStateStormThreshold, defaultDStateStormThreshold),
		envx.Int64Knob(envnames.EnvInotifyMaxInstancesCeiling, &p.InotifyMaxInstancesCeiling, defaultInotifyMaxInstancesCeiling),
		envx.Int64Knob(envnames.EnvInotifyMaxWatchesCeiling, &p.InotifyMaxWatchesCeiling, defaultInotifyMaxWatchesCeiling),
		envx.BoolKnob(envnames.EnvInotifyEvictRunawayPod, &p.InotifyEvictRunawayPod, true),
	}
}

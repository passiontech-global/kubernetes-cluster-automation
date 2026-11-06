// config_pressure.go — the leak/pressure-guard knobs:
// PressureConfig, its defaults and its
// NODE_HOST_AGENT_DSTATE_STORM_THRESHOLD env row (the W7-H1 D-state
// storm + A2 zombie storm thresholds and the W2 PSI memory-thrash
// guard all read this group).
package wdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// PressureConfig groups the leak/pressure guard knobs: the W7-H1
// D-state storm + A2 zombie storm thresholds and the W2 PSI
// memory-thrash guard — latch when /proc/pressure/memory `full
// avg60` exceeds PSIFullAvg60 (percent) AND MemAvailable/MemTotal
// drops under MemFreeMinRatio for ConsecNeeded cycles.
type PressureConfig struct {
	DStateStormThreshold int     // total D-state procs → storm latch (5)
	ZombieStormThreshold int     // defunct children of one parent → storm
	PSIFullAvg60         float64 // PSI memory full avg60 percent (25)
	MemFreeMinRatio      float64 // free-mem ratio floor (0.08)
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
}

// envKnobs returns the pressure domain's env row — the W7 D-state
// storm threshold (empty env → in-package default).
func (p *PressureConfig) envKnobs() []envx.Knob {
	return []envx.Knob{
		envx.IntKnob(envnames.EnvDstateStormThreshold, &p.DStateStormThreshold, defaultDStateStormThreshold),
	}
}

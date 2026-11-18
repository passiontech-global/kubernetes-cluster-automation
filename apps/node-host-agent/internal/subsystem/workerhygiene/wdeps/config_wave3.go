// config_wave3.go — Wave-3 self-healing guard knobs (#3 UDP stale sockets,
// #4 mount-max / shared-storm / loop GC, #9 CPU CFS / VMA pressure).
package wdeps

import (
	"math"
	"strconv"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Wave3Config carries every knob for the Wave-3 workerhygiene guards.
type Wave3Config struct {
	// #3 Connected-UDP dead-backend socket destroyer.
	UDPStaleDestroyEnabled bool
	UDPStalePodCIDRs       string
	UDPStaleMaxKills       int

	// #4 Mount-max, shared peer-group storm & orphan /dev/loop* GC.
	MountTableEnterRatio float64
	MountSharedStormMax  int
	MountMaxCeiling      int64
	LoopGCEnabled        bool
	HostDevDir           string // host /dev (default /dev; /host/dev in DaemonSet)
	SysBlockDir          string // host /sys/block (default /sys/block; /host/sys/block in DaemonSet)

	// #9 CPU CFS bandwidth throttling & per-PID VMA max_map_count guards.
	CPUCFSThrottleRatio float64
	CPUHostIdleMinRatio float64
	VMAPressureRatio    float64
	VMAMaxCeiling       int64
}

func float64Knob(name string, dst *float64, def float64) envx.Knob {
	return envx.Knob{
		Name: name,
		Resolve: func(k string) {
			*dst = def
			if v := envx.String(k, ""); v != "" {
				// Ratios must be finite and in (0, 1] — a NaN/Inf or a
				// >1 value would silently disable every pressure guard.
				if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 &&
					!math.IsNaN(f) && !math.IsInf(f, 0) && f <= 1.0 {
					*dst = f
				} else {
					envx.Warnf("invalid %s (want finite 0 < f <= 1): %q — using default", k, v)
				}
			}
		},
	}
}

func (g *Wave3Config) envKnobs(hostPath func(string) string) []envx.Knob {
	g.HostDevDir = hostPath("/dev")
	g.SysBlockDir = hostPath("/sys/block")
	return []envx.Knob{
		envx.BoolKnob(envnames.EnvUDPStaleDestroyEnabled, &g.UDPStaleDestroyEnabled, true),
		envx.StringKnob(envnames.EnvUDPStalePodCIDRs, &g.UDPStalePodCIDRs, ""),
		envx.IntKnob(envnames.EnvUDPStaleMaxKills, &g.UDPStaleMaxKills, 16),
		float64Knob(envnames.EnvMountTableEnterRatio, &g.MountTableEnterRatio, 0.80),
		envx.IntKnob(envnames.EnvMountSharedStormMax, &g.MountSharedStormMax, 4096),
		envx.Int64Knob(envnames.EnvMountMaxCeiling, &g.MountMaxCeiling, 200000),
		envx.BoolKnob(envnames.EnvLoopGCEnabled, &g.LoopGCEnabled, true),
		float64Knob(envnames.EnvCPUCFSThrottleRatio, &g.CPUCFSThrottleRatio, 0.50),
		float64Knob(envnames.EnvCPUHostIdleMinRatio, &g.CPUHostIdleMinRatio, 0.40),
		float64Knob(envnames.EnvVMAPressureRatio, &g.VMAPressureRatio, 0.85),
		envx.Int64Knob(envnames.EnvVMAMaxCeiling, &g.VMAMaxCeiling, 1048576),
	}
}

func (g *Wave3Config) applyDefaults() {
	if g.UDPStaleMaxKills <= 0 {
		g.UDPStaleMaxKills = 16
	}
	if g.MountTableEnterRatio <= 0 {
		g.MountTableEnterRatio = 0.80
	}
	if g.MountSharedStormMax <= 0 {
		g.MountSharedStormMax = 4096
	}
	if g.MountMaxCeiling <= 0 {
		g.MountMaxCeiling = 200000
	}
	if g.HostDevDir == "" {
		g.HostDevDir = "/dev"
	}
	if g.SysBlockDir == "" {
		g.SysBlockDir = "/sys/block"
	}
	if g.CPUCFSThrottleRatio <= 0 {
		g.CPUCFSThrottleRatio = 0.50
	}
	if g.CPUHostIdleMinRatio <= 0 {
		g.CPUHostIdleMinRatio = 0.40
	}
	if g.VMAPressureRatio <= 0 {
		g.VMAPressureRatio = 0.85
	}
	if g.VMAMaxCeiling <= 0 {
		g.VMAMaxCeiling = 1048576
	}
}

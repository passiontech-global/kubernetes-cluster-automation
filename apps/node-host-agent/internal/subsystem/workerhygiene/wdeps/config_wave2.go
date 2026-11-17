// config_wave2.go — the wave-2 self-healing guard knobs (P0.3
// ephemeral-port pressure, P1.5 hung runc reaper, P1.6 CSI
// registration guard, P2.11 netfilter guard, P2.12 GPU PCIe guard).
// One domain group so the env surface, defaults and tests stay
// together; the checks themselves live in the runtime/ctr/guards
// domain packages and read cfg.Wave2.
package wdeps

import (
	"strconv"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Wave2Config carries every knob the wave-2 self-healing checks
// read. Mode fields are envx.Mode (On/Off/Auto) — the *_MODE knobs
// are tri-state so an operator can force a guard on a node where
// auto-detection would miss it, or off where it misfires.
type Wave2Config struct {
	// P0.3 — ephemeral-port-pressure (runtime_ephemeral_ports.go):
	// netlink sock-diag census of per-destination ephemeral port
	// usage + CLOSE_WAIT leaks, SYN_SENT destroy, and the
	// leaking-pod eviction rails.
	PortEvictRunawayPod      bool    // evict a pod holding >= MinPct of leaking sockets
	SynSentKillEnabled       bool    // destroy stuck SYN_SENT sockets via SOCK_DESTROY
	SynSentMinRetrans        int     // idiag_retrans floor for a wedged SYN_SENT socket
	SynSentMaxKills          int     // per-cycle SOCK_DESTROY cap
	MaxConcurrent            int     // ip_local_port_range-derived ephemeral ceiling hint
	PortTupleRatioThreshold  float64 // used/max ratio that arms the pressure gauge
	PortCloseWaitMax         int     // absolute CLOSE_WAIT count that arms pressure
	PortLeakWindowSec        int     // seconds a pod must sustain the leak share
	PortLeakMinPct           int     // pod must hold >= this % of leaking sockets
	PortLeakEvictCooldownMin int     // last-port-leak-evict budget

	// P1.5 — hung-runc-reaper (ctr/runc_hang.go): runc/crun
	// processes wedged in S state past the age bound, confirmed
	// over consecutive cycles before a bounded kill.
	HungRuncKillEnabled      bool // kill confirmed-hung runtimes (off = detect-only)
	HungRuncAgeSec           int  // minimum runtime age in S state
	HungRuncConfirmCycles    int  // consecutive cycles a pid must appear
	HungRuncMaxKillsPerCycle int  // per-cycle kill cap

	// P1.6 — csi-registration-guard (runtime/csi_gpu_reg.go):
	// kubelet plugins_registry vs CSINode.spec.drivers desync
	// healer — orphan -reg.sock removal, stale node-plugin pod
	// bounce, CSIRegistrationWedged latch.
	CSIGuardMode              envx.Mode // auto = only when a CSI plugin exists
	CSIHealEnabled            bool      // master heal switch (off = detect-only)
	CSIGuardProbeSec          int       // unix-dial timeout per registration socket
	CSIGuardECONNRefusedCycle int       // consecutive ECONNREFUSED cycles before -reg.sock removal
	CSIGuardMissingMin        int       // minutes a Ready plugin pod may miss registration
	CSIGuardBounceCooldownMin int       // last-csi-reg-bounce budget

	// P2.12 — gpu-pcie-guard (runtime/csi_gpu_reg.go +
	// hostmetrics gpu_pcie.go): sysfs 0x10de census vs
	// nvidia.com/gpu allocatable vs device-plugin pod health.
	GPUGuardMode              envx.Mode
	GPUHealEnabled            bool // master heal switch (off = detect-only)
	GPUGuardProbeSec          int  // sysfs rescan cadence hint
	GPUGuardDesyncMin         int  // minutes allocatable/plugin desync must persist
	GPUGuardBounceCooldownMin int  // last-gpu-plugin-bounce budget

	// P2.11 — netfilter-guard (guards/netfilter_guard.go): stuck
	// nft/iptables commands, xtables.lock wedge probe, legacy-rule
	// leakage gauge.
	NetfilterGuardMode          envx.Mode // on = always run; auto reserved
	NetfilterGuardIntervalSec   int       // seconds between guard sweeps
	NetfilterGuardCmdTimeoutSec int       // per-command wall bound
	NetfilterGuardLockPath      string    // host xtables.lock path
	NetfilterGuardHungCmdSec    int       // command age that counts as hung
	NetfilterGuardStuckCycles   int       // consecutive cycles a hung cmd must persist
	NetfilterGuardMaxKillsCycle int       // per-cycle kill cap
	NetfilterGuardKillEnabled   bool      // kill hung commands (off = detect-only)
	NetfilterGuardLegacyProbe   bool      // run iptables-legacy-save for the leak gauge
}

// envKnobs is the wave-2 env surface — appended after the Runtime
// rows in ConfigFromEnv so the pre-existing knob order is untouched.
func (g *Wave2Config) envKnobs() []envx.Knob {
	return []envx.Knob{
		envx.BoolKnob(envnames.EnvPortEvictRunawayPod, &g.PortEvictRunawayPod, true),
		envx.BoolKnob(envnames.EnvPortDestroySynSent, &g.SynSentKillEnabled, true),
		envx.IntKnob(envnames.EnvPortSynSentMinRetrans, &g.SynSentMinRetrans, 4),
		envx.IntKnob(envnames.EnvMaxConcurrent, &g.MaxConcurrent, 0),
		{Name: envnames.EnvPortTupleRatioThreshold, Resolve: func(name string) {
			if v := envx.String(name, ""); v != "" {
				if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
					g.PortTupleRatioThreshold = f
				}
			}
		}},
		envx.IntKnob(envnames.EnvPortCloseWaitMax, &g.PortCloseWaitMax, 4096),
		envx.IntKnob(envnames.EnvPortLeakWindowSec, &g.PortLeakWindowSec, 120),
		envx.IntKnob(envnames.EnvPortLeakMinPct, &g.PortLeakMinPct, 50),
		envx.IntKnob(envnames.EnvPortLeakEvictCooldownMin, &g.PortLeakEvictCooldownMin, 15),
		envx.BoolKnob(envnames.EnvCtrKillHungRunc, &g.HungRuncKillEnabled, true),
		envx.IntKnob(envnames.EnvCtrRuncMaxAge, &g.HungRuncAgeSec, 180),
		envx.IntKnob(envnames.EnvHungRuncConfirmCycles, &g.HungRuncConfirmCycles, 2),
		envx.IntKnob(envnames.EnvHungRuncMaxKillsPerCycle, &g.HungRuncMaxKillsPerCycle, 4),
		{Name: envnames.EnvCSIGuardMode, Resolve: func(name string) {
			g.CSIGuardMode = envx.ModeEnv(name, envx.ModeAuto)
		}},
		envx.BoolKnob(envnames.EnvCSIHealEnabled, &g.CSIHealEnabled, true),
		envx.IntKnob(envnames.EnvCSIGuardProbeSec, &g.CSIGuardProbeSec, 15),
		envx.IntKnob(envnames.EnvCSIGuardECONNRefusedCycles, &g.CSIGuardECONNRefusedCycle, 3),
		envx.IntKnob(envnames.EnvCSIGuardMissingMin, &g.CSIGuardMissingMin, 5),
		envx.IntKnob(envnames.EnvCSIGuardBounceCooldownMin, &g.CSIGuardBounceCooldownMin, 30),
		{Name: envnames.EnvGPUGuardMode, Resolve: func(name string) {
			g.GPUGuardMode = envx.ModeEnv(name, envx.ModeAuto)
		}},
		envx.BoolKnob(envnames.EnvGPUHealEnabled, &g.GPUHealEnabled, true),
		envx.IntKnob(envnames.EnvGPUGuardProbeSec, &g.GPUGuardProbeSec, 15),
		envx.IntKnob(envnames.EnvGPUGuardDesyncMin, &g.GPUGuardDesyncMin, 5),
		envx.IntKnob(envnames.EnvGPUGuardBounceCooldownMin, &g.GPUGuardBounceCooldownMin, 30),
		{Name: envnames.EnvNetfilterGuardMode, Resolve: func(name string) {
			g.NetfilterGuardMode = envx.ModeEnv(name, envx.ModeOn)
		}},
		envx.IntKnob(envnames.EnvNetfilterGuardIntervalSec, &g.NetfilterGuardIntervalSec, 15),
		envx.IntKnob(envnames.EnvNetfilterGuardCmdTimeoutSec, &g.NetfilterGuardCmdTimeoutSec, 60),
		// Empty default — the check resolves <Disk.HostRunDir>/
		// xtables.lock so pod mode lands on /host/run (the HOST
		// lock), never the container's own /run.
		envx.StringKnob(envnames.EnvNetfilterGuardLockPath, &g.NetfilterGuardLockPath, ""),
		envx.IntKnob(envnames.EnvNetfilterMaxAge, &g.NetfilterGuardHungCmdSec, 120),
		envx.IntKnob(envnames.EnvNetfilterGuardStuckCycles, &g.NetfilterGuardStuckCycles, 2),
		envx.IntKnob(envnames.EnvNetfilterGuardMaxKillsCycle, &g.NetfilterGuardMaxKillsCycle, 1),
		envx.BoolKnob(envnames.EnvNetfilterKillHung, &g.NetfilterGuardKillEnabled, true),
		// Plan step 3 — the legacy-leak gauge is part of the check,
		// not optional instrumentation.
		envx.BoolKnob(envnames.EnvNetfilterGuardLegacyProbe, &g.NetfilterGuardLegacyProbe, true),
	}
}

// applyDefaults fills the wave-2 knobs — called from Config's
// ApplyDefaults after the domain groups.
func (g *Wave2Config) applyDefaults() {
	if g.PortTupleRatioThreshold <= 0 {
		g.PortTupleRatioThreshold = 0.80
	}
	if g.PortCloseWaitMax <= 0 {
		g.PortCloseWaitMax = 4096
	}
	if g.SynSentMinRetrans <= 0 {
		g.SynSentMinRetrans = 4
	}
	if g.SynSentMaxKills <= 0 {
		g.SynSentMaxKills = 128
	}
	if g.MaxConcurrent <= 0 {
		// ip_local_port_range default 32768-60999 ≈ 28232 usable
		// ephemeral ports; MaxConcurrent is only a hint for the
		// pressure ratio when /proc/sys/net/ipv4/ip_local_port_range
		// can't be read — the check re-derives the real ceiling.
		g.MaxConcurrent = 28232
	}
	if g.PortLeakWindowSec <= 0 {
		g.PortLeakWindowSec = 120
	}
	if g.PortLeakMinPct <= 0 {
		g.PortLeakMinPct = 50
	}
	if g.PortLeakEvictCooldownMin <= 0 {
		g.PortLeakEvictCooldownMin = 15
	}
	if g.HungRuncAgeSec <= 0 {
		g.HungRuncAgeSec = 180
	}
	if g.HungRuncConfirmCycles <= 0 {
		g.HungRuncConfirmCycles = 2
	}
	if g.HungRuncMaxKillsPerCycle <= 0 {
		g.HungRuncMaxKillsPerCycle = 4
	}
	if g.CSIGuardMode == 0 && !envx.IsSet(envnames.EnvCSIGuardMode) {
		// envKnobs already defaulted Auto; this guard is for
		// hand-built Configs (tests) where envKnobs never ran.
		g.CSIGuardMode = envx.ModeAuto
	}
	if g.CSIGuardProbeSec <= 0 {
		g.CSIGuardProbeSec = 15
	}
	if g.CSIGuardECONNRefusedCycle <= 0 {
		g.CSIGuardECONNRefusedCycle = 3
	}
	if g.CSIGuardMissingMin <= 0 {
		g.CSIGuardMissingMin = 5
	}
	if g.CSIGuardBounceCooldownMin <= 0 {
		g.CSIGuardBounceCooldownMin = 30
	}
	if g.GPUGuardProbeSec <= 0 {
		g.GPUGuardProbeSec = 15
	}
	if g.GPUGuardDesyncMin <= 0 {
		g.GPUGuardDesyncMin = 5
	}
	if g.GPUGuardBounceCooldownMin <= 0 {
		g.GPUGuardBounceCooldownMin = 30
	}
	if g.NetfilterGuardIntervalSec <= 0 {
		g.NetfilterGuardIntervalSec = 15
	}
	if g.NetfilterGuardCmdTimeoutSec <= 0 {
		g.NetfilterGuardCmdTimeoutSec = 60
	}
	// NetfilterGuardLockPath stays "" by default — the check
	// resolves <Disk.HostRunDir>/xtables.lock so pod mode lands on
	// the host lock file, not the container's /run.
	if g.NetfilterGuardHungCmdSec <= 0 {
		g.NetfilterGuardHungCmdSec = 120
	}
	if g.NetfilterGuardStuckCycles <= 0 {
		g.NetfilterGuardStuckCycles = 2
	}
	if g.NetfilterGuardMaxKillsCycle <= 0 {
		g.NetfilterGuardMaxKillsCycle = 1
	}
}

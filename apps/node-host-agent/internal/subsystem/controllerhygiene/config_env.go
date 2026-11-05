package controllerhygiene

import (
	"os"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/envx"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: the parsed
// node-watchdog.conf the env → conf → package-default chains fall
// through to (w.wdCfg — may be nil, treated as an empty conf), its
// per-cycle reloader (Config.WatchdogSrc), the shared watchdog state
// dir/log file, the shared journal-unreadable detector inputs, and
// the hostPath join that prefixes host-fs paths with the host root
// ("/host" in the DaemonSet, identity standalone). HostRoot itself is
// NOT a dep: every host-fs path in the config is hostPath()-derived,
// and the ShouldRun(hostRoot) enable-gate stays in the caller.
type EnvDeps struct {
	// Watchdog is the parsed /etc/node-watchdog.conf — the middle
	// layer of every envOr/envIntOr/envDurOr chain. Nil → empty conf
	// (all conf values zero → package defaults apply).
	Watchdog *watchdogconf.Config
	// WatchdogSrc is the per-cycle conf reloader (Config.WatchdogSrc).
	WatchdogSrc *watchdogconf.Reloader
	// WatchdogStateDir / WatchdogLogFile are the shared
	// node-watchdog state dir + log file buildAgentConfig resolves
	// once for the whole pod.
	WatchdogStateDir string
	WatchdogLogFile  string
	// JournalDirs / JournalUnreadableNeeded are the shared journald
	// blindness-detector inputs buildAgentConfig resolves once for
	// workerhygiene + controllerhygiene.
	JournalDirs             []string
	JournalUnreadableNeeded int
	// HostPath joins a host-absolute path under the host-fs root.
	// Nil → identity (host paths used verbatim).
	HostPath func(string) string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob controllerhygiene
// reads and returns a Config ready for New — the env contract lives in
// the package, not in cmd/agent. Enabled is always true here: the wire
// func set it unconditionally and the enable gate
// (NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE "auto"/ShouldRun) plus the
// New error path stay in the caller. Fields wiring never set
// (Hub.SelfEndpoint, KineTTL.MinProcAge, KinePool.DBPortFallback,
// OOMLoop shield adjs, the Feeder probe/remediate cadence knobs,
// EtcdGuard.MinRun, the W8 CPFreeze/PKIDrift knobs, …) stay zero —
// New's applyDefaults fills them exactly as before.
//
// hostPath — NOT the package defaults — supplies the host-fs paths:
// defaultKubeconfig & friends hardcode the "/host" prefix and would
// be wrong on a standalone host (hostRoot "/").
func ConfigFromEnv(d EnvDeps) Config {
	hostPath := d.HostPath
	if hostPath == nil {
		hostPath = func(p string) string { return p }
	}
	// wd is the watchdogconf middle layer of the env → conf →
	// package-default chains; a nil Watchdog dep is an empty conf.
	var wd watchdogconf.Config
	if d.Watchdog != nil {
		wd = *d.Watchdog
	}
	return Config{
		Enabled:          true,
		Interval:         envx.Duration("NODE_HOST_AGENT_CONTROLLER_INTERVAL", defaultInterval),
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
		WatchdogSrc:      d.WatchdogSrc,
		ProcRoot:         envx.String("NODE_HOST_AGENT_PROC_ROOT", defaultProcRoot),
		// No env knob — hostPath-derived like the Admin* paths.
		K0sControllerUnitFile: hostPath("/etc/systemd/system/k0scontroller.service"),
		// env → wdCfg → package defaults; SelfAPI stays EMPTY when
		// neither is set (the solo/dead-fallback fences gate on
		// non-empty — a made-up identity would crown every
		// unconfigured controller first-hub).
		Hub: HubConfig{
			SelfAPI:     envx.Or("NODE_HOST_AGENT_API_SELF", wd.APISelf),
			PeerAPI:     envx.Or("NODE_HOST_AGENT_API_PEER", wd.APIPeer),
			KineDBProbe: envx.Or("NODE_HOST_AGENT_KINE_DB_PROBE", wd.KineDBProbe),
		},
		Sig13: Sig13Config{
			Mode: envx.Or("NODE_HOST_AGENT_SIG13_AUTOFIX", wd.Sig13Autofix),
			StaleMinErrs: envx.IntOr("NODE_HOST_AGENT_STALE_MIN_ERRS",
				wd.Sig13StaleMinErrs, defaultStaleMinErrs),
			GapMin: envx.Int64Or("NODE_HOST_AGENT_GAP_MIN",
				wd.Sig13GapMin, defaultGapMin),
			GapCycles: envx.IntOr("NODE_HOST_AGENT_GAP_CYCLES",
				wd.Sig13GapCycles, defaultGapCycles),
			FrozenCycles: envx.IntOr("NODE_HOST_AGENT_FROZEN_CYCLES",
				wd.Sig13FrozenCycles, defaultFrozenCycles),
			SoloCycles: envx.IntOr("NODE_HOST_AGENT_SOLO_CYCLES",
				wd.Sig13SoloCycles, defaultSoloCycles),
			MinRestart: envx.DurOr("NODE_HOST_AGENT_SIG13_MIN_RESTART_S",
				wd.Sig13MinRestartS, defaultMinRestart),
		},
		KineTTL: KineTTLConfig{
			Mode: envx.Or("NODE_HOST_AGENT_KINE_TTL_AUTOFIX", wd.KineTTLAutofix),
			MinRestart: envx.DurOr("NODE_HOST_AGENT_KINE_TTL_MIN_RESTART_S",
				wd.KineTTLMinRestartS, defaultTTLMinRestart),
			CtlRestart: envx.DurOr("NODE_HOST_AGENT_KINE_TTL_CTL_RESTART_S",
				wd.KineTTLCtlRestartS, defaultTTLCtlRestart),
			RewedgeCycles: envx.IntOr("NODE_HOST_AGENT_KINE_TTL_REWEDGE_CYCLES",
				wd.KineTTLRewedgeCycle, defaultTTLRewedgeCycles),
		},
		KinePool: KinePoolConfig{
			Mode: envx.Or("NODE_HOST_AGENT_KINE_POOL_AUTOFIX", wd.KinePoolAutofix),
			MaxConns: envx.IntOr("NODE_HOST_AGENT_KINE_POOL_MAX_CONNS",
				wd.KinePoolMaxConns, defaultPoolMaxConns),
			Cycles: envx.IntOr("NODE_HOST_AGENT_KINE_POOL_CYCLES",
				wd.KinePoolCycles, defaultPoolCycles),
			MinRestart: envx.DurOr("NODE_HOST_AGENT_KINE_POOL_MIN_RESTART_S",
				wd.KinePoolMinRestartS, defaultPoolMinRestart),
		},
		OOMLoop: OOMLoopConfig{
			Mode: envx.Or("NODE_HOST_AGENT_OOMLOOP_AUTOFIX", wd.OOMLoopAutofix),
			MinKills: envx.IntOr("NODE_HOST_AGENT_OOMLOOP_MIN_KILLS",
				wd.OOMLoopMinKills, defaultOOMMinKills),
			Window: envx.DurOr("NODE_HOST_AGENT_OOMLOOP_WINDOW_S",
				wd.OOMLoopWindowS, defaultOOMWindow),
			// No env knob — hostPath-derived.
			CGroupEventsFile: hostPath("/sys/fs/cgroup/system.slice/" +
				"k0scontroller.service/memory.events"),
		},
		// Admin* + Feeder paths are hostPath()-derived — NOT the
		// package defaults, which hardcode the "/host" prefix.
		AdminKubeconfig: hostPath("/var/lib/k0s/pki/admin.conf"),
		AdminCert:       hostPath("/var/lib/k0s/pki/admin.crt"),
		AdminKey:        hostPath("/var/lib/k0s/pki/admin.key"),
		AdminCA:         hostPath("/var/lib/k0s/pki/ca.crt"),
		InsecureTLS:     envx.Bool("NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS", true),
		Feeder: FeederConfig{
			Enabled: envx.Bool("NODE_HOST_AGENT_ENABLE_FEEDER", true),
			// NOTIFY_SOCKET is a systemd contract, not a
			// NODE_HOST_AGENT_* knob — read it directly.
			NotifySocket:      os.Getenv("NOTIFY_SOCKET"),
			StateDir:          hostPath("/var/lib/k0s-systemd-watchdog"),
			RemediatePeerFile: hostPath("/etc/default/k0scontroller-watchdog"),
		},
		// hostPath default — NOT defaultK0sDir, which hardcodes "/host".
		K0sDir: envx.String("NODE_HOST_AGENT_K0S_DIR",
			hostPath("/var/lib/k0s")),
		EtcdGuard: EtcdGuardConfig{
			Endpoint:    envx.String("NODE_HOST_AGENT_ETCD_ENDPOINT", defaultEtcdEndpoint),
			DBSizeLimit: envx.Int64("NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT", 0),
		},
		JournalDirs:             d.JournalDirs,
		JournalUnreadableNeeded: d.JournalUnreadableNeeded,
	}
}

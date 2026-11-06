package controllerhygiene

import (
	"os"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly. It embeds the shared
// hostctx.Deps watchdog/host-context bundle: the parsed
// node-watchdog.conf the env → conf → package-default chains fall
// through to (may be nil, treated as an empty conf), its per-cycle
// reloader (Config.WatchdogSrc), the shared watchdog state dir/log
// file, the systemd client, the shared journal-unreadable detector
// inputs, and the hostPath join — all via field promotion. HostRoot
// itself is NOT consumed: every host-fs path in the config is
// hostPath()-derived, and the ShouldRun(hostRoot) enable-gate stays
// in the caller.
type EnvDeps struct {
	hostctx.Deps
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob controllerhygiene
// reads and returns a Config ready for New — the env contract lives in
// the package, not in cmd/agent. The enable gate
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
	cfg := Config{
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
		WatchdogSrc:      d.WatchdogSrc,
		// No env knob — hostPath-derived like the Admin* paths.
		K0sControllerUnitFile: hostPath("/etc/systemd/system/k0scontroller.service"),
		OOMLoop: OOMLoopConfig{
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
		Feeder: FeederConfig{
			StateDir:          hostPath("/var/lib/k0s-systemd-watchdog"),
			RemediatePeerFile: hostPath("/etc/default/k0scontroller-watchdog"),
		},
		JournalDirs:             d.JournalDirs,
		JournalUnreadableNeeded: d.JournalUnreadableNeeded,
		Systemd:                 d.Systemd,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob("NODE_HOST_AGENT_CONTROLLER_INTERVAL", &cfg.Interval, defaultInterval),
		envx.StringKnob("NODE_HOST_AGENT_PROC_ROOT", &cfg.ProcRoot, defaultProcRoot),
		// env → wdCfg → package defaults; SelfAPI stays EMPTY when
		// neither is set (the solo/dead-fallback fences gate on
		// non-empty — a made-up identity would crown every
		// unconfigured controller first-hub).
		envx.OrKnob("NODE_HOST_AGENT_API_SELF", &cfg.Hub.SelfAPI, wd.APISelf),
		envx.OrKnob("NODE_HOST_AGENT_API_PEER", &cfg.Hub.PeerAPI, wd.APIPeer),
		envx.OrKnob("NODE_HOST_AGENT_KINE_DB_PROBE", &cfg.Hub.KineDBProbe, wd.KineDBProbe),
		envx.OrKnob("NODE_HOST_AGENT_SIG13_AUTOFIX", &cfg.Sig13.Mode, wd.Sig13Autofix),
		envx.IntOrKnob("NODE_HOST_AGENT_STALE_MIN_ERRS", &cfg.Sig13.StaleMinErrs,
			wd.Sig13StaleMinErrs, defaultStaleMinErrs),
		envx.Int64OrKnob("NODE_HOST_AGENT_GAP_MIN", &cfg.Sig13.GapMin,
			wd.Sig13GapMin, defaultGapMin),
		envx.IntOrKnob("NODE_HOST_AGENT_GAP_CYCLES", &cfg.Sig13.GapCycles,
			wd.Sig13GapCycles, defaultGapCycles),
		envx.IntOrKnob("NODE_HOST_AGENT_FROZEN_CYCLES", &cfg.Sig13.FrozenCycles,
			wd.Sig13FrozenCycles, defaultFrozenCycles),
		envx.IntOrKnob("NODE_HOST_AGENT_SOLO_CYCLES", &cfg.Sig13.SoloCycles,
			wd.Sig13SoloCycles, defaultSoloCycles),
		envx.DurOrKnob("NODE_HOST_AGENT_SIG13_MIN_RESTART_S", &cfg.Sig13.MinRestart,
			wd.Sig13MinRestartS, defaultMinRestart),
		envx.OrKnob("NODE_HOST_AGENT_KINE_TTL_AUTOFIX", &cfg.KineTTL.Mode, wd.KineTTLAutofix),
		envx.DurOrKnob("NODE_HOST_AGENT_KINE_TTL_MIN_RESTART_S", &cfg.KineTTL.MinRestart,
			wd.KineTTLMinRestartS, defaultTTLMinRestart),
		envx.DurOrKnob("NODE_HOST_AGENT_KINE_TTL_CTL_RESTART_S", &cfg.KineTTL.CtlRestart,
			wd.KineTTLCtlRestartS, defaultTTLCtlRestart),
		envx.IntOrKnob("NODE_HOST_AGENT_KINE_TTL_REWEDGE_CYCLES", &cfg.KineTTL.RewedgeCycles,
			wd.KineTTLRewedgeCycle, defaultTTLRewedgeCycles),
		envx.OrKnob("NODE_HOST_AGENT_KINE_POOL_AUTOFIX", &cfg.KinePool.Mode, wd.KinePoolAutofix),
		envx.IntOrKnob("NODE_HOST_AGENT_KINE_POOL_MAX_CONNS", &cfg.KinePool.MaxConns,
			wd.KinePoolMaxConns, defaultPoolMaxConns),
		envx.IntOrKnob("NODE_HOST_AGENT_KINE_POOL_CYCLES", &cfg.KinePool.Cycles,
			wd.KinePoolCycles, defaultPoolCycles),
		envx.DurOrKnob("NODE_HOST_AGENT_KINE_POOL_MIN_RESTART_S", &cfg.KinePool.MinRestart,
			wd.KinePoolMinRestartS, defaultPoolMinRestart),
		envx.OrKnob("NODE_HOST_AGENT_OOMLOOP_AUTOFIX", &cfg.OOMLoop.Mode, wd.OOMLoopAutofix),
		envx.IntOrKnob("NODE_HOST_AGENT_OOMLOOP_MIN_KILLS", &cfg.OOMLoop.MinKills,
			wd.OOMLoopMinKills, defaultOOMMinKills),
		envx.DurOrKnob("NODE_HOST_AGENT_OOMLOOP_WINDOW_S", &cfg.OOMLoop.Window,
			wd.OOMLoopWindowS, defaultOOMWindow),
		envx.BoolKnob("NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS", &cfg.InsecureTLS, true),
		envx.BoolKnob("NODE_HOST_AGENT_ENABLE_FEEDER", &cfg.Feeder.Enabled, true),
		// NOTIFY_SOCKET is a systemd contract, not a
		// NODE_HOST_AGENT_* knob — read it directly.
		{Name: "NOTIFY_SOCKET", Resolve: func(k string) {
			cfg.Feeder.NotifySocket = os.Getenv(k)
		}},
		// hostPath default — NOT defaultK0sDir, which hardcodes "/host".
		envx.StringKnob("NODE_HOST_AGENT_K0S_DIR", &cfg.K0sDir,
			hostPath("/var/lib/k0s")),
		envx.StringKnob("NODE_HOST_AGENT_ETCD_ENDPOINT", &cfg.EtcdGuard.Endpoint, defaultEtcdEndpoint),
		envx.Int64Knob("NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT", &cfg.EtcdGuard.DBSizeLimit, 0),
	})
	return cfg
}

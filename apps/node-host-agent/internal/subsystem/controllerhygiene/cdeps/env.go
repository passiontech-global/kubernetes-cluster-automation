package cdeps

import (
	"os"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sdnotify"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
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
// inputs, and the HostPath join — all via field promotion. HostRoot
// itself is NOT consumed: every host-fs path in the config is
// PathJoin()-derived, and the ShouldRun(hostRoot) enable-gate stays
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
// d.PathJoin (the nil-safe HostPath join) — NOT the package
// defaults — supplies the host-fs paths: defaultKubeconfig &
// friends hardcode the "/host" prefix and would be wrong on a
// standalone host (hostRoot "/").
func ConfigFromEnv(d EnvDeps) Config {
	// wd is the watchdogconf middle layer of the env → conf →
	// package-default chains; a nil Watchdog dep is an empty conf.
	var wd watchdogconf.Config
	if d.Watchdog != nil {
		wd = *d.Watchdog
	}
	cfg := Config{
		Base: subframe.FromDeps(d.Deps),
		// No env knob — PathJoin-derived like the Admin* paths.
		K0sControllerUnitFile: d.PathJoin("/etc/systemd/system/k0scontroller.service"),
		// The snapshot verifier's second default dir is a host path —
		// PathJoin-derived or the DaemonSet would scan the pod's
		// (empty) /var/backups/etcd instead of the host's.
		EtcdBackupDir: d.PathJoin("/var/backups/etcd"),
		OOMLoop: OOMLoopConfig{
			// No env knob — PathJoin-derived.
			CGroupEventsFile: d.PathJoin("/sys/fs/cgroup/system.slice/" +
				"k0scontroller.service/memory.events"),
		},
		// Admin* + Feeder paths are PathJoin()-derived — NOT the
		// package defaults, which hardcode the "/host" prefix.
		AdminKubeconfig: d.PathJoin("/var/lib/k0s/pki/admin.conf"),
		AdminCert:       d.PathJoin("/var/lib/k0s/pki/admin.crt"),
		AdminKey:        d.PathJoin("/var/lib/k0s/pki/admin.key"),
		AdminCA:         d.PathJoin("/var/lib/k0s/pki/ca.crt"),
		// Same contract for the konnectivity UDS root and the kine
		// cert dir — defaultK0sRunDir ("/host/run/k0s") and the
		// applyPKIDriftDefaults prefix ("/host/etc/kine/pki") would
		// 404 a standalone host (hostRoot "/").
		K0sRunDir: d.PathJoin("/run/k0s"),
		PKIDrift: PKIDriftConfig{
			KinePKIDir: d.PathJoin("/etc/kine/pki"),
		},
		// hostctx already resolved NODE_HOST_AGENT_TEXTFILE_DIR with
		// the shared hostPath default — the prom writers must honor
		// the same override, not re-derive the dir.
		TextfileDir: d.TextfileDir,
		Feeder: FeederConfig{
			StateDir:          d.PathJoin("/var/lib/k0s-systemd-watchdog"),
			RemediatePeerFile: d.PathJoin("/etc/default/k0scontroller-watchdog"),
		},
		JournalDirs:             d.JournalDirs,
		JournalUnreadableNeeded: d.JournalUnreadableNeeded,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob(envnames.EnvControllerInterval, &cfg.Interval, defaultInterval),
		envx.StringKnob(envnames.EnvProcRoot, &cfg.ProcRoot, defaultProcRoot),
		// env → wdCfg → package defaults; SelfAPI stays EMPTY when
		// neither is set (the solo/dead-fallback fences gate on
		// non-empty — a made-up identity would crown every
		// unconfigured controller first-hub).
		envx.OrKnob(envnames.EnvAPISelf, &cfg.Hub.SelfAPI, wd.APISelf),
		envx.OrKnob(envnames.EnvAPIPeer, &cfg.Hub.PeerAPI, wd.APIPeer),
		envx.OrKnob(envnames.EnvKineDBProbe, &cfg.Hub.KineDBProbe, wd.KineDBProbe),
		envx.OrKnob(envnames.EnvSig13Autofix, &cfg.Sig13.Mode, wd.Sig13Autofix),
		envx.IntOrKnob(envnames.EnvStaleMinErrs, &cfg.Sig13.StaleMinErrs,
			wd.Sig13StaleMinErrs, defaultStaleMinErrs),
		envx.Int64OrKnob(envnames.EnvGapMin, &cfg.Sig13.GapMin,
			wd.Sig13GapMin, defaultGapMin),
		envx.IntOrKnob(envnames.EnvGapCycles, &cfg.Sig13.GapCycles,
			wd.Sig13GapCycles, defaultGapCycles),
		envx.IntOrKnob(envnames.EnvFrozenCycles, &cfg.Sig13.FrozenCycles,
			wd.Sig13FrozenCycles, defaultFrozenCycles),
		envx.IntOrKnob(envnames.EnvSoloCycles, &cfg.Sig13.SoloCycles,
			wd.Sig13SoloCycles, defaultSoloCycles),
		envx.DurOrKnob(envnames.EnvSig13MinRestartS, &cfg.Sig13.MinRestart,
			wd.Sig13MinRestartS, defaultMinRestart),
		envx.OrKnob(envnames.EnvKineTTLAutofix, &cfg.KineTTL.Mode, wd.KineTTLAutofix),
		envx.DurOrKnob(envnames.EnvKineTTLMinRestartS, &cfg.KineTTL.MinRestart,
			wd.KineTTLMinRestartS, defaultTTLMinRestart),
		envx.DurOrKnob(envnames.EnvKineTTLCtlRestartS, &cfg.KineTTL.CtlRestart,
			wd.KineTTLCtlRestartS, defaultTTLCtlRestart),
		envx.IntOrKnob(envnames.EnvKineTTLRewedgeCycles, &cfg.KineTTL.RewedgeCycles,
			wd.KineTTLRewedgeCycle, defaultTTLRewedgeCycles),
		envx.OrKnob(envnames.EnvKinePoolAutofix, &cfg.KinePool.Mode, wd.KinePoolAutofix),
		envx.IntOrKnob(envnames.EnvKinePoolMaxConns, &cfg.KinePool.MaxConns,
			wd.KinePoolMaxConns, defaultPoolMaxConns),
		envx.IntOrKnob(envnames.EnvKinePoolCycles, &cfg.KinePool.Cycles,
			wd.KinePoolCycles, defaultPoolCycles),
		envx.DurOrKnob(envnames.EnvKinePoolMinRestartS, &cfg.KinePool.MinRestart,
			wd.KinePoolMinRestartS, defaultPoolMinRestart),
		envx.OrKnob(envnames.EnvOomloopAutofix, &cfg.OOMLoop.Mode, wd.OOMLoopAutofix),
		envx.IntOrKnob(envnames.EnvOomloopMinKills, &cfg.OOMLoop.MinKills,
			wd.OOMLoopMinKills, DefaultOOMMinKills),
		envx.DurOrKnob(envnames.EnvOomloopWindowS, &cfg.OOMLoop.Window,
			wd.OOMLoopWindowS, defaultOOMWindow),
		envx.BoolKnob(envnames.EnvControllerInsecureTLS, &cfg.InsecureTLS, true),
		envx.BoolKnob(envnames.EnvEnableFeeder, &cfg.Feeder.Enabled, true),
		// NOTIFY_SOCKET is a systemd contract, not a
		// NODE_HOST_AGENT_* knob — the const lives in
		// platform/sdnotify; read it directly.
		{Name: sdnotify.SocketEnv, Resolve: func(k string) {
			cfg.Feeder.NotifySocket = os.Getenv(k)
		}},
		// PathJoin default — NOT defaultK0sDir, which hardcodes "/host".
		envx.StringKnob(envnames.EnvK0sDir, &cfg.K0sDir,
			d.PathJoin("/var/lib/k0s")),
		envx.StringKnob(envnames.EnvEtcdEndpoint, &cfg.EtcdGuard.Endpoint, DefaultEtcdEndpoint),
		envx.Int64Knob(envnames.EnvEtcdDBSizeLimit, &cfg.EtcdGuard.DBSizeLimit, 0),
		// spof-streak + backup-health: the single-controller SPOF override
		// (0 = auto — an unset PeerAPI means single-controller) and
		// the etcd snapshot verifier dir ("" = the k0s defaults).
		envx.IntKnob(envnames.EnvTotalControllers, &cfg.TotalControllers, 0),
		envx.StringKnob(envnames.EnvEtcdSnapshotDir, &cfg.EtcdSnapshotDir, ""),
	})
	return cfg
}

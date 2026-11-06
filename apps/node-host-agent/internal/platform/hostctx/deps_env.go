// deps_env.go — DepsFromEnv: the shared host-side env surface,
// symmetric with each subsystem's ConfigFromEnv. The inputs that are
// NOT env-derived (the hostPath joiner + hostRoot produced by the
// standalone flip / HOST_ROOT resolution, the resolved node name,
// the systemd client built for that root) arrive via EnvParams;
// every NODE_HOST_AGENT_* shared knob is resolved here and spliced
// into the returned Deps — so cmd/agent's buildAgentConfig no longer
// owns the shared env contract.
package hostctx

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvParams bundles the DepsFromEnv inputs that are NOT env-derived —
// the caller (cmd/agent's buildAgentConfig) resolves them from flags
// and host topology before the shared env surface is read.
type EnvParams struct {
	// HostPath joins a host-absolute path under the host fs root —
	// the env-derived defaults below (watchdog conf/state/log,
	// journal dirs, textfile dir) are all prefixed through it, so it
	// must be the resolved joiner (identity when HostRoot == "/").
	// Nil → identity join (host paths used verbatim).
	HostPath func(string) string
	// HostRoot is the resolved host fs root itself ("/host" in the
	// DaemonSet, "/" standalone) — the nsenter decision input and
	// the ShouldRun/Detect probe root.
	HostRoot string
	// NodeName is the resolved node identity — env/flag precedence
	// (NODE_HOST_AGENT_NODE_NAME > NODE_NAME > --node-name) already
	// applied by the caller. NODE_HOST_AGENT_NODE_NAME is still
	// consulted here as the final override so a Deps built from a
	// partially-resolved name keeps the documented precedence.
	NodeName string
	// Systemd is the shared host-systemd client the caller builds
	// for HostRoot — spliced straight through into Deps.Systemd.
	Systemd *systemd.Client
}

// DepsFromEnv resolves the shared watchdog/host context the same way
// the subsystem ConfigFromEnv constructors resolve their own env
// contract: the caller supplies only the non-env inputs and every
// NODE_HOST_AGENT_* knob below is owned by this constructor:
//
//	NODE_HOST_AGENT_WATCHDOG_CONF              conf path (+ Load + Reloader)
//	NODE_HOST_AGENT_WATCHDOG_STATE_DIR         shared state dir
//	NODE_HOST_AGENT_WATCHDOG_LOG               shared log file
//	NODE_HOST_AGENT_JOURNAL_DIRS               journald witness dirs
//	NODE_HOST_AGENT_JOURNAL_UNREADABLE_NEEDED  blindness-detector threshold
//	NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR        shared vars dir
//	NODE_HOST_AGENT_TEXTFILE_DIR               node-exporter textfile dir
//	NODE_HOST_AGENT_NODE_NAME                  node-name override
//
// A conf parse failure is not fatal — the agent runs on the empty
// conf exactly like the shell modules did without a sourced
// node-watchdog.conf.
func DepsFromEnv(p EnvParams) Deps {
	hostPath := p.HostPath
	if hostPath == nil {
		hostPath = func(s string) string { return s }
	}

	// The shared host-side inputs: the node-watchdog.conf parser
	// feeds API_BACKENDS / OVERLAY_* / DNS_FALLBACK_MAP into
	// apiprober, workerhygiene, nethealth and hostmetrics.
	wdConfPath := envx.String("NODE_HOST_AGENT_WATCHDOG_CONF",
		hostPath("/etc/node-watchdog.conf"))
	wdCfg, err := watchdogconf.Load(wdConfPath)
	if err != nil {
		logger().Error("watchdog conf parse failed — running on defaults",
			"path", wdConfPath, "error", err)
		wdCfg, _ = watchdogconf.Parse(nil)
	}
	// One shared reloader: hostconfig rewrites the conf every
	// converge, so conf-consuming subsystems re-read it per cycle
	// instead of pinning the startup parse (the runner re-sourced it
	// every run — API_BACKENDS / OVERLAY_* / WD_SIG_* changes land
	// next cycle).
	wdReloader := watchdogconf.NewReloader(wdConfPath, wdCfg)

	// Shared journald inputs for the journal-unreadable blindness
	// detector (workerhygiene + controllerhygiene): the storage dirs
	// are the "journald is installed" witness — a host with no
	// journald fails every read by config and must never latch.
	// hostPath() makes them unprefixed in standalone mode.
	journalDirs := envx.List("NODE_HOST_AGENT_JOURNAL_DIRS")
	if journalDirs == nil {
		journalDirs = []string{
			hostPath("/var/log/journal"), hostPath("/run/log/journal")}
	}

	return Deps{
		Watchdog:    wdCfg,
		WatchdogSrc: wdReloader,
		WatchdogStateDir: envx.String("NODE_HOST_AGENT_WATCHDOG_STATE_DIR",
			hostPath("/var/lib/node-watchdog")),
		WatchdogLogFile: envx.String("NODE_HOST_AGENT_WATCHDOG_LOG",
			hostPath("/var/log/node-watchdog.log")),
		HostPath:    hostPath,
		HostRoot:    p.HostRoot,
		Systemd:     p.Systemd,
		JournalDirs: journalDirs,
		JournalUnreadableNeeded: envx.Int(
			"NODE_HOST_AGENT_JOURNAL_UNREADABLE_NEEDED", 5),
		// VarsDir/TextfileDir stay shared: workerhygiene
		// (systemd_watchdog_hosts), kinedb (Detect), hubsync
		// (VarsDir) and hostconfig itself all read the same vars
		// dir, and the textfile dir feeds both the standalone prom
		// writer and kinedb's prom files.
		VarsDir: envx.String("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR",
			"/config/vars"),
		TextfileDir: envx.String("NODE_HOST_AGENT_TEXTFILE_DIR",
			hostPath("/var/lib/node-exporter/textfile")),
		NodeName: envx.String("NODE_HOST_AGENT_NODE_NAME", p.NodeName),
	}
}

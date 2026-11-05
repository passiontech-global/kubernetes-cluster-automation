package nethealth

import (
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/envx"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: the shared watchdog
// state dir/log, the host root (nsenter decision + Config field), the
// parsed watchdog conf + its per-cycle reloader, the systemd client,
// and the hostPath join that prefixes host-fs paths with the host
// root ("/host" in the DaemonSet, identity standalone).
type EnvDeps struct {
	WatchdogStateDir string
	WatchdogLogFile  string
	HostRoot         string
	Watchdog         *watchdogconf.Config
	WatchdogSrc      *watchdogconf.Reloader
	Systemd          *systemd.Client
	// HostPath joins a host-absolute path under the host-fs root.
	// Nil → identity (host paths used verbatim).
	HostPath func(string) string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob nethealth reads
// and returns a Config ready for New — the env contract lives in the
// package, not in cmd/agent. Enabled is always true here: the wire
// func set it unconditionally and the enable gate
// (NODE_HOST_AGENT_ENABLE_NETHEALTH) stays in the caller.
func ConfigFromEnv(d EnvDeps) Config {
	hostPath := d.HostPath
	if hostPath == nil {
		hostPath = func(p string) string { return p }
	}
	return Config{
		Enabled:          true,
		Interval:         envx.Duration("NODE_HOST_AGENT_NETHEALTH_INTERVAL", defaultInterval),
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
		// hostPath defaults — NOT defaultHostResolvConf/defaultHostsFile,
		// which hardcode the "/host" prefix and would be wrong on a
		// standalone host (hostRoot "/").
		HostResolvConf: envx.String("NODE_HOST_AGENT_HOST_RESOLV_CONF",
			hostPath("/etc/resolv.conf")),
		HostsFile: envx.String("NODE_HOST_AGENT_HOSTS_FILE",
			hostPath("/etc/hosts")),
		ProcNetUDP:   envx.String("NODE_HOST_AGENT_PROC_NET_UDP", defaultProcNetUDP),
		ProcNetUDP6:  envx.String("NODE_HOST_AGENT_PROC_NET_UDP6", defaultProcNetUDP6),
		UptimeFile:   envx.String("NODE_HOST_AGENT_UPTIME_FILE", defaultUptimeFile),
		HostRoot:     d.HostRoot,
		Watchdog:     d.Watchdog,
		WatchdogSrc:  d.WatchdogSrc,
		Systemd:      d.Systemd,
		ConsecNeeded: envx.Int("NODE_HOST_AGENT_NETHEALTH_CONSEC_NEEDED", defaultConsecNeeded),
		MinRestart:   envx.Duration("NODE_HOST_AGENT_NETHEALTH_MIN_RESTART", defaultMinRestart),
		// W8: pref-1499 direct-underlay TCP bypass; empty env → nil →
		// applyDefaults' package default [22 6443 8132 9443 39901].
		NebulaDirectTCPPorts: envx.IntList("NODE_HOST_AGENT_NEBULA_DIRECT_TCP_PORTS"),
	}
}

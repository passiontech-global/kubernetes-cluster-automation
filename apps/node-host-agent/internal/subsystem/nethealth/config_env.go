package nethealth

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly. It embeds the shared
// hostctx.Deps watchdog/host-context bundle — this subsystem consumes
// the shared watchdog state dir/log, the host root (nsenter decision
// + Config field), the parsed watchdog conf + its per-cycle reloader,
// the systemd client, and the hostPath join — all via field
// promotion.
type EnvDeps struct {
	hostctx.Deps
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob nethealth reads
// and returns a Config ready for New — the env contract lives in the
// package, not in cmd/agent. The enable gate
// (NODE_HOST_AGENT_ENABLE_NETHEALTH) stays in the caller.
func ConfigFromEnv(d EnvDeps) Config {
	cfg := Config{
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
		HostRoot:         d.HostRoot,
		Watchdog:         d.Watchdog,
		WatchdogSrc:      d.WatchdogSrc,
		Systemd:          d.Systemd,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob("NODE_HOST_AGENT_NETHEALTH_INTERVAL", &cfg.Interval, defaultInterval),
		// hostPath defaults — NOT defaultHostResolvConf/defaultHostsFile,
		// which hardcode the "/host" prefix and would be wrong on a
		// standalone host (hostRoot "/").
		envx.StringKnob("NODE_HOST_AGENT_HOST_RESOLV_CONF", &cfg.HostResolvConf,
			d.PathJoin("/etc/resolv.conf")),
		envx.StringKnob("NODE_HOST_AGENT_HOSTS_FILE", &cfg.HostsFile,
			d.PathJoin("/etc/hosts")),
		envx.StringKnob("NODE_HOST_AGENT_PROC_NET_UDP", &cfg.ProcNetUDP, defaultProcNetUDP),
		envx.StringKnob("NODE_HOST_AGENT_PROC_NET_UDP6", &cfg.ProcNetUDP6, defaultProcNetUDP6),
		envx.StringKnob("NODE_HOST_AGENT_UPTIME_FILE", &cfg.UptimeFile, defaultUptimeFile),
		envx.IntKnob("NODE_HOST_AGENT_NETHEALTH_CONSEC_NEEDED", &cfg.ConsecNeeded, defaultConsecNeeded),
		envx.DurationKnob("NODE_HOST_AGENT_NETHEALTH_MIN_RESTART", &cfg.MinRestart, defaultMinRestart),
		// W8: pref-1499 direct-underlay TCP bypass; empty env → nil →
		// applyDefaults' package default [22 6443 8132 9443 39901].
		envx.IntListKnob("NODE_HOST_AGENT_NEBULA_DIRECT_TCP_PORTS", &cfg.NebulaDirectTCPPorts),
	})
	return cfg
}

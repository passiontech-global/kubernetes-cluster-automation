package nethealth

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
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
		Base: subframe.FromDeps(d.Deps),
		// hostctx already resolved NODE_HOST_AGENT_TEXTFILE_DIR with
		// the shared hostPath default — the MTU gauge must honor the
		// same override, not re-derive the dir from HostRoot.
		TextfileDir: d.TextfileDir,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob(envnames.EnvNethealthInterval, &cfg.Interval, defaultInterval),
		// hostPath defaults — NOT defaultHostResolvConf/defaultHostsFile,
		// which hardcode the "/host" prefix and would be wrong on a
		// standalone host (hostRoot "/").
		envx.StringKnob(envnames.EnvHostResolvConf, &cfg.HostResolvConf,
			d.PathJoin("/etc/resolv.conf")),
		envx.StringKnob(envnames.EnvHostsFile, &cfg.HostsFile,
			d.PathJoin("/etc/hosts")),
		envx.StringKnob(envnames.EnvProcNetUDP, &cfg.ProcNetUDP, defaultProcNetUDP),
		envx.StringKnob(envnames.EnvProcNetUDP6, &cfg.ProcNetUDP6, defaultProcNetUDP6),
		envx.StringKnob(envnames.EnvUptimeFile, &cfg.UptimeFile, defaultUptimeFile),
		envx.IntKnob(envnames.EnvNethealthConsecNeeded, &cfg.ConsecNeeded, defaultConsecNeeded),
		envx.DurationKnob(envnames.EnvNethealthMinRestart, &cfg.MinRestart, defaultMinRestart),
		// W8: pref-1499 direct-underlay TCP bypass; empty env → nil →
		// applyDefaults' package default [22 6443 8132 9443 39901].
		envx.IntListKnob(envnames.EnvNebulaDirectTCPPorts, &cfg.NebulaDirectTCPPorts),
	})
	return cfg
}

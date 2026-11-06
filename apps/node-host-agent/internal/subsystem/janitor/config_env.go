package janitor

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the
// values cmd/agent used to splice into the config directly. It
// embeds the shared hostctx.Deps watchdog/host-context bundle; this
// subsystem consumes the systemd client and the shared watchdog
// state dir/log file via field promotion (the promoted HostPath is
// currently unused — the janitor's own defaults are already
// host-absolute).
type EnvDeps struct {
	hostctx.Deps
}

// ConfigFromEnv resolves the NODE_HOST_AGENT_* knobs the
// watchdog-state janitor reads and returns a Config ready for
// New — the env contract lives in the package, not in
// cmd/agent. The enable gate
// (NODE_HOST_AGENT_ENABLE_JANITOR) stays in the caller. Consumes only
// EnvDeps.WatchdogStateDir, .WatchdogLogFile and .Systemd.
func ConfigFromEnv(d EnvDeps) Config {
	cfg := Config{
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
		Systemd:          d.Systemd,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob("NODE_HOST_AGENT_JANITOR_INTERVAL", &cfg.Interval, defaultInterval),
		envx.StringKnob("NODE_HOST_AGENT_PROC_ROOT", &cfg.ProcRoot, defaultProcRoot),
		envx.DurationKnob("NODE_HOST_AGENT_JANITOR_LATCH_MAX_AGE", &cfg.LatchMaxAge, latchMaxAge),
	})
	return cfg
}

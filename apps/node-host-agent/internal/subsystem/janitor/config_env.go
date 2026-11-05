package janitor

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the
// values cmd/agent used to splice into the config directly: the
// systemd client and the shared watchdog state dir/log file. It is a
// deliberate copy of the four fields the wire call passes (the
// janitor must not depend on workerhygiene's EnvDeps type).
type EnvDeps struct {
	Systemd          *systemd.Client
	WatchdogStateDir string
	WatchdogLogFile  string
	// HostPath joins a host-absolute path under the host-fs root.
	// Accepted for parity with the other subsystem EnvDeps; currently
	// unused — the janitor's own defaults are already host-absolute.
	HostPath func(string) string
}

// ConfigFromEnv resolves the NODE_HOST_AGENT_* knobs the
// watchdog-state janitor reads and returns a Config ready for
// New — the env contract lives in the package, not in
// cmd/agent. Enabled is always true here: the wire func set it
// unconditionally and the enable gate
// (NODE_HOST_AGENT_ENABLE_JANITOR) stays in the caller. Consumes only
// EnvDeps.WatchdogStateDir, .WatchdogLogFile and .Systemd.
func ConfigFromEnv(d EnvDeps) Config {
	cfg := Config{
		Enabled:          true,
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

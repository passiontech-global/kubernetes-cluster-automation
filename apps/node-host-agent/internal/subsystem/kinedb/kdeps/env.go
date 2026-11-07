// env.go — the NODE_HOST_AGENT_* env contract kinedb reads, resolved
// beside the Config defaults it fills (the cdeps/env.go role). Was
// the flat package's config_env.go.
package kdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly. It embeds the shared
// hostctx.Deps watchdog/host-context bundle; this subsystem consumes
// the hostPath join (prefixes host-fs paths with the host root —
// "/host" in the DaemonSet, identity standalone) and the shared
// node-exporter textfile dir via field promotion.
type EnvDeps struct {
	hostctx.Deps
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob kinedb reads
// and returns a Config ready for New — the env contract lives in the
// package, not in cmd/agent. The caller only builds the config after
// the enable gate (NODE_HOST_AGENT_ENABLE_KINEDB=true|auto + Detect)
// passed.
func ConfigFromEnv(d EnvDeps) Config {
	cfg := Config{
		TextfileDir: d.TextfileDir,
		Clock:       d.Clock,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		// PathJoin(DefaultEnvFile) keeps the Detect() probe path and
		// the configured EnvFile on the same file.
		envx.StringKnob(envnames.EnvKinedbEnvFile, &cfg.EnvFile,
			d.PathJoin(DefaultEnvFile)),
		envx.StringKnob(envnames.EnvKinedbGuardStateDir, &cfg.GuardStateDir,
			d.PathJoin(defaultGuardStateDir)),
		// W8-CP2: in-container postgres data dir for the repack
		// headroom gate; empty → package default.
		envx.StringKnob(envnames.EnvKinedbPgDataDir, &cfg.PGDataDir, ""),
		// W13-ST2: the physical-backup verifier dir + cadence.
		envx.StringKnob(envnames.EnvKinedbBackupDir, &cfg.BackupDir,
			d.PathJoin(defaultBackupDir)),
		envx.DurationKnob(envnames.EnvKinedbBackupInterval,
			&cfg.BackupInterval, defaultBackupInterval),
	})
	return cfg
}

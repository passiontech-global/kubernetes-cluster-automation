package kinedb

import (
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
	hostPath := d.HostPath
	if hostPath == nil {
		hostPath = func(p string) string { return p }
	}
	cfg := Config{
		TextfileDir: d.TextfileDir,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		// hostPath(defaultEnvFile) keeps the Detect() probe path and
		// the configured EnvFile on the same file.
		envx.StringKnob("NODE_HOST_AGENT_KINEDB_ENV_FILE", &cfg.EnvFile,
			hostPath(defaultEnvFile)),
		envx.StringKnob("NODE_HOST_AGENT_KINEDB_GUARD_STATE_DIR", &cfg.GuardStateDir,
			hostPath(defaultGuardStateDir)),
		// W8-CP2: in-container postgres data dir for the repack
		// headroom gate; empty → package default.
		envx.StringKnob("NODE_HOST_AGENT_KINEDB_PG_DATA_DIR", &cfg.PGDataDir, ""),
	})
	return cfg
}

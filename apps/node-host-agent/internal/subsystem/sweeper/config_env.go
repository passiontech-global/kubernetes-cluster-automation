package sweeper

import (
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: the shared lazily-
// built kube clientset (its csOnce). New rejects a nil Client. It
// embeds the shared hostctx.Deps watchdog/host-context bundle — only
// the clock cell promotes out of it (a zero Deps leaves Config.Clock
// unset → applyDefaults arms its own).
type EnvDeps struct {
	hostctx.Deps
	Client kubernetes.Interface
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob the orphan-dir
// sweeper reads and returns a Config ready for New — the env contract
// lives in the package, not in cmd/agent. Defaults are the package's
// own (they mirror the DaemonSet env defaults 1:1). The enable gate
// (NODE_HOST_AGENT_ENABLE_SWEEPER) and the kube-client build stay in
// the caller.
func ConfigFromEnv(d EnvDeps) Config {
	cfg := Config{
		Base:   subframe.FromDeps(d.Deps),
		Client: d.Client,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.StringKnob(envnames.EnvSweepBaseDir, &cfg.BaseDir, envnames.DefaultSweepBaseDir),
		envx.DurationKnob(envnames.EnvSweepMinAge, &cfg.MinAge, defaultMinAge),
		envx.IntKnob(envnames.EnvSweepMaxDelete, &cfg.MaxDelete, defaultMaxDelete),
		envx.DurationKnob(envnames.EnvSweepInterval, &cfg.Interval, defaultInterval),
		envx.StringKnob(envnames.EnvMountsFile, &cfg.MountsFile, defaultMountsFile),
		envx.DurationKnob(envnames.EnvRequestTimeout, &cfg.RequestTimeout, defaultRequestTimeout),
	})
	return cfg
}

// The concourse shared-cache pruner moved to
// internal/subsystem/concoursecache — see
// concoursecache.ConfigFromEnv (it still reads the shared
// NODE_HOST_AGENT_SWEEP_BASE_DIR for the same openebs root).

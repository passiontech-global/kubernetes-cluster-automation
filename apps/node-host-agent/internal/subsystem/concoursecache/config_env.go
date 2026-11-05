package concoursecache

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// defaultBaseDir is the openebs hostdir root — duplicated from
// sweeper. Both packages read the SAME env var
// (NODE_HOST_AGENT_SWEEP_BASE_DIR) since the pruner walks the
// pvc-*/shared-cache children of the root the orphan sweeper cleans.
const defaultBaseDir = "/var/openebs/local"

// Knobs bundles everything the caller needs to run the
// shared-cache pruner: the pruner Config plus the two env-resolved
// scheduling inputs a cycle.Every wraps pruner.Sweep in — the openebs
// root it sweeps and the cadence. The pruner config itself has no
// env-tunable fields (a bare Config{} IS the
// script-parity default) but is returned so the caller passes one
// resolved value through.
type Knobs struct {
	Config    Config
	CacheRoot string
	Interval  time.Duration
}

// ConfigFromEnv resolves the NODE_HOST_AGENT_* knobs the
// concourse-cache pruner reads. NODE_HOST_AGENT_SWEEP_BASE_DIR is
// shared with the orphan sweeper (same openebs root — the pruner
// walks its pvc-*/shared-cache children); the enable gate
// (NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE) stays in the caller.
//
// Unlike every other subsystem env loader this takes no EnvDeps:
// the pruner is pure host-fs work — nothing injectable (no kube
// client, watchdog conf, systemd or host-path seams) — so the env
// surface stays self-contained and callers have nothing to wire.
func ConfigFromEnv() Knobs {
	return Knobs{
		Config: Config{},
		CacheRoot: envx.String("NODE_HOST_AGENT_SWEEP_BASE_DIR",
			defaultBaseDir),
		Interval: envx.Duration("NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL",
			DefaultInterval),
	}
}

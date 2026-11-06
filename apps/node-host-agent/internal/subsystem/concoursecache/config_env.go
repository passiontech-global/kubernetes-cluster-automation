package concoursecache

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// The openebs hostdir root is envnames.DefaultSweepBaseDir —
// shared with sweeper (both read EnvSweepBaseDir) since the pruner
// walks the pvc-*/shared-cache children of the root the orphan
// sweeper cleans.

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
		CacheRoot: envx.String(envnames.EnvSweepBaseDir,
			envnames.DefaultSweepBaseDir),
		Interval: envx.Duration(envnames.EnvConcourseCacheInterval,
			DefaultInterval),
	}
}

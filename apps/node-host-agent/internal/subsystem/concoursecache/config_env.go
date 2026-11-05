package concoursecache

import (
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/envx"
)

// defaultBaseDir is the openebs hostdir root — duplicated from
// sweeper. Both packages read the SAME env var
// (NODE_HOST_AGENT_SWEEP_BASE_DIR) since the pruner walks the
// pvc-*/shared-cache children of the root the orphan sweeper cleans.
const defaultBaseDir = "/var/openebs/local"

// ConcourseCacheKnobs bundles everything the caller needs to run the
// shared-cache pruner: the pruner Config plus the two env-resolved
// scheduling inputs a cycle.Every wraps pruner.Sweep in — the openebs
// root it sweeps and the cadence. The pruner config itself has no
// env-tunable fields (a bare ConcourseCacheConfig{} IS the
// script-parity default) but is returned so the caller passes one
// resolved value through.
type ConcourseCacheKnobs struct {
	Config    ConcourseCacheConfig
	CacheRoot string
	Interval  time.Duration
}

// ConcourseCacheFromEnv resolves the NODE_HOST_AGENT_* knobs the
// concourse-cache pruner reads. NODE_HOST_AGENT_SWEEP_BASE_DIR is
// shared with the orphan sweeper (same openebs root — the pruner
// walks its pvc-*/shared-cache children); the enable gate
// (NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE) stays in the caller.
func ConcourseCacheFromEnv() ConcourseCacheKnobs {
	return ConcourseCacheKnobs{
		Config: ConcourseCacheConfig{},
		CacheRoot: envx.String("NODE_HOST_AGENT_SWEEP_BASE_DIR",
			defaultBaseDir),
		Interval: envx.Duration("NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL",
			DefaultConcourseCacheInterval),
	}
}

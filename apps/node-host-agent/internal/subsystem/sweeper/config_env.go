package sweeper

import (
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: the shared lazily-
// built kube clientset (its csOnce). New rejects a nil Client.
type EnvDeps struct {
	Client kubernetes.Interface
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob the orphan-dir
// sweeper reads and returns a Config ready for New — the env contract
// lives in the package, not in cmd/agent. Defaults are the package's
// own (they mirror the DaemonSet env defaults 1:1). The enable gate
// (NODE_HOST_AGENT_ENABLE_SWEEPER) and the kube-client build stay in
// the caller.
func ConfigFromEnv(d EnvDeps) Config {
	return Config{
		BaseDir:        envx.String("NODE_HOST_AGENT_SWEEP_BASE_DIR", defaultBaseDir),
		MinAge:         envx.Duration("NODE_HOST_AGENT_SWEEP_MIN_AGE", defaultMinAge),
		MaxDelete:      envx.Int("NODE_HOST_AGENT_SWEEP_MAX_DELETE", defaultMaxDelete),
		Interval:       envx.Duration("NODE_HOST_AGENT_SWEEP_INTERVAL", defaultInterval),
		MountsFile:     envx.String("NODE_HOST_AGENT_MOUNTS_FILE", defaultMountsFile),
		RequestTimeout: envx.Duration("NODE_HOST_AGENT_REQUEST_TIMEOUT", defaultRequestTimeout),
		Client:         d.Client,
	}
}

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

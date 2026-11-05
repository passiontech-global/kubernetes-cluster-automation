package sweeper

import (
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

// The concourse shared-cache pruner moved to
// internal/subsystem/concoursecache — see
// concoursecache.ConcourseCacheFromEnv (it still reads the shared
// NODE_HOST_AGENT_SWEEP_BASE_DIR for the same openebs root).

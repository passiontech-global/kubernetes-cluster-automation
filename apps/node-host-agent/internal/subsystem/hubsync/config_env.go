package hubsync

import (
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: the shared lazily-
// built kube clientset (its csOnce — serves the Lease and the
// api-backend-guard token Secret), the lease-holder identity
// (POD_NAME), the shared vars dir, and the already-resolved local
// binary path (resolveLocalBinary stays in cmd/agent — it stats
// os.Executable).
type EnvDeps struct {
	Client      kubernetes.Interface
	Identity    string
	VarsDir     string
	LocalBinary string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob hubsync reads
// and returns a Config ready for New — the env contract lives in the
// package, not in cmd/agent. The pod-mode gate (!standalone), the
// podName-empty check and the Enabled() startup fast-path log stay in
// the caller — read the returned cfg.SSHKeyPath for the resolved
// converge-key path (Enabled(cfg.SSHKeyPath) is the same check).
func ConfigFromEnv(d EnvDeps) Config {
	return Config{
		Client:         d.Client,
		Identity:       d.Identity,
		VarsDir:        d.VarsDir,
		NebulaCertsDir: envx.String("NODE_HOST_AGENT_NEBULA_CERTS_DIR", defaultNebulaCertsDir),
		SSHKeyPath:     envx.String("NODE_HOST_AGENT_CONVERGE_SSH_KEY", defaultSSHKeyPath),
		LocalBinary:    d.LocalBinary,
	}
}

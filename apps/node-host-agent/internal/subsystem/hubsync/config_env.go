// config_env.go — the NODE_HOST_AGENT_* env contract for hubsync:
// ConfigFromEnv resolves the knobs into a Config ready for New.
package hubsync

import (
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly. It embeds the shared
// hostctx.Deps watchdog/host-context bundle (only the shared vars dir
// promotes out of it); the named fields are the hubsync-only inputs:
// the shared lazily-built kube clientset (its csOnce — serves the
// Lease and the api-backend-guard token Secret), the lease-holder
// identity (POD_NAME), and the already-resolved local binary path
// (resolveLocalBinary stays in cmd/agent — it stats os.Executable).
type EnvDeps struct {
	hostctx.Deps
	Client      kubernetes.Interface
	Identity    string
	LocalBinary string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob hubsync reads
// and returns a Config ready for New — the env contract lives in the
// package, not in cmd/agent. The pod-mode gate (!standalone), the
// podName-empty check and the Enabled() startup fast-path log stay in
// the caller — read the returned cfg.SSHKeyPath for the resolved
// converge-key path (Enabled(cfg.SSHKeyPath) is the same check).
func ConfigFromEnv(d EnvDeps) Config {
	cfg := Config{
		Client:      d.Client,
		Identity:    d.Identity,
		VarsDir:     d.VarsDir,
		LocalBinary: d.LocalBinary,
		StateDir:    d.WatchdogStateDir,
		Clock:       d.Clock,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.StringKnob(envnames.EnvNebulaCertsDir, &cfg.NebulaCertsDir, defaultNebulaCertsDir),
		envx.StringKnob(envnames.EnvConvergeSSHKey, &cfg.SSHKeyPath, defaultSSHKeyPath),
		envx.StringKnob(envnames.EnvHubsyncSSHHostKeyFingerprint, &cfg.SSHHostKeyFingerprint, ""),
		envx.BoolKnob(envnames.EnvHubsyncSSHAllowInsecureHostKey, &cfg.SSHAllowInsecureHostKey, false),
	})
	return cfg
}

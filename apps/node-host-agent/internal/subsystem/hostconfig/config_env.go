package hostconfig

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly. It embeds the shared
// hostctx.Deps watchdog/host-context bundle (node identity, the host
// root and the shared vars dir — also a watcher dir — promote out of
// it); Hostname is the hostconfig-only input (the os.Hostname()
// fallback identity).
type EnvDeps struct {
	hostctx.Deps
	Hostname string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob hostconfig
// reads and returns a Config ready for New — the env contract lives
// in the package, not in cmd/agent. Two wiring concerns moved in with
// it, keyed on HostRoot: the Runner selection ("/" = the standalone
// systemd binary already sits inside the host namespaces →
// DirectRunner; anything else nsenters into PID 1 like the retired
// ansible pod did) and the DirWatcher construction (vars dir +
// nebula certs mount — vars/cert changes converge on the next poll
// instead of waiting out the full interval). The caller only builds
// the config after the enable gate
// (NODE_HOST_AGENT_ENABLE_HOSTCONFIG=true|auto + the vars-dir
// defaults.yaml probe) passed.
func ConfigFromEnv(d EnvDeps) Config {
	var runner Runner = NsenterRunner{}
	if d.HostRoot == "/" {
		runner = DirectRunner{}
	}
	cfg := Config{
		NodeName: d.NodeName,
		Hostname: d.Hostname,
		HostRoot: d.HostRoot,
		VarsDir:  d.VarsDir,
		Runner:   runner,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.StringKnob(envnames.EnvNebulaCertsDir, &cfg.NebulaCertsDir,
			defaultNebulaCertsDir),
		envx.StringKnob(envnames.EnvWatchdogScriptsDir, &cfg.WatchdogScriptsDir,
			defaultWatchdogDir),
		envx.DurationKnob(envnames.EnvHostconfigInterval, &cfg.Interval,
			defaultInterval),
	})
	// vars dir + nebula certs mount — vars/cert changes converge on
	// the next poll instead of waiting out the full interval.
	cfg.Watcher = &DirWatcher{Dirs: []string{d.VarsDir, cfg.NebulaCertsDir}}
	return cfg
}

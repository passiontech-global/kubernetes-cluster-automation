package hostconfig

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: node identity
// (hnode — NODE_HOST_AGENT_NODE_NAME resolved in main — plus the
// os.Hostname() fallback), the host root, and the shared vars dir
// (also a watcher dir).
type EnvDeps struct {
	NodeName string
	Hostname string
	HostRoot string
	VarsDir  string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob hostconfig
// reads and returns a Config ready for New — the env contract lives
// in the package, not in cmd/agent. Two wiring concerns moved in with
// it, keyed on HostRoot: the Runner selection ("/" = the standalone
// systemd binary already sits inside the host namespaces →
// DirectRunner; anything else nsenters into PID 1 like the retired
// ansible pod did) and the DirWatcher construction (vars dir +
// nebula certs mount — vars/cert changes converge on the next poll
// instead of waiting out the full interval). Enabled is always true
// here: the caller only builds the config after the enable gate
// (NODE_HOST_AGENT_ENABLE_HOSTCONFIG=true|auto + the vars-dir
// defaults.yaml probe) passed.
func ConfigFromEnv(d EnvDeps) Config {
	var runner Runner = NsenterRunner{}
	if d.HostRoot == "/" {
		runner = DirectRunner{}
	}
	cfg := Config{
		Enabled:  true,
		NodeName: d.NodeName,
		Hostname: d.Hostname,
		HostRoot: d.HostRoot,
		VarsDir:  d.VarsDir,
		Runner:   runner,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.StringKnob("NODE_HOST_AGENT_NEBULA_CERTS_DIR", &cfg.NebulaCertsDir,
			defaultNebulaCertsDir),
		envx.StringKnob("NODE_HOST_AGENT_WATCHDOG_SCRIPTS_DIR", &cfg.WatchdogScriptsDir,
			defaultWatchdogDir),
		envx.DurationKnob("NODE_HOST_AGENT_HOSTCONFIG_INTERVAL", &cfg.Interval,
			defaultInterval),
	})
	// vars dir + nebula certs mount — vars/cert changes converge on
	// the next poll instead of waiting out the full interval.
	cfg.Watcher = &DirWatcher{Dirs: []string{d.VarsDir, cfg.NebulaCertsDir}}
	return cfg
}

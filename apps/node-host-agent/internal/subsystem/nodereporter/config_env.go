package nodereporter

import (
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: the shared lazily-
// built kube clientset (its csOnce), this node's name (hnode —
// NODE_HOST_AGENT_NODE_NAME/NODE_NAME resolved in main), and the
// shared watchdog state dir + log file.
type EnvDeps struct {
	Client           kubernetes.Interface
	NodeName         string
	WatchdogStateDir string
	WatchdogLogFile  string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob nodereporter
// reads and returns a Config ready for New — the env contract lives
// in the package, not in cmd/agent. New still rejects a nil Client or
// empty NodeName. The enable gate (NODE_HOST_AGENT_ENABLE_REPORTER)
// and the node-name-empty check stay in the caller; the NPD-monitor
// port knobs keep their applyDefaults values (they were never
// env-driven).
func ConfigFromEnv(d EnvDeps) Config {
	cfg := Config{
		NodeName:         d.NodeName,
		Client:           d.Client,
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob("NODE_HOST_AGENT_REPORTER_INTERVAL", &cfg.Interval, defaultInterval),
		envx.StringKnob("NODE_HOST_AGENT_EVENT_NAMESPACE", &cfg.EventNamespace, defaultEventNamespace),
	})
	return cfg
}

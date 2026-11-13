package nodereporter

import (
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly. It embeds the shared
// hostctx.Deps watchdog/host-context bundle (this node's name and the
// shared watchdog state dir + log file promote out of it); Client is
// the subsystem-unique shared lazily-built kube clientset (its
// csOnce).
type EnvDeps struct {
	hostctx.Deps
	Client kubernetes.Interface
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
		Base:     subframe.FromDeps(d.Deps),
		NodeName: d.NodeName,
		Client:   d.Client,
		// The shared host-systemd client rides the embedded
		// hostctx.Deps — the reporter never builds its own.
		Systemd: d.Systemd,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob(envnames.EnvReporterInterval, &cfg.Interval, defaultInterval),
		envx.StringKnob(envnames.EnvEventNamespace, &cfg.EventNamespace, defaultEventNamespace),
	})
	return cfg
}

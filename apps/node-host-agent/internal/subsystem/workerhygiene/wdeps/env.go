// env.go — the NODE_HOST_AGENT_* env contract: EnvDeps (the non-env
// inputs) and ConfigFromEnv, which assembles the per-domain knob
// rows from config_<domain>.go in the pre-split table's order and
// applies them through envx.
package wdeps

import (
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/topology"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the
// values cmd/agent used to splice into the configs directly. It
// embeds the shared hostctx.Deps watchdog/host-context bundle —
// this node's name (also the topology.Load registry key), the
// shared watchdog state dir/log file, the parsed
// node-watchdog.conf + its per-cycle reloader, the systemd client,
// the vars dir the T15 host-list fallback reads, the shared
// journal-unreadable detector inputs, and the hostPath join all
// promote out of it. Client is the only subsystem-unique input:
// the shared lazily-built kube clientset (its csOnce — the
// build-failure → disable-the-subsystem contract stays in the
// caller, which invokes csOnce BEFORE calling ConfigFromEnv; New
// still rejects a nil Client).
type EnvDeps struct {
	hostctx.Deps
	Client kubernetes.Interface
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob workerhygiene
// reads and returns a Config ready for New — the env contract lives
// in the package, not in cmd/agent. The enable gate
// (NODE_HOST_AGENT_ENABLE_HYGIENE) plus the node-name-empty and
// kube-client-build checks stay in the caller. Fields wiring never
// set (KubeletHealthzURL, the T15 feeder knobs, the wave-2/7/8/9/10
// defaults, …) stay zero — New's applyDefaults fills them exactly as
// before.
func ConfigFromEnv(d EnvDeps) Config {
	hostPath := d.HostPath
	if hostPath == nil {
		hostPath = func(p string) string { return p }
	}
	cfg := Config{
		NodeName:         d.NodeName,
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
		Journal: JournalConfig{
			Dirs:             d.JournalDirs,
			UnreadableNeeded: d.JournalUnreadableNeeded,
		},
		Systemd:     d.Systemd,
		Watchdog:    d.Watchdog,
		WatchdogSrc: d.WatchdogSrc,
		Client:      d.Client,
	}
	// The env surface, one row per knob — the rows live beside
	// their domain's type in config_<domain>.go; the assembly
	// order below is the pre-split table's exact order (shared
	// wiring, net, kubelet, cilium, ctr, teardown, pressure,
	// calico, shared budgets, runtime). Every row writes a
	// distinct field, so order is documentation, not semantics.
	var knobs []envx.Knob
	knobs = append(knobs, cfg.wiringEnvKnobs(hostPath)...)
	knobs = append(knobs, cfg.Net.envKnobs(hostPath)...)
	knobs = append(knobs, cfg.Kubelet.envKnobs(hostPath, d)...)
	knobs = append(knobs, cfg.Cilium.envKnobs(hostPath)...)
	knobs = append(knobs, cfg.Ctr.envKnobs(hostPath)...)
	knobs = append(knobs, cfg.Teardown.envKnobs()...)
	knobs = append(knobs, cfg.Pressure.envKnobs()...)
	knobs = append(knobs, cfg.Calico.envKnobs()...)
	knobs = append(knobs, cfg.budgetEnvKnobs()...)
	knobs = append(knobs, cfg.Runtime.envKnobs(hostPath)...)
	envx.Apply(knobs)
	if d.Watchdog != nil {
		// API_BACKENDS → the watch-wedge check's upstream-stale gate
		// (module 06); kept current per-cycle by WatchdogSrc.
		cfg.APIBackends = d.Watchdog.APIBackendIPs()
	}
	return cfg
}

// KubeletWatchdogHosts resolves the T15 opt-in host list:
// NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS → systemd_watchdog_hosts in
// cluster.yaml (topology.Load over the vars dir). A missing/broken
// vars dir yields nil — the feeder self-gates on k0sworker.service,
// so the list is advisory. Ported verbatim from cmd/agent.
func KubeletWatchdogHosts(varsDir, nodeName string) []string {
	if l := envx.List("NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS"); l != nil {
		return l
	}
	t, err := topology.Load(topology.Config{VarsDir: varsDir, NodeName: nodeName})
	if err != nil {
		return nil
	}
	return t.Vars.StrList("systemd_watchdog_hosts")
}

// The watchdog-state janitor (stale-latch reaper + retired-unit
// sweep) moved to internal/subsystem/janitor — see
// janitor.ConfigFromEnv.

package workerhygiene

import (
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/topology"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the
// values cmd/agent used to splice
// into the configs directly: the shared lazily-built kube clientset
// (its csOnce — the build-failure → disable-the-subsystem contract
// stays in the caller, which invokes csOnce BEFORE calling
// ConfigFromEnv; New still rejects a nil Client), this node's name
// (hnode — NODE_HOST_AGENT_NODE_NAME/NODE_NAME resolved in main),
// the shared watchdog state dir/log file, the parsed
// node-watchdog.conf + its per-cycle reloader, the systemd client,
// the vars dir the T15 host-list fallback reads, the shared
// journal-unreadable detector inputs, and the hostPath join that
// prefixes host-fs paths with the host root ("/host" in the
// DaemonSet, identity standalone).
type EnvDeps struct {
	Client           kubernetes.Interface
	NodeName         string
	Systemd          *systemd.Client
	Watchdog         *watchdogconf.Config
	WatchdogSrc      *watchdogconf.Reloader
	WatchdogStateDir string
	WatchdogLogFile  string
	// VarsDir feeds the kubeletWatchdogHosts fallback
	// (systemd_watchdog_hosts out of cluster.yaml); NodeName is both
	// the Config field and the topology.Load registry key.
	VarsDir string
	// JournalDirs / JournalUnreadableNeeded are the shared journald
	// blindness-detector inputs buildAgentConfig resolves once for
	// workerhygiene + controllerhygiene.
	JournalDirs             []string
	JournalUnreadableNeeded int
	// HostPath joins a host-absolute path under the host-fs root.
	// Nil → identity (host paths used verbatim).
	HostPath func(string) string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob workerhygiene
// reads and returns a Config ready for New — the env contract lives
// in the package, not in cmd/agent. Enabled is always true here: the
// wire func set it unconditionally and the enable gate
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
		Enabled:          true,
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
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.DurationKnob("NODE_HOST_AGENT_HYGIENE_INTERVAL", &cfg.Interval, defaultInterval),
		envx.StringKnob("NODE_HOST_AGENT_PROC_ROOT", &cfg.ProcRoot, defaultProcRoot),
		// hostPath defaults — NOT the package defaults
		// (defaultCtrTaskRoot & friends hardcode the "/host"
		// prefix and would be wrong on a standalone host).
		envx.StringKnob("NODE_HOST_AGENT_CTR_TASK_ROOT", &cfg.CtrTaskRoot,
			hostPath("/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io")),
		envx.StringKnob("NODE_HOST_AGENT_SANDBOX_CTL_ROOT", &cfg.SandboxCtlRoot,
			hostPath("/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim")),
		envx.StringKnob("NODE_HOST_AGENT_K0S_WORKER_UNIT", &cfg.K0sWorkerUnitFile,
			hostPath("/etc/systemd/system/k0sworker.service")),
		envx.StringKnob("NODE_HOST_AGENT_HOST_RESOLV_CONF", &cfg.Net.HostResolvConf,
			hostPath("/etc/resolv.conf")),
		// W7 knobs — empty env → in-package defaults.
		envx.StringKnob("NODE_HOST_AGENT_LOCALDNS_PROBE_ADDR", &cfg.Net.LocalDNSProbeAddr, ""),
		envx.StringKnob("NODE_HOST_AGENT_LOCALDNS_PROBE_NAME", &cfg.Net.LocalDNSProbeName, ""),
		envx.StringKnob("NODE_HOST_AGENT_KUBELET_PODS_DIR", &cfg.Kubelet.PodsDir,
			hostPath("/var/lib/k0s/kubelet/pods")),
		// A4 probes: kubelet :10250 denies anonymous healthz, so
		// the syncloop probe authenticates with the pod SA token.
		envx.StringKnob("NODE_HOST_AGENT_KUBELET_SYNCLOOP_URL", &cfg.Kubelet.SyncloopURL, ""),
		envx.OrKnob("NODE_HOST_AGENT_KUBELET_TOKEN_FILE", &cfg.Kubelet.TokenPath,
			defaultKubeletTokenPath),
		// T15 opt-in host list: env override →
		// systemd_watchdog_hosts out of the vars dir
		// (cluster.yaml) — resolved by kubeletWatchdogHosts below.
		// Absent vars dir is not an error — the feeder self-gates on
		// k0sworker.service anyway.
		{Name: "NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS", Resolve: func(string) {
			cfg.Kubelet.WatchdogHosts = kubeletWatchdogHosts(d.VarsDir, d.NodeName)
		}},
		envx.StringKnob("NODE_HOST_AGENT_CILIUM_SOCKET", &cfg.Cilium.Socket,
			hostPath("/run/cilium/cilium.sock")),
		// W7 knob — empty env → in-package default.
		envx.StringKnob("NODE_HOST_AGENT_CILIUM_ENVOY_ADMIN_URL", &cfg.Cilium.EnvoyAdminURL, ""),
		// A4 probe: k0s puts the containerd socket at
		// /run/k0s/containerd.sock (not inside the state dir).
		envx.StringKnob("NODE_HOST_AGENT_CONTAINERD_SOCKET", &cfg.Ctr.Socket,
			hostPath("/run/k0s/containerd.sock")),
		envx.DurationKnob("NODE_HOST_AGENT_HYGIENE_STUCK_DELETE_AGE", &cfg.Teardown.StuckDeleteAge, defaultStuckDeleteAge),
		envx.DurationKnob("NODE_HOST_AGENT_HYGIENE_STUCK_WEDGE_AGE", &cfg.Teardown.StuckWedgeAge, defaultStuckWedgeAge),
		envx.IntKnob("NODE_HOST_AGENT_HYGIENE_MAX_FORCE_DELETE", &cfg.Teardown.MaxForceDelete, defaultMaxForceDelete),
		// W7 knob — empty env → in-package default.
		envx.IntKnob("NODE_HOST_AGENT_DSTATE_STORM_THRESHOLD", &cfg.Pressure.DStateStormThreshold, defaultDStateStormThreshold),
		// W7 knobs — empty env → in-package defaults.
		envx.StringKnob("NODE_HOST_AGENT_CALICO_FELIX_READY_URL", &cfg.Calico.FelixReadyURL, ""),
		envx.IntKnob("NODE_HOST_AGENT_CALICO_ORPHAN_VETH_THRESHOLD", &cfg.Calico.OrphanVethThreshold, defaultCalicoOrphanVethThresh),
		envx.IntKnob("NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED", &cfg.ConsecNeeded, defaultConsecNeeded),
		envx.DurationKnob("NODE_HOST_AGENT_HYGIENE_MIN_RESTART_INTERVAL", &cfg.MinRestartInterval, defaultMinRestartInterval),
	})
	if d.Watchdog != nil {
		// API_BACKENDS → the watch-wedge check's upstream-stale gate
		// (module 06); kept current per-cycle by WatchdogSrc.
		cfg.APIBackends = d.Watchdog.APIBackendIPs()
	}
	return cfg
}

// kubeletWatchdogHosts resolves the T15 opt-in host list:
// NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS → systemd_watchdog_hosts in
// cluster.yaml (topology.Load over the vars dir). A missing/broken
// vars dir yields nil — the feeder self-gates on k0sworker.service,
// so the list is advisory. Ported verbatim from cmd/agent.
func kubeletWatchdogHosts(varsDir, nodeName string) []string {
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

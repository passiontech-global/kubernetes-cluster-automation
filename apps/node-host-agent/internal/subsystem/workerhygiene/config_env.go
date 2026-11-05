package workerhygiene

import (
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/envx"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
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
		Interval:         envx.Duration("NODE_HOST_AGENT_HYGIENE_INTERVAL", defaultInterval),
		WatchdogStateDir: d.WatchdogStateDir,
		WatchdogLogFile:  d.WatchdogLogFile,
		ProcRoot:         envx.String("NODE_HOST_AGENT_PROC_ROOT", defaultProcRoot),
		// hostPath defaults — NOT the package defaults
		// (defaultCtrTaskRoot & friends hardcode the "/host"
		// prefix and would be wrong on a standalone host).
		CtrTaskRoot: envx.String("NODE_HOST_AGENT_CTR_TASK_ROOT",
			hostPath("/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io")),
		SandboxCtlRoot: envx.String("NODE_HOST_AGENT_SANDBOX_CTL_ROOT",
			hostPath("/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim")),
		HostResolvConf: envx.String("NODE_HOST_AGENT_HOST_RESOLV_CONF",
			hostPath("/etc/resolv.conf")),
		K0sWorkerUnitFile: envx.String("NODE_HOST_AGENT_K0S_WORKER_UNIT",
			hostPath("/etc/systemd/system/k0sworker.service")),
		KubeletPodsDir: envx.String("NODE_HOST_AGENT_KUBELET_PODS_DIR",
			hostPath("/var/lib/k0s/kubelet/pods")),
		CiliumSocket: envx.String("NODE_HOST_AGENT_CILIUM_SOCKET",
			hostPath("/run/cilium/cilium.sock")),
		// A4 probes: k0s puts the containerd socket at
		// /run/k0s/containerd.sock (not inside the state dir); kubelet
		// :10250 denies anonymous healthz, so the syncloop probe
		// authenticates with the pod SA token.
		ContainerdSocket: envx.String("NODE_HOST_AGENT_CONTAINERD_SOCKET",
			hostPath("/run/k0s/containerd.sock")),
		KubeletSyncloopURL: envx.String("NODE_HOST_AGENT_KUBELET_SYNCLOOP_URL", ""),
		KubeletTokenPath: envx.Or("NODE_HOST_AGENT_KUBELET_TOKEN_FILE",
			defaultKubeletTokenPath),
		Systemd:     d.Systemd,
		Watchdog:    d.Watchdog,
		WatchdogSrc: d.WatchdogSrc,
		// T15 opt-in host list: env override →
		// systemd_watchdog_hosts out of the vars dir
		// (cluster.yaml). Absent vars dir is not an error — the
		// feeder self-gates on k0sworker.service anyway.
		KubeletWatchdogHosts:    kubeletWatchdogHosts(d.VarsDir, d.NodeName),
		StuckDeleteAge:          envx.Duration("NODE_HOST_AGENT_HYGIENE_STUCK_DELETE_AGE", defaultStuckDeleteAge),
		StuckWedgeAge:           envx.Duration("NODE_HOST_AGENT_HYGIENE_STUCK_WEDGE_AGE", defaultStuckWedgeAge),
		MaxForceDelete:          envx.Int("NODE_HOST_AGENT_HYGIENE_MAX_FORCE_DELETE", defaultMaxForceDelete),
		ConsecNeeded:            envx.Int("NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED", defaultConsecNeeded),
		MinRestartInterval:      envx.Duration("NODE_HOST_AGENT_HYGIENE_MIN_RESTART_INTERVAL", defaultMinRestartInterval),
		JournalDirs:             d.JournalDirs,
		JournalUnreadableNeeded: d.JournalUnreadableNeeded,
		// W7 knobs — empty env → in-package defaults.
		DStateStormThreshold:      envx.Int("NODE_HOST_AGENT_DSTATE_STORM_THRESHOLD", defaultDStateStormThreshold),
		CiliumEnvoyAdminURL:       envx.String("NODE_HOST_AGENT_CILIUM_ENVOY_ADMIN_URL", ""),
		LocalDNSProbeAddr:         envx.String("NODE_HOST_AGENT_LOCALDNS_PROBE_ADDR", ""),
		LocalDNSProbeName:         envx.String("NODE_HOST_AGENT_LOCALDNS_PROBE_NAME", ""),
		CalicoFelixReadyURL:       envx.String("NODE_HOST_AGENT_CALICO_FELIX_READY_URL", ""),
		CalicoOrphanVethThreshold: envx.Int("NODE_HOST_AGENT_CALICO_ORPHAN_VETH_THRESHOLD", defaultCalicoOrphanVethThresh),
		Client:                    d.Client,
	}
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
// janitor.JanitorConfigFromEnv.

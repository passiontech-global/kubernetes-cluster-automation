package hostmetrics

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly: node identity, the
// shared watchdog state dir, the standalone flag, the watchdogconf-
// derived egress relays + nebula net name (path defaults), and the
// hostPath join that prefixes host-fs paths with the host root
// ("/host" in the DaemonSet, identity standalone).
type EnvDeps struct {
	NodeName            string
	WatchdogStateDir    string
	Standalone          bool
	OverlayEgressRelays []string // watchdogconf OVERLAY_EGRESS_RELAYS
	NebulaNet           string   // watchdogconf NEBULA_NET — cert path default
	// HostPath joins a host-absolute path under the host-fs root.
	// Nil → identity (host paths used verbatim).
	HostPath func(string) string
}

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob the collector
// reads and returns a Config ready for New — the env contract lives in
// the package, not in cmd/agent. The enable gate
// (NODE_HOST_AGENT_ENABLE_HOSTMETRICS) and the standalone textfile
// ticker stay in the caller; HostRoot is left unset so applyDefaults
// keeps its "/host"-or-"/" auto-detect.
func ConfigFromEnv(d EnvDeps) Config {
	hostPath := d.HostPath
	if hostPath == nil {
		hostPath = func(p string) string { return p }
	}
	cfg := Config{
		NodeName:         d.NodeName,
		WatchdogStateDir: d.WatchdogStateDir,
		Standalone:       d.Standalone,
		EgressRelays:     d.OverlayEgressRelays,
	}
	// The env surface, one row per knob in declaration order.
	envx.Apply([]envx.Knob{
		envx.StringKnob("NODE_HOST_AGENT_KEY_USERS_FILE", &cfg.KeyUsersFile,
			defaultKeyUsersFile),
		envx.DurationKnob("NODE_HOST_AGENT_LATCH_INTERVAL", &cfg.LatchInterval,
			defaultLatchInterval),
		envx.StringKnob("NODE_HOST_AGENT_SYS_CLASS_NET", &cfg.SysClassNet, defaultSysClassNet),
		envx.StringKnob("NODE_HOST_AGENT_NEBULA_IFACE", &cfg.NebulaIface, defaultNebulaIface),
		envx.StringKnob("NODE_HOST_AGENT_HOST_ROUTE_FILE", &cfg.RouteFile, defaultRouteFile),
		envx.StringKnob("NODE_HOST_AGENT_K0S_CONFIG", &cfg.K0sConfigFile,
			defaultK0sConfigFile),
		envx.StringKnob("NODE_HOST_AGENT_K0S_UNIT", &cfg.K0sUnitFile,
			hostPath(defaultK0sUnitFile)),
		envx.StringKnob("NODE_HOST_AGENT_NEBULA_CERT", &cfg.NebulaCertFile,
			hostPath("/etc/nebula/"+d.NebulaNet+"/host.crt")),
		// empty env → nil → applyDefaults' expected key set.
		envx.ListKnob("NODE_HOST_AGENT_K0S_EXPECTED_KCM_ARGS", &cfg.ExpectedKCMArgs),
		envx.StringKnob("NODE_HOST_AGENT_PSI_FILE", &cfg.PSIFile, defaultPSIFile),
		envx.DurationKnob("NODE_HOST_AGENT_CPU_DELIVERED_INTERVAL",
			&cfg.CPUDeliveredInterval, defaultCPUDeliveredIn),
		// W7-H5/H6 telemetry files.
		envx.StringKnob("NODE_HOST_AGENT_CONNTRACK_STAT_FILE", &cfg.ConntrackStatFile,
			defaultConntrackStatFile),
		envx.StringKnob("NODE_HOST_AGENT_ARP_TABLE_FILE", &cfg.ARPTableFile,
			defaultARPTableFile),
		envx.ListKnob("NODE_HOST_AGENT_CGROUP_MEM_UNITS", &cfg.CgroupMemUnits),
		// envList → default-closure: a set env wins verbatim (even an
		// empty-looking parse is nil → defaults); unset falls back to
		// the hostPath-joined mount set — NOT defaultFilesystemTargets,
		// which assumes the "/host" prefix literally.
		{Name: "NODE_HOST_AGENT_FILESYSTEM_TARGETS", Resolve: func(k string) {
			if l := envx.List(k); l != nil {
				cfg.FilesystemTargets = l
			} else {
				cfg.FilesystemTargets = []string{
					hostPath("/etc"), hostPath("/var/lib/k0s"), "/var/openebs/local",
				}
			}
		}},
	})
	return cfg
}

package hostmetrics

import (
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/envx"
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
		KeyUsersFile: envx.String("NODE_HOST_AGENT_KEY_USERS_FILE",
			defaultKeyUsersFile),
		LatchInterval: envx.Duration("NODE_HOST_AGENT_LATCH_INTERVAL",
			defaultLatchInterval),
		SysClassNet: envx.String("NODE_HOST_AGENT_SYS_CLASS_NET", defaultSysClassNet),
		NebulaIface: envx.String("NODE_HOST_AGENT_NEBULA_IFACE", defaultNebulaIface),
		RouteFile:   envx.String("NODE_HOST_AGENT_HOST_ROUTE_FILE", defaultRouteFile),
		K0sConfigFile: envx.String("NODE_HOST_AGENT_K0S_CONFIG",
			defaultK0sConfigFile),
		K0sUnitFile: envx.String("NODE_HOST_AGENT_K0S_UNIT",
			hostPath(defaultK0sUnitFile)),
		NebulaCertFile: envx.String("NODE_HOST_AGENT_NEBULA_CERT",
			hostPath("/etc/nebula/"+d.NebulaNet+"/host.crt")),
		// empty env → nil → applyDefaults' expected key set.
		ExpectedKCMArgs: envx.List("NODE_HOST_AGENT_K0S_EXPECTED_KCM_ARGS"),
		PSIFile:         envx.String("NODE_HOST_AGENT_PSI_FILE", defaultPSIFile),
		EgressRelays:    d.OverlayEgressRelays,
		CPUDeliveredInterval: envx.Duration(
			"NODE_HOST_AGENT_CPU_DELIVERED_INTERVAL", defaultCPUDeliveredIn),
		// W7-H5/H6 telemetry files.
		ConntrackStatFile: envx.String("NODE_HOST_AGENT_CONNTRACK_STAT_FILE",
			defaultConntrackStatFile),
		ARPTableFile: envx.String("NODE_HOST_AGENT_ARP_TABLE_FILE",
			defaultARPTableFile),
		CgroupMemUnits: envx.List("NODE_HOST_AGENT_CGROUP_MEM_UNITS"),
	}
	// envList → default-closure: a set env wins verbatim (even an
	// empty-looking parse is nil → defaults); unset falls back to the
	// hostPath-joined mount set — NOT defaultFilesystemTargets, which
	// assumes the "/host" prefix literally.
	if l := envx.List("NODE_HOST_AGENT_FILESYSTEM_TARGETS"); l != nil {
		cfg.FilesystemTargets = l
	} else {
		cfg.FilesystemTargets = []string{
			hostPath("/etc"), hostPath("/var/lib/k0s"), "/var/openebs/local",
		}
	}
	return cfg
}

package hostmetrics

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// EnvDeps carries the non-env inputs ConfigFromEnv needs — the values
// cmd/agent used to splice into Config directly. It embeds the shared
// hostctx.Deps watchdog/host-context bundle (node identity, the
// shared watchdog state dir/log file and the hostPath join promote
// out of it — the promoted WatchdogLogFile is the shared appended
// watchdog log the latch ticker's STATE-ENTER lines must reach for
// nodereporter's Event rules); the named fields below are the
// hostmetrics-only inputs: the standalone flag and the
// watchdogconf-derived egress relays + nebula net name (path
// defaults — extracted off Watchdog by the caller because the knobs
// read differently here).
type EnvDeps struct {
	hostctx.Deps
	Standalone          bool
	OverlayEgressRelays []string // watchdogconf OVERLAY_EGRESS_RELAYS
	NebulaNet           string   // watchdogconf NEBULA_NET — cert path default
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
		envx.StringKnob(envnames.EnvWatchdogLogFile, &cfg.WatchdogLogFile,
			d.WatchdogLogFile),
		envx.StringKnob(envnames.EnvKeyUsersFile, &cfg.KeyUsersFile,
			defaultKeyUsersFile),
		envx.DurationKnob(envnames.EnvLatchInterval, &cfg.LatchInterval,
			defaultLatchInterval),
		envx.StringKnob(envnames.EnvSysClassNet, &cfg.SysClassNet, defaultSysClassNet),
		envx.StringKnob(envnames.EnvNebulaIface, &cfg.NebulaIface, defaultNebulaIface),
		envx.StringKnob(envnames.EnvHostRouteFile, &cfg.RouteFile, defaultRouteFile),
		envx.StringKnob(envnames.EnvK0sConfig, &cfg.K0sConfigFile,
			defaultK0sConfigFile),
		envx.StringKnob(envnames.EnvK0sUnit, &cfg.K0sUnitFile,
			hostPath(defaultK0sUnitFile)),
		envx.StringKnob(envnames.EnvNebulaCert, &cfg.NebulaCertFile,
			hostPath("/etc/nebula/"+d.NebulaNet+"/host.crt")),
		// empty env → nil → applyDefaults' expected key set.
		envx.ListKnob(envnames.EnvK0sExpectedKcmArgs, &cfg.ExpectedKCMArgs),
		envx.StringKnob(envnames.EnvPsiFile, &cfg.PSIFile, defaultPSIFile),
		envx.DurationKnob(envnames.EnvCPUDeliveredInterval,
			&cfg.CPUDeliveredInterval, defaultCPUDeliveredIn),
		// W7-H5/H6 telemetry files.
		envx.StringKnob(envnames.EnvConntrackStatFile, &cfg.ConntrackStatFile,
			defaultConntrackStatFile),
		envx.StringKnob(envnames.EnvArpTableFile, &cfg.ARPTableFile,
			defaultARPTableFile),
		envx.ListKnob(envnames.EnvCgroupMemUnits, &cfg.CgroupMemUnits),
		// envList → default-closure: a set env wins verbatim (even an
		// empty-looking parse is nil → defaults); unset falls back to
		// the hostPath-joined mount set — NOT defaultFilesystemTargets,
		// which assumes the "/host" prefix literally.
		{Name: envnames.EnvFilesystemTargets, Resolve: func(k string) {
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

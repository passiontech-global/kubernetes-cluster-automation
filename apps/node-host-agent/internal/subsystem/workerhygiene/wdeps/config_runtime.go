// config_runtime.go — the runtime-resource guard paths:
// RuntimeConfig, its defaults and its NODE_HOST_AGENT_CGROUP_ROOT /
// NODE_HOST_AGENT_SYSTEMD_SESSIONS_DIR env rows (the cgroup-v2
// unified hierarchy root and the logind session dir the six W10
// guards scan).
package wdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// RuntimeConfig groups the runtime-resource guard paths — the
// cgroup-v2 unified hierarchy root (dying-descendant guard +
// memory.reclaim writes) and the logind session dir the session
// janitor scans. Everything else the guards touch lives under
// already-shared roots (ProcRoot for diskstats/PSI/sysctls,
// WatchdogStateDir for markers, SysClassNet for the neb1 gate).
type RuntimeConfig struct {
	// Both paths default through ConfigFromEnv: hostPath-joined
	// defaults behind NODE_HOST_AGENT_CGROUP_ROOT /
	// NODE_HOST_AGENT_SYSTEMD_SESSIONS_DIR; a direct-New caller
	// gets the unprefixed host paths from applyDefaults.
	CgroupRoot  string // cgroup v2 root ("/host/sys/fs/cgroup" in-pod)
	SessionsDir string // /run/systemd/sessions on the host
}

// applyDefaults fills the unprefixed host paths for direct-New
// callers — ConfigFromEnv already resolved both knobs through
// hostPath, so a non-empty field is never touched.
func (r *RuntimeConfig) applyDefaults() {
	if r.CgroupRoot == "" {
		r.CgroupRoot = defaultCgroupRoot
	}
	if r.SessionsDir == "" {
		r.SessionsDir = defaultSystemdSessionsDir
	}
}

// envKnobs returns the W10 runtime-resource guard env rows —
// hostPath defaults like the wiring block (the package defaults are
// unprefixed host-absolute paths; the "/host" prefix is the
// DaemonSet's, not the constant's).
func (r *RuntimeConfig) envKnobs(hostPath func(string) string) []envx.Knob {
	return []envx.Knob{
		envx.StringKnob("NODE_HOST_AGENT_CGROUP_ROOT", &r.CgroupRoot,
			hostPath("/sys/fs/cgroup")),
		envx.StringKnob("NODE_HOST_AGENT_SYSTEMD_SESSIONS_DIR", &r.SessionsDir,
			hostPath("/run/systemd/sessions")),
	}
}

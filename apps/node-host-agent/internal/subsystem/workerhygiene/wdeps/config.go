// config.go — the shared workerhygiene Config: the top-level knob
// struct, the subsystem wiring defaults + env rows. The per-domain
// sub-configs (Kubelet/Teardown/Ctr/Cilium/Disk/Net/Pressure/Calico/
// Journal/Host/Runtime) live in config_<domain>.go beside their own
// defaults and env rows; ApplyDefaults below orchestrates them in a
// fixed order. The Seams test-seam funcs live in seams.go, grouped
// by concern (Probe/Host/Ctr/Cilium).
package wdeps

import (
	"path/filepath"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Subsystem wiring defaults — the /host mount convention mirrors the
// shell DaemonSet host mounts; the per-domain knobs live next to
// their checks.
const (
	DefaultInterval           = 2 * time.Minute
	defaultCycleTimeout       = 15 * time.Minute // controllerhygiene cdeps defaultCycleTimeout parity
	defaultWatchdogStateDir   = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile    = "/host/var/log/node-watchdog.log"
	defaultProcRoot           = "/proc" // hostPID:true makes pod /proc == host /proc
	defaultK0sWorkerUnitFile  = "/host/etc/systemd/system/k0sworker.service"
	defaultConsecNeeded       = 2                // shell CONSEC_NEEDED=2
	defaultMinRestartInterval = 30 * time.Minute // shell MIN_RESTART_INTERVAL_S=1800
	// defaultSysClassNet is the host sysfs net mount the iface
	// checks (MTU drift, calico veth, netns reaper) read through.
	defaultSysClassNet      = "/sys/class/net"
	defaultNebulaIface      = "neb1"
	defaultHostResolvConf   = "/host/etc/resolv.conf"
	defaultKubeletPodsDir   = "/host/var/lib/k0s/kubelet/pods"
	defaultK0sDataDir       = "/host/var/lib/k0s"
	defaultContainerdSocket = "/host/run/k0s/containerd.sock"
)

// Config carries the hygiene knobs — all test-injectable. The knobs
// are grouped into per-domain sub-structs mirroring the check
// families (Kubelet/Teardown/Ctr/Cilium/Disk/Net/Pressure/Calico/
// Journal/Host); only the genuinely shared wiring and rate budgets
// stay top-level, and the unexported test-seam funcs live under
// Seams. The shared wiring block includes the promoted host
// paths/ifaces read by ≥2 domain packages (CtrSocket, K0sDataDir,
// PodsDir, SysClassNet, NebulaIface, HostResolvConf) — same
// precedent as CtrTaskRoot.
type Config struct {
	// Base is the shared watchdog-subsystem block — cadence, the
	// watchdog state dir (state-*/last-*/consecutive-* files) +
	// appended watchdog log (NPD filelog), ProcRoot, the systemd
	// client driving host restarts/probes (nsenter-wrapped inside
	// the container; nil → all systemd-dependent checks degrade to
	// the "cannot determine → keep" branch, log-only), the parsed
	// node-watchdog.conf (the runner's per-module WD_SIG_<NAME>=off
	// kill switch plus, through APIBackendIPs, the watch-wedge
	// check's upstream-stale gate) and its per-cycle reloader
	// (subframe.FromDeps). The live clock seam stays
	// Seams.Host.Clock — the field checks and tests re-stub — and
	// ApplyDefaults arms THAT cell when unset, so the store is
	// built with the explicit-clock subframe.StoreAt form, never
	// the promoted Base.Store (Base.Clock may be nil or a
	// different cell than the armed seams one).
	subframe.Base
	NodeName          string // this node (spec.nodeName)
	CtrTaskRoot       string // containerd runtime-v2 task dirs
	SandboxCtlRoot    string // sandbox-controller shim dirs
	K0sWorkerUnitFile string // presence gates all checks
	// MountinfoFile is the HOST /proc/1/mountinfo the W15-R1b
	// mountinfo-hygiene check reads — ProcRoot is the host /proc
	// (hostPID), so the default derives from it.
	MountinfoFile string
	// Promoted wiring paths/ifaces — read by ≥2 domain packages
	// (ctr + kubelet read CtrSocket, ctr + runtime read K0sDataDir,
	// kubelet + runtime read PodsDir, cilium + guards + runtime read
	// SysClassNet, cilium + runtime read NebulaIface, pods + the
	// textfile wiring read HostResolvConf).
	CtrSocket      string // containerd grpc unix socket under /host/run
	K0sDataDir     string // /var/lib/k0s — disk-high ingest-GC trigger
	PodsDir        string // host kubelet pod dirs (05/06)
	SysClassNet    string // /sys/class/net — MTU reads (B4)
	NebulaIface    string // overlay iface MTU baseline (neb1 = 1300)
	HostResolvConf string // host resolv.conf (dns drift baseline)
	Client         kubernetes.Interface
	// APIBackends are the "ip[:port]" apiserver endpoints module 06
	// gates on — wired from watchdogconf.APIBackendIPs() by main
	// (kept current by WatchdogSrc when set).
	APIBackends []string
	// ConsecNeeded / MinRestartInterval / ProbeGap are the shared
	// budgets every check reads — the consecutive-suspect gate, the
	// per-action rate limit and the inter-probe retry sleep.
	ConsecNeeded       int           // consecutive suspect cycles before action
	MinRestartInterval time.Duration // rate-limit budget for recreating actions
	ProbeGap           time.Duration // sleep between probe retries (05/32)
	// CycleTimeout is the per-Cycle deadline Run applies around each
	// Cycle (controllerhygiene cdeps.CycleTimeout parity): every
	// spawned command and HTTP probe is ctx-aware, so a stalled
	// check is aborted instead of starving the later guards past
	// this bound on any tick. <=0 → defaultCycleTimeout (15m).
	CycleTimeout time.Duration

	// Per-check-domain knob groups.
	Kubelet  KubeletConfig  // 05/06 stall + watch-wedge, T15 feeder, A4 syncloop
	Teardown TeardownConfig // 36-pod-teardown ages + force-delete cap
	Ctr      CtrConfig      // containerd socket/tasks/ingest/meta knobs
	Cilium   CiliumConfig   // 32/35/38 agent, envoy, MTU/WG, BPF maps
	Disk     DiskConfig     // /var/lib/k0s watermarks, disk-bloat, pod logs
	Net      NetConfig      // resolv.conf, /sys/class/net, netns, DNS probes
	Pressure PressureConfig // D-state/zombie storms, PSI memory thrash
	Calico   CalicoConfig   // calico-hygiene felix + orphan-veth knobs
	Journal  JournalConfig  // journald blindness-detector inputs
	Host     HostConfig     // hostmetrics markers + node events (KR1/ST2)
	Runtime  RuntimeConfig  // cgroup/session/io-pressure guard paths

	// Seams are the unexported test seams — every check reads them
	// through h.cfg.Seams so tests re-stub a live Hygiene after New.
	// The fields are grouped by concern (Probe/Host/Ctr/Cilium) —
	// see seams.go.
	Seams Seams
}

// applyDefaults fills every unset knob — the per-group methods below
// own their own fields exactly like the old flat pass did.
func (c *Config) ApplyDefaults() {
	c.applyWiringDefaults()
	c.Kubelet.applyDefaults()
	c.Teardown.applyDefaults()
	c.Ctr.applyDefaults()
	c.Cilium.applyDefaults()
	c.Disk.applyDefaults()
	c.Net.applyDefaults()
	c.Pressure.applyDefaults()
	c.Calico.applyDefaults()
	c.Journal.applyDefaults()
	c.Host.applyDefaults(c.WatchdogStateDir)
	c.Runtime.applyDefaults()
	c.Seams.applyDefaults(c)
}

// applyWiringDefaults fills the top-level host paths, cadence and
// shared budgets.
func (c *Config) applyWiringDefaults() {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.CycleTimeout <= 0 {
		c.CycleTimeout = defaultCycleTimeout
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultWatchdogLogFile
	}
	if c.ProcRoot == "" {
		c.ProcRoot = defaultProcRoot
	}
	if c.MountinfoFile == "" {
		c.MountinfoFile = filepath.Join(c.ProcRoot, "1", "mountinfo")
	}
	if c.CtrTaskRoot == "" {
		c.CtrTaskRoot = defaultCtrTaskRoot
	}
	if c.SandboxCtlRoot == "" {
		c.SandboxCtlRoot = defaultSandboxCtlRoot
	}
	if c.K0sWorkerUnitFile == "" {
		c.K0sWorkerUnitFile = defaultK0sWorkerUnitFile
	}
	if c.CtrSocket == "" {
		c.CtrSocket = defaultContainerdSocket
	}
	if c.K0sDataDir == "" {
		c.K0sDataDir = defaultK0sDataDir
	}
	if c.PodsDir == "" {
		c.PodsDir = defaultKubeletPodsDir
	}
	if c.SysClassNet == "" {
		c.SysClassNet = defaultSysClassNet
	}
	if c.NebulaIface == "" {
		c.NebulaIface = defaultNebulaIface
	}
	if c.HostResolvConf == "" {
		c.HostResolvConf = defaultHostResolvConf
	}
	if c.ConsecNeeded <= 0 {
		c.ConsecNeeded = defaultConsecNeeded
	}
	if c.MinRestartInterval <= 0 {
		c.MinRestartInterval = defaultMinRestartInterval
	}
	if c.ProbeGap <= 0 {
		c.ProbeGap = probeGap
	}
}

// wiringEnvKnobs returns the shared host-path env rows — the
// hostPath-joined defaults (NOT the package defaults, which hardcode
// the "/host" DaemonSet prefix and would be wrong on a standalone
// host). These held the head of the pre-split knob table; the
// domain rows follow in ConfigFromEnv's assembly order. The
// containerd socket, kubelet pods dir and resolv.conf rows joined
// this block when their knobs promoted to the top-level Config.
func (c *Config) wiringEnvKnobs(hostPath func(string) string) []envx.Knob {
	return []envx.Knob{
		envx.DurationKnob(envnames.EnvHygieneInterval, &c.Interval, DefaultInterval),
		envx.DurationKnob(envnames.EnvHygieneCycleTimeout, &c.CycleTimeout, defaultCycleTimeout),
		envx.StringKnob(envnames.EnvProcRoot, &c.ProcRoot, defaultProcRoot),
		envx.StringKnob(envnames.EnvCtrTaskRoot, &c.CtrTaskRoot,
			hostPath("/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io")),
		envx.StringKnob(envnames.EnvSandboxCtlRoot, &c.SandboxCtlRoot,
			hostPath("/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim")),
		envx.StringKnob(envnames.EnvK0sWorkerUnit, &c.K0sWorkerUnitFile,
			hostPath("/etc/systemd/system/k0sworker.service")),
		envx.StringKnob(envnames.EnvMountinfoFile, &c.MountinfoFile,
			hostPath("/proc/1/mountinfo")),
		envx.StringKnob(envnames.EnvContainerdSocket, &c.CtrSocket,
			hostPath("/run/k0s/containerd.sock")),
		envx.StringKnob(envnames.EnvKubeletPodsDir, &c.PodsDir,
			hostPath("/var/lib/k0s/kubelet/pods")),
		envx.StringKnob(envnames.EnvHostResolvConf, &c.HostResolvConf,
			hostPath("/etc/resolv.conf")),
	}
}

// budgetEnvKnobs returns the shared consecutive-suspect / rate-limit
// budget rows — they sat between the calico and runtime rows in the
// pre-split table; ConfigFromEnv keeps that position.
func (c *Config) budgetEnvKnobs() []envx.Knob {
	return []envx.Knob{
		envx.IntKnob(envnames.EnvHygieneConsecNeeded, &c.ConsecNeeded, defaultConsecNeeded),
		envx.DurationKnob(envnames.EnvHygieneMinRestartInterval, &c.MinRestartInterval, defaultMinRestartInterval),
	}
}

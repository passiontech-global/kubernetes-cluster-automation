package workerhygiene

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// Subsystem wiring defaults — the /host mount convention mirrors the
// shell DaemonSet host mounts; the per-domain knobs live next to
// their checks.
const (
	defaultInterval           = 2 * time.Minute
	defaultWatchdogStateDir   = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile    = "/host/var/log/node-watchdog.log"
	defaultProcRoot           = "/proc" // hostPID:true makes pod /proc == host /proc
	defaultK0sWorkerUnitFile  = "/host/etc/systemd/system/k0sworker.service"
	defaultConsecNeeded       = 2                // shell CONSEC_NEEDED=2
	defaultMinRestartInterval = 30 * time.Minute // shell MIN_RESTART_INTERVAL_S=1800
	// defaultSysClassNet is the host sysfs net mount the iface
	// checks (MTU drift, calico veth, netns reaper) read through.
	defaultSysClassNet = "/sys/class/net"
)

// Config carries the hygiene knobs — all test-injectable. The knobs
// are grouped into per-domain sub-structs mirroring the check
// families (Kubelet/Teardown/Ctr/Cilium/Disk/Net/Pressure/Calico/
// Journal/Host); only the genuinely shared wiring and rate budgets
// stay top-level, and the unexported test-seam funcs live under
// Seams.
type Config struct {
	NodeName          string        // this node (spec.nodeName)
	Interval          time.Duration // check cadence
	Enabled           bool          // false → Run idles until ctx done
	WatchdogStateDir  string        // state-*/last-*/consecutive-* files
	WatchdogLogFile   string        // appended watchdog log (NPD filelog)
	ProcRoot          string        // host /proc
	CtrTaskRoot       string        // containerd runtime-v2 task dirs
	SandboxCtlRoot    string        // sandbox-controller shim dirs
	K0sWorkerUnitFile string        // presence gates all checks
	Client            kubernetes.Interface
	// Systemd drives host restarts/probes (nsenter-wrapped inside the
	// container). nil → all systemd-dependent checks degrade to the
	// "cannot determine → keep" branch (log-only).
	Systemd *systemd.Client
	// Watchdog is the parsed node-watchdog.conf — feeds the runner's
	// per-module kill switch (WD_SIG_<NAME>=off) and, through
	// APIBackendIPs, the upstream-stale gate of the watch-wedge
	// check. nil → every check runs (pre-conf behaviour).
	Watchdog *watchdogconf.Config
	// WatchdogSrc, when set, re-reads the conf every Cycle so
	// hostconfig rewrites (WD_SIG_*, API_BACKENDS) apply live —
	// APIBackends below is then refreshed from the file each cycle.
	WatchdogSrc *watchdogconf.Reloader
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
	Seams Seams
}

// KubeletConfig groups the kubelet-side knobs: the 05/06 stall and
// watch-wedge pod dirs/probes, the A4 syncloop probe auth, and the
// T15 watchdog-feeder cadence/gates.
type KubeletConfig struct {
	PodsDir     string        // host kubelet pod dirs (05/06)
	HealthzURL  string        // kubelet :10250 probe (05)
	WatchMinAge time.Duration // pod age without pod dir → watch wedge (06)
	// WatchdogHosts is the cluster var systemd_watchdog_hosts —
	// the T15 opt-in host list the shell feeder unit gated on (wired
	// by main from the vars dir / env). The feeder activates when this
	// node is listed here OR by default on any worker node
	// (K0sWorkerUnitFile present) — in the agent port the T15 pilot
	// graduated fleet-wide, so an empty list never disables it.
	WatchdogHosts []string
	WdInterval    time.Duration // feeder probe cadence (15s)
	WdMaxFail     int           // consecutive fails → remediate gates (4 = ~60s)
	WdProbeURL    string        // kubelet :10248 healthz — body must be "ok"
	// WdReprobeGap is the sleep between the remediate Gate-0
	// re-probes — the shell's "probe twice 3s apart" self-correct
	// window before any gate runs.
	WdReprobeGap time.Duration
	// APIFallbackURL is the G4 last-resort /livez target when no
	// API backends are configured (worker-local api-local-lb :7443).
	APIFallbackURL string
	SyncloopURL    string // kubelet :10250 /healthz/syncloop (PLEG)
	// TokenPath is the bearer-token file attached to kubelet's
	// secure-port probes — kubelet denies anonymous /healthz access,
	// so the syncloop probe authenticates with the pod SA token
	// (requires get on nonResourceURL /healthz/syncloop). Empty or
	// unreadable → the probe runs unauthenticated and 401/403
	// answers mark the check inconclusive, not down.
	TokenPath string
}

// TeardownConfig groups the pod-teardown knobs (36-pod-teardown.sh).
type TeardownConfig struct {
	StuckDeleteAge time.Duration // Terminating age → force-delete candidate
	StuckWedgeAge  time.Duration // Terminating age + task dir → wedge latch
	MaxForceDelete int           // force-delete cap per cycle
}

// CtrConfig groups the containerd knobs: the A4 socket hang probe,
// the 31-ctr-tasks per-cycle cleanup caps, the A3 ingest GC, the W9
// content prune budget and the KR3 meta.db journal probe.
type CtrConfig struct {
	Socket             string        // containerd grpc unix socket under /host/run
	IngestDir          string        // containerd content ingest dir (39)
	IngestMaxAge       time.Duration // ingest dir mtime older than → stale (3h)
	IngestScanInterval time.Duration // periodic rescan even under disk WM (6h)
	MaxTaskClean       int           // wedged ctr task dir cap per cycle (31)
	MaxShimKill        int           // orphan shim kill cap per cycle (31)
	// MetaJournalFn is the KR3 journal probe — `journalctl
	// -u k0sworker -u containerd --since "3 minutes ago"`. nil →
	// Systemd.ExecCombined default; a nil Systemd leaves the journal
	// half of the check inconclusive (the orphan-shim half still runs).
	MetaJournalFn func(ctx context.Context) (string, error)
}

// CiliumConfig groups the cilium knobs: the 32 agent healthz/socket,
// the 35/38 unix-socket consumers, the B1 envoy probes, the B4/W5.6
// MTU + WireGuard iface knobs and the W8-NM3 BPF map latch ratio.
type CiliumConfig struct {
	HealthzURL      string  // cilium-agent :9879 probe (32)
	Socket          string  // cilium agent unix socket (35)
	EnvoyReadyURL   string  // cilium-envoy admin :9964/ready
	EnvoyAdminURL   string  // envoy :9901 /stats?filter=update_rejected
	Iface           string  // cilium host iface (cilium_net)
	WG0Iface        string  // cilium WG tunnel iface (cilium_wg0)
	RuntimeConfig   string  // agent-runtime-config.json MTU fallback
	BPFMapHighRatio float64 // critical-map fill ratio → latch (0.90)
}

// DiskConfig groups the disk knobs: the /var/lib/k0s watermarks that
// trigger the ingest GC, the W6.3 disk-bloat runaway detector, the
// /var/log/pods walk (BUG-H8) and the W10-ST2 orphan-hostPath roots.
type DiskConfig struct {
	K0sDataDir    string  // /var/lib/k0s — disk-high ingest-GC trigger
	HighWatermark float64 // /var/lib/k0s used ratio triggering GC
	// W6.3 disk-bloat runaway detector: above BloatWatermark
	// the bounded emptyDir/snapshot walk runs (gated by
	// BloatScanInterval — the walk costs IO on the disk that is
	// already full); above BloatCriticalWatermark a
	// non-system pod holding more than BloatPodThresholdBytes
	// may be evicted through the API (last-disk-bloat-evict budget).
	BloatWatermark         float64
	BloatCriticalWatermark float64
	BloatPodThresholdBytes int64
	BloatScanInterval      time.Duration
	PodLogsDir             string // /var/log/pods walk root (BUG-H8)
	// OrphanHostPathDirs are the host-side local-provisioner roots
	// ST2 scans for pvc-* dirs whose PV is gone.
	OrphanHostPathDirs []string
}

// NetConfig groups the network knobs: the dns-resolv drift baseline,
// the /sys/class/net + overlay-iface MTU reads (B4), the W9 orphan
// cni-* netns reaper root and the W7-H3 node-local-dns datapath probe.
type NetConfig struct {
	HostResolvConf    string // host resolv.conf (dns drift baseline)
	SysClassNet       string // /sys/class/net — MTU reads (B4)
	NebulaIface       string // overlay iface MTU baseline (neb1 = 1300)
	NetnsDir          string // host /run/netns — orphan cni-* netns files
	LocalDNSProbeAddr string // node-local-dns :53 probe target (169.254.20.10:53)
	LocalDNSProbeName string // query name the DNS probe resolves
}

// PressureConfig groups the leak/pressure guard knobs: the W7-H1
// D-state storm + A2 zombie storm thresholds and the W2 PSI
// memory-thrash guard — latch when /proc/pressure/memory `full
// avg60` exceeds PSIFullAvg60 (percent) AND MemAvailable/MemTotal
// drops under MemFreeMinRatio for ConsecNeeded cycles.
type PressureConfig struct {
	DStateStormThreshold int     // total D-state procs → storm latch (5)
	ZombieStormThreshold int     // defunct children of one parent → storm
	PSIFullAvg60         float64 // PSI memory full avg60 percent (25)
	MemFreeMinRatio      float64 // free-mem ratio floor (0.08)
}

// CalicoConfig groups the W7-H7 calico-hygiene knobs — the felix
// readiness probe and the orphan cali* veth leak headroom.
type CalicoConfig struct {
	FelixReadyURL       string // calico-node felix :9099/readiness probe
	OrphanVethThreshold int    // cali* ifaces above the pod count → leak (50)
}

// JournalConfig groups the journald blindness-detector inputs shared
// with controllerhygiene via EnvDeps.
type JournalConfig struct {
	// Dirs are the host journal storage roots — the
	// journal-unreadable latch may only fire while at least one
	// exists (a host with no journald at all fails every read by
	// configuration, not by fault).
	Dirs []string
	// UnreadableNeeded is the consecutive-failed-read budget
	// before state-journal-unreadable latches; <=0 → 5.
	UnreadableNeeded int
}

// HostConfig groups the W10 KR1/ST2 host-side markers: the
// hostmetrics kmsg scanner's files this check consumes (defaults
// derive from WatchdogStateDir so both subsystems agree on the file
// contract without wiring) and the SystemOOMVictim event sink.
type HostConfig struct {
	OOMVictimFile      string // "<epoch> <comm>" latest host-level victim
	OOMCountFile       string // cumulative host-level OOM kills
	ConntrackDropsFile string // cumulative nf_conntrack table-full records
	// EventNamespace receives the SystemOOMVictim node event.
	EventNamespace string
}

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

// Seams groups the unexported test-seam funcs. Every one has a
// production default filled by applyDefaults; tests re-stub them on
// the live Hygiene (h.cfg.Seams.<name>) after New.
type Seams struct {
	// killFn delivers signals — seam for tests (SIGKILL on pause /
	// proxy-agent/shim/cilium pids, and signal-0 liveness probes).
	killFn func(pid int, sig syscall.Signal) error
	// nowFn supplies the current time — seam for tests.
	nowFn func() time.Time
	// probeHTTP does one GET and returns nil only on a 2xx response
	// (BUG-H7 — a 500/503 means the probed service is wedged, not
	// "the listener is alive"). Seam.
	probeHTTP func(ctx context.Context, url string, timeout time.Duration) error
	// unixGet GETs path over a unix socket and returns the body —
	// the cilium-dbg endpoint list replacement (35). Seam.
	unixGet func(ctx context.Context, socket, path string) ([]byte, error)
	// ctrRmImage removes one image from the k8s.io containerd
	// namespace — the corrupted-layer remedy (37), `k0s ctr
	// --namespace k8s.io images rm --sync <image>` via the systemd
	// exec wrapper. nil → Systemd.Exec default. Seam.
	ctrRmImage func(ctx context.Context, image string) error
	// journalFn returns the k0sworker journal window — the runner's
	// shared -10min snapshot (05/06). nil → Systemd.Journal.
	journalFn func(ctx context.Context) (string, error)
	// journalAnyFn is the A5 second probe — `journalctl -n 1
	// --no-pager` with NO unit filter. An empty k0sworker window is
	// only corruption evidence when journald ITSELF has nothing (or
	// only corrupt warnings) to say — a quiet unit on a healthy
	// journald must not trigger the rotate+vacuum remedy. nil →
	// Systemd.ExecCombined (stderr folded in — journald's own
	// diagnostics, e.g. "File ... is corrupt", never reach stdout).
	journalAnyFn func(ctx context.Context) (string, error)
	// probeBodyOK does one GET and reports whether the trimmed body is
	// exactly "ok" — the :10248 healthz contract (curl -s body compare
	// parity: a wedged kubelet can still answer HTTP with a non-ok
	// body, so any-HTTP-code-alive is not enough here). Seam.
	probeBodyOK func(ctx context.Context, url string, timeout time.Duration) bool
	// probeHTTPStatus does one GET and returns the status code — the
	// probeHTTP variant for endpoints where the CODE is the verdict
	// (syncloop 500 vs healthz 200, envoy /ready 503) or where ANY
	// answer proves liveness (kubelet :10250 /healthz, api /livez —
	// a 401/403 is an auth denial, not a dead listener). bearer != ""
	// attaches an Authorization header (kubelet :10250 requires
	// auth). Seam.
	probeHTTPStatus func(ctx context.Context, url, bearer string, timeout time.Duration) (int, error)
	// probeUnixSock connects to a unix socket under a deadline — the
	// containerd-socket hang probe (A4). Seam.
	probeUnixSock func(ctx context.Context, socket string, timeout time.Duration) error
	// statfsFn reads fs usage for the ingest-GC disk trigger (A3).
	// Seam for tests (default unix.Statfs).
	statfsFn func(string, *unix.Statfs_t) error
	// ctrRmIngest removes one stale ingest ref — `k0s ctr -n k8s.io
	// content ingest rm <ref>` via the systemd exec wrapper (A3).
	// nil → Systemd.Exec default. Seam.
	ctrRmIngest func(ctx context.Context, ref string) error
	// ctrPruneContent runs the store-wide content GC — `k0s ctr -n
	// k8s.io content prune` via the systemd exec wrapper (W9). It
	// only fires while /var/lib/k0s sits above the high watermark,
	// on the last-content-gc 6h budget. nil → Systemd.Exec
	// default. Seam.
	ctrPruneContent func(ctx context.Context) error
	// wgAllowedIPsFn returns how many cilium_wg0 peers carry a real
	// allowed-ips set — `wg show cilium_wg0 allowed-ips` parsed
	// (peers at "(none)" are wiped). nil → Systemd.Exec default.
	// Seam for the W5.6 check.
	wgAllowedIPsFn func(ctx context.Context) (int, error)
	// ciliumEncryptPeersFn returns the expected WG peer count —
	// `cilium-dbg encrypt status` parsed. An error or a count <=0
	// makes the caller fall back to ReadyNodes-1. nil →
	// Systemd.Exec default. Seam.
	ciliumEncryptPeersFn func(ctx context.Context) (int, error)
	// httpGetBody GETs a plain-HTTP endpoint and returns the body —
	// the envoy admin stats page (W7-H3 xDS NACK guard). Seam.
	httpGetBody func(ctx context.Context, url string, timeout time.Duration) ([]byte, error)
	// dnsProbe sends one UDP DNS query for a fixed cluster name to
	// addr and reports whether a well-formed answer returns before
	// the deadline — the node-local-dns :53 datapath probe
	// (W7-H3). Seam.
	dnsProbe func(addr, name string, timeout time.Duration) bool
	// reniceFn drops one pid to the lowest CPU scheduling priority
	// (renice +19) — the io-pressure throttler's CPU half. Default
	// syscall.Setpriority; tests record instead of renicing.
	reniceFn func(pid int) error
	// ioniceIdleFn puts one pid in the idle I/O scheduling class
	// (ionice -c 3) — the io-pressure throttler's I/O half. Default
	// the ioprio_set syscall (ionice_other.go reports unsupported
	// off-Linux). Seam.
	ioniceIdleFn func(pid int) error
	// podLogFn returns a tail of one pod's current log — the
	// clock-jump healer's konnectivity evidence read. Default the
	// kube-client GetLogs call; tests stub with canned output.
	podLogFn func(ctx context.Context, ns, name string, tailLines int64) (string, error)
}

// applyDefaults fills every unset knob — the per-group methods below
// own their own fields exactly like the old flat pass did.
func (c *Config) applyDefaults() {
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
		c.Interval = defaultInterval
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
	if c.CtrTaskRoot == "" {
		c.CtrTaskRoot = defaultCtrTaskRoot
	}
	if c.SandboxCtlRoot == "" {
		c.SandboxCtlRoot = defaultSandboxCtlRoot
	}
	if c.K0sWorkerUnitFile == "" {
		c.K0sWorkerUnitFile = defaultK0sWorkerUnitFile
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

func (k *KubeletConfig) applyDefaults() {
	if k.PodsDir == "" {
		k.PodsDir = defaultKubeletPodsDir
	}
	if k.HealthzURL == "" {
		k.HealthzURL = defaultKubeletHealthzURL
	}
	if k.WatchMinAge <= 0 {
		k.WatchMinAge = defaultKubeletWatchMinAge
	}
	if k.WdInterval <= 0 {
		k.WdInterval = defaultKubeletWdInterval
	}
	if k.WdMaxFail <= 0 {
		k.WdMaxFail = defaultKubeletWdMaxFail
	}
	if k.WdProbeURL == "" {
		k.WdProbeURL = defaultKubeletWdProbeURL
	}
	if k.WdReprobeGap <= 0 {
		k.WdReprobeGap = defaultKubeletWdReprobeGap
	}
	if k.APIFallbackURL == "" {
		k.APIFallbackURL = defaultAPIFallbackURL
	}
	if k.SyncloopURL == "" {
		k.SyncloopURL = defaultKubeletSyncloopURL
	}
	if k.TokenPath == "" {
		k.TokenPath = defaultKubeletTokenPath
	}
}

func (t *TeardownConfig) applyDefaults() {
	if t.StuckDeleteAge <= 0 {
		t.StuckDeleteAge = defaultStuckDeleteAge
	}
	if t.StuckWedgeAge <= 0 {
		t.StuckWedgeAge = defaultStuckWedgeAge
	}
	if t.MaxForceDelete <= 0 {
		t.MaxForceDelete = defaultMaxForceDelete
	}
}

func (g *CtrConfig) applyDefaults() {
	if g.Socket == "" {
		g.Socket = defaultContainerdSocket
	}
	if g.IngestDir == "" {
		g.IngestDir = defaultCtrIngestDir
	}
	if g.IngestMaxAge <= 0 {
		g.IngestMaxAge = ctrIngestMaxAge
	}
	if g.IngestScanInterval <= 0 {
		g.IngestScanInterval = ctrIngestScanInterval
	}
	if g.MaxTaskClean <= 0 {
		g.MaxTaskClean = defaultMaxCtrTaskClean
	}
	if g.MaxShimKill <= 0 {
		g.MaxShimKill = defaultMaxShimKill
	}
}

func (cl *CiliumConfig) applyDefaults() {
	if cl.HealthzURL == "" {
		cl.HealthzURL = defaultCiliumHealthzURL
	}
	if cl.Socket == "" {
		cl.Socket = defaultCiliumSocket
	}
	if cl.EnvoyReadyURL == "" {
		cl.EnvoyReadyURL = defaultCiliumEnvoyReadyURL
	}
	if cl.EnvoyAdminURL == "" {
		cl.EnvoyAdminURL = defaultCiliumEnvoyAdminURL
	}
	if cl.Iface == "" {
		cl.Iface = defaultCiliumIface
	}
	if cl.WG0Iface == "" {
		cl.WG0Iface = defaultCiliumWG0Iface
	}
	if cl.RuntimeConfig == "" {
		cl.RuntimeConfig = defaultCiliumRuntimeConfig
	}
	if cl.BPFMapHighRatio <= 0 {
		cl.BPFMapHighRatio = defaultBPFMapHighRatio
	}
}

func (d *DiskConfig) applyDefaults() {
	if d.K0sDataDir == "" {
		d.K0sDataDir = defaultK0sDataDir
	}
	if d.HighWatermark <= 0 {
		d.HighWatermark = k0sDiskHighWatermark
	}
	if d.BloatWatermark <= 0 {
		d.BloatWatermark = k0sDiskBloatWatermark
	}
	if d.BloatCriticalWatermark <= 0 {
		d.BloatCriticalWatermark = k0sDiskBloatCriticalWatermark
	}
	if d.BloatPodThresholdBytes <= 0 {
		d.BloatPodThresholdBytes = diskBloatPodThresholdBytes
	}
	if d.BloatScanInterval <= 0 {
		d.BloatScanInterval = diskBloatScanInterval
	}
	if d.PodLogsDir == "" {
		d.PodLogsDir = defaultPodLogsDir
	}
	if len(d.OrphanHostPathDirs) == 0 {
		// Paths are used RAW (no HostRoot prefix): the DaemonSet
		// mounts host /var/openebs/local at the SAME container path
		// (sweeper contract). /opt/local-path-provisioner has no
		// container mount — ReadDir just misses there — but is the
		// real host path in standalone mode. Extra provisioner
		// roots need a matching DS hostPath mount to be scanned.
		d.OrphanHostPathDirs = []string{
			"/var/openebs/local",
			"/opt/local-path-provisioner",
		}
	}
}

func (n *NetConfig) applyDefaults() {
	if n.HostResolvConf == "" {
		n.HostResolvConf = defaultHostResolvConf
	}
	if n.SysClassNet == "" {
		n.SysClassNet = defaultSysClassNet
	}
	if n.NebulaIface == "" {
		n.NebulaIface = defaultNebulaIface
	}
	if n.NetnsDir == "" {
		n.NetnsDir = defaultNetnsDir
	}
	if n.LocalDNSProbeAddr == "" {
		n.LocalDNSProbeAddr = defaultLocalDNSProbeAddr
	}
	if n.LocalDNSProbeName == "" {
		n.LocalDNSProbeName = defaultLocalDNSProbeName
	}
}

func (p *PressureConfig) applyDefaults() {
	if p.DStateStormThreshold <= 0 {
		p.DStateStormThreshold = defaultDStateStormThreshold
	}
	if p.ZombieStormThreshold <= 0 {
		p.ZombieStormThreshold = zombieStormThreshold
	}
	if p.PSIFullAvg60 <= 0 {
		p.PSIFullAvg60 = defaultPSIFullAvg60
	}
	if p.MemFreeMinRatio <= 0 {
		p.MemFreeMinRatio = defaultMemFreeMinRatio
	}
}

func (cl *CalicoConfig) applyDefaults() {
	if cl.FelixReadyURL == "" {
		cl.FelixReadyURL = defaultCalicoFelixReadyURL
	}
	if cl.OrphanVethThreshold <= 0 {
		cl.OrphanVethThreshold = defaultCalicoOrphanVethThresh
	}
}

func (j *JournalConfig) applyDefaults() {
	if len(j.Dirs) == 0 {
		// /host mount convention like the other defaults; standalone
		// wiring passes the unprefixed host paths.
		j.Dirs = []string{
			"/host/var/log/journal", "/host/run/log/journal"}
	}
	if j.UnreadableNeeded <= 0 {
		j.UnreadableNeeded = defaultJournalUnreadableNeeded
	}
}

// applyDefaults fills the Wave-10 (KR1/KR3/ST2) defaults —
// WatchdogStateDir is already resolved by applyWiringDefaults, so
// the marker-file paths derive from the same dir hostmetrics writes
// into.
func (hc *HostConfig) applyDefaults(stateDir string) {
	if hc.OOMVictimFile == "" {
		hc.OOMVictimFile = filepath.Join(stateDir,
			"kmsg-host-oom-victim")
	}
	if hc.OOMCountFile == "" {
		hc.OOMCountFile = filepath.Join(stateDir,
			"kmsg-host-oom-count")
	}
	if hc.ConntrackDropsFile == "" {
		hc.ConntrackDropsFile = filepath.Join(stateDir,
			"kmsg-conntrack-drops")
	}
	if hc.EventNamespace == "" {
		hc.EventNamespace = "default"
	}
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

// applyDefaults fills the production implementations of every test
// seam. cfg carries the already-defaulted knob groups — the systemd
// exec defaults capture c.Systemd, and the cilium encrypt-peers
// default goes through the unixGet seam + Cilium.Socket.
func (s *Seams) applyDefaults(c *Config) {
	if s.httpGetBody == nil {
		// Plain HTTP (no TLS) — the envoy admin stats page lives on
		// loopback :9901. A non-200 is an error: the reject-delta
		// verdict is unreadable, not "zero".
		s.httpGetBody = probee.HTTPBody
	}
	if s.dnsProbe == nil {
		s.dnsProbe = probee.DNSQuery
	}
	if s.killFn == nil {
		s.killFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	if s.nowFn == nil {
		s.nowFn = time.Now
	}
	if s.probeHTTP == nil {
		// BUG-H7: an HTTP response no longer counts as alive on its
		// own — a wedged cilium-agent :9879/healthz answering 500/503
		// must read as DOWN. Only a 2xx is a pass; insecure TLS stays
		// (kubelet cert SANs don't cover 127.0.0.1, curl -ks parity).
		s.probeHTTP = probee.HTTPGet
	}
	if s.unixGet == nil {
		s.unixGet = probee.UnixGet
	}
	if s.ctrRmImage == nil {
		sd := c.Systemd
		s.ctrRmImage = func(ctx context.Context, image string) error {
			if sd == nil {
				return errors.New("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "--namespace", "k8s.io", "images", "rm", "--sync", image)
			return err
		}
	}
	if s.journalFn == nil {
		sd := c.Systemd
		s.journalFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				// Fail, not empty: a nil client fed the unreadable
				// tracker a fake "journald-wide empty reply" verdict.
				return "", errors.New("no systemd client wired")
			}
			return sd.Journal(ctx, "k0sworker.service", journalWindow)
		}
	}
	if s.journalAnyFn == nil {
		sd := c.Systemd
		s.journalAnyFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				return "", errors.New("no systemd client wired")
			}
			return sd.ExecCombined(ctx,
				"journalctl", "-n", "1", "--no-pager")
		}
	}
	if s.probeBodyOK == nil {
		// kubelet :10248 contract (curl -s parity): the healthz port is
		// unauthenticated plaintext and the body must be exactly "ok" —
		// a wedged kubelet can still answer HTTP with a non-ok body.
		s.probeBodyOK = probee.BodyOK
	}
	if s.probeHTTPStatus == nil {
		// Same insecure-TLS transport as probeHTTP — the status code
		// is the verdict (syncloop 500, envoy /ready 503).
		s.probeHTTPStatus = probee.HTTPStatus
	}
	if s.probeUnixSock == nil {
		// A successful dial IS the verdict — a close error (e.g. the
		// peer reset first) must not downgrade it.
		s.probeUnixSock = probee.UnixDial
	}
	if s.statfsFn == nil {
		s.statfsFn = unix.Statfs
	}
	if s.ctrRmIngest == nil {
		sd := c.Systemd
		s.ctrRmIngest = func(ctx context.Context, ref string) error {
			if sd == nil {
				return errors.New("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "-n", "k8s.io", "content", "ingest", "rm", ref)
			return err
		}
	}
	if s.ctrPruneContent == nil {
		sd := c.Systemd
		s.ctrPruneContent = func(ctx context.Context) error {
			if sd == nil {
				return errors.New("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "-n", "k8s.io", "content", "prune")
			return err
		}
	}
	if s.wgAllowedIPsFn == nil {
		sd := c.Systemd
		s.wgAllowedIPsFn = func(ctx context.Context) (int, error) {
			if sd == nil {
				return 0, errors.New("no systemd client wired")
			}
			out, err := sd.Exec(ctx, "wg", "show", "cilium_wg0", "allowed-ips")
			if err != nil {
				return 0, err
			}
			return parseWGAllowedIPs(out), nil
		}
	}
	if s.reniceFn == nil {
		s.reniceFn = func(pid int) error {
			return syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19)
		}
	}
	if s.ioniceIdleFn == nil {
		s.ioniceIdleFn = ioniceIdle // build-tag split: linux ioprio_set
	}
	if s.podLogFn == nil {
		s.podLogFn = func(ctx context.Context, ns, name string, tail int64) (string, error) {
			if c.Client == nil {
				return "", errors.New("no kube client wired")
			}
			res := c.Client.CoreV1().Pods(ns).GetLogs(name,
				&corev1.PodLogOptions{TailLines: &tail}).Do(ctx)
			b, err := res.Raw()
			return string(b), err
		}
	}
	if s.ciliumEncryptPeersFn == nil {
		s.ciliumEncryptPeersFn = func(ctx context.Context) (int, error) {
			// The agent's own API beats `cilium-dbg`: the binary only
			// lives INSIDE the cilium-agent container — an sd.Exec on
			// the host always fails and silently degrades every cycle
			// to the ReadyNodes-1 fallback. /v1/healthz's
			// cluster.nodes[] lists exactly the remote cilium members
			// this node should peer with (virtual/liqo nodes run no
			// agent, so they never appear).
			body, err := s.unixGet(ctx, c.Cilium.Socket, "/v1/healthz")
			if err != nil {
				return 0, err
			}
			n, ok := parseCiliumHealthNodes(body)
			if !ok {
				return 0, errors.New("no cluster.nodes in cilium healthz")
			}
			return n, nil
		}
	}
}

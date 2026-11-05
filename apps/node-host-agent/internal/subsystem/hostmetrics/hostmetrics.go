// Package hostmetrics exposes node-local filesystem state as
// Prometheus metrics, collected at scrape time.
//
// Sources (all paths configurable, host-mounted into the agent pod):
//
//   - Watchdog state latches: node-watchdog writes
//     /var/lib/node-watchdog/state-<name> while a failure signal is
//     active and deletes it on recovery (state_enter/state_exit in
//     watchdog/lib.sh). Each present latch exports
//     node_host_agent_watchdog_state{node,state}=1. States seen by an
//     earlier scrape keep exporting 0 after the latch clears, matching
//     the watchdog's own emit-0 semantics so alerts auto-resolve.
//   - Nebula interface: /sys/class/net/<neb1>/operstate →
//     node_host_agent_nebula_interface_up.
//   - Overlay route: any route via the nebula interface in the host
//     route table (/proc/1/net/route) →
//     node_host_agent_nebula_route_present.
//   - k0s config drift: mirrors the node-config-agent drift check —
//     on nodes where k0scontroller.service exists (control plane),
//     node_k0s_config_drift{reason,key}=1 per finding: a removed flag
//     still present, an unexpected/missing KCM extraArgs key vs
//     ExpectedKCMArgs, or an unreadable k0s.yaml.
//   - Nebula cert expiry: replaces the shell's `nebula-cert print`
//     fork — parses the PEM-wrapped protobuf NebulaCertificate
//     directly and exports node_host_agent_nebula_cert_days_left plus
//     the watchdog-state-style series
//     node_host_agent_watchdog_state{state="nebula-cert-expiring"}.
//   - PSI overload: /proc/pressure/cpu some avg60 →
//     node_watchdog_psi_cpu_some_avg60, and drives the
//     state-node-overloaded latch with hysteresis (>=40% enter,
//     <25% exit) — the runner's node-overloaded signal every restart
//     gate reads.
//   - cpu-delivered probe (lib.sh measure_cpu_delivered): a fixed
//     ~0.3 cpu-s busy loop on a locked thread (RUSAGE_THREAD) vs wall
//     clock → node_cpu_delivered_ratio +
//     node_cpu_delivered_probe_wall_seconds — the ground-truth
//     "how much of 1 vCPU did the hypervisor actually give" steal
//     canary guest accounting can't see.
//   - fail2ban banned counts: fail2ban-banned file ("jail=N ...")
//     written by the nethealth check → node_fail2ban_banned_ips{jail}.
//   - egress relay state: per OVERLAY_EGRESS_RELAYS target,
//     node_overlay_egress_relay_active{target} = 1 while
//     egress-state-<ip> is "relay" (emitted for every configured
//     target — absent vs 0 must stay distinguishable).
//   - clock sync (H1): adjtimex(2) →
//     node_host_agent_clock_unsynchronized (STA_UNSYNC flag) +
//     node_host_agent_clock_estimated_error_seconds (Esterror,
//     exported µs→s) — a silently drifting clock breaks cert
//     validation, etcd and log ordering long before anyone notices.
//   - conntrack table (H2): nf_conntrack_{count,max} →
//     node_host_agent_conntrack_{entries,limit,used_ratio} — a full
//     table drops NEW flows silently (DNS timeouts with zero
//     packet-loss evidence).
//   - filesystem inodes + hung-mount probe (H3/H7): statfs(2) over
//     FilesystemTargets → node_host_agent_filesystem_inodes_* and
//     node_host_agent_filesystem_probe_stalled — inode exhaustion
//     fails every create while df still shows free GB, and a hung
//     mount wedges any process that stats it (the probe runs with a
//     deadline on a spare goroutine — a stuck syscall can't be
//     cancelled, so at most one goroutine per mount is allowed to
//     pile up).
//   - FD + socket pressure (H6): /proc/sys/fs/file-nr +
//     /proc/1/net/sockstat → node_host_agent_filefd_* +
//     node_host_agent_sockstat_* — fd exhaustion and orphan/TIME_WAIT
//     pileups present as accept/connect flakes.
//   - On-disk PKI cert expiry (2.4): *.crt/*.pem under the k0s/kine
//     PKI dirs → node_host_agent_pki_cert_days_left{path} — the
//     apiserver/etcd/kubelet-client certs expire silently; a lapsed
//     cert surfaces as a control-plane outage weeks after the
//     warning should have fired.
//   - inotify pressure (A1/H8): /proc/[0-9]*/fdinfo sweep (cached
//     60s — a full walk per scrape is too heavy) vs
//     /proc/sys/fs/inotify/max_user_{instances,watches} →
//     node_host_agent_inotify_{instances,watches}_used_ratio. An
//     inotify-instance leak presents as `too many open files` while
//     fs.file-nr is nearly empty; over 80% the top 3 holder PIDs are
//     logged once per episode.
//   - zombie + cgroup pids pressure (A2): state Z entries under
//     ProcRoot → node_host_agent_processes_zombie_count, and
//     pids.current/pids.max of the k0s/kubepods slices →
//     node_host_agent_cgroup_pids_used_ratio{slice} — pids.max
//     exhaustion is `fork: resource temporarily unavailable` while
//     CPU looks idle.
//   - MTU drift (B4): cilium_net MTU (sysfs, falling back to
//     agent-runtime-config.json) vs the nebula overlay MTU →
//     node_host_agent_mtu_drift = 1 when the pod datapath MTU
//     exceeds the overlay's — packets then die silently on
//     FRAG_NEEDED (1300-byte neb1 vs 1500 pods).
//
// Emission policy (documented choice): watchdog_state emits for every
// latch ever observed (1 while latched, 0 after clear). The
// nebula_* metrics emit only when the interface exists — on non-nebula
// nodes they are absent rather than 0, so "interface missing" is
// distinguishable from "interface down". The nebula cert days gauge
// emits only when the cert parses. node_k0s_config_drift emits
// only where the k0s controller unit exists — workers carry no series.
// The clock/conntrack/filefd/sockstat gauges emit only when their
// source reads or parses; filesystem_probe_stalled emits for EVERY
// configured mount — a 0 means the probe answered in time, so
// "reachable and boring" stays distinguishable from "never probed".
package hostmetrics

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"
)

// Defaults — paths are the host mounts the DaemonSet provides.
// Domain-specific defaults live with their collect_*.go files; the
// ones here are shared across collect domains (or used by the
// latch files).
const (
	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	defaultSysClassNet      = "/sys/class/net"
	defaultNebulaIface      = "neb1"
	// defaultProcRoot is the host /proc — plain /proc under
	// hostPID:true (the pod's /proc is the host's); the inotify
	// fdinfo and zombie scans walk it.
	defaultProcRoot = "/proc"
	// W8-KR3: /proc/key-users — kernel keyring quota pressure.
	defaultKeyUsersFile = "/proc/key-users"
	// kernelKeysPressureRatio arms state-kernel-keys-pressure.
	kernelKeysPressureRatio = 0.80
	// defaultLatchInterval is the Run() ticker's cadence (BUG-H5) —
	// the watchdog-state file contract must hold even when nothing
	// scrapes this collector (DaemonSet mode).
	defaultLatchInterval = 30 * time.Second
)

// Config carries the host paths — all test-injectable.
type Config struct {
	NodeName         string
	WatchdogStateDir string
	SysClassNet      string
	NebulaIface      string
	RouteFile        string
	K0sConfigFile    string
	K0sUnitFile      string
	NebulaCertFile   string
	// PSIFile is /proc/pressure/cpu — drives the overload gauge +
	// state-node-overloaded latch.
	PSIFile string
	// PSIMemoryFile/PSIIOFile are /proc/pressure/{memory,io} — the
	// W5.7 some/full avg60 gauges (memory-reclaim and block-IO stall
	// evidence the cpu PSI can't see). Missing files (PSI off in the
	// kernel) simply emit no series.
	PSIMemoryFile string
	PSIIOFile     string
	// VMStatFile is /proc/vmstat — pswpin/pswpout swap-thrash
	// counters (W5.7).
	VMStatFile string
	// EgressRelays is OVERLAY_EGRESS_RELAYS (wired from watchdogconf
	// by main) — each target gets a relay-active gauge.
	EgressRelays []string
	// CPUDeliveredInterval bounds how often the busy-loop probe runs
	// (shell: once per 2m run).
	CPUDeliveredInterval time.Duration
	RemovedFlags         []string
	ExpectedKCMArgs      []string
	// ConntrackCountFile/ConntrackMaxFile are
	// /proc/sys/net/netfilter/nf_conntrack_{count,max} — the H2
	// conntrack-table-pressure gauges.
	ConntrackCountFile string
	ConntrackMaxFile   string
	// FileNRFile is /proc/sys/fs/file-nr ("allocated unused max")
	// and SockstatFile /proc/1/net/sockstat — the H6 fd/socket
	// pressure gauges.
	FileNRFile   string
	SockstatFile string
	// FilesystemTargets are the mounts statfs'd per scrape for the
	// inode gauges (H3) and the hung-mount probe (H7).
	FilesystemTargets []string
	// HostRoot prefixes host-side paths that live under the
	// DaemonSet's host-fs mount (PKI dirs, the cilium runtime
	// config) — "/host" in the pod, "/" standalone. Empty
	// auto-detects: "/host" when that dir exists, else "/".
	HostRoot string
	// PKICertPaths are the cert sources (2.4): each entry is either
	// a directory scanned one level deep for *.crt/*.pem files or a
	// single cert file — default the k0s/kine PKI paths under
	// HostRoot. The {path} label carries the HostRoot-relative path
	// so the series reads identically on pods and standalone hosts.
	PKICertPaths []string
	// ProcRoot is the host /proc — the inotify fdinfo and zombie
	// scans walk it (hostPID:true makes the pod's /proc the host's).
	ProcRoot string
	// InotifyScanInterval caches the fdinfo sweep — one full
	// /proc/*/fdinfo walk is too expensive to run per scrape.
	InotifyScanInterval time.Duration
	// InotifyMaxInstancesFile/InotifyMaxWatchesFile are the
	// /proc/sys/fs/inotify/max_user_* limits the used ratios divide
	// by.
	InotifyMaxInstancesFile string
	InotifyMaxWatchesFile   string
	// CgroupRoot is the cgroup-v2 mount; CgroupPidsSlices are the
	// cgroup-relative dirs whose pids.current/pids.max feed
	// node_host_agent_cgroup_pids_used_ratio{slice}.
	CgroupRoot       string
	CgroupPidsSlices []string
	// CiliumIface is the cilium host-side interface for the B4 MTU
	// drift check vs NebulaIface; CiliumWG0Iface is the WireGuard
	// datapath iface checked against NebulaIface minus the ~60B
	// encapsulation overhead (W9 double-encap guard);
	// CiliumRuntimeConfig is the fallback MTU source
	// (agent-runtime-config.json under HostRoot).
	CiliumIface         string
	CiliumWG0Iface      string
	CiliumRuntimeConfig string
	// ConntrackStatFile is /proc/net/stat/nf_conntrack — the
	// per-CPU conntrack counters (insert_failed/drop for W7-H5);
	// ARPTableFile is /proc/net/arp — the ARP neighbour-table fill
	// gauge.
	ConntrackStatFile string
	ARPTableFile      string
	// CgroupMemUnits are the system.slice unit names whose
	// memory.events feed the W7-H6 high/oom_kill counters.
	CgroupMemUnits []string
	// KeyUsersFile is /proc/key-users — the W8-KR3 kernel keyring
	// quota source (per-UID usage vs maxkeys).
	KeyUsersFile string
	// OpenEBSLocalDir is the localpv-provisioner hostPath root —
	// /var/openebs/local in both pod and standalone mode (the
	// DaemonSet mounts it at the same path, not under /host).
	// LocalPVScanInterval caches the per-PVC du walk: a full
	// filesystem walk per PVC per scrape is too heavy on a node
	// with hundreds of volumes (W9).
	OpenEBSLocalDir     string
	LocalPVScanInterval time.Duration
	// Standalone marks systemd (non-pod) mode — informational only;
	// the latch ticker runs regardless (BUG-H5).
	Standalone bool
	// LatchInterval is the Run() latch-maintenance cadence; <=0 →
	// 30s. Seamed so tests don't wait real seconds.
	LatchInterval time.Duration

	// nowFn supplies the current time — seam for tests.
	nowFn func() time.Time
	// cpuMeasure replaces the real RUSAGE_THREAD busy-loop for
	// tests: returns (ratio, wallSeconds, ok).
	cpuMeasure func() (ratio, wall float64, ok bool)
	// adjtimexFn reads kernel clock-sync state (H1) — seam for
	// tests (default unix.Adjtimex).
	adjtimexFn func(*unix.Timex) (int, error)
	// statfsFn probes one mount — seam for tests, including a fake
	// that hangs to exercise the stalled path (default unix.Statfs).
	statfsFn func(string, *unix.Statfs_t) error
	// fsProbeTimeout bounds one statfs probe before the mount is
	// reported stalled — seam so tests don't wait the full 2s.
	fsProbeTimeout time.Duration
}

func (c *Config) applyDefaults() {
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.SysClassNet == "" {
		c.SysClassNet = defaultSysClassNet
	}
	if c.NebulaIface == "" {
		c.NebulaIface = defaultNebulaIface
	}
	if c.RouteFile == "" {
		c.RouteFile = defaultRouteFile
	}
	if c.K0sConfigFile == "" {
		c.K0sConfigFile = defaultK0sConfigFile
	}
	if c.K0sUnitFile == "" {
		c.K0sUnitFile = defaultK0sUnitFile
	}
	if c.NebulaCertFile == "" {
		c.NebulaCertFile = defaultNebulaCertFile
	}
	if c.PSIFile == "" {
		c.PSIFile = defaultPSIFile
	}
	if c.PSIMemoryFile == "" {
		c.PSIMemoryFile = defaultPSIMemoryFile
	}
	if c.PSIIOFile == "" {
		c.PSIIOFile = defaultPSIIOFile
	}
	if c.VMStatFile == "" {
		c.VMStatFile = defaultVMStatFile
	}
	if c.CPUDeliveredInterval <= 0 {
		c.CPUDeliveredInterval = defaultCPUDeliveredIn
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	if len(c.RemovedFlags) == 0 {
		c.RemovedFlags = defaultRemovedFlags
	}
	if len(c.ExpectedKCMArgs) == 0 {
		c.ExpectedKCMArgs = defaultExpectedKCMArgs
	}
	if c.ConntrackCountFile == "" {
		c.ConntrackCountFile = defaultConntrackCountFile
	}
	if c.ConntrackMaxFile == "" {
		c.ConntrackMaxFile = defaultConntrackMaxFile
	}
	if c.FileNRFile == "" {
		c.FileNRFile = defaultFileNRFile
	}
	if c.SockstatFile == "" {
		c.SockstatFile = defaultSockstatFile
	}
	if len(c.FilesystemTargets) == 0 {
		c.FilesystemTargets = defaultFilesystemTargets
	}
	if c.adjtimexFn == nil {
		c.adjtimexFn = unix.Adjtimex
	}
	if c.statfsFn == nil {
		c.statfsFn = unix.Statfs
	}
	if c.fsProbeTimeout <= 0 {
		c.fsProbeTimeout = defaultFSProbeTimeout
	}
	if c.HostRoot == "" {
		// Auto-detect: "/host" when the DaemonSet mount is there,
		// "/" otherwise (standalone systemd binary on the host).
		if fi, err := os.Stat("/host"); err == nil && fi.IsDir() {
			c.HostRoot = "/host"
		} else {
			c.HostRoot = "/"
		}
	}
	if len(c.PKICertPaths) == 0 {
		c.PKICertPaths = make([]string, 0, len(defaultPKIHostPaths))
		for _, p := range defaultPKIHostPaths {
			c.PKICertPaths = append(c.PKICertPaths,
				filepath.Join(c.HostRoot, p))
		}
	}
	if c.ProcRoot == "" {
		c.ProcRoot = defaultProcRoot
	}
	if c.InotifyScanInterval <= 0 {
		c.InotifyScanInterval = defaultInotifyScanInterval
	}
	if c.InotifyMaxInstancesFile == "" {
		c.InotifyMaxInstancesFile = defaultInotifyMaxInstFile
	}
	if c.InotifyMaxWatchesFile == "" {
		c.InotifyMaxWatchesFile = defaultInotifyMaxWatchFile
	}
	if c.CgroupRoot == "" {
		c.CgroupRoot = defaultCgroupRoot
	}
	if len(c.CgroupPidsSlices) == 0 {
		c.CgroupPidsSlices = defaultCgroupPidsSlices
	}
	if c.CiliumIface == "" {
		c.CiliumIface = defaultCiliumIface
	}
	if c.CiliumWG0Iface == "" {
		c.CiliumWG0Iface = defaultCiliumWG0Iface
	}
	if c.CiliumRuntimeConfig == "" {
		c.CiliumRuntimeConfig = filepath.Join(c.HostRoot,
			"run/cilium/state/agent-runtime-config.json")
	}
	if c.ConntrackStatFile == "" {
		c.ConntrackStatFile = defaultConntrackStatFile
	}
	if c.ARPTableFile == "" {
		c.ARPTableFile = defaultARPTableFile
	}
	if len(c.CgroupMemUnits) == 0 {
		c.CgroupMemUnits = defaultCgroupMemUnits
	}
	if c.KeyUsersFile == "" {
		c.KeyUsersFile = defaultKeyUsersFile
	}
	if c.OpenEBSLocalDir == "" {
		c.OpenEBSLocalDir = defaultOpenEBSLocalDir
	}
	if c.LocalPVScanInterval <= 0 {
		c.LocalPVScanInterval = defaultLocalPVScanEvery
	}
	if c.LatchInterval <= 0 {
		c.LatchInterval = defaultLatchInterval
	}
}

// Collector implements prometheus.Collector — all reads happen at
// scrape time, so no goroutine or refresh interval is needed.
type Collector struct {
	cfg Config

	// state is the shared watchdog-state contract handle (hoststate):
	// the last-* rate budgets and the kmsg counter files go through it
	// so the on-disk format stays the lib.sh parity every subsystem
	// shares. Now is a closure over c.cfg.nowFn — tests re-stub the
	// clock after New() and the store must observe the new one.
	state *hoststate.Store

	// Hoisted out of the scrape path in New(): drift regexes are
	// compiled once and the expected-KCM set is built once — the
	// per-scrape work left in collectK0sDrift is a stat + map lookups.
	removedFlagRe map[string]*regexp.Regexp
	expectedKCM   map[string]bool

	mu sync.Mutex
	// seenStates tracks the emit-0 bookkeeping per dynamic latch:
	// zero time = the latch is active on disk (or the cert-owned
	// series is live); non-zero = the scrape that first saw it
	// cleared — the entry emits 0 until seenStateTTL then drops.
	seenStates map[string]time.Time

	// k0s.yaml cache, guarded by mu: the file changes on k0s upgrades
	// (rare), not per-scrape — a stat+mtime+size check gates the
	// re-read/re-parse. A failed stat serves no stale data.
	k0sLoaded bool
	k0sMtime  time.Time
	k0sSize   int64
	k0sData   []byte
	k0sParsed map[string]any
	k0sOK     bool

	descWatchdog    *prometheus.Desc
	descNebUp       *prometheus.Desc
	descNebRoute    *prometheus.Desc
	descNebCertDays *prometheus.Desc
	descK0sDrift    *prometheus.Desc
	descPSI         *prometheus.Desc
	descCPURatio    *prometheus.Desc
	descCPUWall     *prometheus.Desc
	descF2B         *prometheus.Desc
	descEgressRelay *prometheus.Desc

	// Gray-failure telemetry (H1 clock, H2 conntrack, H3 inodes,
	// H6 fd/sockets, H7 hung-mount probe).
	descClockUnsync    *prometheus.Desc
	descClockEstErr    *prometheus.Desc
	descCtEntries      *prometheus.Desc
	descCtLimit        *prometheus.Desc
	descCtRatio        *prometheus.Desc
	descFSInodesTotal  *prometheus.Desc
	descFSInodesFree   *prometheus.Desc
	descFSInodesRatio  *prometheus.Desc
	descFSProbeStalled *prometheus.Desc
	descFSReadonly     *prometheus.Desc
	descFileFDAlloc    *prometheus.Desc
	descFileFDMax      *prometheus.Desc
	descFileFDRatio    *prometheus.Desc
	descSockTCPInuse   *prometheus.Desc
	descSockTCPOrphan  *prometheus.Desc
	descSockTCPTW      *prometheus.Desc
	descSockUsed       *prometheus.Desc

	// Wave-2 additions: 2.4 PKI certs, A1 inotify, A2 zombie/cgroup
	// pids, B4 MTU drift.
	descPKIDays        *prometheus.Desc
	descInotifyInst    *prometheus.Desc
	descInotifyWatches *prometheus.Desc
	descZombies        *prometheus.Desc
	descCgroupPids     *prometheus.Desc
	descMTUDrift       *prometheus.Desc

	// W5.7 PSI memory/io avg60 gauges + vmstat swap-thrash counters.
	descPSIMemSome *prometheus.Desc
	descPSIMemFull *prometheus.Desc
	descPSIIOSome  *prometheus.Desc
	descPSIIOFull  *prometheus.Desc
	descPSWPIn     *prometheus.Desc
	descPSWPOut    *prometheus.Desc

	// W7 additions: H1 d-state processes, H2 cri-containerd scope
	// footprint, H5 conntrack insert_failed/drop + ARP entries,
	// H6 cgroup memory.events counters.
	descDState        *prometheus.Desc
	descSystemdScopes *prometheus.Desc
	descCtInsertFail  *prometheus.Desc
	descCtDrops       *prometheus.Desc
	descARPEntries    *prometheus.Desc
	descCgMemHigh     *prometheus.Desc
	descCgMemOOMKill  *prometheus.Desc

	// W8 additions: KR3 kernel keyring quota + TCP close_wait.
	descKernelKeys *prometheus.Desc
	descSockTCPCW  *prometheus.Desc

	// W9 additions: per-PVC LocalPV dir bytes.
	descLocalPVDirBytes *prometheus.Desc

	// Legacy node-watchdog aliases — the prom_emit textfile series
	// the fluxcd PrometheusRules still alert on
	// (node_watchdog_state{signal}, node_watchdog_egress_relay{target}).
	// Emitted alongside the node_host_agent_* names so the same
	// registry serves pods AND the standalone textfile writer keeps
	// the node-exporter contract on out-of-cluster hosts.
	descWatchdogLegacy    *prometheus.Desc
	descEgressRelayLegacy *prometheus.Desc

	// descMeta maps each desc to its fqName/help for textfile
	// rendering — a prometheus.Metric carries the Desc but the
	// fqName is only reachable through Desc.String(), so the writer
	// keeps its own table.
	descMeta map[*prometheus.Desc]descMeta

	// cpu-delivered probe bookkeeping (mu): the busy-loop runs in a
	// goroutine — a scrape triggers it and serves the last result;
	// a scrape must never block up to ~6s on steal measurement.
	cpuRunning bool
	cpuLast    time.Time
	cpuRatio   float64
	cpuWall    float64
	cpuOK      bool
	cpuSink    uint64 // busy-loop sink, mu-guarded

	// fsInflight (mu) holds the start time of each mount's in-kernel
	// statfs probe — a hung syscall can't be cancelled, so a scrape
	// that finds an in-flight probe reports stalled only once the
	// deadline has elapsed, WITHOUT spawning another (bounds stuck
	// goroutines at one per mount).
	fsInflight map[string]time.Time
	// fsStalledLogged (mu) edge-triggers the hung-mount Warn: the
	// stall logs once per mount per episode instead of once per
	// scrape for the whole outage.
	fsStalledLogged map[string]bool

	// inotify sweep cache (mu): the /proc/*/fdinfo walk is done at
	// most once per InotifyScanInterval — the scrape serves the
	// cached result.
	inoAt          time.Time
	inoInstances   uint64
	inoWatches     uint64
	inoTop         []inotifyConsumer
	inoWarnedInst  bool // edge-triggered >80% Warn per episode
	inoWarnedWatch bool

	// localpv walk cache (mu): the per-PVC du walk is cached for
	// LocalPVScanInterval — walking every volume dir per scrape is
	// too heavy on a node with hundreds of LocalPVs.
	lpvAt    time.Time
	lpvBytes map[string]int64
}

// New returns the Collector. Register it on the agent's registry,
// and wire its Latches() half in as the latch-ticker subsystem.
func New(cfg Config) *Collector {
	cfg.applyDefaults()
	c := &Collector{cfg: cfg, seenStates: map[string]time.Time{},
		fsInflight: map[string]time.Time{}, fsStalledLogged: map[string]bool{}}
	c.state = hoststate.New(cfg.WatchdogStateDir, "",
		func() time.Time { return c.cfg.nowFn() }, logger)
	c.removedFlagRe = make(map[string]*regexp.Regexp, len(cfg.RemovedFlags))
	for _, flag := range cfg.RemovedFlags {
		// Anchored key match (same shape as the canonical
		// grep "^[[:space:]]*flag[[:space:]]*:") over the raw file —
		// a removed flag may hide in ANY extraArgs block
		// (api/controllerManager/scheduler), and a substring match
		// would fire on comments or values.
		c.removedFlagRe[flag] = regexp.MustCompile(
			`(?m)^\s*` + regexp.QuoteMeta(flag) + `\s*:`)
	}
	c.expectedKCM = make(map[string]bool, len(cfg.ExpectedKCMArgs))
	for _, k := range cfg.ExpectedKCMArgs {
		c.expectedKCM[k] = true
	}
	c.descWatchdog = prometheus.NewDesc(
		"node_host_agent_watchdog_state",
		"node-watchdog state-* latch present (1) or previously seen and cleared (0).",
		[]string{"node", "state"}, nil)
	c.descNebUp = prometheus.NewDesc(
		"node_host_agent_nebula_interface_up",
		"Nebula interface operstate is up (emitted only when the interface exists).",
		nil, nil)
	c.descNebRoute = prometheus.NewDesc(
		"node_host_agent_nebula_route_present",
		"A host route via the Nebula interface exists (emitted only when the interface exists).",
		nil, nil)
	c.descNebCertDays = prometheus.NewDesc(
		"node_host_agent_nebula_cert_days_left",
		"Days until the nebula host certificate notAfter (emitted only when the cert parses).",
		nil, nil)
	c.descK0sDrift = prometheus.NewDesc(
		"node_k0s_config_drift",
		"/etc/k0s/k0s.yaml drifted vs expected config (1=drift): "+
			"removed-flag still present, extra/missing KCM extraArgs key, "+
			"or unreadable config (emitted only on nodes running "+
			"k0scontroller.service).",
		[]string{"reason", "key"}, nil)
	c.descPSI = prometheus.NewDesc(
		"node_watchdog_psi_cpu_some_avg60",
		"PSI cpu some avg60 — share of time runnable tasks stalled (runner's overload signal).",
		nil, nil)
	c.descCPURatio = prometheus.NewDesc(
		"node_cpu_delivered_ratio",
		"Share of 1 vCPU actually delivered by the hypervisor — busy-loop probe (~0.3 cpu-s, 1.0 = no steal).",
		nil, nil)
	c.descCPUWall = prometheus.NewDesc(
		"node_cpu_delivered_probe_wall_seconds",
		"Wall-clock the cpu-delivered probe ran — abnormal growth = the probe itself stalled.",
		nil, nil)
	c.descF2B = prometheus.NewDesc(
		"node_fail2ban_banned_ips",
		"Currently banned IPs per fail2ban jail (emitted only when the banned file exists).",
		[]string{"jail"}, nil)
	c.descEgressRelay = prometheus.NewDesc(
		"node_overlay_egress_relay_active",
		"Egress target currently routed via the overlay relay (1) or direct underlay (0).",
		[]string{"target"}, nil)
	c.descWatchdogLegacy = prometheus.NewDesc(
		"node_watchdog_state",
		"Signal currently active on node-watchdog (1 = state file exists).",
		[]string{"signal"}, nil)
	c.descEgressRelayLegacy = prometheus.NewDesc(
		"node_watchdog_egress_relay",
		"Egress target currently routed via overlay relay (1) or direct (0).",
		[]string{"target"}, nil)

	// Gray-failure telemetry — all carry the node label so a
	// federated store can attribute them back to the agent host.
	c.descClockUnsync = prometheus.NewDesc(
		"node_host_agent_clock_unsynchronized",
		"Kernel clock reports STA_UNSYNC via adjtimex (1 = not synchronized; emitted only when the syscall succeeds).",
		[]string{"node"}, nil)
	c.descClockEstErr = prometheus.NewDesc(
		"node_host_agent_clock_estimated_error_seconds",
		"adjtimex Timex.Esterror exported as seconds — the kernel's own bound on clock error.",
		[]string{"node"}, nil)
	c.descCtEntries = prometheus.NewDesc(
		"node_host_agent_conntrack_entries",
		"nf_conntrack_count — conntrack table entries currently tracked.",
		[]string{"node"}, nil)
	c.descCtLimit = prometheus.NewDesc(
		"node_host_agent_conntrack_limit",
		"nf_conntrack_max — conntrack table capacity.",
		[]string{"node"}, nil)
	c.descCtRatio = prometheus.NewDesc(
		"node_host_agent_conntrack_used_ratio",
		"Conntrack table fill ratio (entries/limit; emitted only when both files parse and limit > 0).",
		[]string{"node"}, nil)
	c.descFSInodesTotal = prometheus.NewDesc(
		"node_host_agent_filesystem_inodes_total",
		"Total inodes on the probed mount (statfs Files).",
		[]string{"node", "mount"}, nil)
	c.descFSInodesFree = prometheus.NewDesc(
		"node_host_agent_filesystem_inodes_free",
		"Free inodes on the probed mount (statfs Ffree).",
		[]string{"node", "mount"}, nil)
	c.descFSInodesRatio = prometheus.NewDesc(
		"node_host_agent_filesystem_inodes_used_ratio",
		"Used-inode share of the probed mount ((Files-Ffree)/Files; emitted only when statfs succeeds).",
		[]string{"node", "mount"}, nil)
	c.descFSProbeStalled = prometheus.NewDesc(
		"node_host_agent_filesystem_probe_stalled",
		"statfs probe of this mount exceeded the deadline (1 = hung mount; emitted for every configured target).",
		[]string{"node", "mount"}, nil)
	c.descFileFDAlloc = prometheus.NewDesc(
		"node_host_agent_filefd_allocated",
		"file-nr field 0 — file handles currently allocated.",
		[]string{"node"}, nil)
	c.descFileFDMax = prometheus.NewDesc(
		"node_host_agent_filefd_maximum",
		"file-nr field 2 — file handle limit.",
		[]string{"node"}, nil)
	c.descFileFDRatio = prometheus.NewDesc(
		"node_host_agent_filefd_used_ratio",
		"file-nr allocated/maximum (emitted only when file-nr parses and max > 0).",
		[]string{"node"}, nil)
	c.descSockTCPInuse = prometheus.NewDesc(
		"node_host_agent_sockstat_tcp_inuse",
		"sockstat TCP inuse — TCP sockets in use.",
		[]string{"node"}, nil)
	c.descSockTCPOrphan = prometheus.NewDesc(
		"node_host_agent_sockstat_tcp_orphan",
		"sockstat TCP orphan — orphaned (not attached to a socket) TCP connections.",
		[]string{"node"}, nil)
	c.descSockTCPTW = prometheus.NewDesc(
		"node_host_agent_sockstat_tcp_tw",
		"sockstat TCP tw — TCP sockets in TIME_WAIT.",
		[]string{"node"}, nil)
	c.descSockUsed = prometheus.NewDesc(
		"node_host_agent_sockstat_sockets_used",
		"sockstat 'sockets: used' — total sockets in use across protocols.",
		[]string{"node"}, nil)

	// Wave-2 gray-failure telemetry — same node-label convention.
	c.descPKIDays = prometheus.NewDesc(
		"node_host_agent_pki_cert_days_left",
		"Days until the earliest notAfter of the on-disk PKI cert at this path (emitted only when a cert parses).",
		[]string{"node", "path"}, nil)
	c.descInotifyInst = prometheus.NewDesc(
		"node_host_agent_inotify_instances_used_ratio",
		"inotify fds in use / max_user_instances (emitted only when the limit parses and is > 0).",
		[]string{"node"}, nil)
	c.descInotifyWatches = prometheus.NewDesc(
		"node_host_agent_inotify_watches_used_ratio",
		"inotify watches in use / max_user_watches (emitted only when the limit parses and is > 0).",
		[]string{"node"}, nil)
	c.descZombies = prometheus.NewDesc(
		"node_host_agent_processes_zombie_count",
		"Processes in state Z under the host proc root (emitted only when the scan succeeds).",
		[]string{"node"}, nil)
	c.descCgroupPids = prometheus.NewDesc(
		"node_host_agent_cgroup_pids_used_ratio",
		"pids.current / pids.max of the slice (emitted only when both files parse and max > 0).",
		[]string{"node", "slice"}, nil)
	c.descMTUDrift = prometheus.NewDesc(
		"node_host_agent_mtu_drift",
		"cilium datapath MTU exceeds the nebula overlay MTU (1 = drift; emitted only when both MTUs resolve).",
		[]string{"node"}, nil)
	c.descFSReadonly = prometheus.NewDesc(
		"node_host_agent_filesystem_readonly",
		"Probed mount reports ST_RDONLY via statfs (1 = filesystem remounted read-only; emitted only when statfs succeeds).",
		[]string{"node", "mount"}, nil)

	// W5.7 — PSI memory/io some+full avg60 and vmstat swap counters.
	c.descPSIMemSome = prometheus.NewDesc(
		"node_host_agent_psi_memory_some_avg60",
		"PSI memory some avg60 — share of time any task stalled on memory reclaim.",
		[]string{"node"}, nil)
	c.descPSIMemFull = prometheus.NewDesc(
		"node_host_agent_psi_memory_full_avg60",
		"PSI memory full avg60 — share of time ALL non-idle tasks stalled on memory reclaim (thrashing).",
		[]string{"node"}, nil)
	c.descPSIIOSome = prometheus.NewDesc(
		"node_host_agent_psi_io_some_avg60",
		"PSI io some avg60 — share of time any task stalled on block IO.",
		[]string{"node"}, nil)
	c.descPSIIOFull = prometheus.NewDesc(
		"node_host_agent_psi_io_full_avg60",
		"PSI io full avg60 — share of time ALL non-idle tasks stalled on block IO (disk saturation).",
		[]string{"node"}, nil)
	c.descPSWPIn = prometheus.NewDesc(
		"node_host_agent_vmstat_pswpin_total",
		"/proc/vmstat pswpin — cumulative pages swapped in (swap thrash evidence).",
		[]string{"node"}, nil)
	c.descPSWPOut = prometheus.NewDesc(
		"node_host_agent_vmstat_pswpout_total",
		"/proc/vmstat pswpout — cumulative pages swapped out (swap thrash evidence).",
		[]string{"node"}, nil)

	// W7 gray-failure telemetry — same node-label convention.
	c.descDState = prometheus.NewDesc(
		"node_host_agent_dstate_processes",
		"Processes in state D (uninterruptible sleep) under the host proc root (emitted only when the scan succeeds).",
		[]string{"node"}, nil)
	c.descSystemdScopes = prometheus.NewDesc(
		"node_host_agent_systemd_scopes_count",
		"cri-containerd-*.scope dirs under the kubepods cgroup slice — the abandoned-scope footprint slowing PID 1 D-Bus.",
		[]string{"node"}, nil)
	c.descCtInsertFail = prometheus.NewDesc(
		"node_host_agent_conntrack_insert_failed_total",
		"Sum of the insert_failed column across all CPU rows of /proc/net/stat/nf_conntrack (UDP tuple-collision drops).",
		[]string{"node"}, nil)
	c.descCtDrops = prometheus.NewDesc(
		"node_host_agent_conntrack_drops_total",
		"Sum of the drop column across all CPU rows of /proc/net/stat/nf_conntrack.",
		[]string{"node"}, nil)
	c.descARPEntries = prometheus.NewDesc(
		"node_host_agent_arp_entries",
		"Entries in /proc/net/arp — ARP neighbour-table fill vs gc_thresh headroom.",
		[]string{"node"}, nil)
	c.descCgMemHigh = prometheus.NewDesc(
		"node_host_agent_cgroup_memory_high_events_total",
		"memory.events `high` of the unit — direct-reclaim throttling episodes (freeze, not OOMKill).",
		[]string{"node", "unit"}, nil)
	c.descCgMemOOMKill = prometheus.NewDesc(
		"node_host_agent_cgroup_memory_oom_kill_events_total",
		"memory.events `oom_kill` of the unit — actual OOM kills counted by the cgroup.",
		[]string{"node", "unit"}, nil)

	// W8-KR3 — /proc/key-users: worst per-UID keyring quota fill;
	// /proc/net/sockstat TCP close_wait (hung client sockets).
	c.descKernelKeys = prometheus.NewDesc(
		"node_host_agent_kernel_keys_used_ratio",
		"Highest per-UID keyring fill ratio from /proc/key-users (instantiated/max; >0.80 latches state-kernel-keys-pressure).",
		[]string{"node"}, nil)
	c.descSockTCPCW = prometheus.NewDesc(
		"node_host_agent_sockstat_tcp_close_wait",
		"sockstat TCP close_wait — sockets stuck half-closed waiting for local close().",
		[]string{"node"}, nil)

	// W9 — OpenEBS LocalPV per-volume dir bytes (bounded du walk,
	// 15m cache).
	c.descLocalPVDirBytes = prometheus.NewDesc(
		"node_host_agent_localpv_dir_bytes",
		"Bytes under the OpenEBS LocalPV pvc-* volume dir (bounded walk; emitted per pvc-* dir present).",
		[]string{"node", "pvc_volume"}, nil)

	c.descMeta = map[*prometheus.Desc]descMeta{}
	for _, d := range []struct {
		desc *prometheus.Desc
		name string
		help string
	}{
		{c.descWatchdog, "node_host_agent_watchdog_state",
			"node-watchdog state-* latch present (1) or previously seen and cleared (0)."},
		{c.descWatchdogLegacy, "node_watchdog_state",
			"Signal currently active on node-watchdog (1 = state file exists)."},
		{c.descNebUp, "node_host_agent_nebula_interface_up",
			"Nebula interface operstate is up (emitted only when the interface exists)."},
		{c.descNebRoute, "node_host_agent_nebula_route_present",
			"A host route via the Nebula interface exists (emitted only when the interface exists)."},
		{c.descNebCertDays, "node_host_agent_nebula_cert_days_left",
			"Days until the nebula host certificate notAfter (emitted only when the cert parses)."},
		{c.descK0sDrift, "node_k0s_config_drift",
			"/etc/k0s/k0s.yaml drifted vs expected config (1=drift)."},
		{c.descPSI, "node_watchdog_psi_cpu_some_avg60",
			"PSI cpu some avg60 — share of time runnable tasks stalled (runner's overload signal)."},
		{c.descCPURatio, "node_cpu_delivered_ratio",
			"Share of 1 vCPU actually delivered by the hypervisor — busy-loop probe (~0.3 cpu-s, 1.0 = no steal)."},
		{c.descCPUWall, "node_cpu_delivered_probe_wall_seconds",
			"Wall-clock the cpu-delivered probe ran — abnormal growth = the probe itself stalled."},
		{c.descF2B, "node_fail2ban_banned_ips",
			"Currently banned IPs per fail2ban jail (emitted only when the banned file exists)."},
		{c.descEgressRelay, "node_overlay_egress_relay_active",
			"Egress target currently routed via the overlay relay (1) or direct underlay (0)."},
		{c.descEgressRelayLegacy, "node_watchdog_egress_relay",
			"Egress target currently routed via overlay relay (1) or direct (0)."},
		{c.descClockUnsync, "node_host_agent_clock_unsynchronized",
			"Kernel clock reports STA_UNSYNC via adjtimex (1 = not synchronized)."},
		{c.descClockEstErr, "node_host_agent_clock_estimated_error_seconds",
			"adjtimex Timex.Esterror exported as seconds."},
		{c.descCtEntries, "node_host_agent_conntrack_entries",
			"nf_conntrack_count — conntrack table entries currently tracked."},
		{c.descCtLimit, "node_host_agent_conntrack_limit",
			"nf_conntrack_max — conntrack table capacity."},
		{c.descCtRatio, "node_host_agent_conntrack_used_ratio",
			"Conntrack table fill ratio (entries/limit)."},
		{c.descFSInodesTotal, "node_host_agent_filesystem_inodes_total",
			"Total inodes on the probed mount (statfs Files)."},
		{c.descFSInodesFree, "node_host_agent_filesystem_inodes_free",
			"Free inodes on the probed mount (statfs Ffree)."},
		{c.descFSInodesRatio, "node_host_agent_filesystem_inodes_used_ratio",
			"Used-inode share of the probed mount."},
		{c.descFSProbeStalled, "node_host_agent_filesystem_probe_stalled",
			"statfs probe of this mount exceeded the deadline (1 = hung mount)."},
		{c.descFileFDAlloc, "node_host_agent_filefd_allocated",
			"file-nr field 0 — file handles currently allocated."},
		{c.descFileFDMax, "node_host_agent_filefd_maximum",
			"file-nr field 2 — file handle limit."},
		{c.descFileFDRatio, "node_host_agent_filefd_used_ratio",
			"file-nr allocated/maximum."},
		{c.descSockTCPInuse, "node_host_agent_sockstat_tcp_inuse",
			"sockstat TCP inuse — TCP sockets in use."},
		{c.descSockTCPOrphan, "node_host_agent_sockstat_tcp_orphan",
			"sockstat TCP orphan — orphaned TCP connections."},
		{c.descSockTCPTW, "node_host_agent_sockstat_tcp_tw",
			"sockstat TCP tw — TCP sockets in TIME_WAIT."},
		{c.descSockUsed, "node_host_agent_sockstat_sockets_used",
			"sockstat 'sockets: used' — total sockets in use."},
		{c.descPKIDays, "node_host_agent_pki_cert_days_left",
			"Days until the earliest notAfter of the on-disk PKI cert at this path."},
		{c.descInotifyInst, "node_host_agent_inotify_instances_used_ratio",
			"inotify fds in use / max_user_instances."},
		{c.descInotifyWatches, "node_host_agent_inotify_watches_used_ratio",
			"inotify watches in use / max_user_watches."},
		{c.descZombies, "node_host_agent_processes_zombie_count",
			"Processes in state Z under the host proc root."},
		{c.descCgroupPids, "node_host_agent_cgroup_pids_used_ratio",
			"pids.current / pids.max of the slice."},
		{c.descMTUDrift, "node_host_agent_mtu_drift",
			"cilium datapath MTU exceeds the nebula overlay MTU (1 = drift)."},
		{c.descFSReadonly, "node_host_agent_filesystem_readonly",
			"Probed mount reports ST_RDONLY via statfs (1 = filesystem remounted read-only)."},
		{c.descPSIMemSome, "node_host_agent_psi_memory_some_avg60",
			"PSI memory some avg60 — share of time any task stalled on memory reclaim."},
		{c.descPSIMemFull, "node_host_agent_psi_memory_full_avg60",
			"PSI memory full avg60 — share of time all tasks stalled on memory reclaim."},
		{c.descPSIIOSome, "node_host_agent_psi_io_some_avg60",
			"PSI io some avg60 — share of time any task stalled on block IO."},
		{c.descPSIIOFull, "node_host_agent_psi_io_full_avg60",
			"PSI io full avg60 — share of time all tasks stalled on block IO."},
		{c.descPSWPIn, "node_host_agent_vmstat_pswpin_total",
			"/proc/vmstat pswpin — cumulative pages swapped in."},
		{c.descPSWPOut, "node_host_agent_vmstat_pswpout_total",
			"/proc/vmstat pswpout — cumulative pages swapped out."},
		{c.descDState, "node_host_agent_dstate_processes",
			"Processes in state D (uninterruptible sleep) under the host proc root."},
		{c.descSystemdScopes, "node_host_agent_systemd_scopes_count",
			"cri-containerd-*.scope dirs under the kubepods cgroup slice."},
		{c.descCtInsertFail, "node_host_agent_conntrack_insert_failed_total",
			"insert_failed column sum over all CPU rows of nf_conntrack stats."},
		{c.descCtDrops, "node_host_agent_conntrack_drops_total",
			"drop column sum over all CPU rows of nf_conntrack stats."},
		{c.descARPEntries, "node_host_agent_arp_entries",
			"Entries in the ARP neighbour table."},
		{c.descCgMemHigh, "node_host_agent_cgroup_memory_high_events_total",
			"memory.events high of the unit — direct-reclaim throttling."},
		{c.descCgMemOOMKill, "node_host_agent_cgroup_memory_oom_kill_events_total",
			"memory.events oom_kill of the unit."},
		{c.descKernelKeys, "node_host_agent_kernel_keys_used_ratio",
			"Highest per-UID keyring fill ratio from /proc/key-users."},
		{c.descSockTCPCW, "node_host_agent_sockstat_tcp_close_wait",
			"sockstat TCP close_wait."},
		{c.descLocalPVDirBytes, "node_host_agent_localpv_dir_bytes",
			"Bytes under the OpenEBS LocalPV pvc-* volume dir."},
	} {
		c.descMeta[d.desc] = descMeta{name: d.name, help: d.help}
	}
	return c
}

// descMeta carries the fqName + help text of one descriptor — the
// textfile writer's header lines (a Metric's Desc does not expose the
// name programmatically).
type descMeta struct {
	name string
	help string
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descWatchdog
	ch <- c.descWatchdogLegacy
	ch <- c.descNebUp
	ch <- c.descNebRoute
	ch <- c.descNebCertDays
	ch <- c.descK0sDrift
	ch <- c.descPSI
	ch <- c.descCPURatio
	ch <- c.descCPUWall
	ch <- c.descF2B
	ch <- c.descEgressRelay
	ch <- c.descEgressRelayLegacy
	ch <- c.descClockUnsync
	ch <- c.descClockEstErr
	ch <- c.descCtEntries
	ch <- c.descCtLimit
	ch <- c.descCtRatio
	ch <- c.descFSInodesTotal
	ch <- c.descFSInodesFree
	ch <- c.descFSInodesRatio
	ch <- c.descFSProbeStalled
	ch <- c.descFileFDAlloc
	ch <- c.descFileFDMax
	ch <- c.descFileFDRatio
	ch <- c.descSockTCPInuse
	ch <- c.descSockTCPOrphan
	ch <- c.descSockTCPTW
	ch <- c.descSockUsed
	ch <- c.descPKIDays
	ch <- c.descInotifyInst
	ch <- c.descInotifyWatches
	ch <- c.descZombies
	ch <- c.descCgroupPids
	ch <- c.descMTUDrift
	ch <- c.descFSReadonly
	ch <- c.descPSIMemSome
	ch <- c.descPSIMemFull
	ch <- c.descPSIIOSome
	ch <- c.descPSIIOFull
	ch <- c.descPSWPIn
	ch <- c.descPSWPOut
	ch <- c.descDState
	ch <- c.descSystemdScopes
	ch <- c.descCtInsertFail
	ch <- c.descCtDrops
	ch <- c.descARPEntries
	ch <- c.descCgMemHigh
	ch <- c.descCgMemOOMKill
	ch <- c.descKernelKeys
	ch <- c.descSockTCPCW
	ch <- c.descLocalPVDirBytes
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	// Side-effect probes run BEFORE the state-dir scan so a latch
	// they transition shows up in this scrape's watchdog_state.
	avg60, psiOK := c.psiAvg60()
	if psiOK {
		c.updateOverloadLatch(avg60)
	}
	c.maybeMeasureCPU()
	// The cert is parsed once per scrape and shared between the
	// watchdog-state latch bookkeeping and the days-left gauge.
	certDays, certOK := c.nebulaCertDaysLeft()
	c.updateCertLatch(certDays, certOK)
	c.collectWatchdog(ch, certDays, certOK)
	c.collectNebula(ch)
	c.collectNebulaCert(ch, certDays, certOK)
	c.collectK0sDrift(ch)
	c.collectPSI(ch, avg60, psiOK)
	c.collectCPUDelivered(ch)
	c.collectFail2ban(ch)
	c.collectEgressRelay(ch)
	c.collectClock(ch)
	c.collectConntrack(ch)
	c.collectFilesystem(ch)
	c.collectFileFD(ch)
	c.collectSockstat(ch)
	c.collectPKICerts(ch)
	c.collectInotify(ch)
	c.collectZombies(ch)
	c.collectCgroupPids(ch)
	c.collectMTUDrift(ch)
	c.collectMemoryIO(ch)
	c.collectSystemdScopes(ch)
	c.collectARP(ch)
	c.collectCgroupMemEvents(ch)
	c.collectKernelKeys(ch)
	c.collectLocalPVUsage(ch)
}

// --- node-exporter textfile rendering (standalone prom_emit port) ---

// TextfileName is the prom file the standalone writer renders —
// node-watchdog.prom, the same name prom_emit used.
const TextfileName = "node-watchdog.prom"

// collectAll drains a full Collect into a slice — the textfile
// writer's scrape (Collect pushes; a reader must consume
// concurrently or the collector blocks on the channel).
func (c *Collector) collectAll() []prometheus.Metric {
	ch := make(chan prometheus.Metric, 64)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
}

// WriteTextfile renders the full metric set in node-exporter
// textfile format and atomically installs it as
// <dir>/node-watchdog.prom (tmp + rename — node_exporter only reads
// complete files). This is the standalone equivalent of prom_emit:
// on out-of-cluster hosts (api-lb VMs, kine DB VM, hubs) there is no
// Prometheus scrape, so the same series the /metrics endpoint
// exports are dropped into the textfile dir instead.
func (c *Collector) WriteTextfile(dir string) error {
	series := map[string][]string{}
	metaByName := map[string]descMeta{}
	counterSeries := map[string]bool{}
	var names []string
	for _, m := range c.collectAll() {
		meta, ok := c.descMeta[m.Desc()]
		if !ok {
			continue
		}
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			continue
		}
		// Counters land on dm.Counter, gauges on dm.Gauge — the
		// vmstat swap-thrash series (W5.7) are the first counters in
		// the set; skipping non-gauges would silently drop them from
		// node-watchdog.prom on standalone VMs.
		val, isCounter := float64(0), false
		switch {
		case dm.Gauge != nil && dm.Gauge.Value != nil:
			val = dm.Gauge.GetValue()
		case dm.Counter != nil && dm.Counter.Value != nil:
			val, isCounter = dm.Counter.GetValue(), true
		default:
			continue
		}
		var sb strings.Builder
		sb.WriteString(meta.name)
		if len(dm.Label) > 0 {
			sb.WriteByte('{')
			for i, l := range dm.Label {
				if i > 0 {
					sb.WriteByte(',')
				}
				sb.WriteString(l.GetName())
				sb.WriteString(`="`)
				sb.WriteString(promfile.EscapeLabelValue(l.GetValue()))
				sb.WriteByte('"')
			}
			sb.WriteByte('}')
		}
		sb.WriteByte(' ')
		sb.WriteString(strconv.FormatFloat(val, 'g', -1, 64))
		if _, seen := series[meta.name]; !seen {
			names = append(names, meta.name)
			metaByName[meta.name] = meta
		}
		if isCounter {
			counterSeries[meta.name] = true
		}
		series[meta.name] = append(series[meta.name], sb.String())
	}
	sort.Strings(names)

	var b promfile.Builder
	for _, name := range names {
		typ := "gauge"
		if counterSeries[name] {
			typ = "counter"
		}
		b.HeaderType(name, metaByName[name].help, typ)
		samples := series[name]
		sort.Strings(samples)
		// Dedupe identical sample lines — a duplicated series makes
		// the textfile collector reject the WHOLE file (the same
		// constraint prom_emit's `emitted` bookkeeping guarded).
		last := ""
		for _, s := range samples {
			if s == last {
				continue
			}
			last = s
			b.Line(s)
		}
	}

	return promfile.Write(dir, TextfileName, []byte(b.String()))
}

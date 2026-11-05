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
	"bufio"
	"cmp"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/yaml"
)

// Defaults — paths are the host mounts the DaemonSet provides.
const (
	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	defaultSysClassNet      = "/sys/class/net"
	defaultNebulaIface      = "neb1"
	defaultRouteFile        = "/proc/1/net/route"
	defaultK0sConfigFile    = "/etc/k0s/k0s.yaml"
	defaultK0sUnitFile      = "/etc/systemd/system/k0scontroller.service"
	defaultNebulaCertFile   = "/host/etc/nebula/interdc/host.crt"
	defaultPSIFile          = "/proc/pressure/cpu"
	defaultPSIMemoryFile    = "/proc/pressure/memory"
	defaultPSIIOFile        = "/proc/pressure/io"
	defaultVMStatFile       = "/proc/vmstat"
	// H2 conntrack table + H6 fd/socket sources.
	defaultConntrackCountFile = "/proc/sys/net/netfilter/nf_conntrack_count"
	defaultConntrackMaxFile   = "/proc/sys/net/netfilter/nf_conntrack_max"
	defaultFileNRFile         = "/proc/sys/fs/file-nr"
	defaultSockstatFile       = "/proc/1/net/sockstat"
	// defaultFSProbeTimeout bounds one statfs probe — a hung mount
	// blocks the syscall in uninterruptible sleep, so the deadline
	// is the only "still alive" signal (H7).
	defaultFSProbeTimeout = 2 * time.Second
	// psiOverloadedOn/Off are the node-overloaded hysteresis — the
	// runner's load15>4*ncpu test replaced by PSI some avg60 (actual
	// stall evidence, not raw load): enter the latch at >=40%,
	// release below 25%.
	psiOverloadedOn  = 40.0
	psiOverloadedOff = 25.0
	// cpuDeliveredTarget is the fixed busy-loop work (~0.3 cpu-s —
	// ~0.1% of a 5m cycle on a healthy node, ~6s wall at 95% steal).
	cpuDeliveredTarget    = 0.3
	cpuDeliveredMaxWall   = 60 * time.Second
	defaultCPUDeliveredIn = 2 * time.Minute
	// A1 inotify + A2 zombie/pids + B4 MTU-drift sources. ProcRoot is
	// plain /proc (hostPID:true makes the pod's /proc the host's);
	// the inotify fdinfo sweep is cached — walking every fdinfo file
	// per scrape is too heavy on a busy node.
	defaultProcRoot            = "/proc"
	defaultInotifyScanInterval = 60 * time.Second
	defaultInotifyMaxInstFile  = "/proc/sys/fs/inotify/max_user_instances"
	defaultInotifyMaxWatchFile = "/proc/sys/fs/inotify/max_user_watches"
	defaultCgroupRoot          = "/sys/fs/cgroup"
	defaultCiliumIface         = "cilium_net"
	defaultCiliumWG0Iface      = "cilium_wg0"
	// W9 LocalPV telemetry: the openebs localpv-provisioner
	// hostPath root + the du-walk cache TTL + per-volume entry cap.
	defaultOpenEBSLocalDir  = "/var/openebs/local"
	defaultLocalPVScanEvery = 15 * time.Minute
	localPVMaxWalkEntries   = 20000
	// W7 sources: H5 conntrack per-CPU stats + ARP table, H6 cgroup
	// memory.events units under system.slice/.
	defaultConntrackStatFile = "/proc/net/stat/nf_conntrack"
	defaultARPTableFile      = "/proc/net/arp"
	// inotifyWarnRatio is the fill ratio that logs the top-3 holder
	// report — early enough to find the leaker before
	// max_user_instances is hit.
	inotifyWarnRatio = 0.80
	// W8-KR3: /proc/key-users — kernel keyring quota pressure.
	defaultKeyUsersFile = "/proc/key-users"
	// kernelKeysPressureRatio arms state-kernel-keys-pressure.
	kernelKeysPressureRatio = 0.80
	// defaultLatchInterval is the Run() ticker's cadence (BUG-H5) —
	// the watchdog-state file contract must hold even when nothing
	// scrapes this collector (DaemonSet mode).
	defaultLatchInterval = 30 * time.Second
)

// nebulaCertWarnDays mirrors module 13-nebula-health: fewer than this
// many days to notAfter latches the nebula-cert-expiring signal.
const nebulaCertWarnDays = 30

const (
	// seenStateTTL bounds how long a cleared dynamic latch keeps
	// emitting an explicit 0 — long enough for any Prometheus
	// for:/auto-resolve window, then the bookkeeping entry is dropped
	// so the map cannot grow forever.
	seenStateTTL = 6 * time.Hour
	// maxSeenStates hard-bounds the seenStates map — the
	// longest-cleared entries are evicted first when it overflows.
	maxSeenStates = 256
)

// defaultRemovedFlags are k0s config keys removed upstream whose
// presence means the rendered config drifted from the expected one.
var defaultRemovedFlags = []string{"concurrent-service-syncs"}

// defaultFilesystemTargets are the mounts statfs'd per scrape —
// the inode + hung-mount canaries for the dirs that hurt most when
// the fs underneath wedges or runs out of inodes (host /etc, the
// k0s data dir, the OpenEBS local-path provisioner root).
var defaultFilesystemTargets = []string{
	"/host/etc", "/host/var/lib/k0s", "/var/openebs/local",
}

// defaultPKIHostPaths are the PKI sources scanned for *.crt/*.pem —
// host-relative, joined under HostRoot: the k0s apiserver+etcd cert
// dirs, the kubelet client bundle (a single file), and the kine
// etcd-pki dir on standalone DB VMs.
var defaultPKIHostPaths = []string{
	"var/lib/k0s/pki",
	"var/lib/k0s/pki/etcd",
	"var/lib/k0s/kubelet/pki/kubelet-client-current.pem",
	"etc/kine/pki",
}

// defaultCgroupPidsSlices are the cgroup-v2 dirs whose
// pids.current/pids.max feed the pids-used-ratio gauge (A2) — the
// k0s units plus the whole pod workload slice.
var defaultCgroupPidsSlices = []string{
	"system.slice/k0sworker.service",
	"system.slice/k0scontroller.service",
	"kubepods.slice",
}

// defaultCgroupMemUnits are the system.slice units whose
// memory.events feed the W7-H6 reclaim-throttling counters — the
// k0s daemons whose freeze-under-high is the classic gray failure.
var defaultCgroupMemUnits = []string{
	"k0scontroller.service",
	"k0sworker.service",
}

// defaultExpectedKCMArgs is the expected key set of
// spec.controllerManager.extraArgs — the 11 keys pinned identically in
// all three bootstrap/*/k0sctl.yaml (cicd/nonprod/production). A node
// carrying extra/missing keys vs this set drifts (extra-key/missing-key).
var defaultExpectedKCMArgs = []string{
	"concurrent-deployment-syncs",
	"concurrent-gc-syncs",
	"concurrent-replicaset-syncs",
	"kube-api-burst",
	"kube-api-qps",
	"leader-elect-lease-duration",
	"leader-elect-renew-deadline",
	"leader-elect-retry-period",
	"node-monitor-grace-period",
	"node-monitor-period",
	"terminated-pod-gc-threshold",
}

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

// inotifyConsumer is one process's inotify footprint — kept for the
// top-3 holder report when a used ratio crosses the warn line.
type inotifyConsumer struct {
	pid       int
	name      string
	instances uint64
	watches   uint64
}

// New returns the Collector. Register it on the agent's registry.
func New(cfg Config) *Collector {
	cfg.applyDefaults()
	c := &Collector{cfg: cfg, seenStates: map[string]time.Time{},
		fsInflight: map[string]time.Time{}, fsStalledLogged: map[string]bool{}}
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

// collectWatchdog scans state-* latch files. certDays/certOK fold the
// agent-computed nebula cert expiry into the latch bookkeeping: the
// shell module 13 used to own the state-nebula-cert-expiring file —
// now the series is driven by cert parsing whenever the cert reads.
func (c *Collector) collectWatchdog(ch chan<- prometheus.Metric, certDays int64, certOK bool) {
	present := map[string]bool{}
	entries, err := os.ReadDir(c.cfg.WatchdogStateDir)
	switch {
	case err == nil:
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			if name, ok := strings.CutPrefix(e.Name(), "state-"); ok && name != "" {
				present[name] = true
			}
		}
	case os.IsNotExist(err):
		// The dir is gone — the latches really are absent, so the
		// emit-0 cleared bookkeeping below is honest (a node
		// without node-watchdog keeps exporting 0s).
	default:
		// A ReadDir error other than NotExist leaves `present`
		// empty — letting it fall through would stamp every latched
		// state cleared and emit a false 0 for the whole family
		// despite on-disk latches. Serve the last-known values
		// unchanged instead (active entries keep 1, cleared
		// entries keep their emit-0 state); the bookkeeping map
		// is left untouched so no TTL eviction is manufactured.
		logger().Debug("hostmetrics: watchdog state dir unreadable — "+
			"serving previous watchdog_state values",
			"dir", c.cfg.WatchdogStateDir, "error", err)
		c.mu.Lock()
		prev := make(map[string]bool, len(c.seenStates))
		for s, clearedAt := range c.seenStates {
			prev[s] = clearedAt.IsZero()
		}
		c.mu.Unlock()
		for name, active := range prev {
			v := 0.0
			if active {
				v = 1
			}
			ch <- prometheus.MustNewConstMetric(c.descWatchdog,
				prometheus.GaugeValue, v, c.cfg.NodeName, name)
			ch <- prometheus.MustNewConstMetric(c.descWatchdogLegacy,
				prometheus.GaugeValue, v, name)
		}
		return
	}
	if certOK && certDays < nebulaCertWarnDays {
		present["nebula-cert-expiring"] = true
	}
	c.mu.Lock()
	now := c.cfg.nowFn()
	// Cleared-state bookkeeping: an entry absent from this scrape's
	// latches is stamped with now on the first cleared scrape and
	// dropped once it has emitted 0 for seenStateTTL. The cert-owned
	// series counts as active while the cert parses — the signal
	// must emit an explicit 0 from then on (alert contract), even if
	// the cert later disappears.
	for s, clearedAt := range c.seenStates {
		if present[s] || (certOK && s == "nebula-cert-expiring") {
			continue
		}
		if clearedAt.IsZero() {
			c.seenStates[s] = now
		} else if now.Sub(clearedAt) >= seenStateTTL {
			delete(c.seenStates, s)
		}
	}
	for name := range present {
		c.seenStates[name] = time.Time{}
	}
	if certOK {
		c.seenStates["nebula-cert-expiring"] = time.Time{}
	}
	// Hard bound: a latch storm must not grow the map without limit —
	// evict the longest-cleared entries first (active entries, zero
	// time, are never evicted). Single pass: collect the cleared
	// entries, sort oldest-first, delete the overflow — if the map is
	// still over-cap afterwards it is all-active and stays so.
	if len(c.seenStates) > maxSeenStates {
		type clearedState struct {
			state string
			at    time.Time
		}
		var evictable []clearedState
		for s, at := range c.seenStates {
			if !at.IsZero() {
				evictable = append(evictable, clearedState{s, at})
			}
		}
		slices.SortFunc(evictable, func(a, b clearedState) int { return a.at.Compare(b.at) })
		over := min(len(c.seenStates)-maxSeenStates, len(evictable))
		for _, e := range evictable[:over] {
			delete(c.seenStates, e.state)
		}
	}
	seen := make([]string, 0, len(c.seenStates))
	for name := range c.seenStates {
		seen = append(seen, name)
	}
	c.mu.Unlock()
	for _, name := range seen {
		v := 0.0
		if present[name] {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.descWatchdog,
			prometheus.GaugeValue, v, c.cfg.NodeName, name)
		// Legacy alias: prom_emit's node_watchdog_state{signal} —
		// the fluxcd PrometheusRules query this exact series.
		ch <- prometheus.MustNewConstMetric(c.descWatchdogLegacy,
			prometheus.GaugeValue, v, name)
	}
}

// collectNebula emits interface + route state, only when the nebula
// interface exists on the node.
func (c *Collector) collectNebula(ch chan<- prometheus.Metric) {
	oper, err := os.ReadFile(
		filepath.Join(c.cfg.SysClassNet, c.cfg.NebulaIface, "operstate"))
	if err != nil {
		return // interface absent → metrics absent (documented choice)
	}
	up := 0.0
	switch strings.TrimSpace(string(oper)) {
	// TUN devices (neb1 is nebula's tun) often report "unknown" rather
	// than "up" — the link exists and is administratively up.
	case "up", "unknown":
		up = 1
	}
	ch <- prometheus.MustNewConstMetric(c.descNebUp,
		prometheus.GaugeValue, up)

	present := 0.0
	if f, err := os.Open(c.cfg.RouteFile); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			// /proc/net/route columns: Iface Destination Gateway ...
			if len(fields) >= 2 && fields[0] == c.cfg.NebulaIface {
				present = 1
				break
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(c.descNebRoute,
		prometheus.GaugeValue, present)
}

// updateCertLatch mirrors 13-nebula-health.sh's FILE contract — the
// nodereporter and prom filelog consumers read files, not metric
// series: state-nebula-cert-expiring is created (state_enter, epoch
// content, only while absent) when days < nebulaCertWarnDays and
// removed on recovery, and nebula-cert-days-left is rewritten on
// every parsed scrape (shell wrote it every run). An absent or
// unparseable cert CLEARS both files — the shell left the latch
// behind on `[ -s "$cert" ]` failure, but a permanent phantom latch
// breaks both the file consumers and the emit-0 alert contract (a
// gone cert cannot be "expiring").
func (c *Collector) updateCertLatch(days int64, ok bool) {
	dir := c.cfg.WatchdogStateDir
	latch := filepath.Join(dir, "state-nebula-cert-expiring")
	if !ok {
		_ = os.Remove(latch)
		_ = os.Remove(filepath.Join(dir, "nebula-cert-days-left"))
		return
	}
	daysPath := filepath.Join(dir, "nebula-cert-days-left")
	tmp := filepath.Join(dir, ".tmp-"+filepath.Base(daysPath))
	if err := os.WriteFile(tmp,
		[]byte(strconv.FormatInt(days, 10)+"\n"), 0o644); err == nil {
		_ = os.Rename(tmp, daysPath)
	}
	_, statErr := os.Stat(latch)
	switch {
	case days < nebulaCertWarnDays && statErr != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp = filepath.Join(dir, ".tmp-"+filepath.Base(latch))
		if werr := os.WriteFile(tmp, []byte(content), 0o644); werr != nil {
			logger().Warn("hostmetrics: nebula-cert-expiring latch write failed",
				"path", latch, "error", werr)
		} else if rerr := os.Rename(tmp, latch); rerr != nil {
			logger().Warn("hostmetrics: nebula-cert-expiring latch install failed",
				"path", latch, "error", rerr)
		} else {
			logger().Info("hostmetrics: nebula-cert-expiring latch set",
				"daysLeft", days,
				"warnDays", nebulaCertWarnDays, "path", latch)
		}
	case days >= nebulaCertWarnDays && statErr == nil:
		if rerr := os.Remove(latch); rerr != nil {
			logger().Warn("hostmetrics: nebula-cert-expiring latch remove failed",
				"path", latch, "error", rerr)
		} else {
			logger().Info("hostmetrics: nebula-cert-expiring latch cleared",
				"daysLeft", days, "path", latch)
		}
	}
}

// collectNebulaCert emits the cert days-left gauge — only when the
// cert parses (absent/garbage cert → absent series, distinguishing
// "no cert" from "0 days").
func (c *Collector) collectNebulaCert(ch chan<- prometheus.Metric, daysLeft int64, ok bool) {
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descNebCertDays,
		prometheus.GaugeValue, float64(daysLeft))
}

// nebulaCertDaysLeft returns days until notAfter, and ok=false when
// the cert is absent or unparseable. Integer-day truncation matches
// the shell's ((exp - now) / 86400).
func (c *Collector) nebulaCertDaysLeft() (int64, bool) {
	data, err := os.ReadFile(c.cfg.NebulaCertFile)
	if err != nil {
		return 0, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return 0, false
	}
	notAfter, ok := nebulaCertNotAfter(block.Bytes)
	if !ok {
		return 0, false
	}
	return (notAfter - time.Now().Unix()) / 86400, true
}

// --- minimal protobuf wire reader for NebulaCertificate ---
// host.crt is a PEM block ("-----BEGIN NEBULA CERTIFICATE-----")
// wrapping a protobuf NebulaCertificate. Only two fields matter:
//
//	NebulaCertificate        field 1 "details"  — wire type 2 (LEN)
//	NebulaCertificateDetails field 6 "not_after" — wire type 0 (varint int64)
//
// Any anomaly (truncation, bad wire type, missing field) → ok=false;
// the caller treats the cert as unreadable and emits nothing. This
// avoids pulling in the slackhq/nebula dependency for one field.

// readVarint decodes one protobuf varint; n=0 signals truncation or
// overflow (>10 bytes / >64 bits).
func readVarint(b []byte) (v uint64, n int) {
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if i == 9 && c > 1 { // 10th byte may only carry 1 bit
			return 0, 0
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

// skipWire returns the length in bytes of the protobuf value at b[0]
// for the given wire type. Only the four fixed types are supported —
// group wire types (3/4, deprecated) are treated as unparseable.
func skipWire(b []byte, wire int) (int, bool) {
	switch wire {
	case 0: // varint
		_, n := readVarint(b)
		return n, n > 0
	case 1: // fixed64
		if len(b) < 8 {
			return 0, false
		}
		return 8, true
	case 2: // length-delimited
		ln, n := readVarint(b)
		if n == 0 || uint64(len(b)-n) < ln {
			return 0, false
		}
		return n + int(ln), true
	case 5: // fixed32
		if len(b) < 4 {
			return 0, false
		}
		return 4, true
	}
	return 0, false
}

// nebulaCertNotAfter extracts not_after (unix seconds) from the DER
// body of a nebula PEM cert.
func nebulaCertNotAfter(der []byte) (int64, bool) {
	for len(der) > 0 {
		tag, n := readVarint(der)
		if n == 0 {
			return 0, false
		}
		der = der[n:]
		field, wire := int(tag>>3), int(tag&7)
		if field == 1 && wire == 2 {
			ln, m := readVarint(der)
			if m == 0 || uint64(len(der)-m) < ln {
				return 0, false
			}
			return nebulaDetailsNotAfter(der[m : m+int(ln)])
		}
		m, ok := skipWire(der, wire)
		if !ok {
			return 0, false
		}
		der = der[m:]
	}
	return 0, false
}

// nebulaDetailsNotAfter scans a NebulaCertificateDetails body for
// field 6 (not_after, varint int64). Skips every other field by wire
// type so unknown/added fields can't break the parse.
func nebulaDetailsNotAfter(b []byte) (int64, bool) {
	for len(b) > 0 {
		tag, n := readVarint(b)
		if n == 0 {
			return 0, false
		}
		b = b[n:]
		field, wire := int(tag>>3), int(tag&7)
		if field == 6 && wire == 0 {
			v, m := readVarint(b)
			if m == 0 {
				return 0, false
			}
			return int64(v), true
		}
		m, ok := skipWire(b, wire)
		if !ok {
			return 0, false
		}
		b = b[m:]
	}
	return 0, false
}

// kcmExtraArgKeys returns the sorted key set of
// spec.controllerManager.extraArgs in the parsed k0s.yaml — the same
// key list node-config-agent's drift task extracts with its awk block.
func kcmExtraArgKeys(parsed map[string]any) []string {
	spec, _ := parsed["spec"].(map[string]any)
	cm, _ := spec["controllerManager"].(map[string]any)
	ea, _ := cm["extraArgs"].(map[string]any)
	keys := make([]string, 0, len(ea))
	for k := range ea {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// k0sConfig returns the raw bytes and parsed form of k0s.yaml,
// re-reading only when the file's mtime+size changed since the last
// scrape. ok=false means the file was unreadable or unparseable at
// read time — the caller keeps the old drift=1 "unreadable" finding.
func (c *Collector) k0sConfig() (data []byte, parsed map[string]any, ok bool) {
	fi, err := os.Stat(c.cfg.K0sConfigFile)
	if err != nil {
		return nil, nil, false // gone/un-statable → never serve cache
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.k0sLoaded && fi.ModTime().Equal(c.k0sMtime) && fi.Size() == c.k0sSize {
		return c.k0sData, c.k0sParsed, c.k0sOK
	}
	data, err = os.ReadFile(c.cfg.K0sConfigFile)
	var p map[string]any
	var uerr error
	if err == nil {
		uerr = yaml.Unmarshal(data, &p)
	}
	ok = err == nil && uerr == nil
	if !ok {
		cause := err
		if cause == nil {
			cause = uerr
		}
		// Cached per mtime+size — this fires once per file change,
		// not once per scrape.
		logger().Debug("hostmetrics: k0s config unreadable/unparseable — "+
			"drift reports {unreadable,k0s.yaml}",
			"path", c.cfg.K0sConfigFile,
			"error", cause)
	}
	c.k0sLoaded = true
	c.k0sMtime = fi.ModTime()
	c.k0sSize = fi.Size()
	c.k0sData = data
	c.k0sParsed = p
	c.k0sOK = ok
	return data, p, ok
}

// driftFinding is one k0s config drift result — reason is
// removed-flag / extra-key / missing-key / unreadable, key the flag
// or extraArgs key it fired on (the metric's {reason,key} labels).
type driftFinding struct{ reason, key string }

// scanK0sDrift computes every drift finding on one read of k0s.yaml —
// shared between the node_k0s_config_drift collector and the
// check-k0s-drift CLI. parseOK=false (unreadable/unparseable file)
// keeps the old drift=1 semantics as a single {unreadable,k0s.yaml}.
func scanK0sDrift(data []byte, parsed map[string]any, parseOK bool,
	removedRe map[string]*regexp.Regexp, expected map[string]bool,
	expectedOrder []string) []driftFinding {
	if !parseOK {
		return []driftFinding{{"unreadable", "k0s.yaml"}}
	}
	var findings []driftFinding
	for flag, re := range removedRe {
		if re.Match(data) {
			findings = append(findings, driftFinding{"removed-flag", flag})
		}
	}
	nodeKeys := kcmExtraArgKeys(parsed)
	nodeSet := make(map[string]bool, len(nodeKeys))
	for _, k := range nodeKeys {
		nodeSet[k] = true
		// A removed flag found in extraArgs reports only under
		// removed-flag — no double counting as extra-key.
		if _, isRemoved := removedRe[k]; !expected[k] && !isRemoved {
			findings = append(findings, driftFinding{"extra-key", k})
		}
	}
	for _, k := range expectedOrder {
		if !nodeSet[k] {
			findings = append(findings, driftFinding{"missing-key", k})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].reason != findings[j].reason {
			return findings[i].reason < findings[j].reason
		}
		return findings[i].key < findings[j].key
	})
	return findings
}

// collectK0sDrift emits node_k0s_config_drift{reason,key} on
// controller nodes (detected via the k0scontroller.service unit file).
// One series per finding at value 1; a clean config emits
// {reason="none",key="none"} 0.
func (c *Collector) collectK0sDrift(ch chan<- prometheus.Metric) {
	if _, err := os.Stat(c.cfg.K0sUnitFile); err != nil {
		return // not a k0s controller → no series
	}
	data, parsed, ok := c.k0sConfig()
	findings := scanK0sDrift(data, parsed, ok, c.removedFlagRe,
		c.expectedKCM, c.cfg.ExpectedKCMArgs)
	if len(findings) == 0 {
		ch <- prometheus.MustNewConstMetric(c.descK0sDrift,
			prometheus.GaugeValue, 0, "none", "none")
		return
	}
	for _, f := range findings {
		ch <- prometheus.MustNewConstMetric(c.descK0sDrift,
			prometheus.GaugeValue, 1, f.reason, f.key)
	}
}

// --- PSI overload (runner's node-overloaded) ---

// psiAvg60 parses the "some avg60=" field of /proc/pressure/cpu.
// ok=false on a missing/malformed file — the latch is left untouched
// (inconclusive, like the other file-based signals).
func (c *Collector) psiAvg60() (float64, bool) {
	data, err := os.ReadFile(c.cfg.PSIFile)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "some" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg60" {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0, false
			}
			return x, true
		}
	}
	return 0, false
}

// updateOverloadLatch drives state-node-overloaded with hysteresis:
// >=psiOverloadedOn enters, <psiOverloadedOff exits, between the
// thresholds the current state persists. Written only on transition —
// the file content is when the condition STARTED.
func (c *Collector) updateOverloadLatch(avg60 float64) {
	p := filepath.Join(c.cfg.WatchdogStateDir, "state-node-overloaded")
	_, err := os.Stat(p)
	switch {
	case avg60 >= psiOverloadedOn && err != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
		if werr := os.WriteFile(tmp, []byte(content), 0o644); werr != nil {
			logger().Warn("hostmetrics: node-overloaded latch write failed",
				"path", p, "error", werr)
		} else if rerr := os.Rename(tmp, p); rerr != nil {
			logger().Warn("hostmetrics: node-overloaded latch install failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: node-overloaded latch set — "+
				"PSI cpu some avg60 above threshold",
				"avg60", avg60,
				"enterThreshold", psiOverloadedOn, "path", p)
		}
	case avg60 < psiOverloadedOff && err == nil:
		if rerr := os.Remove(p); rerr != nil {
			logger().Warn("hostmetrics: node-overloaded latch remove failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: node-overloaded latch cleared — "+
				"PSI cpu some avg60 back below threshold",
				"avg60", avg60,
				"exitThreshold", psiOverloadedOff, "path", p)
		}
	}
}

// collectPSI emits the avg60 gauge only when PSI parsed.
func (c *Collector) collectPSI(ch chan<- prometheus.Metric, avg60 float64, ok bool) {
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descPSI,
		prometheus.GaugeValue, avg60)
}

// --- cpu-delivered probe (lib.sh measure_cpu_delivered) ---

// maybeMeasureCPU re-arms the busy-loop probe every
// CPUDeliveredInterval. The probe itself runs in a goroutine so a
// scrape never blocks on wall-clock steal; the gauges serve the last
// completed measurement.
func (c *Collector) maybeMeasureCPU() {
	c.mu.Lock()
	if c.cpuRunning ||
		c.cfg.nowFn().Sub(c.cpuLast) < c.cfg.CPUDeliveredInterval {
		c.mu.Unlock()
		return
	}
	c.cpuRunning = true
	c.mu.Unlock()
	go func() {
		ratio, wall, ok := c.measureCPU()
		c.mu.Lock()
		c.cpuRunning = false
		c.cpuLast = c.cfg.nowFn()
		if ok {
			c.cpuRatio, c.cpuWall, c.cpuOK = ratio, wall, true
		}
		c.mu.Unlock()
		if !ok {
			logger().Warn("hostmetrics: cpu-delivered probe did not " +
				"complete — serving previous result",
			)
		}
	}()
}

// measureCPU burns a fixed ~0.3 cpu-s on a LOCKED thread and returns
// ratio = cpu_target / wall (capped 1.0 — jiffies overshoot can make
// wall slightly under target). RUSAGE_THREAD isolates the probe from
// other goroutines' CPU — the shell measured the whole-process
// jiffies; a locked thread is the closest Go equivalent.
func (c *Collector) measureCPU() (ratio, wall float64, ok bool) {
	if c.cfg.cpuMeasure != nil {
		return c.cfg.cpuMeasure()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var ru0, ru1 unix.Rusage
	if unix.Getrusage(unix.RUSAGE_THREAD, &ru0) != nil {
		return 0, 0, false
	}
	cpuAt := func(r *unix.Rusage) float64 {
		return float64(r.Utime.Sec) + float64(r.Utime.Usec)/1e6 +
			float64(r.Stime.Sec) + float64(r.Stime.Usec)/1e6
	}
	wall0 := time.Now()
	var sink uint64
	for i := uint64(0); ; i++ {
		sink += i // any real work — jiffie-counted CPU
		if i%65536 == 0 {
			if unix.Getrusage(unix.RUSAGE_THREAD, &ru1) != nil {
				return 0, 0, false
			}
			if cpuAt(&ru1)-cpuAt(&ru0) >= cpuDeliveredTarget {
				break
			}
			if time.Since(wall0) > cpuDeliveredMaxWall {
				return 0, 0, false // probe itself stalled — no metric
			}
		}
	}
	c.mu.Lock()
	c.cpuSink = sink
	c.mu.Unlock()
	wall = time.Since(wall0).Seconds()
	if wall <= 0 {
		return 0, 0, false
	}
	ratio = cpuDeliveredTarget / wall
	if ratio > 1 {
		ratio = 1
	}
	return ratio, wall, true
}

// collectCPUDelivered emits the last completed probe — absent before
// the first measurement (shell: no cpu-delivered file → no metric,
// never a fake 0).
func (c *Collector) collectCPUDelivered(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	ok, ratio, wall := c.cpuOK, c.cpuRatio, c.cpuWall
	c.mu.Unlock()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descCPURatio,
		prometheus.GaugeValue, ratio)
	ch <- prometheus.MustNewConstMetric(c.descCPUWall,
		prometheus.GaugeValue, wall)
}

// --- fail2ban banned counts (50-fail2ban.sh + prom_emit) ---

// collectFail2ban emits node_fail2ban_banned_ips{jail} from the
// fail2ban-banned file — absent when the file is (node without
// fail2ban → absent series, never a fake 0).
func (c *Collector) collectFail2ban(ch chan<- prometheus.Metric) {
	data, err := os.ReadFile(
		filepath.Join(c.cfg.WatchdogStateDir, "fail2ban-banned"))
	if err != nil {
		return
	}
	for _, pair := range strings.Fields(string(data)) {
		jail, n, ok := strings.Cut(pair, "=")
		if !ok || jail == "" {
			continue
		}
		v, err := strconv.ParseFloat(n, 64)
		if err != nil {
			continue // malformed entry — never emit junk (file contract)
		}
		ch <- prometheus.MustNewConstMetric(c.descF2B,
			prometheus.GaugeValue, v, jail)
	}
}

// --- overlay egress relay state (12-overlay-egress + prom_emit) ---

// collectEgressRelay emits node_overlay_egress_relay_active for
// EVERY configured relay — a 0 while the target is direct vs an
// absent series for "never relayed" must stay distinguishable.
func (c *Collector) collectEgressRelay(ch chan<- prometheus.Metric) {
	for _, r := range c.cfg.EgressRelays {
		v := 0.0
		data, err := os.ReadFile(
			filepath.Join(c.cfg.WatchdogStateDir, "egress-state-"+r))
		if err == nil && strings.TrimSpace(string(data)) == "relay" {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.descEgressRelay,
			prometheus.GaugeValue, v, r)
		// Legacy alias: prom_emit's node_watchdog_egress_relay{target}.
		ch <- prometheus.MustNewConstMetric(c.descEgressRelayLegacy,
			prometheus.GaugeValue, v, r)
	}
}

// --- H1: clock sync (adjtimex) ---

// collectClock emits the clock-sync gauges only when adjtimex
// succeeds — an absent series means the syscall failed
// (inconclusive), never a fake "synchronized" 0.
func (c *Collector) collectClock(ch chan<- prometheus.Metric) {
	var tx unix.Timex
	if _, err := c.cfg.adjtimexFn(&tx); err != nil {
		return
	}
	unsync := 0.0
	if tx.Status&unix.STA_UNSYNC != 0 {
		unsync = 1
	}
	ch <- prometheus.MustNewConstMetric(c.descClockUnsync,
		prometheus.GaugeValue, unsync, c.cfg.NodeName)
	// Timex.Esterror is microseconds — export seconds.
	ch <- prometheus.MustNewConstMetric(c.descClockEstErr,
		prometheus.GaugeValue, float64(tx.Esterror)/1e6, c.cfg.NodeName)
}

// --- H2: conntrack table pressure ---

// readUintFile parses a single-integer procfs/sysfs file
// (nf_conntrack_{count,max} shape — leading whitespace + trailing
// newline tolerated).
func readUintFile(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// collectConntrack emits entries/limit each only when its own file
// parses (a node without the conntrack module has no files → absent
// series, not a fake 0) and the ratio only when both parsed and the
// limit is non-zero.
func (c *Collector) collectConntrack(ch chan<- prometheus.Metric) {
	count, countOK := readUintFile(c.cfg.ConntrackCountFile)
	limit, limitOK := readUintFile(c.cfg.ConntrackMaxFile)
	if countOK {
		ch <- prometheus.MustNewConstMetric(c.descCtEntries,
			prometheus.GaugeValue, float64(count), c.cfg.NodeName)
	}
	if limitOK {
		ch <- prometheus.MustNewConstMetric(c.descCtLimit,
			prometheus.GaugeValue, float64(limit), c.cfg.NodeName)
	}
	if countOK && limitOK && limit > 0 {
		ch <- prometheus.MustNewConstMetric(c.descCtRatio,
			prometheus.GaugeValue,
			float64(count)/float64(limit), c.cfg.NodeName)
	}
	// W7-H5: the per-CPU stat counters — insert_failed grows on the
	// UDP source-port tuple collision (A+AAAA race) long before the
	// table fills; drop counts the packets conntrack refused. Both
	// are cumulative kernel counters → CounterValue.
	if st, ok := conntrackStatCounters(c.cfg.ConntrackStatFile,
		"insert_failed", "drop"); ok {
		if v, found := st["insert_failed"]; found {
			ch <- prometheus.MustNewConstMetric(c.descCtInsertFail,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
		if v, found := st["drop"]; found {
			ch <- prometheus.MustNewConstMetric(c.descCtDrops,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
	}
}

// conntrackStatCounters parses /proc/net/stat/nf_conntrack — a
// header line of column names followed by one HEX value row per
// CPU; the named columns are summed across all CPUs. ok=false when
// the file is unreadable or the header carries none of the wanted
// columns (conntrack module absent → absent series, no fake 0).
func conntrackStatCounters(path string, keys ...string) (map[string]uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return nil, false
	}
	header := strings.Fields(lines[0])
	idx := map[string]int{}
	for _, k := range keys {
		for i, name := range header {
			if name == k {
				idx[k] = i
			}
		}
	}
	if len(idx) == 0 {
		return nil, false
	}
	out := map[string]uint64{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != len(header) {
			continue // malformed CPU row — never emit junk
		}
		for k, i := range idx {
			if v, err := strconv.ParseUint(f[i], 16, 64); err == nil {
				out[k] += v
			}
		}
	}
	return out, true
}

// --- H3+H7: filesystem inode stats + hung-mount probe ---

// fsResult is one statfs probe outcome.
type fsResult struct {
	st  unix.Statfs_t
	err error
}

// probeFS statfs's one mount under the fsProbeTimeout deadline. A
// hung mount blocks the syscall in uninterruptible sleep — it can't
// be cancelled — so the call runs on a goroutine and the scrape
// moves on after the deadline. stalled=true means the deadline
// passed with the syscall still stuck (or an earlier probe of the
// same mount has been in the kernel past the deadline — at most one
// goroutine per mount is allowed to pile up). A scrape that lands
// while a still-fresh probe is in flight reports stalled=0, not 1:
// "probe running" is not "probe hung", and two overlapping scrapers
// must not manufacture a hung-mount alert. ok=true only when statfs
// completed without error.
func (c *Collector) probeFS(mount string) (st unix.Statfs_t, stalled, ok bool) {
	c.mu.Lock()
	if start, inflight := c.fsInflight[mount]; inflight {
		c.mu.Unlock()
		return unix.Statfs_t{},
			c.cfg.nowFn().Sub(start) >= c.cfg.fsProbeTimeout, false
	}
	c.fsInflight[mount] = c.cfg.nowFn()
	c.mu.Unlock()

	res := make(chan fsResult, 1)
	go func() {
		var r fsResult
		r.err = c.cfg.statfsFn(mount, &r.st)
		c.mu.Lock()
		delete(c.fsInflight, mount)
		c.mu.Unlock()
		res <- r // buffered — never blocks after a timed-out scrape
	}()

	timer := time.NewTimer(c.cfg.fsProbeTimeout)
	defer timer.Stop()
	select {
	case r := <-res:
		if r.err != nil {
			return unix.Statfs_t{}, false, false
		}
		return r.st, false, true
	case <-timer.C:
		return unix.Statfs_t{}, true, false
	}
}

// collectFilesystem emits per-mount inode gauges plus the
// probe_stalled signal for EVERY configured target — a 0 means the
// probe answered in time (even with an error), so "reachable but
// boring" stays distinguishable from "never probed". Inode gauges
// emit only on a successful statfs — a failed/hung probe emits no
// fake numbers. A successful probe also exports the ST_RDONLY flag
// (W5.3): one read-only mount latches state-filesystem-readonly for
// nodereporter's FilesystemReadOnly condition.
func (c *Collector) collectFilesystem(ch chan<- prometheus.Metric) {
	anyRO := false
	probed := false // at least one statfs answered — the latch's evidence base
	for _, mount := range c.cfg.FilesystemTargets {
		st, stalled, ok := c.probeFS(mount)
		v := 0.0
		if stalled {
			v = 1
		}
		// Edge-triggered log: a stall warns once per mount per
		// episode (a hung mount stays stalled for the whole outage),
		// and recovery logs once — per-scrape repeats would drown
		// the log without adding information.
		c.mu.Lock()
		wasLogged := c.fsStalledLogged[mount]
		if stalled {
			c.fsStalledLogged[mount] = true
		} else {
			delete(c.fsStalledLogged, mount)
		}
		c.mu.Unlock()
		switch {
		case stalled && !wasLogged:
			logger().Warn("hostmetrics: statfs probe exceeded deadline — "+
				"possible hung mount",
				"mount", mount,
				"timeout", c.cfg.fsProbeTimeout)
		case !stalled && wasLogged:
			logger().Info("hostmetrics: statfs probe answering again — "+
				"mount recovered",
				"mount", mount)
		}
		ch <- prometheus.MustNewConstMetric(c.descFSProbeStalled,
			prometheus.GaugeValue, v, c.cfg.NodeName, mount)
		if !ok {
			continue
		}
		probed = true
		ro := 0.0
		if st.Flags&unix.ST_RDONLY != 0 {
			ro = 1
			anyRO = true
		}
		ch <- prometheus.MustNewConstMetric(c.descFSReadonly,
			prometheus.GaugeValue, ro, c.cfg.NodeName, mount)
		ch <- prometheus.MustNewConstMetric(c.descFSInodesTotal,
			prometheus.GaugeValue, float64(st.Files), c.cfg.NodeName, mount)
		ch <- prometheus.MustNewConstMetric(c.descFSInodesFree,
			prometheus.GaugeValue, float64(st.Ffree), c.cfg.NodeName, mount)
		if st.Files > 0 && st.Ffree <= st.Files {
			// Ffree > Files wraps uint64 — pseudo/network filesystems
			// can report free inodes above the total.
			used := float64(st.Files-st.Ffree) / float64(st.Files)
			ch <- prometheus.MustNewConstMetric(c.descFSInodesRatio,
				prometheus.GaugeValue, used, c.cfg.NodeName, mount)
		}
	}
	c.updateFSReadonlyLatch(anyRO, probed)
}

// updateFSReadonlyLatch drives state-filesystem-readonly (W5.3):
// set when ANY successfully probed mount carries ST_RDONLY, cleared
// once every probed mount is rw again. probed=false (every statfs
// failed or stalled) leaves the latch untouched — inconclusive
// evidence must neither set nor clear it, the same rule the
// overload latch follows on an unparseable PSI file.
func (c *Collector) updateFSReadonlyLatch(anyRO, probed bool) {
	p := filepath.Join(c.cfg.WatchdogStateDir, "state-filesystem-readonly")
	_, err := os.Stat(p)
	switch {
	case anyRO && err != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
		if werr := os.WriteFile(tmp, []byte(content), 0o644); werr != nil {
			logger().Warn("hostmetrics: filesystem-readonly latch write failed",
				"path", p, "error", werr)
		} else if rerr := os.Rename(tmp, p); rerr != nil {
			logger().Warn("hostmetrics: filesystem-readonly latch install failed",
				"path", p, "error", rerr)
		} else {
			logger().Warn("hostmetrics: filesystem-readonly latch set — "+
				"a probed mount reports ST_RDONLY",
				"path", p)
		}
	case probed && !anyRO && err == nil:
		if rerr := os.Remove(p); rerr != nil {
			logger().Warn("hostmetrics: filesystem-readonly latch remove failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: filesystem-readonly latch cleared — "+
				"all probed mounts rw again",
				"path", p)
		}
	}
}

// --- H6: FD + socket pressure (file-nr, sockstat) ---

// collectFileFD parses /proc/sys/fs/file-nr — "allocated unused
// max" (fields 0 and 2; the middle "unused" field is always ~0 on
// modern kernels). Absent/malformed → no series.
func (c *Collector) collectFileFD(ch chan<- prometheus.Metric) {
	data, err := os.ReadFile(c.cfg.FileNRFile)
	if err != nil {
		return
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return
	}
	alloc, errA := strconv.ParseFloat(f[0], 64)
	maxFD, errM := strconv.ParseFloat(f[2], 64)
	if errA != nil || errM != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descFileFDAlloc,
		prometheus.GaugeValue, alloc, c.cfg.NodeName)
	ch <- prometheus.MustNewConstMetric(c.descFileFDMax,
		prometheus.GaugeValue, maxFD, c.cfg.NodeName)
	if maxFD > 0 {
		ch <- prometheus.MustNewConstMetric(c.descFileFDRatio,
			prometheus.GaugeValue, alloc/maxFD, c.cfg.NodeName)
	}
}

// collectSockstat parses /proc/1/net/sockstat — section lines of
// "NAME: key N key N ..." pairs ("sockets: used 1847",
// "TCP: inuse 25 orphan 0 tw 4 alloc 1200 mem 456"). Each gauge
// emits only when its key parsed — a node missing a section keeps
// that series absent rather than 0.
func (c *Collector) collectSockstat(ch chan<- prometheus.Metric) {
	f, err := os.Open(c.cfg.SockstatFile)
	if err != nil {
		return
	}
	defer f.Close()
	var tcpInuse, tcpOrphan, tcpTW, tcpCW, sockUsed float64
	var tcpInuseOK, tcpOrphanOK, tcpTWOK, tcpCWOK, sockUsedOK bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// "NAME:" + an even number of key/value fields → odd total.
		if len(fields) < 3 || len(fields)%2 == 0 {
			continue
		}
		kv := make(map[string]float64, len(fields)/2)
		good := true
		for i := 1; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i+1], 64)
			if err != nil {
				good = false
				break
			}
			kv[fields[i]] = v
		}
		if !good {
			continue // malformed line — never emit junk
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "TCP":
			if v, ok := kv["inuse"]; ok {
				tcpInuse, tcpInuseOK = v, true
			}
			if v, ok := kv["orphan"]; ok {
				tcpOrphan, tcpOrphanOK = v, true
			}
			if v, ok := kv["tw"]; ok {
				tcpTW, tcpTWOK = v, true
			}
			// close_wait/cw — kernels that report it carry hung
			// half-closed sockets here (W8-KR3 companion metric).
			if v, ok := kv["close_wait"]; ok {
				tcpCW, tcpCWOK = v, true
			} else if v, ok := kv["cw"]; ok {
				tcpCW, tcpCWOK = v, true
			}
		case "sockets":
			if v, ok := kv["used"]; ok {
				sockUsed, sockUsedOK = v, true
			}
		}
	}
	if sockUsedOK {
		ch <- prometheus.MustNewConstMetric(c.descSockUsed,
			prometheus.GaugeValue, sockUsed, c.cfg.NodeName)
	}
	if tcpInuseOK {
		ch <- prometheus.MustNewConstMetric(c.descSockTCPInuse,
			prometheus.GaugeValue, tcpInuse, c.cfg.NodeName)
	}
	if tcpOrphanOK {
		ch <- prometheus.MustNewConstMetric(c.descSockTCPOrphan,
			prometheus.GaugeValue, tcpOrphan, c.cfg.NodeName)
	}
	if tcpTWOK {
		ch <- prometheus.MustNewConstMetric(c.descSockTCPTW,
			prometheus.GaugeValue, tcpTW, c.cfg.NodeName)
	}
	if tcpCWOK {
		ch <- prometheus.MustNewConstMetric(c.descSockTCPCW,
			prometheus.GaugeValue, tcpCW, c.cfg.NodeName)
	}
}

// --- 2.4: on-disk PKI cert expiry ---

// pkiCertFiles expands one PKICertPaths entry: a directory yields
// its *.crt/*.pem children one level deep, a regular file is taken
// as-is.
func pkiCertFiles(path string) []string {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !fi.IsDir() {
		return []string{path}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); strings.HasSuffix(n, ".crt") || strings.HasSuffix(n, ".pem") {
			files = append(files, filepath.Join(path, n))
		}
	}
	sort.Strings(files)
	return files
}

// pemDaysLeft returns days until the EARLIEST notAfter of any cert
// block in the PEM data — a bundle file exports its worst member.
// ok=false when no block parses.
func pemDaysLeft(data []byte, now int64) (float64, bool) {
	var min time.Time
	ok := false
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue // a non-cert PEM block must not kill the file
		}
		if !ok || cert.NotAfter.Before(min) {
			min, ok = cert.NotAfter, true
		}
	}
	if !ok {
		return 0, false
	}
	// math.Floor, not truncation: -1.9d must read -2, not -1 — an
	// already-expired cert rounds AWAY from zero like the positive
	// side does toward it.
	return math.Floor(float64(min.Unix()-now) / 86400), true
}

// collectPKICerts emits days-left per cert file — absent when no
// cert under the source parses (same no-fake-0 rule as the nebula
// cert gauge). The path label strips the HostRoot mount prefix so
// pods and standalone hosts emit identical series.
func (c *Collector) collectPKICerts(ch chan<- prometheus.Metric) {
	now := c.cfg.nowFn().Unix()
	for _, src := range c.cfg.PKICertPaths {
		for _, f := range pkiCertFiles(src) {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			days, ok := pemDaysLeft(data, now)
			if !ok {
				continue
			}
			// Keep the leading slash: HostRoot="/" strips it while
			// HostRoot="/host" leaves it — the label must read
			// identically on pods and standalone hosts.
			label := strings.TrimPrefix(f, c.cfg.HostRoot)
			if !strings.HasPrefix(label, "/") {
				label = "/" + label
			}
			ch <- prometheus.MustNewConstMetric(c.descPKIDays,
				prometheus.GaugeValue, days, c.cfg.NodeName, label)
		}
	}
}

// --- A1: inotify instances/watches pressure ---
var pidDirRe = regexp.MustCompile(`^[0-9]+$`)

// inotifyFDTarget is the /proc/<pid>/fd/<fd> symlink target the
// kernel gives an inotify group fd — the same source
// node_exporter/procfs uses to count instances.
const inotifyFDTarget = "anon_inode:inotify"

// sweepInotify walks every /proc/<pid>/fd/* counting inotify
// INSTANCES by fd symlink target and WATCHES by `inotify wd:` lines
// in the matching fdinfo file. The symlink read is mandatory: an
// inotify group holding ZERO watches emits no identifying line in
// fdinfo — the classic inotify_init() fd leak (exactly what the
// instances-used ratio exists to catch) is invisible to any
// fdinfo-only count while the host races max_user_instances.
func (c *Collector) sweepInotify() (inst, watch uint64, top []inotifyConsumer) {
	pids, err := os.ReadDir(c.cfg.ProcRoot)
	if err != nil {
		return 0, 0, nil
	}
	cons := map[int]*inotifyConsumer{}
	for _, p := range pids {
		if !p.IsDir() || !pidDirRe.MatchString(p.Name()) {
			continue
		}
		pid, _ := strconv.Atoi(p.Name())
		fds, err := os.ReadDir(filepath.Join(c.cfg.ProcRoot, p.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(
				c.cfg.ProcRoot, p.Name(), "fd", fd.Name()))
			if err != nil || target != inotifyFDTarget {
				continue
			}
			// fdinfo may be absent or unreadable for a raced fd —
			// the instance still counts, with zero watches.
			var w uint64
			if data, rerr := os.ReadFile(filepath.Join(
				c.cfg.ProcRoot, p.Name(), "fdinfo", fd.Name())); rerr == nil {
				w = uint64(strings.Count(string(data), "inotify wd:"))
			}
			inst++
			watch += w
			cc := cons[pid]
			if cc == nil {
				cc = &inotifyConsumer{pid: pid}
				cons[pid] = cc
			}
			cc.instances++
			cc.watches += w
		}
	}
	for _, cc := range cons {
		data, err := os.ReadFile(filepath.Join(
			c.cfg.ProcRoot, strconv.Itoa(cc.pid), "comm"))
		if err == nil {
			cc.name = strings.TrimSpace(string(data))
		}
	}
	all := make([]inotifyConsumer, 0, len(cons))
	for _, cc := range cons {
		all = append(all, *cc)
	}
	slices.SortFunc(all, func(a, b inotifyConsumer) int {
		if a.watches != b.watches {
			return cmp.Compare(b.watches, a.watches)
		}
		return cmp.Compare(a.pid, b.pid)
	})
	if len(all) > 3 {
		all = all[:3]
	}
	return inst, watch, all
}

// inotifySnapshot returns the cached sweep, re-walking the procfs
// at most once per InotifyScanInterval.
func (c *Collector) inotifySnapshot() (uint64, uint64, []inotifyConsumer) {
	c.mu.Lock()
	if c.cfg.nowFn().Sub(c.inoAt) < c.cfg.InotifyScanInterval {
		inst, watch, top := c.inoInstances, c.inoWatches, c.inoTop
		c.mu.Unlock()
		return inst, watch, top
	}
	c.mu.Unlock()

	// The /proc/*/fdinfo sweep can take seconds on a busy node —
	// run it WITHOUT mu so concurrent scrapes aren't blocked for
	// the whole walk (mu also guards every other collector
	// section's bookkeeping). Two scrapes may then sweep in
	// parallel; the later store wins, harmless for a cache.
	inst, watch, top := c.sweepInotify()
	c.mu.Lock()
	c.inoInstances, c.inoWatches, c.inoTop = inst, watch, top
	c.inoAt = c.cfg.nowFn()
	c.mu.Unlock()
	return inst, watch, top
}

// warnInotifyTop edge-logs the top-3 holder report once per
// over-threshold episode (the fsStalledLogged pattern).
func (c *Collector) warnInotifyTop(kind string, over bool,
	top []inotifyConsumer) {
	c.mu.Lock()
	var warned *bool
	if kind == "instances" {
		warned = &c.inoWarnedInst
	} else {
		warned = &c.inoWarnedWatch
	}
	was := *warned
	*warned = over
	c.mu.Unlock()
	if !over || was {
		return
	}
	parts := make([]string, 0, len(top))
	for _, p := range top {
		parts = append(parts, fmt.Sprintf("pid=%d %s instances=%d watches=%d",
			p.pid, p.name, p.instances, p.watches))
	}
	logger().Warn("hostmetrics: inotify "+kind+" above "+
		strconv.FormatFloat(inotifyWarnRatio*100, 'f', -1, 64)+
		"% of the limit — top holders: "+strings.Join(parts, "; "),
		"kind", kind)
}

// collectInotify emits the two fill ratios — each only when its own
// limit file parses (same per-source rule as conntrack).
func (c *Collector) collectInotify(ch chan<- prometheus.Metric) {
	inst, watch, top := c.inotifySnapshot()
	maxI, instOK := readUintFile(c.cfg.InotifyMaxInstancesFile)
	maxW, watchOK := readUintFile(c.cfg.InotifyMaxWatchesFile)
	if instOK && maxI > 0 {
		r := float64(inst) / float64(maxI)
		ch <- prometheus.MustNewConstMetric(c.descInotifyInst,
			prometheus.GaugeValue, r, c.cfg.NodeName)
		c.warnInotifyTop("instances", r >= inotifyWarnRatio, top)
	}
	if watchOK && maxW > 0 {
		r := float64(watch) / float64(maxW)
		ch <- prometheus.MustNewConstMetric(c.descInotifyWatches,
			prometheus.GaugeValue, r, c.cfg.NodeName)
		c.warnInotifyTop("watches", r >= inotifyWarnRatio, top)
	}
}

// --- A2: zombie count + cgroup pids pressure ---

// collectZombies counts state Z processes under ProcRoot — the
// state char sits right after the LAST ')' because comm can
// contain spaces and parens (same trick as workerhygiene's
// pidLive). Emits only when the proc root scans.
func (c *Collector) collectZombies(ch chan<- prometheus.Metric) {
	entries, err := os.ReadDir(c.cfg.ProcRoot)
	if err != nil {
		return
	}
	var n, dstate float64
	for _, e := range entries {
		if !e.IsDir() || !pidDirRe.MatchString(e.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.cfg.ProcRoot, e.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(data)
		if i := strings.LastIndexByte(s, ')'); i >= 0 {
			if f := strings.Fields(s[i+1:]); len(f) > 0 {
				switch f[0] {
				case "Z":
					n++
				case "D": // W7-H1: uninterruptible-sleep count, same scan
					dstate++
				}
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(c.descZombies,
		prometheus.GaugeValue, n, c.cfg.NodeName)
	ch <- prometheus.MustNewConstMetric(c.descDState,
		prometheus.GaugeValue, dstate, c.cfg.NodeName)
}

// collectCgroupPids emits pids.current/pids.max per slice — a
// missing or non-numeric ("max") limit yields no ratio (never a
// fake 0). The pids.current/pids.max filenames are cgroup-v2
// unified-hierarchy only — k0s hosts are v2; on a v1 host the
// files simply don't exist and no series emits.
func (c *Collector) collectCgroupPids(ch chan<- prometheus.Metric) {
	for _, slice := range c.cfg.CgroupPidsSlices {
		cur, ok := readUintFile(filepath.Join(
			c.cfg.CgroupRoot, slice, "pids.current"))
		if !ok {
			continue
		}
		mx, ok := readUintFile(filepath.Join(
			c.cfg.CgroupRoot, slice, "pids.max"))
		if !ok || mx == 0 {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.descCgroupPids,
			prometheus.GaugeValue, float64(cur)/float64(mx),
			c.cfg.NodeName, slice)
	}
}

// --- B4: MTU drift (cilium datapath vs nebula overlay) ---

// mtuOfIface parses /sys/class/net/<iface>/mtu.
func mtuOfIface(sysnet, iface string) (int64, bool) {
	v, ok := readUintFile(filepath.Join(sysnet, iface, "mtu"))
	if !ok {
		return 0, false
	}
	return int64(v), true
}

// jsonFindInts collects EVERY numeric value of a key named `key`
// (case-insensitive) under decoded JSON — maps AND arrays are
// descended. The cilium runtime config nests its MTU differently
// across agent versions and may carry several `mtu` keys; a
// "first match" walk is nondeterministic because Go map iteration
// order is random.
func jsonFindInts(v any, key string, out *[]int64) {
	switch n := v.(type) {
	case map[string]any:
		for k, val := range n {
			if strings.EqualFold(k, key) {
				if f, ok := val.(float64); ok {
					*out = append(*out, int64(f))
				}
			}
			jsonFindInts(val, key, out)
		}
	case []any:
		for _, val := range n {
			jsonFindInts(val, key, out)
		}
	}
}

// runtimeConfigMTU is the fallback MTU source when the cilium_net
// interface is absent: agent-runtime-config.json under HostRoot.
// With several `mtu` keys the MAX wins — deterministic, and the
// drift check wants the worst-case datapath MTU anyway.
func runtimeConfigMTU(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return 0, false
	}
	var vals []int64
	jsonFindInts(v, "mtu", &vals)
	if len(vals) == 0 {
		return 0, false
	}
	return slices.Max(vals), true
}

// wgEncapOverheadBytes is the WireGuard encapsulation overhead the
// cilium_wg0 MTU must leave under the nebula overlay MTU (W9
// double-encap guard — same constant as workerhygiene).
const wgEncapOverheadBytes = 60

// collectMTUDrift emits 1 when a pod-datapath MTU exceeds what the
// overlay path can carry — a pod holding MTU 1500 dies silently on
// FRAG_NEEDED through neb1 (1300). Two datapaths are checked:
// cilium_net (sysfs, falling back to agent-runtime-config.json)
// must stay <= neb, and cilium_wg0 must stay <= neb-60 to leave
// room for the WG header inside the double-encapsulated path. The
// series emits when the overlay MTU resolves AND at least one
// datapath MTU resolves; absent interfaces simply don't vote.
func (c *Collector) collectMTUDrift(ch chan<- prometheus.Metric) {
	neb, ok := mtuOfIface(c.cfg.SysClassNet, c.cfg.NebulaIface)
	if !ok {
		return
	}
	cil, cilOK := mtuOfIface(c.cfg.SysClassNet, c.cfg.CiliumIface)
	if !cilOK {
		cil, cilOK = runtimeConfigMTU(c.cfg.CiliumRuntimeConfig)
	}
	wg, wgOK := mtuOfIface(c.cfg.SysClassNet, c.cfg.CiliumWG0Iface)
	if !cilOK && !wgOK {
		return
	}
	drift := 0.0
	if (cilOK && cil > neb) || (wgOK && wg > neb-wgEncapOverheadBytes) {
		drift = 1
	}
	ch <- prometheus.MustNewConstMetric(c.descMTUDrift,
		prometheus.GaugeValue, drift, c.cfg.NodeName)
}

// --- W5.7: PSI memory/IO pressure + vmstat swap-thrash counters ---

// psiAvg60Full parses BOTH avg60 values of a PSI file — the "some"
// line (any-task stalled) and the "full" line (all-tasks stalled).
// A missing/unreadable file or a missing field reports that side as
// unparsed — PSI may be compiled out of the kernel and emitting a
// fake 0 would hide that.
func psiAvg60Full(path string) (some, full float64, someOK, fullOK bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || (f[0] != "some" && f[0] != "full") {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg60" {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			if f[0] == "some" {
				some, someOK = x, true
			} else {
				full, fullOK = x, true
			}
		}
	}
	return some, full, someOK, fullOK
}

// vmstatCounters extracts the named cumulative counters from
// /proc/vmstat — "key value" per line (pswpin/pswpout for W5.7).
// Missing keys are simply absent from the map.
func vmstatCounters(path string, keys ...string) map[string]uint64 {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	out := map[string]uint64{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !want[f[0]] {
			continue
		}
		if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
			out[f[0]] = v
		}
	}
	return out
}

// collectMemoryIO emits the PSI memory/io some+full avg60 gauges and
// the vmstat pswpin/pswpout counters — each only when its own source
// parses (a kernel without PSI or a missing vmstat yields absent
// series, never a fake 0 — same emission rule as conntrack).
func (c *Collector) collectMemoryIO(ch chan<- prometheus.Metric) {
	if some, full, someOK, fullOK := psiAvg60Full(c.cfg.PSIMemoryFile); someOK || fullOK {
		if someOK {
			ch <- prometheus.MustNewConstMetric(c.descPSIMemSome,
				prometheus.GaugeValue, some, c.cfg.NodeName)
		}
		if fullOK {
			ch <- prometheus.MustNewConstMetric(c.descPSIMemFull,
				prometheus.GaugeValue, full, c.cfg.NodeName)
		}
	}
	if some, full, someOK, fullOK := psiAvg60Full(c.cfg.PSIIOFile); someOK || fullOK {
		if someOK {
			ch <- prometheus.MustNewConstMetric(c.descPSIIOSome,
				prometheus.GaugeValue, some, c.cfg.NodeName)
		}
		if fullOK {
			ch <- prometheus.MustNewConstMetric(c.descPSIIOFull,
				prometheus.GaugeValue, full, c.cfg.NodeName)
		}
	}
	vm := vmstatCounters(c.cfg.VMStatFile, "pswpin", "pswpout")
	for _, k := range []struct {
		key  string
		desc *prometheus.Desc
	}{
		{"pswpin", c.descPSWPIn},
		{"pswpout", c.descPSWPOut},
	} {
		if v, ok := vm[k.key]; ok {
			ch <- prometheus.MustNewConstMetric(k.desc,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
	}
}

// --- W7: systemd scope footprint, ARP entries, cgroup memory.events ---

// collectSystemdScopes counts cri-containerd-*.scope dirs under the
// kubepods cgroup slice (W7-H2): a leaking abandoned-scope
// footprint is what slows every PID 1 D-Bus call down before
// systemctl-level symptoms appear. Counted directly in the cgroup
// fs — no systemctl fork per scrape. Emits only when the slice
// root exists.
func (c *Collector) collectSystemdScopes(ch chan<- prometheus.Metric) {
	root := filepath.Join(c.cfg.CgroupRoot, "kubepods.slice")
	if _, err := os.Stat(root); err != nil {
		return
	}
	var n float64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), "cri-containerd-") &&
			strings.HasSuffix(d.Name(), ".scope") {
			n++
		}
		return nil
	})
	ch <- prometheus.MustNewConstMetric(c.descSystemdScopes,
		prometheus.GaugeValue, n, c.cfg.NodeName)
}

// collectARP counts /proc/net/arp entry rows (header skipped) — the
// ARP neighbour-table fill half of W7-H5 (gc_thresh overflow drops
// outbound packets while every other signal stays green). Emits
// only when the file reads.
func (c *Collector) collectARP(ch chan<- prometheus.Metric) {
	data, err := os.ReadFile(c.cfg.ARPTableFile)
	if err != nil {
		return
	}
	var n float64
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if i == 0 || len(strings.Fields(line)) == 0 {
			continue
		}
		n++
	}
	ch <- prometheus.MustNewConstMetric(c.descARPEntries,
		prometheus.GaugeValue, n, c.cfg.NodeName)
}

// collectCgroupMemEvents reads memory.events of the configured
// system.slice units (W7-H6): a climbing `high` count is
// direct-reclaim throttling evidence — the unit freezes without an
// OOMKill, the classic healthcheck-timeout-with-no-logs gray
// failure; `oom_kill` counts the kills that do happen. Each series
// emits only when its own field parses.
func (c *Collector) collectCgroupMemEvents(ch chan<- prometheus.Metric) {
	for _, unit := range c.cfg.CgroupMemUnits {
		ev := vmstatCounters(filepath.Join(c.cfg.CgroupRoot,
			"system.slice", unit, "memory.events"), "high", "oom_kill")
		if v, ok := ev["high"]; ok {
			ch <- prometheus.MustNewConstMetric(c.descCgMemHigh,
				prometheus.CounterValue, float64(v), c.cfg.NodeName, unit)
		}
		if v, ok := ev["oom_kill"]; ok {
			ch <- prometheus.MustNewConstMetric(c.descCgMemOOMKill,
				prometheus.CounterValue, float64(v), c.cfg.NodeName, unit)
		}
	}
}

// --- node-exporter textfile rendering (standalone prom_emit port) ---

// TextfileName is the prom file the standalone writer renders —
// node-watchdog.prom, the same name prom_emit used.
const TextfileName = "node-watchdog.prom"

// textfileTmpName is WriteTextfile's staging name. It MUST NOT
// match node_exporter's *.prom textfile glob — the collector would
// ingest a partially-written file (and a ".*-name.prom" prefix
// scheme DOES match: glob * swallows the leading dot).
const textfileTmpName = TextfileName + ".tmp"

// --- W9: OpenEBS LocalPV per-PVC dir bytes ---

// collectLocalPVUsage emits node_host_agent_localpv_dir_bytes per
// pvc-* volume dir under OpenEBSLocalDir. The du walk is cached
// for LocalPVScanInterval — a node with hundreds of LocalPVs would
// otherwise pay a full filesystem walk per PVC per scrape. A
// missing/unreadable root emits nothing (absent, not 0 — "no
// local-path volumes here" must stay distinguishable from "zero
// bytes").
func (c *Collector) collectLocalPVUsage(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	fresh := c.lpvBytes != nil &&
		c.cfg.nowFn().Sub(c.lpvAt) < c.cfg.LocalPVScanInterval
	cached := c.lpvBytes
	c.mu.Unlock()
	bytes := cached
	if !fresh {
		if walked := c.walkLocalPVDirs(); walked != nil {
			c.mu.Lock()
			c.lpvBytes = walked
			c.lpvAt = c.cfg.nowFn()
			c.mu.Unlock()
			bytes = walked
		}
		// A failed walk (root unreadable) keeps serving the last
		// good snapshot rather than blanking every series.
	}
	for pvc, b := range bytes {
		ch <- prometheus.MustNewConstMetric(c.descLocalPVDirBytes,
			prometheus.GaugeValue, float64(b), c.cfg.NodeName, pvc)
	}
}

// walkLocalPVDirs sums the bytes under every pvc-* dir in
// OpenEBSLocalDir. Returns nil when the root can't be listed —
// callers keep the previous cache. Each volume's walk is bounded
// at localPVMaxWalkEntries entries: a runaway PVC with millions of
// files must not stall the scrape; the emitted count is then a
// partial sum (documented on the metric).
func (c *Collector) walkLocalPVDirs() map[string]int64 {
	entries, err := os.ReadDir(c.cfg.OpenEBSLocalDir)
	if err != nil {
		if !os.IsNotExist(err) {
			logger().Debug("hostmetrics: openebs local dir unreadable — "+
				"localpv metrics keep previous snapshot",
				"dir", c.cfg.OpenEBSLocalDir, "error", err)
		}
		return nil
	}
	out := map[string]int64{}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "pvc-") {
			continue
		}
		out[e.Name()] = dirSizeBytes(
			filepath.Join(c.cfg.OpenEBSLocalDir, e.Name()),
			localPVMaxWalkEntries)
	}
	return out
}

// dirSizeBytes is a bounded du: sums regular-file sizes under root,
// stopping after maxEntries entries. Unreadable entries are
// skipped — a permission-denied subtree under-counts rather than
// failing the whole volume.
func dirSizeBytes(root string, maxEntries int) int64 {
	var total int64
	n := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, never fatal
		}
		n++
		if n > maxEntries {
			return fs.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}

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
				sb.WriteString(escapeLabelValue(l.GetValue()))
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

	var b strings.Builder
	for _, name := range names {
		typ := "gauge"
		if counterSeries[name] {
			typ = "counter"
		}
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n",
			name, metaByName[name].help, name, typ)
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
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, textfileTmpName)
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, TextfileName))
}

// escapeLabelValue applies the textfile-format label escaping
// (backslash, double-quote and newline).
func escapeLabelValue(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

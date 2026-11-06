// config.go — Config carries the host paths (all test-injectable)
// and applyDefaults fills every unset knob; EnvDeps/ConfigFromEnv
// live in config_env.go. Split out of hostmetrics.go — the
// workerhygiene/config.go precedent.
package hostmetrics

import (
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Config carries the host paths — all test-injectable.
type Config struct {
	NodeName         string
	WatchdogStateDir string
	// WatchdogLogFile is the shared appended watchdog log — the
	// latch ticker's STATE-ENTER lines must land in the FILE
	// nodereporter tails for its Event rules (Store.AppendLog's
	// slog mirror alone never reaches it). Same path
	// workerhygiene/nethealth/controllerhygiene write.
	WatchdogLogFile string
	SysClassNet     string
	NebulaIface     string
	RouteFile       string
	K0sConfigFile   string
	K0sUnitFile     string
	NebulaCertFile  string
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
	// LocalPortRangeFile is /proc/sys/net/ipv4/ip_local_port_range
	// — the ephemeral source-port pool width the W12-KR3 sockstat
	// saturation ratio divides by; ProcNetTCP/ProcNetTCP6 are the
	// /proc/1/net/tcp{,6} tables the CLOSE_WAIT count scans.
	LocalPortRangeFile string
	ProcNetTCP         string
	ProcNetTCP6        string
	// NetstatFile is /proc/1/net/netstat (TcpExt counters) and
	// SNMPFile /proc/1/net/snmp (Ip/Udp counters) — the kernel
	// TCP/IP stack grey-failure series.
	NetstatFile string
	SNMPFile    string
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
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultWatchdogLogFile
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
	if c.LocalPortRangeFile == "" {
		c.LocalPortRangeFile = defaultLocalPortRangeFile
	}
	if c.ProcNetTCP == "" {
		c.ProcNetTCP = defaultProcNetTCP
	}
	if c.ProcNetTCP6 == "" {
		c.ProcNetTCP6 = defaultProcNetTCP6
	}
	if c.NetstatFile == "" {
		c.NetstatFile = defaultNetstatFile
	}
	if c.SNMPFile == "" {
		c.SNMPFile = defaultSNMPFile
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

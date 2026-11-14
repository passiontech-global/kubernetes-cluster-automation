// config.go — Config carries the host paths (all test-injectable)
// and applyDefaults fills every unset knob; EnvDeps/ConfigFromEnv
// live in config_env.go. Split out of hostmetrics.go — the
// workerhygiene/config.go precedent.
package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/k0sconfig"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Config carries the host paths — all test-injectable.
type Config struct {
	// Base is the shared watchdog-subsystem block — the watchdog
	// state dir, WatchdogLogFile (the shared appended watchdog log
	// the latch ticker's STATE-ENTER lines must land in — the FILE
	// nodereporter tails for its Event rules; Store.AppendLog's
	// slog mirror alone never reaches it, same path
	// workerhygiene/nethealth/controllerhygiene write), HostRoot,
	// ProcRoot and the clock cell splice (subframe.FromDeps).
	subframe.Base
	NodeName       string
	SysClassNet    string
	NebulaIface    string
	RouteFile      string
	K0sConfigFile  string
	K0sUnitFile    string
	NebulaCertFile string
	// PSIFile is /proc/pressure/cpu — drives the overload gauge +
	// state-node-overloaded latch.
	PSIFile string
	// PSIMemoryFile/PSIIOFile are /proc/pressure/{memory,io} — the
	// psi-swap-thrash some/full avg60 gauges (memory-reclaim and block-IO stall
	// evidence the cpu PSI can't see). Missing files (PSI off in the
	// kernel) simply emit no series.
	PSIMemoryFile string
	PSIIOFile     string
	// VMStatFile is /proc/vmstat — pswpin/pswpout swap-thrash
	// counters (psi-swap-thrash).
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
	// MountinfoFile is /proc/1/mountinfo — the
	// mountinfo-entries gauge (line count).
	MountinfoFile string
	// LocalPortRangeFile is /proc/sys/net/ipv4/ip_local_port_range
	// — the ephemeral source-port pool width the conntrack-port-pressure sockstat
	// saturation ratio divides by. (The CLOSE_WAIT/tuple tables moved
	// to the TCPCensusFn netlink dump — no file path involved.)
	LocalPortRangeFile string
	// NetstatFile is /proc/1/net/netstat (TcpExt counters) and
	// SNMPFile /proc/1/net/snmp (Ip/Udp counters) — the kernel
	// TCP/IP stack grey-failure series.
	NetstatFile string
	SNMPFile    string
	// FilesystemTargets are the mounts statfs'd per scrape for the
	// inode gauges (H3) and the hung-mount probe (H7).
	FilesystemTargets []string
	// Base.HostRoot prefixes host-side paths that live under the
	// DaemonSet's host-fs mount (PKI dirs, the cilium runtime
	// config) — "/host" in the pod, "/" standalone. Empty
	// auto-detects: "/host" when that dir exists, else "/".
	// PKICertPaths are the cert sources (2.4): each entry is either
	// a directory scanned one level deep for *.crt/*.pem files or a
	// single cert file — default the k0s/kine PKI paths under
	// HostRoot. The {path} label carries the HostRoot-relative path
	// so the series reads identically on pods and standalone hosts.
	PKICertPaths []string
	// Base.ProcRoot is the host /proc — the inotify fdinfo and
	// zombie scans walk it (hostPID:true makes the pod's /proc the
	// host's).
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
	// encapsulation overhead (double-encap guard);
	// CiliumRuntimeConfig is the fallback MTU source
	// (agent-runtime-config.json under HostRoot).
	CiliumIface         string
	CiliumWG0Iface      string
	CiliumRuntimeConfig string
	// ConntrackStatFile is /proc/net/stat/nf_conntrack — the
	// per-CPU conntrack counters (insert_failed/drop for conntrack-arp-pressure);
	// ARPTableFile is /proc/net/arp — the ARP neighbour-table fill
	// gauge.
	ConntrackStatFile string
	ARPTableFile      string
	// ClocksourceCurrentFile is sysfs clocksource0's current_clocksource
	// and ClocksourceAvailableFile its available_clocksource — the
	// The non-TSC drift gauge (and kvm-clock restore write) reads
	// both every cycle.
	ClocksourceCurrentFile   string
	ClocksourceAvailableFile string
	// CgroupMemUnits are the system.slice unit names whose
	// memory.events feed the memory-events-reclaim high/oom_kill counters.
	CgroupMemUnits []string
	// KeyUsersFile is /proc/key-users — the kernel-keys-pressure kernel keyring
	// quota source (per-UID usage vs maxkeys).
	KeyUsersFile string
	// OpenEBSLocalDir is the localpv-provisioner hostPath root —
	// /var/openebs/local in both pod and standalone mode (the
	// DaemonSet mounts it at the same path, not under /host).
	// LocalPVScanInterval caches the per-PVC du walk: a full
	// filesystem walk per PVC per scrape is too heavy on a node
	// with hundreds of volumes (localpv scan).
	OpenEBSLocalDir     string
	LocalPVScanInterval time.Duration
	// FSBytesTargets are the mounts statfs'd per scrape for the
	// run-tmpfs used-BYTE ratio — tmpfs fills by bytes while the inode
	// gauges still read idle (/run's sockets die first). Defaults
	// are HostRoot-joined for run/k0s and literal for the
	// shared-layout paths (/dev/shm, /var/openebs/local).
	FSBytesTargets []string
	// ContainerdMetaDBFile is the containerd bbolt metadata db —
	// the metadb-bloat bloat gauge (HostRoot-joined by applyDefaults).
	ContainerdMetaDBFile string
	// BpffsDir is the bpffs mount the ebpf-inventory eBPF inventory walks
	// for pinned objects (HostRoot-joined by applyDefaults — pod mode
	// reads /host/sys/fs/bpf, the container's own /sys is wrong);
	// EBPFScanInterval caches the /proc/*/fdinfo sweep like
	// InotifyScanInterval does for inotify.
	BpffsDir         string
	EBPFScanInterval time.Duration
	// Standalone marks systemd (non-pod) mode — informational only;
	// the latch ticker runs regardless (BUG-H5).
	Standalone bool
	// LatchInterval is the Run() latch-maintenance cadence; <=0 →
	// 30s. Seamed so tests don't wait real seconds.
	LatchInterval time.Duration

	// collectCacheTTL overrides the Collect snapshot TTL — 0 →
	// collectSnapshotTTL (10s); a NEGATIVE value disables the cache
	// (the test fixture pins -1: its scrapes mutate host state
	// between gathers and async probes must converge across them).
	collectCacheTTL time.Duration
	// cpuMeasure replaces the real RUSAGE_THREAD busy-loop for
	// tests: returns (ratio, wallSeconds, ok).
	cpuMeasure func() (ratio, wall float64, ok bool)
	// TCPCensusFn reads pid's netns one-pass NETLINK_SOCK_DIAG census
	// (netlinkx.TCPTables) — the sockstat domain's full connection-table
	// read: per-state histogram + per-tuple hot-spot in one dump.
	// nil → netlinkx.TCPTables.
	TCPCensusFn func(pid int) (netlinkx.TCPCensus, error)
	// adjtimexFn reads kernel clock-sync state (H1) — seam for
	// tests (default unix.Adjtimex).
	adjtimexFn func(*unix.Timex) (int, error)
	// statfsFn probes one mount — seam for tests, including a fake
	// that hangs to exercise the stalled path (default unix.Statfs).
	statfsFn func(string, *unix.Statfs_t) error
	// fsProbeTimeout bounds one statfs probe before the mount is
	// reported stalled — seam so tests don't wait the full 2s.
	fsProbeTimeout time.Duration
	// aioNrFile / aioMaxFile / maxUserNSFile and runHostCmd /
	// kmsgDevicePaths default in applyDefaults; tests override them per
	// Config instance rather than mutating package globals.
	aioNrFile       string
	aioMaxFile      string
	maxUserNSFile   string
	runHostCmd      func(ctx context.Context, argv ...string) (string, error)
	kmsgDevicePaths func(hostRoot string) []string
}

func (c *Config) applyDefaults() {
	// HostRoot resolves FIRST — the host-side file defaults below
	// (k0s.yaml, PKI dirs, cgroup/bpffs roots) join under it so the
	// DaemonSet's /host mount and standalone "/" both land right.
	if c.HostRoot == "" {
		// Auto-detect: "/host" when the DaemonSet mount is there,
		// "/" otherwise (standalone systemd binary on the host).
		if fi, err := os.Stat("/host"); err == nil && fi.IsDir() {
			c.HostRoot = "/host"
		} else {
			c.HostRoot = "/"
		}
	}
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
		// HostRoot-joined — /host/etc/k0s/k0s.yaml in the pod,
		// /etc/k0s/k0s.yaml standalone (EnvK0sConfig's env default
		// gets the same hostPath() wrap in config_env.go).
		c.K0sConfigFile = filepath.Join(c.HostRoot, k0sconfig.DefaultConfigFile)
	}
	if c.K0sUnitFile == "" {
		c.K0sUnitFile = filepath.Join(c.HostRoot, k0sconfig.DefaultUnitFile)
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
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
	}
	if len(c.RemovedFlags) == 0 {
		c.RemovedFlags = k0sconfig.DefaultRemovedFlags
	}
	if len(c.ExpectedKCMArgs) == 0 {
		c.ExpectedKCMArgs = k0sconfig.DefaultExpectedKCMArgs
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
	if c.MountinfoFile == "" {
		c.MountinfoFile = defaultMountinfoFile
	}
	if c.LocalPortRangeFile == "" {
		c.LocalPortRangeFile = defaultLocalPortRangeFile
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
	if c.TCPCensusFn == nil {
		c.TCPCensusFn = netlinkx.TCPTables
	}
	if c.collectCacheTTL == 0 {
		c.collectCacheTTL = collectSnapshotTTL
	}
	if c.fsProbeTimeout <= 0 {
		c.fsProbeTimeout = defaultFSProbeTimeout
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
	if c.ClocksourceCurrentFile == "" {
		// HostRoot-joined — /host/sys/... in the pod, /sys/... on a
		// standalone host; sysfs is a host mount like the PKI dirs.
		c.ClocksourceCurrentFile = filepath.Join(c.HostRoot,
			defaultClocksourceCurrentFile)
	}
	if c.ClocksourceAvailableFile == "" {
		c.ClocksourceAvailableFile = filepath.Join(c.HostRoot,
			defaultClocksourceAvailableFile)
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
	if len(c.FSBytesTargets) == 0 {
		// HostRoot-joined for the host-side mounts ("/host/run",
		// "/host/var/lib/k0s" in pod mode — the run-tmpfs spec paths);
		// /dev/shm and /var/openebs/local mount at the same path in
		// both layouts (OpenEBSLocalDir parity).
		c.FSBytesTargets = []string{
			filepath.Join(c.HostRoot, "run"),
			"/dev/shm",
			filepath.Join(c.HostRoot, "var/lib/k0s"),
			"/var/openebs/local",
		}
	}
	if c.ContainerdMetaDBFile == "" {
		c.ContainerdMetaDBFile = filepath.Join(c.HostRoot, defaultContainerdMetaDB)
	}
	if c.BpffsDir == "" {
		c.BpffsDir = filepath.Join(c.HostRoot, defaultBpffsDir)
	}
	if c.EBPFScanInterval <= 0 {
		c.EBPFScanInterval = defaultEBPFScanInterval
	}
	if c.aioNrFile == "" {
		c.aioNrFile = defaultAIONrFile
	}
	if c.aioMaxFile == "" {
		c.aioMaxFile = defaultAIOMaxFile
	}
	if c.maxUserNSFile == "" {
		c.maxUserNSFile = defaultMaxUserNSFile
	}
	if c.runHostCmd == nil {
		c.runHostCmd = defaultRunHostCmd(c.HostRoot)
	}
	if c.kmsgDevicePaths == nil {
		c.kmsgDevicePaths = defaultKmsgDevicePaths
	}
}

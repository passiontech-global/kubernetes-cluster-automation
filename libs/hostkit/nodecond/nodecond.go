// Package nodecond is the single source of truth for every
// NodeCondition name the node stack writes or consumes — the
// node-host-agent (nodereporter) spells them, the
// node-automation-controller consumes them, and the classification
// lists below pin which group each name belongs to so the two apps
// can no longer drift apart.
//
// The constants are untyped strings: they assign directly to a
// corev1.NodeConditionType at the call sites without this package
// importing k8s.io/api — libs/hostkit stays stdlib-only (depguard).
//
// Where the controller's legacy spellings diverged from the names
// the agent actually emits, the AGENT spelling won — only the
// agent-spelled constants exist here:
//
//	SystemdSessionLeak → SystemdSessionBloat
//	ConntrackExhausted → ConntrackPressure
//	JournaldWedged     → JournaldUnreadable
//	ControlPlaneFrozen → ControlPlaneCertReloadStale
package nodecond

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

// Latch-backed NodeConditions — each maps 1:1 to a state-<name>
// latch the node-host-agent writes (internal/latchdefs) and the
// nodereporter reflects onto Node.Status.Conditions with a fresh
// LastHeartbeatTime every cycle. CiliumMTUDrift and CiliumWGStale
// are the newest members: their workerhygiene latches
// (state-cilium-mtu-drift, state-cilium-wg-peer-wipe) are also
// reflected as conditions so the cluster-side consumers see them.
const (
	// hostmetrics — PSI/load/fs/clock-source collectors.
	NodeOverloaded           = "NodeOverloaded"           // PSI hysteresis load latch
	FilesystemReadOnly       = "FilesystemReadOnly"       // statfs ST_RDONLY + state-fs-readonly evidence
	KernelKeysPressure       = "KernelKeysPressure"       // kernel keyring quota guard
	CPUStealPressure         = "CPUStealPressure"         // hypervisor steal-time guard
	ClocksourceUnstable      = "ClocksourceUnstable"      // clocksource drift/instability guard
	MemoryPSIThrashing       = "MemoryPSIThrashing"       // memory PSI full avg60 thrash
	KernelResourceExhaustion = "KernelResourceExhaustion" // pid/fd table exhaustion (pid-fd-pressure latch)
	KernelPageAllocFailure   = "KernelPageAllocFailure"   // kernel page-allocation failure records (page-alloc-failure latch)
	DiskPreFail              = "DiskPreFail"              // ext4 metadata errors or NVMe SMART pre-fail indicators (disk-prefail latch)
	HardwareCorrupted        = "HardwareCorrupted"        // ECC/EDAC memory poison, fatal MCE, or PCIe/NVMe reset loop (hardware-corrupted latch)
	GPUHardwareError         = "GPUHardwareError"         // NVIDIA GPU fatal Xid or nvidia-uvm driver hang (gpu-hardware-error latch)

	// workerhygiene/kernelfail — the self-healing wave-2 pressure
	// and wedge latches.
	EphemeralPortPressure = "EphemeralPortPressure" // P0.3: 4-tuple ephemeral port or CLOSE_WAIT socket exhaustion
	NeighborTablePressure = "NeighborTablePressure" // P0.4: ARP/NDISC neighbor table pinned past ceiling after flush
	NetfilterLockWedged   = "NetfilterLockWedged"   // P2.11: /run/xtables.lock held across cycles
	CSIRegistrationWedged = "CSIRegistrationWedged" // P1.6: kubelet plugins_registry / CSINode desynced from live CSI node pod

	// workerhygiene — container/CNI/runtime hygiene checks.
	CiliumAgentDown        = "CiliumAgentDown"        // cilium-agent healthz down
	CiliumInitStuck        = "CiliumInitStuck"        // cilium endpoints stuck in init
	CiliumEnvoyDown        = "CiliumEnvoyDown"        // cilium-envoy /ready down
	CiliumIPAMExhausted    = "CiliumIPAMExhausted"    // cilium IPAM pool exhausted
	CiliumBPFMapPressure   = "CiliumBPFMapPressure"   // critical BPF maps above 90% capacity
	CiliumMTUDrift         = "CiliumMTUDrift"         // cilium MTU drift across the overlay
	CiliumWGStale          = "CiliumWGStale"          // stale wireguard peer state wiped
	SpegelMirrorDegraded   = "SpegelMirrorDegraded"   // spegel P2P mirror pod not Ready
	CalicoVethLeak         = "CalicoVethLeak"         // cali* veth leak (CNI DEL missed)
	CalicoFelixDown        = "CalicoFelixDown"        // calico-felix readiness down
	ConntrackPressure      = "ConntrackPressure"      // nf_conntrack table at pressure
	KernelSlabLeak         = "KernelSlabLeak"         // unreclaimable slab above threshold
	CgroupDyingLeak        = "CgroupDyingLeak"        // cgroup v2 dying descendants leak
	SystemdSessionBloat    = "SystemdSessionBloat"    // abandoned logind session scopes
	SystemdUnresponsive    = "SystemdUnresponsive"    // PID1 frozen — manager socket unanswered (systemd-unresponsive latch)
	KubeletPLEGUnhealthy   = "KubeletPLEGUnhealthy"   // PLEG relist latency/lag degrading
	DiskSlowIO             = "DiskSlowIO"             // disk write await + io PSI gray failure
	KernelNetShimDegraded  = "KernelNetShimDegraded"  // socket/softnet drops, shim RSS breach
	KubeletRuntimeStall    = "KubeletRuntimeStall"    // phantom-pods runtime wedge (+syncloop/healthz/watch alts)
	KubeletWatchWedge      = "KubeletWatchWedge"      // kubelet pod-assignment watch wedge
	PodTeardownWedged      = "PodTeardownWedged"      // long-Terminating pod with leftover task
	DNSResolvStale         = "DnsResolvStale"         // DNS pod resolv.conf drifted from host
	JournaldUnreadable     = "JournaldUnreadable"     // journalwatch blindness latch
	KonnectivityIPMismatch = "KonnectivityIPMismatch" // konnectivity-agent stale-identifier guard (pod-teardown)
	CiliumEnvoyXDSReject   = "CiliumEnvoyXDSReject"   // cilium-envoy xDS update_rejected streak
	DiskBloatRunaway       = "DiskBloatRunaway"       // disk-bloat runaway detector
	InotifyPressure        = "InotifyPressure"        // inotify instances/watches exhausted past sysctl ceiling (inotify-pressure latch)

	// nethealth — DNS/overlay/nebula/fail2ban/clock guards.
	DNSFallbackActive   = "DnsFallbackActive"   // /etc/hosts pin fallback engaged
	NebulaIsolated      = "NebulaIsolated"      // nebula overlay partitioned
	NebulaDegraded      = "NebulaDegraded"      // nebula relay/latency degraded
	Fail2banDown        = "Fail2banDown"        // fail2ban service down
	ClockUnsynchronized = "ClockUnsynchronized" // kernel clock undisciplined (no sync source)
	NebulaPMTUBlackhole = "NebulaPMTUBlackhole" // DF probes blackhole on the overlay
	ClockSkewDetected   = "ClockSkewDetected"   // synced but >2s off the NTP source
	NebulaMTUBlackhole  = "NebulaMTUBlackhole"  // routeguard NM4 DF-probe MTU blackhole
	NebulaSlowpath      = "NebulaSlowpath"      // nebula dataplane relay/latency degraded
	NebulaSiteedge      = "NebulaSiteedge"      // nebula site-edge peers degraded

	// controllerhygiene — control-plane guards on the node daemons.
	ControlPlaneCertReloadStale = "ControlPlaneCertReloadStale" // cert reload markers stale
	KubeconfigCertExpiring      = "KubeconfigCertExpiring"      // node-daemon kubeconfig cert nearing notAfter
	// ApiserverWatchCacheWedged is the sig13 apiserver watch-cache
	// wedge latch (state-apiserver-cache-wedged) surfaced as a
	// condition: the apiserver serves stale watch-cache data while
	// etcd's revision advances — cluster-side heals (the
	// coredns-stale-watchdog) defer pod churn on a fresh True.
	ApiserverWatchCacheWedged = "ApiserverWatchCacheWedged"

	// nodereporter's own probes.
	WatchdogStale = "WatchdogStale" // node-watchdog last-run older than 20 min

	// workerhygiene D-state/kmsg hang class — D-state storm plus the
	// kernel soft-lockup/RCU-stall evidence latches.
	KernelHungTasks = "KernelHungTasks"

	// Wave-3 self-healing additions.
	MountTablePressure   = "MountTablePressure"   // #4: /proc/1/mountinfo vs fs.mount-max or shared peer-group storm
	EBPFResourcePressure = "EBPFResourcePressure" // #10: kernel eBPF prog/map/bpffs-pin leak past ceiling
	EtcdQuorumDegraded   = "EtcdQuorumDegraded"   // #8: embedded etcd CORRUPT alarm, stuck learner, or WAL fsync storm

	// Wave-4 self-healing additions.
	CondWorkerKubeletCertExpiring = "WorkerKubeletCertExpiring" // #4: kubelet serving cert <14d or live :10250 reload drift (worker-kubelet-cert-expiring latch)
	CondHostKernelDrift           = "HostKernelDrift"           // #9: persistent THP or CNI/overlay rp_filter sysctl drift (host-kernel-drift latch)
	CondSystemdOOMDKill           = "SystemdOOMDKill"           // #9: systemd-oomd pod/k0s slice kill within 30m (systemd-oomd-kill latch)
	CondNetworkMountHung          = "NetworkMountHung"          // #10: NFS/CIFS/FUSE/CephFS mount statfs probe hung (network-mount-hung latch)
	CondNodeLocalDNSNoTrackDrift  = "NodeLocalDNSNoTrackDrift"  // #12: NodeLocalDNS iptables raw NOTRACK rule missing on 169.254.20.10:53 (nodelocaldns-notrack-drift latch)

	// Wave-5 self-healing additions.
	CondK8s135ReadinessDrift = "K8s135ReadinessDrift" // K5: cgroup v2 & kubelet/k0s 1.35+ upgrade readiness drift (k8s135-readiness-drift latch)
	CondKMSv2Unhealthy       = "KMSv2Unhealthy"       // K10: KMSv2 encryption plugin socket or /healthz/kms-provider-* unhealthy (kmsv2-unhealthy latch)
)

// Node/Pod annotation keys carrying the L1 ↔ L3 cooperative
// remediation protocol (node-host-agent ↔ node-automation-controller).
// The cluster side stamps AnnoClusterMaintenanceUntil while a
// cluster-wide operation (Autopilot upgrade, kured drain, Medik8s
// fencing) owns the node; the agent caches it ~30s and pauses local
// service restarts and pod deletion for the window. The agent stamps
// AnnoLocalRemediationUntil (+3m) before restarting a node-local
// service and AnnoLastPodHealedAt after bouncing an infra pod, so the
// cluster side defers remote eviction while L1 self-heals first.
// Untyped strings for the same depguard reason as the conditions.
const (
	AnnoClusterMaintenanceUntil = "passiontech.dev/cluster-maintenance-until"
	AnnoLocalRemediationUntil   = "passiontech.dev/local-remediation-until"
	AnnoLastPodHealedAt         = "passiontech.dev/last-pod-healed-at"
)

// CondLocalRemediation is the NodeCondition node-host-agent writes
// through the nodes/status subresource while L1 self-heals — the
// RBAC-safe Node→Cluster signal (the ClusterRole grants
// nodes/status patch but NOT nodes metadata patch). The condition
// self-expires via LastHeartbeatTime: the cluster side only trusts
// it while the heartbeat is fresh (< ~3m), so a crashed agent
// cannot freeze remote remediation. NOT in HeartbeatSweptNames —
// nodereporter does not own or re-stamp it; the controller's
// node-condition-sweeper garbage-collects the stale True once the
// heartbeat has been frozen past its episode TTL.
const CondLocalRemediation = "LocalRemediationInProgress"

// Monitor- and kubelet-owned NodeConditions — not latch-backed.
// KernelDeadlock and ReadonlyFilesystem are the NPD monitor ports
// the nodereporter evaluates from kmsg signatures and the host
// mount table; InodePressure is kubelet-native (nodefs/imagefs
// inode exhaustion) and since inode-pressure also agent-latched (hostmetrics'
// state-inode-pressure maps onto the same name); the four network
// spellings are the NPD network-monitor condition names the
// controller's partition/storm-gate consumers act on (no agent
// emitter in this repo; both singular and plural upstream
// spellings are live in the cluster).
const (
	KernelDeadlock     = "KernelDeadlock"     // PERMANENT: hung-task/soft-lockup/RCU-stall, latches True for the agent lifetime
	ReadonlyFilesystem = "ReadonlyFilesystem" // watched mountpoints mounted read-only
	InodePressure      = "InodePressure"      // kubelet-native inode exhaustion + agent inode-pressure latch (inode-pressure)
	// HostNetworkProblems is BOTH the NPD host-network monitor spelling
	// AND — since the kernelfail NIC-health guard — an agent-latched
	// condition (host-network-problems latch off physical carrier flap /
	// CRC / TX-timeout evidence), so it sits in HeartbeatSweptNames.
	HostNetworkProblems    = "HostNetworkProblems"    // NPD host network monitor + agent NIC-health latch
	ClusterNetworkProblems = "ClusterNetworkProblems" // NPD cluster network monitor
	HostNetworkProblem     = "HostNetworkProblem"     // singular upstream spelling, still live
	ClusterNetworkProblem  = "ClusterNetworkProblem"  // singular upstream spelling, still live
)

// HeartbeatSweptNames is every NodeCondition the nodereporter owns
// and re-stamps LastHeartbeatTime on each cycle while alive: all 69
// latch-backed conditions plus ReadonlyFilesystem (the NPD mount
// monitor rides the same heartbeat patch). InodePressure is in since
// inode-pressure: the hostmetrics inode-pressure latch sets/clears it and
// kubelet itself never emits a condition of this type, so a frozen
// heartbeat on it can only be a dead reporter's zombie. Deliberately
// NOT here: KernelDeadlock — the permanent latch that never
// reconciles back to False, so a frozen heartbeat on it is
// meaningless. The controller's node-condition-sweeper sweeps
// exactly this set: True here with a frozen LastHeartbeatTime is a
// zombie from a dead reporter.
var HeartbeatSweptNames = []string{
	NodeOverloaded, WatchdogStale,
	CiliumAgentDown, CiliumInitStuck,
	KubeletRuntimeStall, DNSFallbackActive, DNSResolvStale,
	PodTeardownWedged, KubeletWatchWedge, JournaldUnreadable,
	FilesystemReadOnly, KernelHungTasks,
	NebulaIsolated, NebulaDegraded,
	CiliumEnvoyDown, CiliumIPAMExhausted, CiliumBPFMapPressure,
	CiliumMTUDrift, CiliumWGStale,
	SpegelMirrorDegraded, CalicoVethLeak, CalicoFelixDown,
	Fail2banDown, ConntrackPressure, KernelKeysPressure,
	ControlPlaneCertReloadStale, MemoryPSIThrashing,
	ClockUnsynchronized, KernelSlabLeak, NebulaPMTUBlackhole,
	KernelResourceExhaustion, ClockSkewDetected,
	KubeconfigCertExpiring, CPUStealPressure,
	CgroupDyingLeak, SystemdSessionBloat, SystemdUnresponsive,
	KubeletPLEGUnhealthy, DiskSlowIO, KernelNetShimDegraded,
	ClocksourceUnstable,
	InodePressure,
	ReadonlyFilesystem,
	KonnectivityIPMismatch, CiliumEnvoyXDSReject, DiskBloatRunaway,
	NebulaMTUBlackhole, NebulaSlowpath, NebulaSiteedge,
	KernelPageAllocFailure,
	ApiserverWatchCacheWedged,
	// Wave self-healing additions: the kernelfail hardware/neighbor/NIC
	// guards and the workerhygiene inotify healer all project latches
	// through nodereporter, so their conditions ride the same heartbeat
	// — HostNetworkProblems joins because the NIC-health guard now owns
	// the host-network spelling too (NPD no longer has a separate
	// emitter for it).
	DiskPreFail, HardwareCorrupted, GPUHardwareError,
	InotifyPressure, HostNetworkProblems,
	// Wave-2 self-healing additions: the four new latch-backed
	// conditions (ephemeral-port/neighbor pressure, netfilter lock
	// wedge, CSI registration wedge) ride the same heartbeat.
	EphemeralPortPressure, NeighborTablePressure,
	NetfilterLockWedged, CSIRegistrationWedged,
	// Wave-3 self-healing additions.
	MountTablePressure, EBPFResourcePressure, EtcdQuorumDegraded,
	// Wave-4 self-healing additions.
	CondWorkerKubeletCertExpiring, CondHostKernelDrift,
	CondSystemdOOMDKill, CondNetworkMountHung,
	CondNodeLocalDNSNoTrackDrift,
	// Wave-5 self-healing additions.
	CondK8s135ReadinessDrift, CondKMSv2Unhealthy,
}

// HangPreCordonNames are the hang-class conditions node-hang-
// precordon acts on — a sustained True cordons the node (spec.
// unschedulable) so new pods stay off the dying node ahead of the
// NHC reboot. The clock conditions are deliberately NOT here: they
// carry their own longer fuse and live in ClockSkewPreCordonNames.
// InodePressure stays in the set (an inode storm starves the node
// the same way a latch would); since inode-pressure it is also in
// HeartbeatSweptNames (agent-latched). The precordon gates on
// LastTransitionTime, not the heartbeat.
var HangPreCordonNames = []string{
	KernelHungTasks, FilesystemReadOnly, ReadonlyFilesystem, KernelDeadlock,
	KubeletRuntimeStall,
	KubeletWatchWedge, PodTeardownWedged, InodePressure,
	MemoryPSIThrashing, KernelSlabLeak, KernelResourceExhaustion,
	CgroupDyingLeak, CiliumAgentDown, CiliumInitStuck,
	CiliumEnvoyDown, CalicoFelixDown, NebulaIsolated,
	KubeletPLEGUnhealthy, DiskSlowIO,
	// KernelPageAllocFailure and DiskBloatRunaway join the hang
	// class: a kernel that cannot allocate pages and a disk in
	// runaway growth are both "cordon before it dies" signals on
	// the same fuse as the PSI/slab exhaustion latches.
	// SystemdUnresponsive joins too: a frozen PID1 cannot manage
	// the node's services — cordon ahead of the NHC reboot.
	KernelPageAllocFailure, DiskBloatRunaway, SystemdUnresponsive,
	// HardwareCorrupted (ECC/EDAC poison, fatal MCE, PCIe/NVMe reset
	// loop), GPUHardwareError (fatal NVIDIA Xid), and InotifyPressure
	// (inotify instances/watches exhausted) join the 2-minute hang
	// fuse: each is proof the node is actively degrading and new pods
	// must stay off it. DiskPreFail deliberately does NOT live here —
	// it gets its own longer fuse in DiskPreFailPreCordonNames.
	HardwareCorrupted, GPUHardwareError, InotifyPressure,
	// CiliumIPAMExhausted joins the 2m hang fuse: a node whose Cilium
	// IPAM pool is exhausted cannot start new pods and must be
	// precordoned until IPAM recovers (at which point
	// node-hang-precordon auto-uncordons it).
	CiliumIPAMExhausted,
	// Wave-2 self-healing additions: all four new conditions take
	// the standard 2m hang fuse — a node whose ephemeral-port or
	// neighbor table is pinned past ceiling, whose netfilter lock
	// is wedged, or whose CSI registration desynced is actively
	// degrading and new pods must stay off it.
	EphemeralPortPressure, NeighborTablePressure,
	NetfilterLockWedged, CSIRegistrationWedged,
	// Wave-3 self-healing addition: mount-table exhaustion takes the 2m
	// hang fuse so precordon isolates the worker before kernel ENOSPC.
	// EBPFResourcePressure deliberately does NOT live here: cordon does
	// not shrink BPF maps (the Cilium datapath keeps every prog/pin), so
	// the 2m fuse only starts a cluster-wide cordon domino. Like
	// CiliumBPFMapPressure it stays in StormGateNames +
	// HeartbeatSweptNames only. EtcdQuorumDegraded stays off too
	// (control-plane quorum degradation is handled via StormGateNames).
	MountTablePressure,
}

// ClockSkewPreCordonNames are the clock-health conditions on the
// precordon's longer fuse — ClockUnsynchronized (chrony has no
// sync source), ClockSkewDetected (synchronized but >2s off), and
// ClocksourceUnstable (clocksource-unstable: the underlying clocksource itself is
// drifting/unstable — with it, the other two fire and the node's
// whole timebase is untrustworthy, so it precordons on the same
// longer fuse).
var ClockSkewPreCordonNames = []string{
	ClockUnsynchronized, ClockSkewDetected, ClocksourceUnstable,
}

// DiskPreFailPreCordonNames is the pre-fail disk condition on its
// own longer fuse — an ext4 metadata error or NVMe SMART pre-fail
// indicator means the disk may still be serving, so the node gets
// 15 minutes of corroboration (vs the 2m hang fuse) before the
// precordon acts. Separate list for the same reason
// ClockSkewPreCordonNames exists: the fuse differs.
var DiskPreFailPreCordonNames = []string{
	DiskPreFail,
}

// NetworkMountHungPreCordonNames is the hung network/FUSE mount
// condition on its own 5-minute fuse — NFS/CIFS/FUSE/CephFS probes
// need time to distinguish a transient server blip from a wedged
// mount before the precordon isolates the node. Separate list for
// the same reason ClockSkewPreCordonNames and
// DiskPreFailPreCordonNames exist: the fuse differs (5m vs 2m/10m/15m).
var NetworkMountHungPreCordonNames = []string{
	CondNetworkMountHung,
}

// StormGateNames are the node-unhealthy conditions the
// descheduler-storm-gate treats as "rebalancing is actively
// harmful": while any is True (or a storm taint sits on the node)
// the gate suppresses descheduler evictions so the descheduler
// doesn't pile more pods onto a dying node. Includes the
// kubelet-native MemoryPressure/DiskPressure/NetworkUnavailable,
// the NPD network spellings, and the foreign CiliumLRPDegraded
// (no emitter in this repo — kept because the gate must keep
// honoring it). CiliumBPFMapPressure joins per plan: BPF-map
// pressure degrades the CNI data path the same class as the other
// Cilium* latches.
var StormGateNames = []string{
	KubeletRuntimeStall, KubeletWatchWedge, PodTeardownWedged,
	WatchdogStale, HostNetworkProblems, ClusterNetworkProblems,
	HostNetworkProblem, ClusterNetworkProblem,
	"MemoryPressure", "DiskPressure", "NetworkUnavailable",
	FilesystemReadOnly,
	NebulaIsolated, NebulaDegraded, NebulaPMTUBlackhole,
	KernelHungTasks, KernelSlabLeak, ClockUnsynchronized,
	ClockSkewDetected, CalicoFelixDown, CiliumIPAMExhausted,
	CiliumBPFMapPressure,
	InodePressure, MemoryPSIThrashing, CgroupDyingLeak,
	KernelResourceExhaustion, KubeletPLEGUnhealthy,
	SystemdSessionBloat, SystemdUnresponsive, CiliumAgentDown,
	CiliumInitStuck,
	CiliumEnvoyDown, CiliumWGStale, "CiliumLRPDegraded",
	CiliumMTUDrift, ConntrackPressure, JournaldUnreadable,
	ControlPlaneCertReloadStale, DiskSlowIO,
	ClocksourceUnstable, KernelNetShimDegraded,
	ReadonlyFilesystem, KernelDeadlock,
	// Wave-26 classifications: the five conditions that shipped
	// latch-backed but unclassified. KernelPageAllocFailure and
	// DiskBloatRunaway are hang-class (kernel OOM-adjacent /
	// disk-filling node — cordon before read-only); the Cilium
	// xDS reject streak and the two degraded (not partitioned)
	// Nebula paths gate storms only.
	KernelPageAllocFailure, DiskBloatRunaway,
	CiliumEnvoyXDSReject, NebulaSlowpath, NebulaSiteedge,
	NebulaMTUBlackhole,
	// Self-healing wave: hardware corruption, GPU fatal Xid, disk
	// pre-fail, and inotify exhaustion are all "node is degrading —
	// do not rebalance more pods onto it" signals.
	DiskPreFail, HardwareCorrupted, GPUHardwareError, InotifyPressure,
	// Wave-2 self-healing additions: port/neighbor exhaustion and
	// the two wedge conditions are all "node is degrading — do not
	// rebalance more pods onto it" signals (the precordon members
	// must also appear here per TestAllPreCordonConditionsInStormGate).
	EphemeralPortPressure, NeighborTablePressure,
	NetfilterLockWedged, CSIRegistrationWedged,
	// Wave-3 self-healing additions.
	MountTablePressure, EBPFResourcePressure, EtcdQuorumDegraded,
	// Wave-4 self-healing additions: a hung network/FUSE mount
	// (precordon invariant) and recent systemd-oomd cgroup kills
	// within 30m both warn against rebalancing pods onto the node.
	// CondWorkerKubeletCertExpiring (like KubeconfigCertExpiring),
	// CondHostKernelDrift (persistent sysctl/THP drift), and
	// CondNodeLocalDNSNoTrackDrift (like DNSResolvStale/DNSFallbackActive)
	// stay out so they do not freeze the cluster-wide descheduler.
	CondSystemdOOMDKill, CondNetworkMountHung,
	// Wave-5 self-healing additions: CondKMSv2Unhealthy indicates
	// Secret encryption is degraded on a control-plane node (like
	// EtcdQuorumDegraded) and gates descheduler storms;
	// CondK8s135ReadinessDrift is an upgrade-readiness posture audit
	// and stays out so it does not freeze the cluster-wide descheduler.
	CondKMSv2Unhealthy,
}

// PartitionNames are the network-partition conditions the
// partition-pod-evictor acts on: a node True on any of these for
// past the grace window gets its namespace-listed pods evicted to
// healthy peers (rate-limited, quorum-guarded).
var PartitionNames = []string{
	HostNetworkProblems, ClusterNetworkProblems,
	HostNetworkProblem, ClusterNetworkProblem,
	NebulaIsolated, NebulaPMTUBlackhole, NebulaMTUBlackhole,
}

// heartbeatSweptSet backs AgentHeartbeatManaged — built once from
// HeartbeatSweptNames so the freshness gate stays O(1) per probe.
var heartbeatSweptSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(HeartbeatSweptNames))
	for _, name := range HeartbeatSweptNames {
		set[name] = struct{}{}
	}
	return set
}()

// KuredLockAnno is the reboot-drain lock annotation kured holds on
// the node it is draining (weave.works/kured-node-lock). L1
// (nodecoord) checks it on the NODE object and L3
// (node-automation-controller's maintenance mutex) reads the same
// key off the kured DaemonSet — one spelling, both sides.
const KuredLockAnno = "weave.works/kured-node-lock"

// KuredRebootTaintKey is the taint kured places on a node it is
// rebooting (weave.works/kured-node-reboot).
const KuredRebootTaintKey = "weave.works/kured-node-reboot"

// CoordVerdict is the decoded Cluster→Node maintenance state both
// apps derive from the same annotation pair (and optional node taints)
// — the L1 nodecoord cache and any L3 re-derivation must agree
// bit-for-bit.
type CoordVerdict struct {
	// Active is the hold signal: a live maintenance stamp
	// (MaintenanceUntil > now) OR the kured drain lock/reboot taint
	// present.
	Active bool
	// MaintenanceUntil is the parsed
	// AnnoClusterMaintenanceUntil — zero when absent/unparseable.
	MaintenanceUntil time.Time
	// KuredLocked reports the kured drain-lock annotation or reboot
	// taint present — it carries NO timestamp, so consumers needing a
	// freshness bound apply their own TTL on top of this verdict.
	KuredLocked bool
}

// ParseAnnoTime parses an annotation timestamp — RFC3339Nano (which
// also accepts RFC3339 without fractional seconds) first, then a bare
// unix-seconds integer (the legacy stamp format several annotations
// still carry and the hand-set escape hatch). ok=false on
// absent/empty/unparseable input: callers treat a stamp they cannot
// read as no stamp at all, never as now.
func ParseAnnoTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, true
	}
	// Bare unix seconds — but only a plausible epoch: a stamp past
	// 2100 is almost certainly misspelled (e.g. milliseconds pasted
	// as seconds, which once locked maintenance until year 57836),
	// and a non-positive value is never a real stamp.
	if ts, err := strconv.ParseInt(raw, 10, 64); err == nil &&
		ts > 0 && ts <= 4102444800 {
		return time.Unix(ts, 0), true
	}
	return time.Time{}, false
}

// EvaluateCoordAnnos folds a node's annotation map into the
// Cluster→Node maintenance verdict — the single decode both the L1
// nodecoord cache and L3-side consumers share. KuredLocked is pure
// presence (the value is a JSON lock document, not a timestamp);
// Active is KuredLocked OR a MaintenanceUntil still in the future
// at now.
func EvaluateCoordAnnos(annos map[string]string, now time.Time) CoordVerdict {
	var v CoordVerdict
	if t, ok := ParseAnnoTime(annos[AnnoClusterMaintenanceUntil]); ok {
		v.MaintenanceUntil = t
	}
	v.KuredLocked = annos[KuredLockAnno] != ""
	v.Active = v.KuredLocked || v.MaintenanceUntil.After(now)
	return v
}

// EvaluateCoord folds a node's annotation map and taint keys into the
// Cluster→Node maintenance verdict. KuredLocked is true when either
// KuredLockAnno is present in annos or KuredRebootTaintKey is present
// in taintKeys.
func EvaluateCoord(annos map[string]string, taintKeys []string, now time.Time) CoordVerdict {
	v := EvaluateCoordAnnos(annos, now)
	if !v.KuredLocked && slices.Contains(taintKeys, KuredRebootTaintKey) {
		v.KuredLocked = true
		v.Active = true
	}
	return v
}

// AgentHeartbeatManaged reports whether cond is a nodereporter-
// owned condition that carries a live LastHeartbeatTime stamp —
// the set the cluster-side freshness gate consults before acting:
// a condition in HeartbeatSweptNames whose heartbeat is frozen is
// a zombie (the reporter that owns it is dead) and must not drive
// taints, evictions or cordons. Kubelet-native conditions
// (MemoryPressure, DiskPressure, …) and the permanent KernelDeadlock
// latch answer false — their LastHeartbeatTime is not the
// reporter's liveness signal. (InodePressure IS managed: since inode-pressure
// the agent latches it and kubelet never emits the type.)
func AgentHeartbeatManaged(cond string) bool {
	_, ok := heartbeatSweptSet[cond]
	return ok
}

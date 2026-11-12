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
	"strconv"
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
// nodereporter does not own or re-stamp it.
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
	KernelDeadlock         = "KernelDeadlock"         // PERMANENT: hung-task/soft-lockup/RCU-stall, latches True for the agent lifetime
	ReadonlyFilesystem     = "ReadonlyFilesystem"     // watched mountpoints mounted read-only
	InodePressure          = "InodePressure"          // kubelet-native inode exhaustion + agent inode-pressure latch (inode-pressure)
	HostNetworkProblems    = "HostNetworkProblems"    // NPD host network monitor
	ClusterNetworkProblems = "ClusterNetworkProblems" // NPD cluster network monitor
	HostNetworkProblem     = "HostNetworkProblem"     // singular upstream spelling, still live
	ClusterNetworkProblem  = "ClusterNetworkProblem"  // singular upstream spelling, still live
)

// HeartbeatSweptNames is every NodeCondition the nodereporter owns
// and re-stamps LastHeartbeatTime on each cycle while alive: all 49
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
	CgroupDyingLeak, SystemdSessionBloat,
	KubeletPLEGUnhealthy, DiskSlowIO, KernelNetShimDegraded,
	ClocksourceUnstable,
	InodePressure,
	ReadonlyFilesystem,
	KonnectivityIPMismatch, CiliumEnvoyXDSReject, DiskBloatRunaway,
	NebulaMTUBlackhole, NebulaSlowpath, NebulaSiteedge,
	KernelPageAllocFailure,
	ApiserverWatchCacheWedged,
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
	KernelPageAllocFailure, DiskBloatRunaway,
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
	SystemdSessionBloat, CiliumAgentDown, CiliumInitStuck,
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

// CoordVerdict is the decoded Cluster→Node maintenance state both
// apps derive from the same annotation pair — the L1 nodecoord
// cache and any L3 re-derivation must agree bit-for-bit.
type CoordVerdict struct {
	// Active is the hold signal: a live maintenance stamp
	// (MaintenanceUntil > now) OR the kured drain lock present.
	Active bool
	// MaintenanceUntil is the parsed
	// AnnoClusterMaintenanceUntil — zero when absent/unparseable.
	MaintenanceUntil time.Time
	// KuredLocked reports the kured drain-lock annotation present —
	// it carries NO timestamp, so consumers needing a freshness
	// bound apply their own TTL on top of this verdict.
	KuredLocked bool
}

// ParseAnnoTime parses an annotation timestamp — RFC3339Nano and
// RFC3339 first, then a bare unix-seconds integer (the legacy stamp
// format several annotations still carry and the hand-set escape
// hatch). ok=false on absent/empty/unparseable input: callers treat
// a stamp they cannot read as no stamp at all, never as now.
func ParseAnnoTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	if ts, err := strconv.ParseInt(raw, 10, 64); err == nil {
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

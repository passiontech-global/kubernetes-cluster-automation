// conditions.go — latch → NodeCondition surface registry.
//
// A latch may surface as a NodeCondition in nodereporter's
// node.status.conditions output. This file is the single source of
// truth for that mapping: which nodecond type a latch drives, the
// OK/proble reason+message strings, and the alternate state-* latch
// names that share the condition (multi-source conditions like
// KubeletRuntimeStall, which several watchdog modules feed).
//
// nodereporter projects this table into its rendered-condition order
// (conditionOrder in nodereporter/conditions.go) — adding a latch
// with a condition surface is ONE edit here, not a parallel row in
// nodereporter. The K8s Event surface (nodereporter/events.go
// logRules) is a separate contract keyed on ACTION log lines and
// event reasons — it does not consume these strings.
//
// NOT every latch has a condition surface: purely-internal latches
// (infra flags, pressure sub-detectors feeding a shared condition,
// cadence-only markers) are absent from CondDefs on purpose. The
// converse holds too — nodereporter's conditionOrder must name every
// CondDefs key exactly once (enforced by test).
//
// latchdefs stays stdlib-only: Type is the nodecond type NAME as a
// plain string — nodereporter casts it to nodecond.NodeConditionType
// when projecting, so this leaf never imports hostkit.
package latchdefs

// CondDef is the latch→NodeCondition projection metadata for one
// latch. The strings mirror the historical NPD JSON contract —
// reason/message values are operator-facing and must not drift.
type CondDef struct {
	// Type is the nodecond.NodeConditionType NAME this latch drives
	// (e.g. "NodeOverloaded") — kept as string so latchdefs stays
	// stdlib-only.
	Type string

	// DefaultReason is the reason reported while the condition is OK.
	DefaultReason string
	// DefaultMessage is the OK-state message.
	DefaultMessage string
	// ProblemReason is the reason reported while the latch is set.
	ProblemReason string

	// Alts are the OTHER latch names feeding this condition (the
	// condition is OK only when the latch AND all alts are clear).
	// Nil means the latch's own state-* file is the only evidence.
	Alts []string
}

// CondDefs maps a state-* latch name (a Latch* const value) to its
// NodeCondition surface. Keys are the same strings LatchDefs carries
// — kept as plain string keys so the table stays data, not code.
// Order inside the map is irrelevant: nodereporter's conditionOrder
// fixes the rendered order.
var CondDefs = map[string]CondDef{
	LatchNodeOverloaded: {
		Type:           "NodeOverloaded",
		DefaultReason:  "NodeLoadNormal",
		DefaultMessage: "node not overloaded (load15 <= 4xCPU)",
		ProblemReason:  "NodeOverloadedDetected",
	},
	LatchCiliumAgentDown: {
		Type:           "CiliumAgentDown",
		DefaultReason:  "CiliumAgentUp",
		DefaultMessage: "cilium-agent healthz OK",
		ProblemReason:  "CiliumAgentDownDetected",
	},
	LatchCiliumInitStuck: {
		Type:           "CiliumInitStuck",
		DefaultReason:  "CiliumEndpointsReady",
		DefaultMessage: "no cilium endpoint stuck in init (informer healthy)",
		ProblemReason:  "CiliumInitStuckDetected",
	},
	// BUG-H4: the PLEG/syncloop freeze, the hung containerd socket,
	// the kubelet watch-stream wedge and the containerd meta.db
	// corruption latch are runtime stalls too — every latch must
	// light the condition so the existing NHC
	// k0sworker-remediate-exhausted rule keeps working.
	LatchKubeletRuntimeStall: {
		Type:           "KubeletRuntimeStall",
		DefaultReason:  "KubeletRuntimeOk",
		DefaultMessage: "no phantom-pods wedge (ctr alive, tasks > 0)",
		ProblemReason:  "KubeletRuntimeStallDetected",
		Alts: []string{
			LatchKubeletHealthzDown,
			LatchKubeletSyncloopDown,
			LatchContainerdSockDown,
			LatchKubeletWatchWedge,
			LatchContainerdCorrupt,
		},
	},
	LatchDNSFallback: {
		Type:           "DnsFallbackActive",
		DefaultReason:  "DnsDirectOk",
		DefaultMessage: "DNS via resolv.conf healthy, no /etc/hosts pin",
		ProblemReason:  "DnsFallbackEngaged",
	},
	LatchDNSResolvStale: {
		Type:           "DnsResolvStale",
		DefaultReason:  "DnsResolvFresh",
		DefaultMessage: "DNS pods (nld/coredns) resolv.conf matches host",
		ProblemReason:  "DnsResolvStaleDetected",
	},
	LatchPodTeardownWedged: {
		Type:           "PodTeardownWedged",
		DefaultReason:  "PodTeardownOk",
		DefaultMessage: "no long-Terminating pod with leftover task",
		ProblemReason:  "PodTeardownWedgedDetected",
	},
	LatchKubeletWatchWedge: {
		Type:           "KubeletWatchWedge",
		DefaultReason:  "KubeletWatchOk",
		DefaultMessage: "kubelet receives pod assignment normally (no unseen pod)",
		ProblemReason:  "KubeletWatchWedgeDetected",
	},
	LatchJournalUnreadable: {
		Type:           "JournaldUnreadable",
		DefaultReason:  "JournaldReadable",
		DefaultMessage: "journald journal reads return entries",
		ProblemReason:  "JournaldUnreadableDetected",
	},
	LatchFilesystemReadonly: {
		Type:           "FilesystemReadOnly",
		DefaultReason:  "FilesystemReadWrite",
		DefaultMessage: "all probed filesystems are read-write",
		ProblemReason:  "FilesystemReadOnlyDetected",
		Alts:           []string{LatchFSReadonly},
	},
	LatchDStateStorm: {
		Type:           "KernelHungTasks",
		DefaultReason:  "KernelTasksRunOk",
		DefaultMessage: "no D-state task storm (uninterruptible sleep below threshold)",
		ProblemReason:  "KernelHungTasksDetected",
		Alts:           []string{LatchKernelSoftLockup, LatchKernelRCUStall},
	},
	LatchNebulaIsolated: {
		Type:           "NebulaIsolated",
		DefaultReason:  "NebulaMeshHealthy",
		DefaultMessage: "all nebula peers handshake normally",
		ProblemReason:  "NebulaIsolatedDetected",
	},
	LatchNebulaDegraded: {
		Type:           "NebulaDegraded",
		DefaultReason:  "NebulaDataplaneOk",
		DefaultMessage: "nebula dataplane healthy (no relay/latency degradation)",
		ProblemReason:  "NebulaDegradedDetected",
	},
	LatchCiliumEnvoyDown: {
		Type:           "CiliumEnvoyDown",
		DefaultReason:  "CiliumEnvoyReady",
		DefaultMessage: "cilium-envoy admin /ready OK",
		ProblemReason:  "CiliumEnvoyDownDetected",
	},
	LatchCiliumIPAMExhausted: {
		Type:           "CiliumIPAMExhausted",
		DefaultReason:  "CiliumIPAMOk",
		DefaultMessage: "cilium IPAM pool has headroom (no address leak)",
		ProblemReason:  "CiliumIPAMExhaustedDetected",
	},
	LatchCiliumBPFMapPressure: {
		Type:           "CiliumBPFMapPressure",
		DefaultReason:  "CiliumBPFMapsOk",
		DefaultMessage: "critical cilium BPF maps below 90% capacity",
		ProblemReason:  "CiliumBPFMapPressureDetected",
	},
	LatchSpegelMirrorDegraded: {
		Type:           "SpegelMirrorDegraded",
		DefaultReason:  "SpegelMirrorReady",
		DefaultMessage: "spegel P2P mirror pod Ready",
		ProblemReason:  "SpegelMirrorDegradedDetected",
	},
	LatchCalicoVethLeak: {
		Type:           "CalicoVethLeak",
		DefaultReason:  "CalicoVethCountOk",
		DefaultMessage: "cali* veth count matches pod count (no CNI DEL leak)",
		ProblemReason:  "CalicoVethLeakDetected",
	},
	LatchCalicoFelixDown: {
		Type:           "CalicoFelixDown",
		DefaultReason:  "CalicoFelixReady",
		DefaultMessage: "calico felix :9099 readiness OK",
		ProblemReason:  "CalicoFelixDownDetected",
	},
	LatchFail2banDown: {
		Type:           "Fail2banDown",
		DefaultReason:  "Fail2banActive",
		DefaultMessage: "fail2ban service installed and active",
		ProblemReason:  "Fail2banDownDetected",
	},
	LatchConntrackPressure: {
		Type:           "ConntrackPressure",
		DefaultReason:  "ConntrackNormal",
		DefaultMessage: "nf_conntrack table below pressure threshold",
		ProblemReason:  "ConntrackPressureDetected",
	},
	LatchKernelKeysPressure: {
		Type:           "KernelKeysPressure",
		DefaultReason:  "KernelKeysNormal",
		DefaultMessage: "kernel keyring quota below pressure threshold",
		ProblemReason:  "KernelKeysPressureDetected",
	},
	LatchCPCertReloadStale: {
		Type:           "ControlPlaneCertReloadStale",
		DefaultReason:  "ControlPlaneCertReloadFresh",
		DefaultMessage: "control-plane cert reload markers fresh",
		ProblemReason:  "ControlPlaneCertReloadStaleDetected",
	},
	LatchPSIMemoryThrash: {
		Type:           "MemoryPSIThrashing",
		DefaultReason:  "MemoryPSINormal",
		DefaultMessage: "memory PSI full avg60 <= 25% or free memory >= 8%",
		ProblemReason:  "MemoryPSIThrashingDetected",
	},
	LatchClockUnsync: {
		Type:           "ClockUnsynchronized",
		DefaultReason:  "ClockSynchronized",
		DefaultMessage: "kernel clock disciplined (adjtimex synced, esterror <= 500ms)",
		ProblemReason:  "ClockUnsynchronizedDetected",
	},
	LatchKernelSlabLeak: {
		Type:           "KernelSlabLeak",
		DefaultReason:  "KernelSlabNormal",
		DefaultMessage: "unreclaimable kernel slab below pressure threshold",
		ProblemReason:  "KernelSlabLeakDetected",
	},
	LatchNebulaPMTUBlackhole: {
		Type:           "NebulaPMTUBlackhole",
		DefaultReason:  "NebulaPMTUOk",
		DefaultMessage: "nebula overlay passes DF probes at probe size",
		ProblemReason:  "NebulaPMTUBlackholeDetected",
	},
	LatchPIDFDPressure: {
		Type:           "KernelResourceExhaustion",
		DefaultReason:  "KernelResourcesNormal",
		DefaultMessage: "kernel threads/pids and fd table below exhaustion threshold",
		ProblemReason:  "KernelResourceExhaustionDetected",
	},
	LatchClockSkew: {
		Type:           "ClockSkewDetected",
		DefaultReason:  "ClockSkewOk",
		DefaultMessage: "clock offset within 2.0s of NTP source",
		ProblemReason:  "ClockSkewDetected",
	},
	LatchKubeconfigCertExpiring: {
		Type:           "KubeconfigCertExpiring",
		DefaultReason:  "KubeconfigCertValid",
		DefaultMessage: "kubeconfig client certificates valid beyond the expiry horizon",
		ProblemReason:  "KubeconfigCertExpiringDetected",
	},
	LatchCPUStealPressure: {
		Type:           "CPUStealPressure",
		DefaultReason:  "CPUStealNormal",
		DefaultMessage: "hypervisor CPU steal below pressure threshold",
		ProblemReason:  "CPUStealPressureDetected",
	},
	LatchCgroupDyingLeak: {
		Type:           "CgroupDyingLeak",
		DefaultReason:  "CgroupDyingNormal",
		DefaultMessage: "cgroup dying descendants below pressure threshold",
		ProblemReason:  "CgroupDyingLeakDetected",
	},
	LatchSystemdSessionBloat: {
		Type:           "SystemdSessionBloat",
		DefaultReason:  "SystemdSessionsNormal",
		DefaultMessage: "logind session count and D-Bus latency healthy",
		ProblemReason:  "SystemdSessionBloatDetected",
	},
	LatchSystemdUnresponsive: {
		Type:           "SystemdUnresponsive",
		DefaultReason:  "SystemdResponsive",
		DefaultMessage: "systemd PID1 answering manager probes",
		ProblemReason:  "SystemdUnresponsiveDetected",
	},
	LatchKubeletPLEGUnhealthy: {
		Type:           "KubeletPLEGUnhealthy",
		DefaultReason:  "KubeletPLEGHealthy",
		DefaultMessage: "kubelet PLEG relist latency and last-seen lag healthy",
		ProblemReason:  "KubeletPLEGUnhealthyDetected",
	},
	LatchDiskSlowIO: {
		Type:           "DiskSlowIO",
		DefaultReason:  "DiskIONormal",
		DefaultMessage: "disk write await and io PSI within normal bounds",
		ProblemReason:  "DiskSlowIODetected",
	},
	LatchKernelNetShim: {
		Type:           "KernelNetShimDegraded",
		DefaultReason:  "KernelNetShimNormal",
		DefaultMessage: "kernel socket/softnet drop rates and containerd-shim RSS within normal bounds",
		ProblemReason:  "KernelNetShimDegradedDetected",
	},
	LatchClocksourceUnstable: {
		Type:           "ClocksourceUnstable",
		DefaultReason:  "ClocksourceStable",
		DefaultMessage: "kernel clocksource stable (tsc/kvm-clock, no instability records)",
		ProblemReason:  "ClocksourceUnstableDetected",
	},
	LatchCiliumMTUDrift: {
		Type:           "CiliumMTUDrift",
		DefaultReason:  "CiliumMTUAligned",
		DefaultMessage: "cilium datapath MTU matches nebula overlay (no drift)",
		ProblemReason:  "CiliumMTUDriftDetected",
	},
	LatchCiliumWGPeerWipe: {
		Type:           "CiliumWGStale",
		DefaultReason:  "CiliumWGPeersOk",
		DefaultMessage: "cilium_wg0 live peers match expected encryption peers (no stale state)",
		ProblemReason:  "CiliumWGStaleDetected",
	},
	LatchInodePressure: {
		Type:           "InodePressure",
		DefaultReason:  "FilesystemInodesHealthy",
		DefaultMessage: "all monitored filesystems below inode-pressure thresholds",
		ProblemReason:  "FilesystemInodesExhausted",
	},
	LatchKonnectivityIPMismatch: {
		Type:           "KonnectivityIPMismatch",
		DefaultReason:  "KonnectivityIPOk",
		DefaultMessage: "konnectivity-agent identifiers match node IPs",
		ProblemReason:  "KonnectivityIPMismatchDetected",
	},
	LatchCiliumEnvoyXDSReject: {
		Type:           "CiliumEnvoyXDSReject",
		DefaultReason:  "CiliumEnvoyXDSOk",
		DefaultMessage: "cilium-envoy xDS updates accepted (no update_rejected deltas)",
		ProblemReason:  "CiliumEnvoyXDSRejectDetected",
	},
	LatchDiskBloat: {
		Type:           "DiskBloatRunaway",
		DefaultReason:  "DiskBloatNormal",
		DefaultMessage: "no target above the disk-bloat watermark",
		ProblemReason:  "DiskBloatRunawayDetected",
	},
	LatchNebulaMTUBlackhole: {
		Type:           "NebulaMTUBlackhole",
		DefaultReason:  "NebulaMTUOk",
		DefaultMessage: "nebula overlay passes DF probes at full size",
		ProblemReason:  "NebulaMTUBlackholeDetected",
	},
	LatchNebulaSlowpath: {
		Type:           "NebulaSlowpath",
		DefaultReason:  "NebulaFastpathOk",
		DefaultMessage: "nebula dataplane on fast paths within latency bounds",
		ProblemReason:  "NebulaSlowpathDetected",
	},
	LatchNebulaSiteedge: {
		Type:           "NebulaSiteedge",
		DefaultReason:  "NebulaSiteedgeOk",
		DefaultMessage: "nebula site-edge peers reachable",
		ProblemReason:  "NebulaSiteedgeDetected",
	},
	LatchPageAllocFailure: {
		Type:           "KernelPageAllocFailure",
		DefaultReason:  "KernelPageAllocOk",
		DefaultMessage: "no kernel page-allocation failure records",
		ProblemReason:  "KernelPageAllocFailureDetected",
	},
	LatchAPIServerCacheWedged: {
		Type:           "ApiserverWatchCacheWedged",
		DefaultReason:  "APIServerWatchCacheOk",
		DefaultMessage: "apiserver watch-cache tracks etcd revision",
		ProblemReason:  "APIServerWatchCacheWedged",
	},
}

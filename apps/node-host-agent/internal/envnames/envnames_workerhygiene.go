// envnames_workerhygiene.go — the workerhygiene subsystem's env
// contract (the wdeps config_<domain>.go knob rows). The shared
// EnvProcRoot and EnvHostResolvConf live in envnames.go.
package envnames

const (
	// Cadence + wedge budgets (the shared top-level Config rows).
	EnvHygieneInterval           = "NODE_HOST_AGENT_HYGIENE_INTERVAL"
	EnvHygieneCycleTimeout       = "NODE_HOST_AGENT_HYGIENE_CYCLE_TIMEOUT"
	EnvHygieneMinRestartInterval = "NODE_HOST_AGENT_HYGIENE_MIN_RESTART_INTERVAL"
	EnvHygieneConsecNeeded       = "NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED"

	// Shared wiring rows.
	EnvK0sWorkerUnit    = "NODE_HOST_AGENT_K0S_WORKER_UNIT"
	EnvKubeletPodsDir   = "NODE_HOST_AGENT_KUBELET_PODS_DIR"
	EnvContainerdSocket = "NODE_HOST_AGENT_CONTAINERD_SOCKET"
	EnvCtrTaskRoot      = "NODE_HOST_AGENT_CTR_TASK_ROOT"
	EnvSandboxCtlRoot   = "NODE_HOST_AGENT_SANDBOX_CTL_ROOT"

	// Net domain.
	EnvLocaldnsProbeName = "NODE_HOST_AGENT_LOCALDNS_PROBE_NAME"
	EnvLocaldnsProbeAddr = "NODE_HOST_AGENT_LOCALDNS_PROBE_ADDR"

	// Kubelet domain.
	EnvKubeletSyncloopURL   = "NODE_HOST_AGENT_KUBELET_SYNCLOOP_URL"
	EnvKubeletTokenFile     = "NODE_HOST_AGENT_KUBELET_TOKEN_FILE"
	EnvKubeletWatchdogHosts = "NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS"
	EnvKubeletCertMinDays   = "NODE_HOST_AGENT_KUBELET_CERT_MIN_DAYS"
	EnvKubeletPKIDir        = "NODE_HOST_AGENT_KUBELET_PKI_DIR"

	// Cilium domain.
	EnvCiliumSocket          = "NODE_HOST_AGENT_CILIUM_SOCKET"
	EnvCiliumEnvoyAdminURL   = "NODE_HOST_AGENT_CILIUM_ENVOY_ADMIN_URL"
	EnvCiliumIPAMReapEnabled = "NODE_HOST_AGENT_CILIUM_IPAM_REAP_ENABLED"

	// Teardown domain.
	EnvHygieneStuckWedgeAge  = "NODE_HOST_AGENT_HYGIENE_STUCK_WEDGE_AGE"
	EnvHygieneStuckDeleteAge = "NODE_HOST_AGENT_HYGIENE_STUCK_DELETE_AGE"
	EnvHygieneMaxForceDelete = "NODE_HOST_AGENT_HYGIENE_MAX_FORCE_DELETE"

	// Pressure domain.
	EnvDstateStormThreshold = "NODE_HOST_AGENT_DSTATE_STORM_THRESHOLD"

	// Calico domain.
	EnvCalicoFelixReadyURL       = "NODE_HOST_AGENT_CALICO_FELIX_READY_URL"
	EnvCalicoOrphanVethThreshold = "NODE_HOST_AGENT_CALICO_ORPHAN_VETH_THRESHOLD"

	// Runtime domain.
	EnvCgroupRoot         = "NODE_HOST_AGENT_CGROUP_ROOT"
	EnvSystemdSessionsDir = "NODE_HOST_AGENT_SYSTEMD_SESSIONS_DIR"

	// Disk + token guards — the sa-token-ttl projected SA-token TTL floor and
	// the localpv-quota/run-tmpfs disk guards' knobs.
	EnvSATokenMinTTLSec = "NODE_HOST_AGENT_SA_TOKEN_MIN_TTL_S"
	EnvLocalPVQuotaDir  = "NODE_HOST_AGENT_LOCALPV_QUOTA_DIR"
	EnvHostRunDir       = "NODE_HOST_AGENT_HOST_RUN_DIR"
	EnvDevShmDir        = "NODE_HOST_AGENT_DEV_SHM_DIR"

	// Disk/mount rows: the mountinfo-hygiene check's /proc/1/mountinfo view,
	// the writable-layer snapshot root and coredump dir, and
	// the writable-layer Warning threshold (5 GiB default —
	// separate from the 15 GiB disk-bloat eviction threshold).
	EnvMountinfoFile             = "NODE_HOST_AGENT_MOUNTINFO_FILE"
	EnvWLayerSnapshotsDir        = "NODE_HOST_AGENT_WLAYER_SNAPSHOTS_DIR"
	EnvCoredumpDir               = "NODE_HOST_AGENT_COREDUMP_DIR"
	EnvWLayerBloatThresholdBytes = "NODE_HOST_AGENT_WLAYER_BLOAT_THRESHOLD_BYTES"

	// Inotify pressure + orphan pod-volume reaper knobs — the
	// inotify-pressure-hygiene sysctl ceilings/evict switch and the
	// orphan-pod-volumes two-phase confirm age.
	EnvInotifyMaxInstancesCeiling = "NODE_HOST_AGENT_INOTIFY_MAX_INSTANCES_CEILING"
	EnvInotifyMaxWatchesCeiling   = "NODE_HOST_AGENT_INOTIFY_MAX_WATCHES_CEILING"
	EnvInotifyEvictRunawayPod     = "NODE_HOST_AGENT_INOTIFY_EVICT_RUNAWAY_POD"
	EnvOrphanPodVolsMinAge        = "NODE_HOST_AGENT_ORPHAN_POD_VOLS_MIN_AGE"

	// Wave-2 self-healing guards (P0.3–P2.12) — ephemeral-port
	// exhaustion, hung OCI runtimes, CSI registration, GPU PCIe
	// desync, and the netfilter lock wedge. The P0.3/P1.5/P2.11
	// names below are the plan's contract names; the *_GUARD_*
	// extras are implementation knobs layered on top.
	EnvPortTupleRatioThreshold     = "NODE_HOST_AGENT_PORT_TUPLE_RATIO"
	EnvPortCloseWaitMax            = "NODE_HOST_AGENT_PORT_CLOSE_WAIT_MAX"
	EnvPortDestroySynSent          = "NODE_HOST_AGENT_PORT_DESTROY_SYN_SENT"
	EnvPortSynSentMinRetrans       = "NODE_HOST_AGENT_PORT_SYN_SENT_MIN_RETRANS"
	EnvPortEvictRunawayPod         = "NODE_HOST_AGENT_PORT_EVICT_RUNAWAY_POD"
	EnvMaxConcurrent               = "NODE_HOST_AGENT_MAX_CONCURRENT"
	EnvPortLeakWindowSec           = "NODE_HOST_AGENT_PORT_LEAK_WINDOW_SECONDS"
	EnvPortLeakMinPct              = "NODE_HOST_AGENT_PORT_LEAK_MIN_PCT"
	EnvPortLeakEvictCooldownMin    = "NODE_HOST_AGENT_PORT_LEAK_EVICT_COOLDOWN_MIN"
	EnvCtrRuncMaxAge               = "NODE_HOST_AGENT_CTR_RUNC_MAX_AGE"
	EnvCtrKillHungRunc             = "NODE_HOST_AGENT_CTR_KILL_HUNG_RUNC"
	EnvHungRuncConfirmCycles       = "NODE_HOST_AGENT_RUNC_HANG_CONFIRM_CYCLES"
	EnvHungRuncMaxKillsPerCycle    = "NODE_HOST_AGENT_RUNC_HANG_MAX_KILLS_PER_CYCLE"
	EnvCSIGuardMode                = "NODE_HOST_AGENT_CSI_GUARD_MODE"
	EnvCSIHealEnabled              = "NODE_HOST_AGENT_CSI_HEAL_ENABLED"
	EnvCSIGuardProbeSec            = "NODE_HOST_AGENT_CSI_GUARD_PROBE_SECONDS"
	EnvCSIGuardECONNRefusedCycles  = "NODE_HOST_AGENT_CSI_GUARD_ECONNREFUSED_CYCLES"
	EnvCSIGuardMissingMin          = "NODE_HOST_AGENT_CSI_GUARD_MISSING_MINUTES"
	EnvCSIGuardBounceCooldownMin   = "NODE_HOST_AGENT_CSI_GUARD_BOUNCE_COOLDOWN_MIN"
	EnvGPUGuardMode                = "NODE_HOST_AGENT_GPU_GUARD_MODE"
	EnvGPUHealEnabled              = "NODE_HOST_AGENT_GPU_HEAL_ENABLED"
	EnvGPUGuardProbeSec            = "NODE_HOST_AGENT_GPU_GUARD_PROBE_SECONDS"
	EnvGPUGuardDesyncMin           = "NODE_HOST_AGENT_GPU_GUARD_DESYNC_MINUTES"
	EnvGPUGuardBounceCooldownMin   = "NODE_HOST_AGENT_GPU_GUARD_BOUNCE_COOLDOWN_MIN"
	EnvNetfilterMaxAge             = "NODE_HOST_AGENT_NETFILTER_MAX_AGE"
	EnvNetfilterKillHung           = "NODE_HOST_AGENT_NETFILTER_KILL_HUNG"
	EnvNetfilterGuardMode          = "NODE_HOST_AGENT_NETFILTER_GUARD_MODE"
	EnvNetfilterGuardIntervalSec   = "NODE_HOST_AGENT_NETFILTER_GUARD_INTERVAL_SECONDS"
	EnvNetfilterGuardCmdTimeoutSec = "NODE_HOST_AGENT_NETFILTER_GUARD_CMD_TIMEOUT_SECONDS"
	EnvNetfilterGuardLockPath      = "NODE_HOST_AGENT_NETFILTER_GUARD_LOCK_PATH"
	EnvNetfilterGuardStuckCycles   = "NODE_HOST_AGENT_NETFILTER_GUARD_STUCK_CONFIRM_CYCLES"
	EnvNetfilterGuardMaxKillsCycle = "NODE_HOST_AGENT_NETFILTER_GUARD_MAX_KILLS_PER_CYCLE"
	EnvNetfilterGuardLegacyProbe   = "NODE_HOST_AGENT_NETFILTER_GUARD_LEGACY_TABLE_PROBE"

	// Wave-3 self-healing guards: #3 connected-UDP dead-backend socket
	// destroyer, #4 mount-max/shared-storm/loop-GC, and #9 CPU CFS/VMA guards.
	EnvUDPStaleDestroyEnabled = "NODE_HOST_AGENT_UDP_STALE_DESTROY_ENABLED"
	EnvUDPStalePodCIDRs       = "NODE_HOST_AGENT_UDP_STALE_POD_CIDRS"
	EnvUDPStaleMaxKills       = "NODE_HOST_AGENT_UDP_STALE_MAX_KILLS"
	EnvMountTableEnterRatio   = "NODE_HOST_AGENT_MOUNT_TABLE_ENTER_RATIO"
	EnvMountSharedStormMax    = "NODE_HOST_AGENT_MOUNT_SHARED_STORM_MAX"
	EnvMountMaxCeiling        = "NODE_HOST_AGENT_MOUNT_MAX_CEILING"
	EnvLoopGCEnabled          = "NODE_HOST_AGENT_LOOP_GC_ENABLED"
	EnvCPUCFSThrottleRatio    = "NODE_HOST_AGENT_CPU_CFS_THROTTLE_RATIO"
	EnvCPUHostIdleMinRatio    = "NODE_HOST_AGENT_CPU_HOST_IDLE_MIN_RATIO"
	EnvVMAPressureRatio       = "NODE_HOST_AGENT_VMA_PRESSURE_RATIO"
	EnvVMAMaxCeiling          = "NODE_HOST_AGENT_VMA_MAX_CEILING"

	// Wave-7 self-healing guards: orphan containerd snapshot opt-in prune.
	EnvOrphanSnapshotPruneEnabled = "NODE_HOST_AGENT_ORPHAN_SNAPSHOT_PRUNE_ENABLED"
)

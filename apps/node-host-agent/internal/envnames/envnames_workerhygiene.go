// envnames_workerhygiene.go — the workerhygiene subsystem's env
// contract (the wdeps config_<domain>.go knob rows). The shared
// EnvProcRoot and EnvHostResolvConf live in envnames.go.
package envnames

const (
	// Cadence + wedge budgets (the shared top-level Config rows).
	EnvHygieneInterval           = "NODE_HOST_AGENT_HYGIENE_INTERVAL"
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

	// Cilium domain.
	EnvCiliumSocket        = "NODE_HOST_AGENT_CILIUM_SOCKET"
	EnvCiliumEnvoyAdminURL = "NODE_HOST_AGENT_CILIUM_ENVOY_ADMIN_URL"

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

	// Wave-13 guards — the W13-CP3 projected SA-token TTL floor and
	// the W13-ST1/KR3 disk guards' knobs.
	EnvSATokenMinTTLSec = "NODE_HOST_AGENT_SA_TOKEN_MIN_TTL_S"
	EnvLocalPVQuotaDir  = "NODE_HOST_AGENT_LOCALPV_QUOTA_DIR"
	EnvHostRunDir       = "NODE_HOST_AGENT_HOST_RUN_DIR"
)

// envnames_hostmetrics.go — the hostmetrics subsystem's env
// contract: the collector's procfs/sysfs/k0s path knobs and the
// latch-ticker cadence. EnvTextfileInterval (the standalone
// textfile writer cadence) lives in envnames.go — cmd/agent reads
// it, not the collector.
package envnames

const (
	EnvLatchInterval            = "NODE_HOST_AGENT_LATCH_INTERVAL"
	EnvPsiFile                  = "NODE_HOST_AGENT_PSI_FILE"
	EnvSysClassNet              = "NODE_HOST_AGENT_SYS_CLASS_NET"
	EnvArpTableFile             = "NODE_HOST_AGENT_ARP_TABLE_FILE"
	EnvHostRouteFile            = "NODE_HOST_AGENT_HOST_ROUTE_FILE"
	EnvConntrackStatFile        = "NODE_HOST_AGENT_CONNTRACK_STAT_FILE"
	EnvClocksourceCurrentFile   = "NODE_HOST_AGENT_CLOCKSOURCE_CURRENT_FILE"
	EnvClocksourceAvailableFile = "NODE_HOST_AGENT_CLOCKSOURCE_AVAILABLE_FILE"
	EnvCgroupMemUnits           = "NODE_HOST_AGENT_CGROUP_MEM_UNITS"
	EnvFilesystemTargets        = "NODE_HOST_AGENT_FILESYSTEM_TARGETS"
	EnvKeyUsersFile             = "NODE_HOST_AGENT_KEY_USERS_FILE"
	EnvK0sUnit                  = "NODE_HOST_AGENT_K0S_UNIT"
	EnvK0sConfig                = "NODE_HOST_AGENT_K0S_CONFIG"
	EnvK0sExpectedKcmArgs       = "NODE_HOST_AGENT_K0S_EXPECTED_KCM_ARGS"
	EnvNebulaIface              = "NODE_HOST_AGENT_NEBULA_IFACE"
	EnvNebulaCert               = "NODE_HOST_AGENT_NEBULA_CERT"
	EnvWatchdogLogFile          = "NODE_HOST_AGENT_WATCHDOG_LOG_FILE"
	EnvCPUDeliveredInterval     = "NODE_HOST_AGENT_CPU_DELIVERED_INTERVAL"
)

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

	// Neighbor-table self-heal ceilings (kernelfail neighbor.go): the
	// gc_thresh{1,2,3} triplet doubles per 30m spend up to these caps.
	EnvNeighGCThresh1Ceiling = "NODE_HOST_AGENT_NEIGH_GC_THRESH1_CEILING"
	EnvNeighGCThresh2Ceiling = "NODE_HOST_AGENT_NEIGH_GC_THRESH2_CEILING"
	EnvNeighGCThresh3Ceiling = "NODE_HOST_AGENT_NEIGH_GC_THRESH3_CEILING"
	// Physical-NIC flap thresholds (kernelfail nic_health.go):
	// carrier_changes delta per 5m window, NETDEV WATCHDOG TX
	// timeouts per 10m, and the rx_crc+rx_frame delta required in
	// EACH of two consecutive 5m windows.
	EnvNICCarrierFlapThreshold = "NODE_HOST_AGENT_NIC_CARRIER_FLAP_THRESHOLD"
	EnvNICTxTimeoutThreshold   = "NODE_HOST_AGENT_NIC_TX_TIMEOUT_THRESHOLD"
	EnvNICCRErrorThreshold     = "NODE_HOST_AGENT_NIC_CRC_ERROR_THRESHOLD"
)

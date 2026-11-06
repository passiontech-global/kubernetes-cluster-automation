// envnames_nethealth.go — the nethealth subsystem's env contract.
// The shared EnvHostResolvConf lives in envnames.go.
package envnames

const (
	EnvNethealthInterval     = "NODE_HOST_AGENT_NETHEALTH_INTERVAL"
	EnvNethealthMinRestart   = "NODE_HOST_AGENT_NETHEALTH_MIN_RESTART"
	EnvNethealthConsecNeeded = "NODE_HOST_AGENT_NETHEALTH_CONSEC_NEEDED"
	EnvHostsFile             = "NODE_HOST_AGENT_HOSTS_FILE"
	EnvUptimeFile            = "NODE_HOST_AGENT_UPTIME_FILE"
	EnvProcNetUDP            = "NODE_HOST_AGENT_PROC_NET_UDP"
	EnvProcNetUDP6           = "NODE_HOST_AGENT_PROC_NET_UDP6"
	EnvNebulaDirectTCPPorts  = "NODE_HOST_AGENT_NEBULA_DIRECT_TCP_PORTS"
)

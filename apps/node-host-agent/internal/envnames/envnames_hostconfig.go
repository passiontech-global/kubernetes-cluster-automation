// envnames_hostconfig.go — the hostconfig subsystem's env
// contract. The shared EnvHostconfigVarsDir and EnvNebulaCertsDir
// live in envnames.go.
package envnames

const (
	EnvHostconfigInterval = "NODE_HOST_AGENT_HOSTCONFIG_INTERVAL"
	EnvWatchdogScriptsDir = "NODE_HOST_AGENT_WATCHDOG_SCRIPTS_DIR"
)

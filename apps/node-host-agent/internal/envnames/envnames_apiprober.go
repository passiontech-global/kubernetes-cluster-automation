// envnames_apiprober.go — the apiprober subsystem's env contract:
// the APIPROBER_* knob rows plus the guard-conf path.
package envnames

const (
	// EnvAPIGuardConf is the api-backend-guard conf path — the
	// fallback layer below the APIPROBER_* envs.
	EnvAPIGuardConf               = "NODE_HOST_AGENT_API_GUARD_CONF"
	EnvApiproberSocket            = "NODE_HOST_AGENT_APIPROBER_SOCKET"
	EnvApiproberBackend           = "NODE_HOST_AGENT_APIPROBER_BACKEND"
	EnvApiproberCompanionBackends = "NODE_HOST_AGENT_APIPROBER_COMPANION_BACKENDS"
	EnvApiproberMode              = "NODE_HOST_AGENT_APIPROBER_MODE"
	EnvApiproberTokenFile         = "NODE_HOST_AGENT_APIPROBER_TOKEN_FILE"
	EnvApiproberCaFile            = "NODE_HOST_AGENT_APIPROBER_CA_FILE"
	EnvApiproberLivePath          = "NODE_HOST_AGENT_APIPROBER_LIVE_PATH"
	EnvApiproberCachePath         = "NODE_HOST_AGENT_APIPROBER_CACHE_PATH"
	EnvApiproberInterval          = "NODE_HOST_AGENT_APIPROBER_INTERVAL"
	EnvApiproberFailCycles        = "NODE_HOST_AGENT_APIPROBER_FAIL_CYCLES"
	EnvApiproberRecoverCycles     = "NODE_HOST_AGENT_APIPROBER_RECOVER_CYCLES"
	EnvApiproberFrozenCycles      = "NODE_HOST_AGENT_APIPROBER_FROZEN_CYCLES"
	EnvApiproberGapMin            = "NODE_HOST_AGENT_APIPROBER_GAP_MIN"
	EnvApiproberInsecureTLS       = "NODE_HOST_AGENT_APIPROBER_INSECURE_TLS"
)

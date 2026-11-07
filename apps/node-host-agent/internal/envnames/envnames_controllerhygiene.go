// envnames_controllerhygiene.go — the controllerhygiene
// subsystem's env contract: the control-plane guards' knobs
// (feeder gate, api self/peer, k0s dir, etcd, sig13/stale/gap/
// frozen/solo budgets, kine ttl/pool, oomloop). The shared
// EnvProcRoot lives in envnames.go.
package envnames

const (
	// EnvEnableFeeder gates the standalone api-backend feeder
	// inside controllerhygiene — a private gate, read directly
	// (it is NOT a Descriptor.EnvFlag in wiring.go).
	EnvEnableFeeder          = "NODE_HOST_AGENT_ENABLE_FEEDER"
	EnvControllerInterval    = "NODE_HOST_AGENT_CONTROLLER_INTERVAL"
	EnvControllerInsecureTLS = "NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS"
	EnvAPISelf               = "NODE_HOST_AGENT_API_SELF"
	EnvAPIPeer               = "NODE_HOST_AGENT_API_PEER"
	EnvK0sDir                = "NODE_HOST_AGENT_K0S_DIR"
	EnvEtcdEndpoint          = "NODE_HOST_AGENT_ETCD_ENDPOINT"
	EnvEtcdDBSizeLimit       = "NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT"
	EnvSig13Autofix          = "NODE_HOST_AGENT_SIG13_AUTOFIX"
	EnvSig13MinRestartS      = "NODE_HOST_AGENT_SIG13_MIN_RESTART_S"
	EnvStaleMinErrs          = "NODE_HOST_AGENT_STALE_MIN_ERRS"
	EnvGapCycles             = "NODE_HOST_AGENT_GAP_CYCLES"
	EnvGapMin                = "NODE_HOST_AGENT_GAP_MIN"
	EnvFrozenCycles          = "NODE_HOST_AGENT_FROZEN_CYCLES"
	EnvSoloCycles            = "NODE_HOST_AGENT_SOLO_CYCLES"
	EnvKineDBProbe           = "NODE_HOST_AGENT_KINE_DB_PROBE"
	EnvKineTTLAutofix        = "NODE_HOST_AGENT_KINE_TTL_AUTOFIX"
	EnvKineTTLCtlRestartS    = "NODE_HOST_AGENT_KINE_TTL_CTL_RESTART_S"
	EnvKineTTLMinRestartS    = "NODE_HOST_AGENT_KINE_TTL_MIN_RESTART_S"
	EnvKineTTLRewedgeCycles  = "NODE_HOST_AGENT_KINE_TTL_REWEDGE_CYCLES"
	EnvKinePoolAutofix       = "NODE_HOST_AGENT_KINE_POOL_AUTOFIX"
	EnvKinePoolCycles        = "NODE_HOST_AGENT_KINE_POOL_CYCLES"
	EnvKinePoolMaxConns      = "NODE_HOST_AGENT_KINE_POOL_MAX_CONNS"
	EnvKinePoolMinRestartS   = "NODE_HOST_AGENT_KINE_POOL_MIN_RESTART_S"
	EnvOomloopAutofix        = "NODE_HOST_AGENT_OOMLOOP_AUTOFIX"
	EnvOomloopMinKills       = "NODE_HOST_AGENT_OOMLOOP_MIN_KILLS"
	EnvOomloopWindowS        = "NODE_HOST_AGENT_OOMLOOP_WINDOW_S"
	// W13 Gap#2 single-controller SPOF guard (0 = auto: PeerAPI
	// unset means a single-controller topology) and the W13-ST2
	// etcd snapshot verifier dir.
	EnvTotalControllers = "NODE_HOST_AGENT_TOTAL_CONTROLLERS"
	EnvEtcdSnapshotDir  = "NODE_HOST_AGENT_ETCD_SNAPSHOT_DIR"
)

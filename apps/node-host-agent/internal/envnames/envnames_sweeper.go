// envnames_sweeper.go — the sweeper subsystem's env contract.
// EnvSweepBaseDir (the openebs root, shared with concoursecache)
// and EnvRequestTimeout (shared with cmd/agent) live in
// envnames.go.
package envnames

const (
	EnvSweepInterval  = "NODE_HOST_AGENT_SWEEP_INTERVAL"
	EnvSweepMinAge    = "NODE_HOST_AGENT_SWEEP_MIN_AGE"
	EnvSweepMaxDelete = "NODE_HOST_AGENT_SWEEP_MAX_DELETE"
	EnvMountsFile     = "NODE_HOST_AGENT_MOUNTS_FILE"
)

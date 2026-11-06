// envnames_janitor.go — the janitor subsystem's env contract. The
// shared EnvProcRoot lives in envnames.go.
package envnames

const (
	EnvJanitorInterval    = "NODE_HOST_AGENT_JANITOR_INTERVAL"
	EnvJanitorLatchMaxAge = "NODE_HOST_AGENT_JANITOR_LATCH_MAX_AGE"
)

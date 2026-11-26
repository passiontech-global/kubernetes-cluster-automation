// envnames_kinedb.go — the kinedb subsystem's env contract.
package envnames

const (
	EnvKinedbEnvFile       = "NODE_HOST_AGENT_KINEDB_ENV_FILE"
	EnvKinedbGuardStateDir = "NODE_HOST_AGENT_KINEDB_GUARD_STATE_DIR"
	EnvKinedbPgDataDir     = "NODE_HOST_AGENT_KINEDB_PG_DATA_DIR"
	EnvKinedbRuntime       = "NODE_HOST_AGENT_KINEDB_RUNTIME"
	// compact-step-cap: the compact-guard step cap (Go-side knob; the bash
	// compact script's own KINE_GUARD_* vars stay bash-internal).
	EnvKinedbGuardMaxStepRevisions = "NODE_HOST_AGENT_KINEDB_GUARD_MAX_STEP_REVISIONS"
	// backup-health — the physical pg_dump backup verifier.
	EnvKinedbBackupDir      = "NODE_HOST_AGENT_KINEDB_BACKUP_DIR"
	EnvKinedbBackupInterval = "NODE_HOST_AGENT_KINEDB_BACKUP_INTERVAL"
	// Wave-3 #1: int4 sequence auto-widen guard.
	EnvKineSeqWidenEnabled = "NODE_HOST_AGENT_KINE_SEQ_WIDEN_ENABLED"
)

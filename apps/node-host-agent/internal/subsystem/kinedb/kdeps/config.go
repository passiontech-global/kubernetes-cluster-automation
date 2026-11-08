// config.go — the kinedb Config surface: every knob the three
// loops read, the shell-timer-mirroring defaults, ApplyDefaults and
// the injectable seams (Runner, WireFn, StatFSFn). Kept in kdeps
// because all three domain packages consume the same config — the
// cdeps/config.go role.
package kdeps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Defaults mirror the shell scripts + their systemd timers.
const (
	defaultProbeInterval = 2 * time.Minute
	defaultGuardInterval = 10 * time.Minute
	defaultMaintInterval = 24 * time.Hour

	defaultTextfileDir   = "/var/lib/node-exporter/textfile"
	defaultGuardStateDir = "/var/lib/kine-compact-guard"

	// DefaultEnvFile is the stack .env the detection fast-path and
	// the env-file default share — exported because Detect() (root
	// package) must probe the same path ConfigFromEnv defaults to.
	DefaultEnvFile = "/opt/apps/postgres/.env"

	defaultPGContainer  = "kine-postgres"
	defaultPGBContainer = "kine-pgbouncer"
	defaultWireAddr     = "127.0.0.1:6432" // pooler port published on the VM
	defaultPoolerPort   = "5432"           // in-container pgbouncer port (podman net)
	defaultTable        = "kine"
	defaultWaitMax      = 20 // cl_waiting before the pool counts as queued

	// Compact guard thresholds (bash KINE_GUARD_* parity).
	defaultRetainedMax       = 150000
	defaultRowsMax           = 400000
	defaultFrozenCycles      = 4 // ~40min stall at the 10min cadence
	defaultChunkRevisions    = 150000
	defaultTail              = 1000 // keep newest revs (kine safeCompactRev)
	defaultMaxChunks         = 20
	defaultFrozenHeadAdvance = 100  // head must still be moving
	defaultFrozenRetainedMin = 1000 // ...with real debt accumulated
	defaultAdvisoryLockID    = 20260921

	// Maintenance thresholds (bash KINE_REPACK_* parity).
	defaultRepackDeadPct      = 40
	defaultRepackMinHeapBytes = 209715200 // 200MB

	// kine-churn/backup-health: top-churn window and the physical-backup
	// verifier defaults.
	defaultBackupDir      = "/var/backups/kine"
	defaultBackupInterval = 6 * time.Hour

	defaultCmdTimeout     = 2 * time.Minute
	defaultLongCmdTimeout = 15 * time.Minute // compact session, VACUUM, REINDEX, repack

	// CompactRevKey is the kine marker row name — the compaction
	// horizon lives in its prev_revision (probe's revision-horizon
	// read and the guard's compact script both interpolate it).
	CompactRevKey = "compact_rev_key"

	// LockBusyMarker is echoed by the psql scripts when the
	// advisory lock is taken — the guard and the probe's dead-tuple
	// vacuum both detect "another session holds the lock" by
	// matching it.
	LockBusyMarker = "kine-compact-guard advisory lock busy"

	// DefaultPGDataDir is the in-container postgres data dir used
	// when Config.PGDataDir is empty — the WAL/disk-ratio read
	// (probe) and the repack headroom gate (maint) share it.
	DefaultPGDataDir = "/var/lib/postgresql/data"
)

var (
	// Container auto-discovery — the bash rename-resilience
	// (postgres-percona -> percona-postgres broke every check,
	// incident 2026-10-01). Only used when the configured names do
	// not inspect.
	rePGName    = regexp.MustCompile(`(?i)percona|postgres`)
	rePGExclude = regexp.MustCompile(`(?i)cleanup|pgbouncer`)
	rePGBName   = regexp.MustCompile(`(?i)pgbouncer|pgb`)
	// ReTableIdent is the plain-SQL-identifier gate. Table is
	// Sprintf'd into SQL all over the probe/guard/maint queries —
	// interpolation sites go through SQLIdent (identifier
	// positions) or SQLQuote (literal positions), and only a plain
	// SQL identifier is accepted anyway (belt and suspenders). The
	// maint invalid-index reaper applies the same gate to index
	// names before DROP.
	ReTableIdent = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// Runner executes argv with optional stdin — the single command seam
// (podman/docker exec, logs, inspect). The default wires
// hostexec.Run and returns CLEAN stdout: stderr is captured
// separately — folded into the error on failure, debug-logged on
// success — so psql WARNING/NOTICE/version-skew lines cannot poison
// the exact-match stdout parsers.
// env lets a caller feed secrets to the child without placing them
// on argv (`docker exec -e PGPASSWORD` forwards the parent's env —
// `docker exec -e PGPASSWORD=...` would leak the password through
// /proc/<pid>/cmdline). nil env for everything else.
type Runner func(ctx context.Context, env, argv []string, stdin string) (string, error)

// Config carries the kinedb knobs — all test-injectable.
type Config struct {
	ProbeInterval time.Duration // probe loop cadence (2min)
	GuardInterval time.Duration // compact guard cadence (10min)
	MaintInterval time.Duration // maintenance cadence (24h)

	TextfileDir   string // node-exporter textfile dir
	EnvFile       string // postgres stack .env (POSTGRES_USER/PASSWORD)
	GuardStateDir string // last-head/last-compact-rev/freeze-cycles

	Runtime            string // podman|docker; "" → auto-detect
	PGContainer        string // postgres container name
	PGBouncerContainer string // pgbouncer container name
	WireAddr           string // host:port for the wire probe (127.0.0.1:6432)
	PoolerPort         string // in-container pooler port for psql (5432)
	Table              string // kine table name
	WaitMax            int64  // cl_waiting threshold for the pools check

	// Compact guard.
	RetainedMax       int64 // retained revs → fire
	RowsMax           int64 // table rows → fire
	FrozenCycles      int64 // consecutive frozen cycles → candidate
	ChunkRevisions    int64 // revisions per compact chunk
	Tail              int64 // newest revs kept after compact
	MaxChunks         int   // chunk cap per run
	FrozenHeadAdvance int64 // frozen trigger needs head > last+this
	FrozenRetainedMin int64 // ...and retained > this
	AdvisoryLockID    int64 // pg advisory lock key
	// MaxStepRevisions caps how far one compact-guard cycle may
	// advance compact_rev (W16-CP1). 0/absent = disabled = the
	// unbounded head-Tail step (env NODE_HOST_AGENT_KINEDB_GUARD_
	// MAX_STEP_REVISIONS).
	MaxStepRevisions int64

	// Maintenance.
	RepackDeadPct      int64 // dead-tuple % → repack candidate
	RepackMinHeapBytes int64 // heap bytes → repack candidate
	// PGDataDir is the in-container postgres data dir whose free
	// space gates pg_repack (W8-CP2); "" → /var/lib/postgresql/data.
	PGDataDir string

	// backup-health physical-backup verifier: BackupDir is the
	// host dir holding pg_dump -Fc dumps ("" → /var/backups/kine);
	// BackupInterval is the max dump age before the guard creates
	// a fresh one ("" → 6h). Creation also requires >30% free on
	// the backup filesystem.
	BackupDir      string
	BackupInterval time.Duration

	CmdTimeout     time.Duration // per command budget
	LongCmdTimeout time.Duration // compact/vacuum/reindex/repack budget

	// ReadOnly suppresses every mutating path in the probe checks
	// and the WAL/XID hygiene block — the check-kine-db CLI mode:
	// pg_terminate_backend, VACUUM/ANALYZE, ROLLBACK PREPARED,
	// replication-slot drops, pgbouncer RECONNECT/container restarts
	// and every state-file/Prom-textfile write are replaced by
	// "would have done X" diagnostics. The subsystem daemon leaves
	// this false — remediation is its job.
	ReadOnly bool

	// --- injectable seams (defaults follow) ---
	// Clock supplies the current time — the shared timex.Cell seam.
	Clock *timex.Cell
	// Run is the command seam — see Runner. The domain loops reach
	// it through the Deps.Exec* helpers, never directly.
	Run Runner
	// WireFn is the pgbouncer wire-probe seam — the probe package
	// fills the Go-native PG v3 StartupMessage default lazily
	// (the wire probe is probe-domain logic; keeping the default
	// out of ApplyDefaults lets kdeps stay unaware of it).
	WireFn func(ctx context.Context, addr string) bool
	// StatFSFn returns the free-byte ratio of a filesystem — the
	// backup verifier's headroom gate stubs it (the real statfs of
	// a test tmpfs is environment-dependent).
	StatFSFn func(path string) (float64, error)
}

// ApplyDefaults fills every zero knob with the shell-timer default,
// auto-detects the container runtime, validates Table as a plain
// SQL identifier and wires the default seams. Exported so the
// facade (and the kdepstest fixture) can default a caller-built
// Config — was applyDefaults pre-split.
func (c *Config) ApplyDefaults() error {
	if c.ProbeInterval <= 0 {
		c.ProbeInterval = defaultProbeInterval
	}
	if c.GuardInterval <= 0 {
		c.GuardInterval = defaultGuardInterval
	}
	if c.MaintInterval <= 0 {
		c.MaintInterval = defaultMaintInterval
	}
	if c.TextfileDir == "" {
		c.TextfileDir = defaultTextfileDir
	}
	if c.EnvFile == "" {
		c.EnvFile = DefaultEnvFile
	}
	if c.GuardStateDir == "" {
		c.GuardStateDir = defaultGuardStateDir
	}
	if c.Runtime == "" {
		if _, err := exec.LookPath("podman"); err == nil {
			c.Runtime = "podman"
		} else {
			c.Runtime = "docker"
		}
	}
	if c.PGContainer == "" {
		c.PGContainer = defaultPGContainer
	}
	if c.PGBouncerContainer == "" {
		c.PGBouncerContainer = defaultPGBContainer
	}
	if c.WireAddr == "" {
		c.WireAddr = defaultWireAddr
	}
	if c.PoolerPort == "" {
		c.PoolerPort = defaultPoolerPort
	}
	if c.Table == "" {
		c.Table = defaultTable
	}
	if !ReTableIdent.MatchString(c.Table) {
		return fmt.Errorf("kinedb: Table %q is not a plain SQL identifier", c.Table)
	}
	if c.WaitMax <= 0 {
		c.WaitMax = defaultWaitMax
	}
	if c.RetainedMax <= 0 {
		c.RetainedMax = defaultRetainedMax
	}
	if c.RowsMax <= 0 {
		c.RowsMax = defaultRowsMax
	}
	if c.FrozenCycles <= 0 {
		c.FrozenCycles = defaultFrozenCycles
	}
	if c.ChunkRevisions <= 0 {
		c.ChunkRevisions = defaultChunkRevisions
	}
	if c.Tail <= 0 {
		c.Tail = defaultTail
	}
	if c.MaxChunks <= 0 {
		c.MaxChunks = defaultMaxChunks
	}
	if c.FrozenHeadAdvance <= 0 {
		c.FrozenHeadAdvance = defaultFrozenHeadAdvance
	}
	if c.FrozenRetainedMin <= 0 {
		c.FrozenRetainedMin = defaultFrozenRetainedMin
	}
	if c.AdvisoryLockID == 0 {
		c.AdvisoryLockID = defaultAdvisoryLockID
	}
	// W16-CP1: NODE_HOST_AGENT_KINEDB_GUARD_MAX_STEP_REVISIONS
	// overrides the step cap when set to a positive integer —
	// 0/unset/garbage keeps MaxStepRevisions disabled (the
	// unbounded head-Tail step).
	applyStepRevisionEnv(c)
	if c.RepackDeadPct <= 0 {
		c.RepackDeadPct = defaultRepackDeadPct
	}
	if c.RepackMinHeapBytes <= 0 {
		c.RepackMinHeapBytes = defaultRepackMinHeapBytes
	}
	if c.BackupDir == "" {
		c.BackupDir = defaultBackupDir
	}
	if c.BackupInterval <= 0 {
		c.BackupInterval = defaultBackupInterval
	}
	if c.CmdTimeout <= 0 {
		c.CmdTimeout = defaultCmdTimeout
	}
	if c.LongCmdTimeout <= 0 {
		c.LongCmdTimeout = defaultLongCmdTimeout
	}
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
	}
	if c.Run == nil {
		c.Run = func(ctx context.Context, env, argv []string, stdin string) (string, error) {
			out, serr, err := hostexec.RunEnv(ctx, env, argv, stdin)
			// stderr stays out of the returned output — the same
			// split as etcdmaint's CmdRunner. A psql WARNING or a
			// "server version" notice on stderr would otherwise
			// merge into stdout and break the `== "1"` and a|b|c
			// parsers.
			serr = strings.TrimSpace(serr)
			switch {
			case err != nil && serr != "":
				return out, fmt.Errorf("%w: %s", err, serr)
			case serr != "":
				logger().Debug("kinedb command stderr",
					"cmd", argv[0], "stderr", serr)
			}
			return out, err
		}
	}
	if c.StatFSFn == nil {
		c.StatFSFn = statfsFree
	}
	return nil
}

// applyStepRevisionEnv is the W16-CP1 step-cap env rule shared by
// ConfigFromEnv's knob and ApplyDefaults (a directly-constructed
// Config never sees the knob): a positive NODE_HOST_AGENT_KINEDB_
// GUARD_MAX_STEP_REVISIONS becomes the cap; unset/0/garbage stays
// disabled.
func applyStepRevisionEnv(c *Config) {
	if v := strings.TrimSpace(os.Getenv(envnames.EnvKinedbGuardMaxStepRevisions)); v != "" {
		if n, perr := strconv.ParseInt(v, 10, 64); perr == nil && n > 0 {
			c.MaxStepRevisions = n
		}
	}
}

// statfsFree returns the free-byte ratio of the fs holding path —
// the StatFSFn default the backup-health backup verifier's >30%-free gate
// reads.
func statfsFree(path string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return 0, fmt.Errorf("statfs %s", path)
	}
	return float64(st.Bavail) / float64(st.Blocks), nil
}

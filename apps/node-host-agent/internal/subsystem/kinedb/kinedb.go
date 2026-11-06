// Package kinedb ports the three scripts that run on the Kine DB VM
// (passiontech-fluxcd infrastructure/base/node-watchdog/scripts/) —
// the VM lives OUTSIDE the cluster, so these used to be systemd
// timers writing node-exporter textfiles:
//
//   - kine-db-probe.sh      (2min) — app-layer probe of the
//     postgres+pgbouncer stack: container liveness, a pure-Go PG v3
//     StartupMessage wire probe, SCRAM e2e auth through the pooler,
//     .env credential-drift detection, pgbouncer error-log scan,
//     SHOW POOLS server-conn/queue depth and the revision horizon
//     (MAX(id) vs compact_rev_key) that predicts "required revision
//     has been compacted" apiserver wedges.
//   - kine-compact-guard.sh (10min) — emergency compactor: when
//     retained revisions or row count cross the debt thresholds, or
//     compact_rev stays frozen while head advances, it replays kine's
//     own UpdateCompactSQL+CompactSQL in 150K-revision chunks (max 20
//     per run) under a pg advisory lock, then VACUUM (ANALYZE).
//   - kine-db-maint.sh      (daily) — REINDEX TABLE CONCURRENTLY
//     (autovacuum never reindexes; index bloat made kine init exceed
//     the k0s health window, incident 2026-09-28) plus a threshold-
//     gated pg_repack when the heap is genuinely bloated.
//
// All three keep emitting the same node-exporter textfiles atomically
// (tmp + rename) AND register the same series as Prometheus
// collectors on the agent registry. Host commands (podman/docker
// exec, psql, pg_repack) run through one injectable runner seam;
// the wire probe is Go-native and injectable; clock is injectable.
//
// Behaviour-equivalent differences from the shell versions
// (documented, intentional):
//   - The flock on /run/kine-compact-guard.lock is replaced by
//     pg_try_advisory_lock(20260921) held for the whole compact
//     session: the lock + chunk DO blocks + VACUUM + unlock go down
//     ONE psql session (stdin script), so a second guard anywhere
//     skips instead of racing — and the lock auto-releases if the
//     session dies, which flock could not do across a host reboot.
//   - A failed chunk aborts the session before VACUUM instead of
//     vacuuming anyway — ON_ERROR_STOP makes the failure atomic.
//   - e2e auth + SHOW POOLS run psql inside the postgres container
//     against <pgbouncer>:5432 with the .env SCRAM credentials, the
//     exact path kine itself takes (in-container port on the podman
//     network — 6432 is only the published host port); the shell
//     instead exec'd into the pgbouncer container and read
//     userlist.txt.
//   - Heap dead-tuple percentage comes from pg_stat_user_tables
//     (n_dead_tup / (n_live_tup+n_dead_tup)) instead of a full
//     pgstattuple scan — same signal without the table read.
package kinedb

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// Defaults mirror the shell scripts + their systemd timers.
const (
	defaultProbeInterval = 2 * time.Minute
	defaultGuardInterval = 10 * time.Minute
	defaultMaintInterval = 24 * time.Hour

	defaultTextfileDir   = "/var/lib/node-exporter/textfile"
	defaultEnvFile       = "/opt/apps/postgres/.env"
	defaultGuardStateDir = "/var/lib/kine-compact-guard"

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

	defaultCmdTimeout     = 2 * time.Minute
	defaultLongCmdTimeout = 15 * time.Minute // compact session, VACUUM, REINDEX, repack
	pgWireTimeout         = 8 * time.Second

	compactRevKey = "compact_rev_key"

	lockBusyMarker = "kine-compact-guard advisory lock busy"
)

// Probe check names — the kine_db_probe_ok{check=...} label contract.
const (
	checkContainers = "containers"
	checkWire       = "wire"
	checkE2EAuth    = "e2e_auth"
	checkPools      = "pools"
	checkBackendEnv = "backend_env"
	checkLogErrors  = "log_errors"
	checkRevision   = "revision_horizon"
)

var probeChecks = []string{
	checkContainers, checkWire, checkE2EAuth, checkPools,
	checkBackendEnv, checkLogErrors, checkRevision,
}

var (
	// Container auto-discovery — the bash rename-resilience
	// (postgres-percona -> percona-postgres broke every check,
	// incident 2026-10-01). Only used when the configured names do
	// not inspect.
	rePGName    = regexp.MustCompile(`(?i)percona|postgres`)
	rePGExclude = regexp.MustCompile(`(?i)cleanup|pgbouncer`)
	rePGBName   = regexp.MustCompile(`(?i)pgbouncer|pgb`)
	rePGBLogErr = regexp.MustCompile(`server_login_retry|password authentication failed|pooler error`)
	reDeleted   = regexp.MustCompile(`deleted=([0-9]+)`)
	// Table is Sprintf'd into SQL all over the probe/guard/maint
	// queries — interpolation sites go through sqlIdent (identifier
	// positions) or sqlQuote (literal positions), and only a plain
	// SQL identifier is accepted anyway (belt and suspenders).
	reTableIdent = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	repackGlob   = `ls /usr/pgsql-*/bin/pg_repack /usr/lib/postgresql/*/bin/pg_repack 2>/dev/null | head -1`
	pgbAdminDB   = "pgbouncer" // SHOW POOLS lives on the admin console db
	poolDatabase = "postgres"  // the pool kine draws server conns from
)

// runner executes argv with optional stdin — the single command seam
// (podman/docker exec, logs, inspect). The default wires
// hostexec.Run and returns CLEAN stdout: stderr is captured
// separately — folded into the error on failure, debug-logged on
// success — so psql WARNING/NOTICE/version-skew lines cannot poison
// the exact-match stdout parsers.
type runner func(ctx context.Context, argv []string, stdin string) (string, error)

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

	// Maintenance.
	RepackDeadPct      int64 // dead-tuple % → repack candidate
	RepackMinHeapBytes int64 // heap bytes → repack candidate
	// PGDataDir is the in-container postgres data dir whose free
	// space gates pg_repack (W8-CP2); "" → /var/lib/postgresql/data.
	PGDataDir string

	CmdTimeout     time.Duration // per command budget
	LongCmdTimeout time.Duration // compact/vacuum/reindex/repack budget

	// --- injectable seams (defaults follow) ---
	nowFn  func() time.Time
	run    runner
	wireFn func(ctx context.Context, addr string) bool
}

func (c *Config) applyDefaults() error {
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
		c.EnvFile = defaultEnvFile
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
	if !reTableIdent.MatchString(c.Table) {
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
	if c.RepackDeadPct <= 0 {
		c.RepackDeadPct = defaultRepackDeadPct
	}
	if c.RepackMinHeapBytes <= 0 {
		c.RepackMinHeapBytes = defaultRepackMinHeapBytes
	}
	if c.CmdTimeout <= 0 {
		c.CmdTimeout = defaultCmdTimeout
	}
	if c.LongCmdTimeout <= 0 {
		c.LongCmdTimeout = defaultLongCmdTimeout
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	if c.run == nil {
		c.run = func(ctx context.Context, argv []string, stdin string) (string, error) {
			out, serr, err := hostexec.Run(ctx, argv, stdin)
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
	if c.wireFn == nil {
		c.wireFn = func(ctx context.Context, addr string) bool {
			return pgWireProbe(ctx, addr, pgWireTimeout)
		}
	}
	return nil
}

// metrics holds every collector mirrored into the textfiles.
type metrics struct {
	probeOK         *prometheus.GaugeVec // check
	serverConns     *prometheus.GaugeVec // state=active|idle
	clientsWaiting  prometheus.Gauge
	headRevision    prometheus.Gauge
	compactRevision prometheus.Gauge
	retained        prometheus.Gauge
	rows            prometheus.Gauge
	probeLastRun    prometheus.Gauge

	guardOK          prometheus.Gauge
	guardFreeze      prometheus.Gauge
	guardFired       prometheus.Gauge
	guardLastDeleted prometheus.Gauge
	guardLastCompact prometheus.Gauge
	guardLastRun     prometheus.Gauge
	guardRevAfter    prometheus.Gauge

	maintOK       *prometheus.GaugeVec // check=reindex|repack|vacuum_freeze
	maintRelBytes *prometheus.GaugeVec // kind=heap|indexes
	maintLastRun  prometheus.Gauge

	// kine-pg-hygiene + WAL archive guard series (wal_xid_hygiene.go).
	// idleTermTotal mirrors the idleTxTerm counter so the probe
	// textfile can render the cumulative value (prometheus counters
	// cannot be read back).
	idleInTx       prometheus.Gauge
	idleInTxAlias  prometheus.Gauge
	idleTxTerm     prometheus.Counter
	idleTermTotal  int64
	deadTupleRatio prometheus.Gauge
	xidAge         prometheus.Gauge
	walBytes       prometheus.Gauge
	walDiskRatio   prometheus.Gauge
	walArchStale   prometheus.Gauge
	inactiveSlot   prometheus.Gauge

	cycles *prometheus.CounterVec // loop, result
}

func newMetrics() *metrics {
	return &metrics{
		probeOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_probe_ok",
			Help: "App-layer probe result on the kine DB VM (1 = ok, 0 = fail).",
		}, []string{"check"}),
		serverConns: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_pgbouncer_server_conns",
			Help: "pgbouncer server connections for the postgres pool by state.",
		}, []string{"state"}),
		clientsWaiting: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_pgbouncer_clients_waiting",
			Help: "cl_waiting of the postgres pool — deep queue = client spiral.",
		}),
		headRevision: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_head_revision",
			Help: "MAX(id) of the kine table — newest revision on the DB.",
		}),
		compactRevision: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_compact_revision",
			Help: "Current compact horizon (MAX prev_revision of compact_rev_key).",
		}),
		retained: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_retained_revisions",
			Help: "head - compact_rev: revisions still retained (runway for lagging caches).",
		}),
		rows: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_rows",
			Help: "Row count of the kine table — kine boot fill cost.",
		}),
		probeLastRun: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_probe_last_run_timestamp_seconds",
			Help: "Last probe run.",
		}),
		guardOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_ok",
			Help: "Compact guard result (1 = ok/skip, 0 = fail).",
		}),
		guardFreeze: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_freeze_cycles",
			Help: "Consecutive runs compact_rev stayed frozen while head advanced.",
		}),
		guardFired: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_fired",
			Help: "1 when the last guard run executed a compact session.",
		}),
		guardLastDeleted: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_last_deleted_rows",
			Help: "Rows deleted by the last compact run.",
		}),
		guardLastCompact: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_last_compact_timestamp_seconds",
			Help: "Timestamp of the last completed compact run.",
		}),
		guardLastRun: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_last_run_timestamp_seconds",
			Help: "Last guard run.",
		}),
		guardRevAfter: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_compact_rev_after",
			Help: "compact_rev re-read after the last completed compact run.",
		}),
		maintOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_maint_ok",
			Help: "Maintenance job result (1 = ok/skip, 0 = fail).",
		}, []string{"check"}),
		maintRelBytes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_maint_relation_bytes",
			Help: "Heap/index size of the kine table.",
		}, []string{"kind"}),
		maintLastRun: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_maint_last_run_timestamp_seconds",
			Help: "Last maintenance run.",
		}),
		idleInTx: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_idle_in_tx_sessions",
			Help: "Sessions idle in transaction >3min on the postgres/kine databases — autovacuum blockers.",
		}),
		idleInTxAlias: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "node_agent_kine_pg_idle_in_tx_sessions",
			Help: "Alias of kine_db_idle_in_tx_sessions under the node_agent_* alert contract.",
		}),
		idleTxTerm: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_kine_pg_idle_in_tx_terminated_total",
			Help: "Stuck kine sessions terminated by the session reaper.",
		}),
		deadTupleRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "node_agent_kine_pg_dead_tuple_ratio",
			Help: "n_dead_tup / GREATEST(n_live_tup,1) of the kine table — >0.5 means autovacuum lost the race.",
		}),
		xidAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_xid_age_transactions",
			Help: "MAX(age(datfrozenxid)) across databases — distance to XID wraparound pressure.",
		}),
		walBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_wal_bytes",
			Help: "Total bytes in pg_wal (pg_ls_waldir).",
		}),
		walDiskRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_wal_disk_ratio",
			Help: "pg_wal bytes / data filesystem capacity — runaway retention fills the disk to PANIC.",
		}),
		walArchStale: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_wal_archive_stale",
			Help: "1 when pg_stat_archiver has been failing continuously for >30m.",
		}),
		inactiveSlot: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_inactive_slot_retained_bytes",
			Help: "WAL bytes pinned by inactive replication slots.",
		}),
		cycles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "node_host_agent_kinedb_cycles_total",
			Help: "kinedb loop cycles by loop and result.",
		}, []string{"loop", "result"}),
	}
}

func (m *metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.probeOK, m.serverConns, m.clientsWaiting, m.headRevision,
		m.compactRevision, m.retained, m.rows, m.probeLastRun,
		m.guardOK, m.guardFreeze, m.guardFired, m.guardLastDeleted,
		m.guardLastCompact, m.guardLastRun, m.guardRevAfter,
		m.maintOK, m.maintRelBytes, m.maintLastRun,
		m.idleInTx, m.idleInTxAlias, m.idleTxTerm, m.deadTupleRatio,
		m.xidAge, m.walBytes, m.walDiskRatio, m.walArchStale,
		m.inactiveSlot,
		m.cycles,
	}
}

// KineDB runs the probe, compact-guard and maintenance loops.
type KineDB struct {
	cfg Config
	m   *metrics

	// state is the shared watchdog-state contract handle (hoststate)
	// for the GuardStateDir last-* rate budgets (last-pgb-restart).
	// Now is a closure over k.cfg.nowFn — tests re-stub the clock
	// after New() and the store must observe the new one.
	state *hoststate.Store
}

// New returns a KineDB and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*KineDB, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	k := &KineDB{cfg: cfg, m: newMetrics()}
	k.state = hoststate.New(cfg.GuardStateDir, "",
		func() time.Time { return k.cfg.nowFn() }, logger)
	if reg != nil {
		var done []prometheus.Collector
		for _, c := range k.m.collectors() {
			if err := reg.Register(c); err != nil {
				// Roll back the partial registration — without it
				// a retry of New() hits duplicate-registration on
				// the collectors that did succeed.
				for _, r := range done {
					reg.Unregister(r)
				}
				return nil, fmt.Errorf("register kinedb metrics: %w", err)
			}
			done = append(done, c)
		}
	}
	return k, nil
}

// Name identifies the subsystem for logging.
func (k *KineDB) Name() string { return "kinedb" }

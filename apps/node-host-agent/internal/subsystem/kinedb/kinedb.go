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
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	yaml "go.yaml.in/yaml/v3"
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
	rePGName     = regexp.MustCompile(`(?i)percona|postgres`)
	rePGExclude  = regexp.MustCompile(`(?i)cleanup|pgbouncer`)
	rePGBName    = regexp.MustCompile(`(?i)pgbouncer|pgb`)
	rePGBLogErr  = regexp.MustCompile(`server_login_retry|password authentication failed|pooler error`)
	reDeleted    = regexp.MustCompile(`deleted=([0-9]+)`)
	repackGlob   = `ls /usr/pgsql-*/bin/pg_repack /usr/lib/postgresql/*/bin/pg_repack 2>/dev/null | head -1`
	pgbAdminDB   = "pgbouncer" // SHOW POOLS lives on the admin console db
	poolDatabase = "postgres"  // the pool kine draws server conns from
)

// runner executes argv with optional stdin — the single command seam
// (podman/docker exec, logs, inspect). Default is exec.CommandContext.
type runner func(ctx context.Context, argv []string, stdin string) (string, error)

// Config carries the kinedb knobs — all test-injectable.
type Config struct {
	Enabled bool // false → Run idles until ctx done

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

	CmdTimeout     time.Duration // per command budget
	LongCmdTimeout time.Duration // compact/vacuum/reindex/repack budget

	// --- injectable seams (defaults follow) ---
	nowFn  func() time.Time
	run    runner
	wireFn func(ctx context.Context, addr string) bool
}

func (c *Config) applyDefaults() {
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
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			if stdin != "" {
				cmd.Stdin = strings.NewReader(stdin)
			}
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
	}
	if c.wireFn == nil {
		c.wireFn = func(ctx context.Context, addr string) bool {
			return pgWireProbe(ctx, addr, pgWireTimeout)
		}
	}
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

	maintOK       *prometheus.GaugeVec // check=reindex|repack
	maintRelBytes *prometheus.GaugeVec // kind=heap|indexes
	maintLastRun  prometheus.Gauge

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
		m.cycles,
	}
}

// KineDB runs the probe, compact-guard and maintenance loops.
type KineDB struct {
	cfg Config
	m   *metrics
}

// New returns a KineDB and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*KineDB, error) {
	cfg.applyDefaults()
	k := &KineDB{cfg: cfg, m: newMetrics()}
	if reg != nil {
		for _, c := range k.m.collectors() {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register kinedb metrics: %w", err)
			}
		}
	}
	return k, nil
}

// Name identifies the subsystem for logging.
func (k *KineDB) Name() string { return "kinedb" }

// Detect reports whether this host looks like the kine DB VM: either
// the postgres stack env file exists under hostRoot, or cluster.yaml
// in varsDir carries a `kine_db: true` node_exporter_extra_hosts
// entry matching this host (name = hostname or ip = local address).
// hostRoot "" means "/" (already on the host).
func Detect(hostRoot, varsDir string) bool {
	if hostRoot == "" {
		hostRoot = "/"
	}
	envPath := filepath.Join(hostRoot, strings.TrimPrefix(defaultEnvFile, "/"))
	if _, err := os.Stat(envPath); err == nil {
		return true
	}
	if varsDir == "" {
		return false
	}
	entries := readExtraHosts(filepath.Join(varsDir, "cluster.yaml"))
	if len(entries) == 0 {
		return false
	}
	return matchKineDBHost(entries, hostHostname(hostRoot), hostIPs())
}

type extraHost struct {
	Name   string `yaml:"name"`
	IP     string `yaml:"ip"`
	KineDB bool   `yaml:"kine_db"`
}

// readExtraHosts parses node_exporter_extra_hosts out of cluster.yaml.
// Returns nil on any read/parse failure (detection stays fail-quiet).
func readExtraHosts(path string) []extraHost {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		ExtraHosts []extraHost `yaml:"node_exporter_extra_hosts"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return doc.ExtraHosts
}

// matchKineDBHost reports whether any kine_db:true extra-host entry
// names this host or carries one of its IPs.
func matchKineDBHost(entries []extraHost, hostname string, ips map[string]bool) bool {
	for _, e := range entries {
		if !e.KineDB {
			continue
		}
		if hostname != "" && e.Name == hostname {
			return true
		}
		if e.IP != "" && ips[e.IP] {
			return true
		}
	}
	return false
}

func hostHostname(hostRoot string) string {
	if data, err := os.ReadFile(filepath.Join(hostRoot, "etc/hostname")); err == nil {
		if h := strings.TrimSpace(string(data)); h != "" {
			return h
		}
	}
	h, _ := os.Hostname()
	return h
}

// hostIPs returns this host's interface IPs as a set — used to match
// a kine_db extra-host entry to the local machine.
func hostIPs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		out[ip.String()] = true
	}
	return out
}

// Run starts the three loops (probe, compact guard, maintenance) and
// blocks until ctx is cancelled.
func (k *KineDB) Run(ctx context.Context) {
	if !k.cfg.Enabled {
		<-ctx.Done()
		return
	}
	var wg sync.WaitGroup
	for _, l := range []struct {
		name  string
		every time.Duration
		fn    func(context.Context)
	}{
		{"probe", k.cfg.ProbeInterval, func(ctx context.Context) { k.probeCycle(ctx) }},
		{"compact-guard", k.cfg.GuardInterval, func(ctx context.Context) { k.guardCycle(ctx) }},
		{"maint", k.cfg.MaintInterval, func(ctx context.Context) { k.maintCycle(ctx) }},
	} {
		l := l
		wg.Add(1)
		go func() {
			defer wg.Done()
			k.loop(ctx, l.name, l.every, l.fn)
		}()
	}
	wg.Wait()
}

func (k *KineDB) loop(ctx context.Context, name string, every time.Duration, fn func(context.Context)) {
	k.safeCycle(ctx, name, fn)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			k.safeCycle(ctx, name, fn)
		}
	}
}

func (k *KineDB) safeCycle(ctx context.Context, name string, fn func(context.Context)) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("kinedb cycle panicked", "loop", name, "panic", r)
			k.m.cycles.WithLabelValues(name, "panic").Inc()
		}
	}()
	fn(ctx)
}

// --- command + container helpers ---

// exec runs argv under the short command budget.
func (k *KineDB) exec(ctx context.Context, argv []string, stdin string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, k.cfg.CmdTimeout)
	defer cancel()
	return k.cfg.run(cctx, argv, stdin)
}

// execLong runs argv under the maintenance budget.
func (k *KineDB) execLong(ctx context.Context, argv []string, stdin string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, k.cfg.LongCmdTimeout)
	defer cancel()
	return k.cfg.run(cctx, argv, stdin)
}

// discoverContainer returns preferred when it exists, else the first
// running container matching match (and not exclude) — the bash
// rename-resilience for stack redeploys.
func (k *KineDB) discoverContainer(ctx context.Context, preferred string, match, exclude *regexp.Regexp) string {
	if _, err := k.exec(ctx, []string{k.cfg.Runtime, "inspect", preferred}, ""); err == nil {
		return preferred
	}
	out, err := k.exec(ctx, []string{k.cfg.Runtime, "ps", "--format", "{{.Names}}"}, "")
	if err != nil {
		return preferred
	}
	for _, n := range strings.Split(out, "\n") {
		n = strings.TrimSpace(n)
		if n == "" || !match.MatchString(n) {
			continue
		}
		if exclude != nil && exclude.MatchString(n) {
			continue
		}
		return n
	}
	return preferred
}

func (k *KineDB) pgContainerName(ctx context.Context) string {
	return k.discoverContainer(ctx, k.cfg.PGContainer, rePGName, rePGExclude)
}

func (k *KineDB) pgbContainerName(ctx context.Context) string {
	return k.discoverContainer(ctx, k.cfg.PGBouncerContainer, rePGBName, nil)
}

func (k *KineDB) containerRunning(ctx context.Context, name string) bool {
	out, err := k.exec(ctx, []string{k.cfg.Runtime, "inspect", "-f", "{{.State.Running}}", name}, "")
	return err == nil && strings.Contains(out, "true")
}

// creds re-reads the stack .env every cycle — the backend_env check
// exists to catch credential drift, so caching would hide it.
func (k *KineDB) creds() (user, pass string, ok bool) {
	data, err := os.ReadFile(k.cfg.EnvFile)
	if err != nil {
		return "", "", false
	}
	user = envValue(string(data), "POSTGRES_USER")
	pass = envValue(string(data), "POSTGRES_PASSWORD")
	return user, pass, user != "" && pass != ""
}

// envValue extracts KEY=value, removing the chars the bash
// `tr -d "\"' "` deleted — every quote and space, not just the edges.
func envValue(data, key string) string {
	prefix := key + "="
	for _, l := range strings.Split(data, "\n") {
		if strings.HasPrefix(l, prefix) {
			v := strings.TrimPrefix(l, prefix)
			return strings.Map(func(r rune) rune {
				switch r {
				case '"', '\'', ' ':
					return -1
				}
				return r
			}, v)
		}
	}
	return ""
}

// psqlArgs builds `RT exec [-i] -e PGPASSWORD=.. <pg> psql -h 127.0.0.1
// -U <user> -d postgres <extra...>` — every backend query goes through
// the container like the bash originals.
func (k *KineDB) psqlArgs(pg, user, pass string, interactive bool, extra ...string) []string {
	argv := []string{k.cfg.Runtime, "exec"}
	if interactive {
		argv = append(argv, "-i")
	}
	argv = append(argv, "-e", "PGPASSWORD="+pass, pg,
		"psql", "-h", "127.0.0.1", "-U", user, "-d", "postgres")
	return append(argv, extra...)
}

// psqlQuery runs one statement with -tAc (unaligned, tuples only).
func (k *KineDB) psqlQuery(ctx context.Context, pg, user, pass, sql string) (string, error) {
	return k.exec(ctx, k.psqlArgs(pg, user, pass, false, "-tAc", sql), "")
}

// psqlScript runs a multi-statement script in ONE psql session via
// stdin — required for the session-scoped advisory lock to cover the
// chunk loop + vacuum.
func (k *KineDB) psqlScript(ctx context.Context, pg, user, pass, script string) (string, error) {
	return k.execLong(ctx, k.psqlArgs(pg, user, pass, true,
		"-v", "ON_ERROR_STOP=1", "-f", "-"), script)
}

// --- textfile helpers ---

// writeTextfileAtomic writes content to dir/.tmp-* then renames over
// dir/name — the textfile collector rejects partially-written files.
func writeTextfileAtomic(dir, name string, content []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// promBuf accumulates HELP/TYPE/sample lines for one textfile.
// Headers (# HELP / # TYPE) are emitted once per metric family —
// node_exporter's textfile collector rejects duplicate HELP/TYPE
// lines for the same metric name.
type promBuf struct {
	b    strings.Builder
	seen map[string]bool
}

func (p *promBuf) gauge(name, help string, v float64) {
	p.gaugeLabels(name, help, "", v)
}

func (p *promBuf) gaugeLabels(name, help, labels string, v float64) {
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	if !p.seen[name] {
		p.seen[name] = true
		fmt.Fprintf(&p.b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&p.b, "# TYPE %s gauge\n", name)
	}
	val := strconv.FormatFloat(v, 'f', -1, 64)
	if labels != "" {
		fmt.Fprintf(&p.b, "%s{%s} %s\n", name, labels, val)
	} else {
		fmt.Fprintf(&p.b, "%s %s\n", name, val)
	}
}

func (p *promBuf) String() string { return p.b.String() }

func (k *KineDB) emitTextfile(name string, p *promBuf) {
	if err := writeTextfileAtomic(k.cfg.TextfileDir, name, []byte(p.String())); err != nil {
		slog.Warn("kinedb textfile write failed", "file", name, "error", err)
	}
}

// --- small parsing helpers ---

func firstLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// parsePair parses a `a|b` psql -tA row into two int64s.
func parsePair(out string) (a, b int64, err error) {
	f := strings.Split(firstLine(out), "|")
	if len(f) < 2 {
		return 0, 0, fmt.Errorf("expected 2 fields, got %q", firstLine(out))
	}
	if a, err = strconv.ParseInt(strings.TrimSpace(f[0]), 10, 64); err != nil {
		return 0, 0, err
	}
	if b, err = strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64); err != nil {
		return 0, 0, err
	}
	return a, b, nil
}

// parseTriple parses a `a|b|c` psql -tA row into three int64s.
func parseTriple(out string) (a, b, c int64, err error) {
	f := strings.Split(firstLine(out), "|")
	if len(f) < 3 {
		return 0, 0, 0, fmt.Errorf("expected 3 fields, got %q", firstLine(out))
	}
	if a, err = strconv.ParseInt(strings.TrimSpace(f[0]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	if b, err = strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	if c, err = strconv.ParseInt(strings.TrimSpace(f[2]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	return a, b, c, nil
}

// parseQuad parses a `a|b|c|d` psql -tA row into four int64s.
func parseQuad(out string) (a, b, c, d int64, err error) {
	f := strings.Split(firstLine(out), "|")
	if len(f) < 4 {
		return 0, 0, 0, 0, fmt.Errorf("expected 4 fields, got %q", firstLine(out))
	}
	vals := []*int64{&a, &b, &c, &d}
	for i := range vals {
		if *vals[i], err = strconv.ParseInt(strings.TrimSpace(f[i]), 10, 64); err != nil {
			return 0, 0, 0, 0, err
		}
	}
	return a, b, c, d, nil
}

func readIntFile(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func writeIntFile(path string, v int64) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("kinedb state file write failed", "file", path, "error", err)
		return
	}
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(v, 10)+"\n"), 0o644); err != nil {
		slog.Warn("kinedb state file write failed", "file", path, "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		slog.Warn("kinedb state file write failed", "file", path, "error", err)
	}
}

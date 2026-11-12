// Package probe ports kine-db-probe.sh — the 2-minute app-layer
// probe of the postgres+pgbouncer stack on the kine DB VM:
// container liveness, a pure-Go PG v3 StartupMessage wire probe,
// SCRAM e2e auth through the pooler, .env credential-drift
// detection, pgbouncer error-log scan, SHOW POOLS server-conn/queue
// depth and the revision horizon (MAX(id) vs compact_rev_key) that
// predicts "required revision has been compacted" apiserver wedges.
//
// The probe cycle also carries the remediation blocks that share
// its 2-minute cadence (selfheal.go: session reaper + pgbouncer
// wedge restart, hygiene.go: the kine-pg-hygiene census + WAL
// archive guard, churn.go: the top-5 write-churn sampler). The
// compact-guard and maint loops live in their own packages beside
// this one; everything shared goes through kdeps.Deps.
package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// Check names — the kine_db_probe_ok{check=...} label contract.
const (
	CheckContainers = "containers"
	CheckWire       = "wire"
	CheckE2EAuth    = "e2e_auth"
	CheckPools      = "pools"
	CheckBackendEnv = "backend_env"
	CheckLogErrors  = "log_errors"
	CheckRevision   = "revision_horizon"
)

var probeChecks = []string{
	CheckContainers, CheckWire, CheckE2EAuth, CheckPools,
	CheckBackendEnv, CheckLogErrors, CheckRevision,
}

var (
	rePGBLogErr  = regexp.MustCompile(`server_login_retry|password authentication failed|pooler error`)
	pgbAdminDB   = "pgbouncer" // SHOW POOLS lives on the admin console db
	poolDatabase = "postgres"  // the pool kine draws server conns from
)

const pgWireTimeout = 8 * time.Second

// Probe runs the 2-minute check round — the kine-db-probe.sh port
// plus the probe-cadence remediations. Config, metrics, the state
// store, the exec plumbing and the churn hand-off live on the
// shared *kdeps.Deps; the two fields below are the process-lifetime
// state hygiene.go keeps in-process.
type Probe struct {
	d *kdeps.Deps

	// largeKeys is the last successful top-5 census — the persisted
	// last-kine-large-keys budget decides when it refreshes, so a
	// restart re-censuses only after the window (the series goes
	// absent for the remainder — same contract as storelocal's
	// maxObjBytes).
	largeKeysMu   sync.Mutex
	largeKeysRows []largeKeyRow
	largeKeysSeen bool

	// preparedXactRolledBack is the lifetime count behind
	// kine_db_orphan_prepared_xacts_rolled_back_total — cumulative
	// like Metrics.IdleTermTotal (a prometheus Counter resets on
	// restart anyway; the textfile emits the running total every
	// round the block runs).
	preparedXactRolledBack atomic.Int64
}

// New returns the probe loop over d, filling the wire-probe seam
// default (the Go-native PG v3 StartupMessage) when the config
// left it unset.
func New(d *kdeps.Deps) *Probe {
	if d.Cfg.WireFn == nil {
		d.Cfg.WireFn = func(ctx context.Context, addr string) bool {
			return pgWireProbe(ctx, addr, pgWireTimeout)
		}
	}
	return &Probe{d: d}
}

// pgWireProbe dials addr, sends the StartupMessage and classifies the
// first response byte via the shared probee.PGWireProbeWithTimeout helper.
func pgWireProbe(ctx context.Context, addr string, timeout time.Duration) bool {
	return probee.PGWireProbeWithTimeout(ctx, addr, timeout)
}

// poolStats is one parsed SHOW POOLS row for the kine database.
type poolStats struct {
	svActive    int64
	svIdle      int64
	serverConns int64 // sum of every sv_* column (bash parity)
	clWaiting   int64
	// maxWaitSec is the `maxwait` column — the age in seconds of the
	// oldest client queued for a server conn (pgbouncer-pool-starvation starvation
	// signal; maxwait_us's fractional part adds nothing the guard
	// needs).
	maxWaitSec int64
}

// isPoolsHeader reports whether a `SHOW POOLS` field row is the
// column header rather than a data row: f[0]=="database" alone is
// not enough — a pool can literally be named "database" — so the
// row must also carry sv_*/cl_* column names (a data row has numbers
// in those positions; only the header spells the names out).
func isPoolsHeader(f []string) bool {
	if len(f) < 2 || f[0] != "database" {
		return false
	}
	for _, name := range f[1:] {
		if strings.HasPrefix(name, "sv_") || strings.HasPrefix(name, "cl_") {
			return true
		}
	}
	return false
}

// parseShowPools parses `psql -Aqc "SHOW POOLS"` output by header name
// (the shell did the same — sv_* column positions shift between
// pgbouncer versions). SHOW POOLS emits one row per (database,user)
// pair, so every row for dbName is aggregated: sv_* columns sum,
// cl_waiting and maxwait take the worst. Returns false when the
// header or no matching pool row is present.
func parseShowPools(out, dbName string) (poolStats, bool) {
	var hdr map[string]int
	var st poolStats
	seen := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "|")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		switch {
		case isPoolsHeader(f):
			hdr = map[string]int{}
			for i, name := range f {
				hdr[name] = i
			}
		case hdr == nil || f[0] != dbName:
			continue
		default:
			seen = true
			for name, i := range hdr {
				if i >= len(f) {
					continue
				}
				v, err := strconv.ParseInt(f[i], 10, 64)
				if err != nil {
					continue
				}
				switch {
				case name == "sv_active":
					st.svActive += v
				case name == "sv_idle":
					st.svIdle += v
				case name == "cl_waiting" && v > st.clWaiting:
					st.clWaiting = v
				case name == "maxwait" && v > st.maxWaitSec:
					st.maxWaitSec = v
				}
				if strings.HasPrefix(name, "sv_") {
					st.serverConns += v
				}
			}
		}
	}
	return st, seen
}

// Result captures one probe run for emission + tests — was
// probeResult. The exported half is the check-kine-db CLI's report
// surface (the facade renders OK/FAIL lines from it); the rest is
// emission/test internal.
type Result struct {
	Checks  map[string]int64
	Head    int64
	Compact int64
	LiveTup int64
	RevSeen bool
	// Reporting fields for the check-kine-db CLI — names + counters
	// the bash script interpolated into its check lines.
	PGName  string // resolved postgres container name
	PGBName string // resolved pgbouncer container name
	EnvUser string // POSTGRES_USER read from the stack .env
	LogErrs int64  // error-line count in the pgbouncer log window

	pool      poolStats
	poolSeen  bool
	notes     []string
	succeeded bool
	// logScanned is false when `logs` itself failed — log_errors is
	// then inconclusive (a fabricated clean window must neither
	// pass nor fail the probe).
	logScanned bool

	// hyg is the kine-pg-hygiene + WAL archive guard read
	// (hygiene.go) — nil when the block did not run this round
	// (no containers/creds), so emission skips its series.
	hyg *hygieneResult
}

// RunChecks executes every probe check once and fills Result — no
// metrics, no textfile. Cycle adds emission on top; the facade's
// RunCheckCLI consumes the same result for OK/FAIL lines. Was
// runProbeChecks.
func (p *Probe) RunChecks(ctx context.Context) *Result {
	res := &Result{Checks: map[string]int64{}}
	for _, c := range probeChecks {
		res.Checks[c] = 0
	}
	note := func(s string) { res.notes = append(res.notes, s) }

	pg := p.d.PGContainerName(ctx)
	pgb := p.d.PGBContainerName(ctx)
	res.PGName, res.PGBName = pg, pgb

	// (a) containers running — one batched inspect answers both
	// names (was two `inspect -f` forks per cycle).
	running := p.d.ContainersRunning(ctx, pg, pgb)
	if running[0] && running[1] {
		res.Checks[CheckContainers] = 1
	} else {
		note(fmt.Sprintf("containers down (%s and/or %s)", pg, pgb))
	}

	// (b) wire probe — unconditional like the shell: the whole point
	// is catching a pooler that accepts TCP but fails backend auth.
	if p.d.Cfg.WireFn(ctx, p.d.Cfg.WireAddr) {
		res.Checks[CheckWire] = 1
	} else {
		note("wire-probe-fail " + p.d.Cfg.WireAddr)
	}

	user, pass, credOK := p.d.Creds()
	res.EnvUser = user
	if res.Checks[CheckContainers] == 1 {
		// (e) pgbouncer log scan needs no .env creds — the bash
		// ran it whenever both containers were up.
		p.probeLogScan(ctx, pgb, res, note)
		if !credOK {
			note(fmt.Sprintf("missing .env creds (%s)", p.d.Cfg.EnvFile))
		} else {
			// kinedb-maintenance: reap stuck sessions each probe round —
			// idle-in-transaction >5m or a non-maintenance active
			// query >10m holds locks the compact guard needs.
			p.reapStuckSessions(ctx, pg, user, pass, note)
			p.probeAppChecks(ctx, pg, pgb, user, pass, res, note)
			// kine-pg-hygiene + WAL archive guard: cheap pg_stat
			// census each round (idle-in-tx, dead tuples, XID age,
			// pg_wal/archiver/slots) plus the gated remediations.
			p.pgHygiene(ctx, pg, user, pass, res, note)
			// kinedb-maintenance: pgbouncer saturation/auth wedge — deep
			// client queue, or e2e auth failing while the raw
			// backend still logs in, means the pooler itself is
			// the wedge → container restart (15m cooldown).
			// pgbouncer-pool-starvation rides the same check: a starved wait queue
			// (maxwait>10s / cl_waiting with sv_active==0) while
			// the backend idles below the pool's conn count →
			// RECONNECT the stalled server conns first.
			p.checkPGBWedge(ctx, pg, pgb, user, pass, res, note)
			// kine-churn: top-5 write churn — a mutating webhook
			// ping-pong shows up as one resource prefix churning
			// thousands of revisions.
			p.probeTopChurn(ctx, pg, user, pass, note)
		}
	}

	res.succeeded = res.Checks[CheckContainers] == 1 &&
		res.Checks[CheckWire] == 1 &&
		res.Checks[CheckE2EAuth] == 1 &&
		res.Checks[CheckPools] == 1 &&
		res.Checks[CheckBackendEnv] == 1 &&
		// log_errors only counts when the log read worked — like
		// revision_horizon, an inconclusive check zeroes the gauge
		// without failing the probe.
		(!res.logScanned || res.Checks[CheckLogErrors] == 1)
	return res
}

// Cycle runs one full probe round and emits metrics + textfile —
// was probeCycle. Returns the result for tests.
func (p *Probe) Cycle(ctx context.Context) *Result {
	res := p.RunChecks(ctx)

	p.emitProbe(res)
	sum := fmt.Sprintf(
		"containers=%d wire=%d e2e_auth=%d pools=%d backend_env=%d "+
			"log_errors=%d revision_horizon=%d head=%s compact_rev=%s live_tup=%s",
		res.Checks[CheckContainers], res.Checks[CheckWire],
		res.Checks[CheckE2EAuth], res.Checks[CheckPools],
		res.Checks[CheckBackendEnv], res.Checks[CheckLogErrors],
		res.Checks[CheckRevision], kdeps.IntOrNA(res.RevSeen, res.Head),
		kdeps.IntOrNA(res.RevSeen, res.Compact), kdeps.IntOrNA(res.RevSeen, res.LiveTup))
	if res.succeeded {
		logger().Info("kine-db-probe OK: " + sum)
		p.d.M.Cycles.WithLabelValues("probe", "ok").Inc()
	} else {
		logger().Warn("kine-db-probe FAIL: "+sum, "notes", strings.Join(res.notes, " "))
		p.d.M.Cycles.WithLabelValues("probe", "fail").Inc()
	}
	return res
}

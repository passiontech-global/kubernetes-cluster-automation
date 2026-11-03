// probe.go — the 2-minute app-layer probe (kine-db-probe.sh port).
// Checks, each one a kine_db_probe_ok{check=...} series:
//
//	containers       kine-postgres + kine-pgbouncer running
//	wire             StartupMessage → 'R'/'S'/'N'/'K' (TCP alone
//	                 misses "server login has been failing",
//	                 incident 2026-09-25)
//	e2e_auth         .env SCRAM creds through the pooler at
//	                 <pgbouncer>:5432 — the exact path kine takes
//	                 (in-container port; 6432 is the published
//	                 host port only)
//	pools            SHOW POOLS: server conns > 0 and cl_waiting
//	                 <= WaitMax (deep queue = apiserver flap,
//	                 incident 2026-10-01)
//	backend_env      .env creds log into the backend — catches
//	                 the initdb-skip credential drift trap
//	log_errors       pgbouncer log 301s clean of login_retry /
//	                 password failed / pooler error
//	revision_horizon MAX(id) / compact_rev_key / n_live_tup
//	                 → head/compact/retained gauges. kine_db_rows
//	                 is intentionally NOT counted here — COUNT(*)
//	                 seq-scans the very table whose bloat the
//	                 probe monitors, so the bash only ran it in the
//	                 10-min guard. The guard emits kine_db_rows
//	                 into kine-compact-guard.prom instead (never
//	                 both files: duplicate series across textfiles
//	                 fail the whole scrape).
package kinedb

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

// pgStartupMessage builds the protocol-3.0 StartupMessage — the same
// payload the bash probe sent via python:
//
//	\x00\x03\x00\x00 + "user\x00<U>\x00database\x00<D>\x00\x00"
//
// wrapped in the length-prefixed packet.
func pgStartupMessage(user, db string) []byte {
	params := "user\x00" + user + "\x00database\x00" + db + "\x00\x00"
	body := append([]byte{0x00, 0x03, 0x00, 0x00}, params...) // 196608 BE
	pkt := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(pkt, uint32(len(body)+4))
	return append(pkt, body...)
}

// pgFirstByteOK classifies the first server response byte: 'R' auth
// request / 'S' param status / 'N' notice / 'K' backend key all mean
// the pooler is alive; 'E' (ErrorResponse, e.g. server_login_retry),
// RST or timeout mean broken.
func pgFirstByteOK(b byte) bool {
	switch b {
	case 'R', 'S', 'N', 'K':
		return true
	}
	return false
}

// pgWireProbe dials addr, sends the StartupMessage and classifies the
// first response byte — the Go-native port of the python heredoc.
func pgWireProbe(ctx context.Context, addr string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(pgStartupMessage("postgres", "postgres")); err != nil {
		return false
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return false
	}
	return pgFirstByteOK(b[0])
}

// poolStats is one parsed SHOW POOLS row for the kine database.
type poolStats struct {
	svActive    int64
	svIdle      int64
	serverConns int64 // sum of every sv_* column (bash parity)
	clWaiting   int64
}

// parseShowPools parses `psql -Aqc "SHOW POOLS"` output by header name
// (the shell did the same — sv_* column positions shift between
// pgbouncer versions). Returns false when the header or the pool row
// is absent.
func parseShowPools(out, dbName string) (poolStats, bool) {
	var hdr map[string]int
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "|")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		switch f[0] {
		case "database":
			hdr = map[string]int{}
			for i, name := range f {
				hdr[name] = i
			}
		case dbName:
			if hdr == nil {
				continue
			}
			st := poolStats{}
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
					st.svActive = v
				case name == "sv_idle":
					st.svIdle = v
				case name == "cl_waiting":
					st.clWaiting = v
				}
				if strings.HasPrefix(name, "sv_") {
					st.serverConns += v
				}
			}
			return st, true
		}
	}
	return poolStats{}, false
}

// probeResult captures one probe run for emission + tests.
type probeResult struct {
	checks    map[string]int64
	pool      poolStats
	poolSeen  bool
	head      int64
	compact   int64
	liveTup   int64
	revSeen   bool
	notes     []string
	succeeded bool

	// Reporting fields for the check-kine-db CLI — names + counters
	// the bash script interpolated into its check lines.
	pgName  string // resolved postgres container name
	pgbName string // resolved pgbouncer container name
	envUser string // POSTGRES_USER read from the stack .env
	logErrs int64  // error-line count in the pgbouncer log window
}

// runProbeChecks executes every probe check once and fills
// probeResult — no metrics, no textfile. probeCycle adds emission
// on top; RunCheckCLI consumes the same result for OK/FAIL lines.
func (k *KineDB) runProbeChecks(ctx context.Context) *probeResult {
	res := &probeResult{checks: map[string]int64{}}
	for _, c := range probeChecks {
		res.checks[c] = 0
	}
	note := func(s string) { res.notes = append(res.notes, s) }

	pg := k.pgContainerName(ctx)
	pgb := k.pgbContainerName(ctx)
	res.pgName, res.pgbName = pg, pgb

	// (a) containers running.
	if k.containerRunning(ctx, pg) && k.containerRunning(ctx, pgb) {
		res.checks[checkContainers] = 1
	} else {
		note(fmt.Sprintf("containers down (%s and/or %s)", pg, pgb))
	}

	// (b) wire probe — unconditional like the shell: the whole point
	// is catching a pooler that accepts TCP but fails backend auth.
	if k.cfg.wireFn(ctx, k.cfg.WireAddr) {
		res.checks[checkWire] = 1
	} else {
		note(fmt.Sprintf("wire-probe-fail %s", k.cfg.WireAddr))
	}

	user, pass, credOK := k.creds()
	res.envUser = user
	if res.checks[checkContainers] == 1 {
		// (e) pgbouncer log scan needs no .env creds — the bash
		// ran it whenever both containers were up.
		k.probeLogScan(ctx, pgb, res, note)
		if !credOK {
			note(fmt.Sprintf("missing .env creds (%s)", k.cfg.EnvFile))
		} else {
			k.probeAppChecks(ctx, pg, pgb, user, pass, res, note)
		}
	}

	res.succeeded = res.checks[checkContainers] == 1 &&
		res.checks[checkWire] == 1 &&
		res.checks[checkE2EAuth] == 1 &&
		res.checks[checkPools] == 1 &&
		res.checks[checkBackendEnv] == 1 &&
		res.checks[checkLogErrors] == 1
	return res
}

// probeCycle runs one full probe round and emits metrics + textfile.
// Returns the result for tests.
func (k *KineDB) probeCycle(ctx context.Context) *probeResult {
	res := k.runProbeChecks(ctx)

	k.emitProbe(res)
	sum := fmt.Sprintf(
		"containers=%d wire=%d e2e_auth=%d pools=%d backend_env=%d "+
			"log_errors=%d revision_horizon=%d head=%s compact_rev=%s live_tup=%s",
		res.checks[checkContainers], res.checks[checkWire],
		res.checks[checkE2EAuth], res.checks[checkPools],
		res.checks[checkBackendEnv], res.checks[checkLogErrors],
		res.checks[checkRevision], intOrNA(res.revSeen, res.head),
		intOrNA(res.revSeen, res.compact), intOrNA(res.revSeen, res.liveTup))
	if res.succeeded {
		slog.Info("kine-db-probe OK: " + sum)
		k.m.cycles.WithLabelValues("probe", "ok").Inc()
	} else {
		slog.Warn("kine-db-probe FAIL: "+sum, "notes", strings.Join(res.notes, " "))
		k.m.cycles.WithLabelValues("probe", "fail").Inc()
	}
	return res
}

// probeAppChecks covers every check that needs containers + creds.
func (k *KineDB) probeAppChecks(ctx context.Context, pg, pgb, user, pass string,
	res *probeResult, note func(string)) {

	// (c) e2e auth — psql inside the postgres container THROUGH the
	// pooler, SCRAM-SHA-256 end to end (client auth + backend auth +
	// query): the exact path kine takes. When pgbouncer listens on
	// in-container port 5432 with credentials in pgbouncer.ini +
	// userlist.txt (edoburu/pgbouncer compose stack), fall back to
	// querying 127.0.0.1:5432 inside the pgbouncer container.
	out, err := k.exec(ctx, []string{k.cfg.Runtime, "exec",
		"-e", "PGPASSWORD=" + pass, pg,
		"psql", "-h", pgb, "-p", k.cfg.PoolerPort,
		"-U", user, "-d", "postgres", "-tAc", "select 1"}, "")
	if err != nil || strings.TrimSpace(out) != "1" {
		out, err = k.exec(ctx, []string{k.cfg.Runtime, "exec", pgb, "sh", "-c",
			`U=$(sed -n "s/^admin_users *= *//p" /etc/pgbouncer/pgbouncer.ini | cut -d, -f1 | tr -d " "); ` +
				`[ -n "$U" ] || U=$(sed -n "s/^stats_users *= *//p" /etc/pgbouncer/pgbouncer.ini | cut -d, -f1 | tr -d " "); ` +
				`P=$(grep "^\"$U\"" /etc/pgbouncer/userlist.txt | cut -d\" -f4); ` +
				`PGPASSWORD="$P" psql -h 127.0.0.1 -p 5432 -U "$U" postgres -tAc "select 1"`}, "")
	}
	if err == nil && strings.TrimSpace(out) == "1" {
		res.checks[checkE2EAuth] = 1
	} else {
		note(fmt.Sprintf("e2e-auth-fail via %s:%s", pgb, k.cfg.PoolerPort))
	}

	// (f) SHOW POOLS on the admin console — server conns > 0 means
	// the backend auth_user can log in; cl_waiting is the queue
	// depth (client spiral leading indicator). Falls back to
	// in-container :5432 with stats_users from pgbouncer.ini when
	// the direct .env credential/port path is unavailable.
	pools, err := k.exec(ctx, []string{k.cfg.Runtime, "exec",
		"-e", "PGPASSWORD=" + pass, pg,
		"psql", "-h", pgb, "-p", k.cfg.PoolerPort,
		"-U", user, "-d", pgbAdminDB, "-Aqc", "SHOW POOLS"}, "")
	st, ok := parseShowPools(pools, poolDatabase)
	if err != nil || !ok {
		if pools2, err2 := k.exec(ctx, []string{k.cfg.Runtime, "exec", pgb, "sh", "-c",
			`U=$(sed -n "s/^stats_users *= *//p" /etc/pgbouncer/pgbouncer.ini | cut -d, -f1 | tr -d " "); ` +
				`P=$(grep "^\"$U\"" /etc/pgbouncer/userlist.txt | cut -d\" -f4); ` +
				`PGPASSWORD="$P" psql -h 127.0.0.1 -p 5432 -U "$U" pgbouncer -Aqc "SHOW POOLS"`}, ""); err2 == nil {
			err = nil
			st, ok = parseShowPools(pools2, poolDatabase)
		}
	}
	if err == nil {
		if ok {
			res.poolSeen = true
			res.pool = st
			switch {
			case st.serverConns <= 0:
				note("pool-no-server")
			case st.clWaiting > k.cfg.WaitMax:
				note(fmt.Sprintf("pool-queue=%d>%d", st.clWaiting, k.cfg.WaitMax))
			default:
				res.checks[checkPools] = 1
			}
		} else {
			note("show-pools-unparsed")
		}
	} else {
		note(fmt.Sprintf("show-pools-fail: %v", err))
	}

	// (d) backend env drift — the .env credentials must still log
	// into the backend postgres role (initdb-skip trap).
	out, err = k.psqlQuery(ctx, pg, user, pass, "select 1")
	if err == nil && strings.TrimSpace(out) == "1" {
		res.checks[checkBackendEnv] = 1
	} else {
		note(fmt.Sprintf("backend-env-drift user=%s", user))
	}

	// (g) revision horizon — head vs compact_rev + the live-tuple
	// estimate. No COUNT(*): that seq-scans the very table whose
	// bloat this probe monitors — the bash only counted rows in the
	// 10-min guard, which owns the kine_db_rows series. A query
	// failure only zeroes this check, never the probe.
	out, err = k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT COALESCE((SELECT MAX(id) FROM %s),0), "+
			"COALESCE((SELECT MAX(prev_revision) FROM %s WHERE name='%s'),0), "+
			"COALESCE((SELECT n_live_tup FROM pg_stat_user_tables WHERE relname='%[1]s'),0)",
		k.cfg.Table, k.cfg.Table, compactRevKey))
	if err == nil {
		head, crev, live, perr := parseTriple(out)
		if perr == nil {
			res.checks[checkRevision] = 1
			res.revSeen = true
			res.head, res.compact, res.liveTup = head, crev, live
		} else {
			note(fmt.Sprintf("revision-unparsed: %v", perr))
		}
	} else {
		note(fmt.Sprintf("revision-query-fail: %v", err))
	}
}

// probeLogScan is the (e) pgbouncer log check — login retry storms
// + auth failures + pooler errors inside the last 301s (the bash's
// 5m window plus the boundary second). Needs no .env creds, so it
// runs outside probeAppChecks.
func (k *KineDB) probeLogScan(ctx context.Context, pgb string,
	res *probeResult, note func(string)) {
	logs, lerr := k.exec(ctx, []string{k.cfg.Runtime, "logs",
		"--since", "301s", pgb}, "")
	if lerr != nil {
		// A failed `logs` read looks identical to a clean window —
		// surface it so a log_errors pass is not mistaken for real
		// evidence.
		note(fmt.Sprintf("log-scan-fail: %v", lerr))
		slog.Warn("kinedb pgbouncer log scan failed — log_errors check reads a clean window",
			"container", pgb, "error", lerr)
	}
	n := int64(len(rePGBLogErr.FindAllString(logs, -1)))
	res.logErrs = n
	if n == 0 {
		res.checks[checkLogErrors] = 1
	} else {
		note(fmt.Sprintf("log-errors=%d", n))
	}
}

// emitProbe renders the textfile and updates the collectors.
func (k *KineDB) emitProbe(res *probeResult) {
	var p promBuf
	for _, c := range probeChecks {
		p.gaugeLabels("kine_db_probe_ok",
			"App-layer probe result on the kine DB VM (1 = ok, 0 = fail)",
			fmt.Sprintf("check=%q", c), float64(res.checks[c]))
		k.m.probeOK.WithLabelValues(c).Set(float64(res.checks[c]))
	}
	if res.poolSeen {
		p.gaugeLabels("kine_db_pgbouncer_server_conns",
			"pgbouncer server connections for the postgres pool by state",
			`state="active"`, float64(res.pool.svActive))
		p.gaugeLabels("kine_db_pgbouncer_server_conns",
			"pgbouncer server connections for the postgres pool by state",
			`state="idle"`, float64(res.pool.svIdle))
		p.gauge("kine_db_pgbouncer_clients_waiting",
			"cl_waiting of the postgres pool — deep queue = client spiral",
			float64(res.pool.clWaiting))
		k.m.serverConns.WithLabelValues("active").Set(float64(res.pool.svActive))
		k.m.serverConns.WithLabelValues("idle").Set(float64(res.pool.svIdle))
		k.m.clientsWaiting.Set(float64(res.pool.clWaiting))
	}
	if res.revSeen {
		p.gauge("kine_db_head_revision",
			"MAX(id) of the kine table — newest revision on the DB",
			float64(res.head))
		p.gauge("kine_db_compact_revision",
			"Current compact horizon (MAX prev_revision of compact_rev_key)",
			float64(res.compact))
		p.gauge("kine_db_retained_revisions",
			"head - compact_rev: revisions still retained",
			float64(res.head-res.compact))
		// kine_db_rows deliberately absent — emitted by the guard
		// cycle (emitGuard), which owns the COUNT(*).
		k.m.headRevision.Set(float64(res.head))
		k.m.compactRevision.Set(float64(res.compact))
		k.m.retained.Set(float64(res.head - res.compact))
	}
	ts := float64(k.cfg.nowFn().Unix())
	p.gauge("kine_db_probe_last_run_timestamp_seconds",
		"Last probe run", ts)
	k.m.probeLastRun.Set(ts)
	k.emitTextfile("kine-db.prom", &p)
}

func intOrNA(ok bool, v int64) string {
	if !ok {
		return "NA"
	}
	return strconv.FormatInt(v, 10)
}

// probe_app.go — kinedb app-level probe checks: the per-app
// credential/user probe pass (probeAppChecks), the pgbouncer log
// scan fallback (probeLogScan) and result emission (emitProbe).
// Split out of probe.go — probe.go keeps protocol parsing
// (pgbouncer ini/userlist, SHOW POOLS) and cycle orchestration.

package probe

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// probeAppChecks covers every check that needs containers + creds.
func (p *Probe) probeAppChecks(ctx context.Context, pg, pgb, user, pass string,
	res *Result, note func(string)) {

	// (c) e2e auth — psql inside the postgres container THROUGH the
	// pooler, SCRAM-SHA-256 end to end (client auth + backend auth +
	// query): the exact path kine takes. When pgbouncer listens on
	// in-container port 5432 with credentials in pgbouncer.ini +
	// userlist.txt (edoburu/pgbouncer compose stack), fall back to
	// querying 127.0.0.1:5432 inside the pgbouncer container.
	out, err := p.d.ExecEnv(ctx, kdeps.PsqlPassEnv(pass), []string{p.d.Cfg.Runtime, "exec",
		"-e", "PGPASSWORD", pg,
		"psql", "-h", pgb, "-p", p.d.Cfg.PoolerPort,
		"-U", user, "-d", "postgres", "-tAc", "select 1"}, "")
	if err != nil || strings.TrimSpace(out) != "1" {
		// The pgbouncer-container fallback — pgbouncer.go's
		// Go-native port of the old in-container sh -c pipeline
		// (admin_users → stats_users → userlist.txt password).
		if u, pw, ok := p.pgbouncerCreds(ctx, pgb,
			"admin_users", "stats_users"); ok {
			out, err = p.d.ExecEnv(ctx, []string{"PGPASSWORD=" + pw},
				[]string{p.d.Cfg.Runtime, "exec", "-e", "PGPASSWORD", pgb,
					"psql", "-h", "127.0.0.1", "-p", "5432",
					"-U", u, "postgres", "-tAc", "select 1"}, "")
		} else {
			err = errPGBCredsUnavailable
		}
	}
	if err == nil && strings.TrimSpace(out) == "1" {
		res.Checks[CheckE2EAuth] = 1
	} else {
		note(fmt.Sprintf("e2e-auth-fail via %s:%s", pgb, p.d.Cfg.PoolerPort))
	}

	// (f) SHOW POOLS on the admin console — server conns > 0 means
	// the backend auth_user can log in; cl_waiting is the queue
	// depth (client spiral leading indicator). Falls back to
	// in-container :5432 with stats_users from pgbouncer.ini when
	// the direct .env credential/port path is unavailable.
	pools, err := p.d.ExecEnv(ctx, kdeps.PsqlPassEnv(pass), []string{p.d.Cfg.Runtime, "exec",
		"-e", "PGPASSWORD", pg,
		"psql", "-h", pgb, "-p", p.d.Cfg.PoolerPort,
		"-U", user, "-d", pgbAdminDB, "-Aqc", "SHOW POOLS"}, "")
	st, ok := parseShowPools(pools, poolDatabase)
	if err != nil || !ok {
		// stats_users ONLY here — the shell's second fallback never
		// tried admin_users (pgbouncer.go documents the asymmetry).
		if u, pw, ok2 := p.pgbouncerCreds(ctx, pgb, "stats_users"); ok2 {
			if pools2, err2 := p.d.ExecEnv(ctx, []string{"PGPASSWORD=" + pw},
				[]string{p.d.Cfg.Runtime, "exec", "-e", "PGPASSWORD", pgb,
					"psql", "-h", "127.0.0.1", "-p", "5432",
					"-U", u, "pgbouncer", "-Aqc", "SHOW POOLS"}, ""); err2 == nil {
				err = nil
				st, ok = parseShowPools(pools2, poolDatabase)
			}
		}
	}
	if err == nil {
		if ok {
			res.poolSeen = true
			res.pool = st
			switch {
			case st.serverConns <= 0:
				note("pool-no-server")
			case st.clWaiting > p.d.Cfg.WaitMax:
				note(fmt.Sprintf("pool-queue=%d>%d", st.clWaiting, p.d.Cfg.WaitMax))
			default:
				res.Checks[CheckPools] = 1
			}
		} else {
			note("show-pools-unparsed")
		}
	} else {
		note(fmt.Sprintf("show-pools-fail: %v", err))
	}

	// (d) backend env drift — the .env credentials must still log
	// into the backend postgres role (initdb-skip trap).
	out, err = p.d.PsqlQuery(ctx, pg, user, pass, "select 1")
	if err == nil && strings.TrimSpace(out) == "1" {
		res.Checks[CheckBackendEnv] = 1
	} else {
		note("backend-env-drift user=" + user)
	}

	// (g) revision horizon — head vs compact_rev + the live-tuple
	// estimate. No COUNT(*): that seq-scans the very table whose
	// bloat this probe monitors — the bash only counted rows in the
	// 10-min guard, which owns the kine_db_rows series. A query
	// failure only zeroes this check, never the probe.
	out, err = p.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT COALESCE((SELECT MAX(id) FROM %[1]s),0), "+
			"COALESCE((SELECT MAX(prev_revision) FROM %[1]s WHERE name='%s'),0), "+
			"COALESCE((SELECT n_live_tup FROM pg_stat_user_tables WHERE relname=%s),0)",
		kdeps.SQLIdent(p.d.Cfg.Table), kdeps.CompactRevKey, kdeps.SQLQuote(p.d.Cfg.Table)))
	if err == nil {
		head, crev, live, perr := kdeps.ParseTriple(out)
		if perr == nil {
			res.Checks[CheckRevision] = 1
			res.RevSeen = true
			res.Head, res.Compact, res.LiveTup = head, crev, live
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
func (p *Probe) probeLogScan(ctx context.Context, pgb string,
	res *Result, note func(string)) {
	// stderr folded in for THIS call only: pgbouncer logs on its
	// stderr stream and the runner keeps stderr out of the returned
	// output — ExecCombined is the `2>&1` in seam form. argv goes
	// verbatim now: no sh -c means no quoting layer between the
	// configured runtime/container names and the exec.
	logs, lerr := p.d.ExecCombined(ctx,
		[]string{p.d.Cfg.Runtime, "logs", "--since", "301s", pgb})
	if lerr != nil {
		// A failed `logs` read is inconclusive, not clean — leave
		// the check at 0 and exclude it from `succeeded` so a scan
		// failure is not mistaken for real evidence either way.
		note(fmt.Sprintf("log-scan-fail: %v", lerr))
		logger().Warn("kinedb pgbouncer log scan failed — log_errors check is inconclusive",
			"container", pgb, "error", lerr)
		return
	}
	res.logScanned = true
	var n int64
	for _, l := range strings.Split(logs, "\n") {
		if rePGBLogErr.MatchString(l) {
			n++ // grep -c parity: matching LINES, not occurrences
		}
	}
	res.LogErrs = n
	if n == 0 {
		res.Checks[CheckLogErrors] = 1
	} else {
		note(fmt.Sprintf("log-errors=%d", n))
	}
}

// emitProbe renders the textfile and updates the collectors.
func (p *Probe) emitProbe(res *Result) {
	var b promfile.Builder
	for _, c := range probeChecks {
		b.GaugeLabels("kine_db_probe_ok",
			"App-layer probe result on the kine DB VM (1 = ok, 0 = fail)",
			fmt.Sprintf("check=%q", c), float64(res.Checks[c]))
		p.d.M.ProbeOK.WithLabelValues(c).Set(float64(res.Checks[c]))
	}
	if res.poolSeen {
		b.GaugeLabels("kine_db_pgbouncer_server_conns",
			"pgbouncer server connections for the postgres pool by state",
			`state="active"`, float64(res.pool.svActive))
		b.GaugeLabels("kine_db_pgbouncer_server_conns",
			"pgbouncer server connections for the postgres pool by state",
			`state="idle"`, float64(res.pool.svIdle))
		b.Gauge("kine_db_pgbouncer_clients_waiting",
			"cl_waiting of the postgres pool — deep queue = client spiral",
			float64(res.pool.clWaiting))
		// pgbouncer-pool-starvation alert contract series (plan names — kept separate
		// from the kine_db_* family above so the old dashboards do
		// not double-count the same number under two names).
		b.Gauge("kine_pgbouncer_client_waiting_connections",
			"cl_waiting of the postgres pool — clients queued for a server conn (starvation leading edge)",
			float64(res.pool.clWaiting))
		b.Gauge("kine_pgbouncer_maxwait_seconds",
			"maxwait of the postgres pool — age of the oldest queued client; >10s while the backend idles means stalled server conns",
			float64(res.pool.maxWaitSec))
		p.d.M.ServerConns.WithLabelValues("active").Set(float64(res.pool.svActive))
		p.d.M.ServerConns.WithLabelValues("idle").Set(float64(res.pool.svIdle))
		p.d.M.ClientsWaiting.Set(float64(res.pool.clWaiting))
		p.d.M.PgbClientWaiting.Set(float64(res.pool.clWaiting))
		p.d.M.PgbMaxWait.Set(float64(res.pool.maxWaitSec))
	}
	if res.RevSeen {
		b.Gauge("kine_db_head_revision",
			"MAX(id) of the kine table — newest revision on the DB",
			float64(res.Head))
		b.Gauge("kine_db_compact_revision",
			"Current compact horizon (MAX prev_revision of compact_rev_key)",
			float64(res.Compact))
		b.Gauge("kine_db_retained_revisions",
			"head - compact_rev: revisions still retained",
			float64(res.Head-res.Compact))
		// kine_db_rows deliberately absent — emitted by the guard
		// cycle (emitGuard), which owns the COUNT(*).
		p.d.M.HeadRevision.Set(float64(res.Head))
		p.d.M.CompactRevision.Set(float64(res.Compact))
		p.d.M.Retained.Set(float64(res.Head - res.Compact))
	}
	if h := res.hyg; h != nil {
		// Every series gates on its own *Seen flag — a failed
		// stats query leaves the gauge absent (stale) instead of
		// overwriting a real value with a fabricated zero.
		if h.idleSeen {
			b.Gauge("kine_db_idle_in_tx_sessions",
				"Sessions idle in transaction >3min on the postgres/kine databases — autovacuum blockers",
				float64(h.idleInTx))
			b.Gauge("node_agent_kine_pg_idle_in_tx_sessions",
				"Alias of kine_db_idle_in_tx_sessions under the node_agent_* alert contract",
				float64(h.idleInTx))
			p.d.M.IdleInTx.Set(float64(h.idleInTx))
			p.d.M.IdleInTxAlias.Set(float64(h.idleInTx))
		}
		if h.deadSeen {
			b.Gauge("node_agent_kine_pg_dead_tuple_ratio",
				"n_dead_tup/GREATEST(n_live_tup,1) of the kine table — >0.5 means autovacuum lost the race",
				h.deadRatio)
			p.d.M.DeadTupleRatio.Set(h.deadRatio)
		}
		if h.xidSeen {
			b.Gauge("kine_db_xid_age_transactions",
				"MAX(age(datfrozenxid)) across databases — wraparound distance",
				float64(h.xidAge))
			p.d.M.XidAge.Set(float64(h.xidAge))
		}
		if h.walSeen {
			b.Gauge("kine_db_wal_bytes",
				"Total bytes in pg_wal (pg_ls_waldir)",
				float64(h.walBytes))
			p.d.M.WalBytes.Set(float64(h.walBytes))
		}
		if h.walDiskSeen {
			b.Gauge("kine_db_wal_disk_ratio",
				"pg_wal bytes / data filesystem capacity — runaway retention fills the disk to PANIC",
				h.walDiskRatio)
			p.d.M.WalDiskRatio.Set(h.walDiskRatio)
		}
		if h.archiveSeen {
			b.Gauge("kine_db_wal_archive_stale",
				"1 when pg_stat_archiver has been failing continuously for >30m",
				float64(h.archiveStale))
			p.d.M.WalArchStale.Set(float64(h.archiveStale))
		}
		if h.slotSeen {
			b.Gauge("kine_db_inactive_slot_retained_bytes",
				"WAL bytes pinned by inactive replication slots",
				float64(h.slotRetained))
			p.d.M.InactiveSlot.Set(float64(h.slotRetained))
		}
		// invalid-index-reaper item 7 — invalid-index census + seq-scan
		// regression counters. The seq_* series are cumulative
		// pg_stat counters → TYPE counter, like the rollback total
		// in the xact textfile.
		if h.invalidSeen {
			b.Gauge("kine_db_invalid_indexes",
				"Indexes with indisvalid=false in pg_index — dead shells an interrupted REINDEX CONCURRENTLY leaves behind",
				float64(h.invalidIdx))
			p.d.M.InvalidIndexes.Set(float64(h.invalidIdx))
		}
		if h.seqSeen {
			b.HeaderType("kine_db_seq_scans_total",
				"seq_scan of the kine table (pg_stat_user_tables) — sequential scans against the kine heap.",
				"counter")
			b.Line(fmt.Sprintf("kine_db_seq_scans_total %d", h.seqScans))
			b.HeaderType("kine_db_seq_tuples_read_total",
				"seq_tup_read of the kine table (pg_stat_user_tables) — tuples read via seq scans; a spike means planner regression.",
				"counter")
			b.Line(fmt.Sprintf("kine_db_seq_tuples_read_total %d", h.seqTupRead))
			p.d.M.SeqScansVal.Store(h.seqScans)
			p.d.M.SeqTupReadVal.Store(h.seqTupRead)
		}
	}
	// The reaper counter is cumulative state — emitted every round
	// (unlike the seen-gated gauges above, a skipped reap does not
	// make the lifetime total any less true).
	b.Gauge("node_agent_kine_pg_idle_in_tx_terminated_total",
		"Stuck kine sessions terminated by the session reaper",
		float64(p.d.M.IdleTermTotal))
	ts := float64(p.d.Cfg.Clock.Now().Unix())
	b.Gauge("kine_db_probe_last_run_timestamp_seconds",
		"Last probe run", ts)
	p.d.M.ProbeLastRun.Set(ts)
	p.d.EmitTextfile("kine-db.prom", &b)
}

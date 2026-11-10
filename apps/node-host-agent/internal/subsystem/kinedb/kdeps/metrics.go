// metrics.go — the collector mirror every loop's textfile render
// also feeds: the Prometheus-registered half of the dual kine_db_*
// / node-exporter-textfile contract. Lives in kdeps because probe,
// compact and maint each Set their own family's gauges on the one
// shared struct (was the `metrics` type in the flat package).
package kdeps

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds every collector mirrored into the textfiles. All
// fields are exported — each domain package Sets the family it owns
// (probe the kine_db_probe_* / hygiene / WAL / seq-scan series,
// compact the kine_db_guard_* / rows / churn / backup series, maint
// the kine_db_maint_* series) and all three count Cycles.
type Metrics struct {
	ProbeOK         *prometheus.GaugeVec // check
	ServerConns     *prometheus.GaugeVec // state=active|idle
	ClientsWaiting  prometheus.Gauge
	HeadRevision    prometheus.Gauge
	CompactRevision prometheus.Gauge
	Retained        prometheus.Gauge
	Rows            prometheus.Gauge
	ProbeLastRun    prometheus.Gauge

	GuardOK          prometheus.Gauge
	GuardFreeze      prometheus.Gauge
	GuardFired       prometheus.Gauge
	GuardLastDeleted prometheus.Gauge
	GuardLastCompact prometheus.Gauge
	GuardLastRun     prometheus.Gauge
	GuardRevAfter    prometheus.Gauge

	MaintOK       *prometheus.GaugeVec // check=reindex|repack|vacuum_freeze
	MaintRelBytes *prometheus.GaugeVec // kind=heap|indexes
	MaintLastRun  prometheus.Gauge

	// kine-pg-hygiene + WAL archive guard series (probe/hygiene.go).
	// IdleTermTotal mirrors the IdleTxTerm counter so the probe
	// textfile can render the cumulative value (prometheus counters
	// cannot be read back).
	IdleInTx       prometheus.Gauge
	IdleInTxAlias  prometheus.Gauge
	IdleTxTerm     prometheus.Counter
	IdleTermTotal  int64
	DeadTupleRatio prometheus.Gauge
	XidAge         prometheus.Gauge
	WalBytes       prometheus.Gauge
	WalDiskRatio   prometheus.Gauge
	WalArchStale   prometheus.Gauge
	InactiveSlot   prometheus.Gauge

	// pgbouncer-pool-starvation pgbouncer starvation series (plan-mandated names —
	// sibling of ClientsWaiting, not a rename).
	PgbClientWaiting prometheus.Gauge // kine_pgbouncer_client_waiting_connections
	PgbMaxWait       prometheus.Gauge // kine_pgbouncer_maxwait_seconds

	// invalid-index-reaper invalid-index census + seq-scan regression series.
	// SeqScans/SeqTupRead report counter type (the _total
	// contract) via CounterFuncs over the last probe read — a
	// skipped probe round keeps serving the real last value
	// instead of fabricating a zero, mirroring the seen-gated
	// textfile emission.
	InvalidIndexes prometheus.Gauge
	SeqScans       prometheus.Collector // CounterFunc → kine_db_seq_scans_total
	SeqTupRead     prometheus.Collector // CounterFunc → kine_db_seq_tuples_read_total
	SeqScansVal    atomic.Int64
	SeqTupReadVal  atomic.Int64

	// kine-churn/backup-health: top-churn + physical-backup verifier series.
	TopChurn    *prometheus.GaugeVec // resource
	TopHotkey   *prometheus.GaugeVec // key — selfheal-alert-coverage per-object SSA ping-pong
	BackupAge   prometheus.Gauge
	BackupValid prometheus.Gauge

	Cycles *prometheus.CounterVec // loop, result
}

// NewMetrics builds every collector with its contract name/help —
// byte-identical to the pre-split exposition.
func NewMetrics() *Metrics {
	m := &Metrics{
		ProbeOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_probe_ok",
			Help: "App-layer probe result on the kine DB VM (1 = ok, 0 = fail).",
		}, []string{"check"}),
		ServerConns: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_pgbouncer_server_conns",
			Help: "pgbouncer server connections for the postgres pool by state.",
		}, []string{"state"}),
		ClientsWaiting: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_pgbouncer_clients_waiting",
			Help: "cl_waiting of the postgres pool — deep queue = client spiral.",
		}),
		HeadRevision: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_head_revision",
			Help: "MAX(id) of the kine table — newest revision on the DB.",
		}),
		CompactRevision: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_compact_revision",
			Help: "Current compact horizon (MAX prev_revision of compact_rev_key).",
		}),
		Retained: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_retained_revisions",
			Help: "head - compact_rev: revisions still retained (runway for lagging caches).",
		}),
		Rows: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_rows",
			Help: "Row count of the kine table — kine boot fill cost.",
		}),
		ProbeLastRun: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_probe_last_run_timestamp_seconds",
			Help: "Last probe run.",
		}),
		GuardOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_ok",
			Help: "Compact guard result (1 = ok/skip, 0 = fail).",
		}),
		GuardFreeze: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_freeze_cycles",
			Help: "Consecutive runs compact_rev stayed frozen while head advanced.",
		}),
		GuardFired: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_fired",
			Help: "1 when the last guard run executed a compact session.",
		}),
		GuardLastDeleted: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_last_deleted_rows",
			Help: "Rows deleted by the last compact run.",
		}),
		GuardLastCompact: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_last_compact_timestamp_seconds",
			Help: "Timestamp of the last completed compact run.",
		}),
		GuardLastRun: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_last_run_timestamp_seconds",
			Help: "Last guard run.",
		}),
		GuardRevAfter: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_guard_compact_rev_after",
			Help: "compact_rev re-read after the last completed compact run.",
		}),
		MaintOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_maint_ok",
			Help: "Maintenance job result (1 = ok/skip, 0 = fail).",
		}, []string{"check"}),
		MaintRelBytes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_maint_relation_bytes",
			Help: "Heap/index size of the kine table.",
		}, []string{"kind"}),
		MaintLastRun: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_maint_last_run_timestamp_seconds",
			Help: "Last maintenance run.",
		}),
		IdleInTx: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_idle_in_tx_sessions",
			Help: "Sessions idle in transaction >3min on the postgres/kine databases — autovacuum blockers.",
		}),
		IdleInTxAlias: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "node_agent_kine_pg_idle_in_tx_sessions",
			Help: "Alias of kine_db_idle_in_tx_sessions under the node_agent_* alert contract.",
		}),
		IdleTxTerm: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_kine_pg_idle_in_tx_terminated_total",
			Help: "Stuck kine sessions terminated by the session reaper.",
		}),
		DeadTupleRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "node_agent_kine_pg_dead_tuple_ratio",
			Help: "n_dead_tup / GREATEST(n_live_tup,1) of the kine table — >0.5 means autovacuum lost the race.",
		}),
		XidAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_xid_age_transactions",
			Help: "MAX(age(datfrozenxid)) across databases — distance to XID wraparound pressure.",
		}),
		WalBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_wal_bytes",
			Help: "Total bytes in pg_wal (pg_ls_waldir).",
		}),
		WalDiskRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_wal_disk_ratio",
			Help: "pg_wal bytes / data filesystem capacity — runaway retention fills the disk to PANIC.",
		}),
		WalArchStale: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_wal_archive_stale",
			Help: "1 when pg_stat_archiver has been failing continuously for >30m.",
		}),
		InactiveSlot: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_inactive_slot_retained_bytes",
			Help: "WAL bytes pinned by inactive replication slots.",
		}),
		PgbClientWaiting: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_pgbouncer_client_waiting_connections",
			Help: "cl_waiting of the postgres pool — clients queued for a server conn (starvation leading edge).",
		}),
		PgbMaxWait: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_pgbouncer_maxwait_seconds",
			Help: "maxwait of the postgres pool — age of the oldest queued client; >10s while the backend idles means stalled server conns.",
		}),
		InvalidIndexes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_invalid_indexes",
			Help: "Indexes with indisvalid=false in pg_index — dead shells an interrupted REINDEX CONCURRENTLY leaves behind.",
		}),
		TopChurn: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_top_churn_revisions_5m",
			Help: "Top-5 resource prefixes by revision count in the last 5-minute window — mutating-webhook ping-pong detector (kine-churn).",
		}, []string{"resource"}),
		TopHotkey: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kine_db_top_hotkey_revisions_5m",
			Help: "Top-5 full Kine object keys by revision count in the last 5-minute window (>=50 revs, leases/events excluded) — per-object SSA managedFields ping-pong detector.",
		}, []string{"key"}),
		BackupAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_backup_age_seconds",
			Help: "Age of the newest physical pg_dump in the backup dir — staleness of the disaster-recovery path (backup-health).",
		}),
		BackupValid: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kine_db_backup_valid",
			Help: "1 when the newest physical pg_dump passed header verification (PGDMP magic / pg_restore -l) — backup-health.",
		}),
		Cycles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "node_host_agent_kinedb_cycles_total",
			Help: "kinedb loop cycles by loop and result.",
		}, []string{"loop", "result"}),
	}
	// CounterFuncs close over m — the seq_* _total series must
	// report counter type while serving the last real pg_stat
	// read between probe rounds.
	m.SeqScans = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kine_db_seq_scans_total",
		Help: "seq_scan of the kine table (pg_stat_user_tables) — sequential scans against the kine heap.",
	}, func() float64 { return float64(m.SeqScansVal.Load()) })
	m.SeqTupRead = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kine_db_seq_tuples_read_total",
		Help: "seq_tup_read of the kine table (pg_stat_user_tables) — tuples read via seq scans; a spike means planner regression.",
	}, func() float64 { return float64(m.SeqTupReadVal.Load()) })
	return m
}

// Collectors is the full registration set — the facade's New hands
// it to subframe.RegisterAll (whose rollback on failure keeps a
// retried New off duplicate-registration).
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.ProbeOK, m.ServerConns, m.ClientsWaiting, m.HeadRevision,
		m.CompactRevision, m.Retained, m.Rows, m.ProbeLastRun,
		m.GuardOK, m.GuardFreeze, m.GuardFired, m.GuardLastDeleted,
		m.GuardLastCompact, m.GuardLastRun, m.GuardRevAfter,
		m.MaintOK, m.MaintRelBytes, m.MaintLastRun,
		m.IdleInTx, m.IdleInTxAlias, m.IdleTxTerm, m.DeadTupleRatio,
		m.XidAge, m.WalBytes, m.WalDiskRatio, m.WalArchStale,
		m.InactiveSlot,
		m.PgbClientWaiting, m.PgbMaxWait, m.InvalidIndexes,
		m.SeqScans, m.SeqTupRead,
		m.TopChurn, m.TopHotkey, m.BackupAge, m.BackupValid,
		m.Cycles,
	}
}

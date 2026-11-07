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
// This file is the facade only — the loops live in per-domain
// packages under kinedb/ (the controllerhygiene cdeps layout):
//
//   - probe/   — the probe checks plus the probe-cadence
//     remediations (session reaper + pgbouncer wedge in
//     selfheal.go, the pg hygiene/WAL census in hygiene.go, the
//     top-churn sampler in churn.go)
//   - compact/ — the compaction guard plus the backup-health
//     physical-backup verifier that rides its cycle (backup.go)
//   - maint/   — the daily reindex/freeze/repack window
//   - kdeps/   — the shared dependency surface (Config/EnvDeps,
//     Deps, the collector mirror, the exec/psql plumbing, the
//     state-file + SQL-quoting helpers)
//   - kdepstest/ — the shared domain-test fixture
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
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/compact"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/maint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/probe"
)

// The subsystem-convention export surface cmd/agent wires against:
// Config and EnvDeps alias the canonical kdeps types so
// kinedb.Config IS kdeps.Config (no drift possible), and
// ConfigFromEnv forwards to the env resolution that lives in kdeps
// beside the defaults it fills. The names stay here because the
// subsystem convention puts them next to New.
type (
	Config  = kdeps.Config
	EnvDeps = kdeps.EnvDeps
)

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob kinedb reads —
// implementation lives in kdeps (it owns the Config defaults).
func ConfigFromEnv(d EnvDeps) Config { return kdeps.ConfigFromEnv(d) }

// KineDB runs the probe, compact-guard and maintenance loops. It is
// the orchestrator only: everything the loops consume (config,
// metrics, the state store, the exec plumbing, the churn hand-off)
// lives on the embedded *kdeps.Deps — see kdeps/kdeps.go. The embed
// keeps the test contract compiling: k.Cfg, k.State, k.M etc.
// promote through it.
type KineDB struct {
	*kdeps.Deps

	probe *probe.Probe
	guard *compact.Guard
	maint *maint.Maint
}

// New returns a KineDB and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*KineDB, error) {
	d, err := kdeps.NewDeps(cfg)
	if err != nil {
		return nil, err
	}
	k := &KineDB{
		Deps:  d,
		probe: probe.New(d),
		guard: compact.New(d),
		maint: maint.New(d),
	}
	// RegisterAll rolls the partial set back on failure — without
	// it a retry of New() hits duplicate-registration on the
	// collectors that did succeed.
	if err := subframe.RegisterAll(reg, k.M.Collectors()...); err != nil {
		return nil, fmt.Errorf("register kinedb metrics: %w", err)
	}
	return k, nil
}

// Name identifies the subsystem for logging.
func (k *KineDB) Name() string { return "kinedb" }

// kine_storage.go — W10-CP2 Kine store health:
//
//	Sizes the SQLite state.db(+ -wal) — or the etcd/JetStream
//	filestore on non-SQLite backends — into
//	node_agent_kine_{db,wal}_bytes and forces a sqlite3
//	wal_checkpoint(TRUNCATE) when the WAL grows past the
//	threshold (30m cooldown).
package controllerhygiene

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// checkKineStorage is the prometheus `check` label + log context
// for the Kine store health check.
const checkKineStorage = "kine-storage"

// fileRateKineCheckpoint is the WAL-checkpoint cooldown file under
// WatchdogStateDir.
const fileRateKineCheckpoint = "last-kine-wal-checkpoint"

// Kine store health knobs — package vars rather than Config fields
// (Config lives in controllerhygiene.go, outside this file); tests
// shrink them freely. Defaults mirror the plan.
var (
	kineWALCheckpointMinBytes = int64(512 << 20) // 512 MiB WAL → checkpoint
	kineWALCheckpointCooldown = 30 * time.Minute // last-kine-wal-checkpoint budget
	// kineCheckpointFn runs `PRAGMA wal_checkpoint(TRUNCATE)` —
	// package seam (same role Config.xxxFn seams play elsewhere).
	kineCheckpointFn = sqlite3WALCheckpoint
)

// errKineNoSQLite3 marks "host has no sqlite3 binary" — distinct
// from a checkpoint failure so the cooldown stays unspent.
var errKineNoSQLite3 = errors.New("sqlite3 binary not found on host")

const (
	kineCheckpointBudget = 2 * time.Minute // per-checkpoint exec bound
	kineStoreMaxFiles    = 1 << 16         // bounded filestore walk

	// Metric names — the Prometheus alerts (KineDatabaseSizeCritical,
	// NodeKubeconfigCertExpiringSoon) key on these exact series.
	kineDBBytesMetric  = "node_agent_kine_db_bytes"
	kineWALBytesMetric = "node_agent_kine_wal_bytes"
)

// checkKineStorageHealth measures the Kine backing store on this
// controller and keeps the WAL from growing until it fills the
// root filesystem. SQLite/Kine hosts get state.db + state.db-wal
// sizes; non-SQLite backends (embedded etcd, NATS JetStream
// filestore) get the first existing store dir summed with a bounded
// walk — both land on node_agent_kine_db_bytes /
// node_agent_kine_wal_bytes via the node-exporter textfile channel.
// A WAL over kineWALCheckpointMinBytes triggers `PRAGMA
// wal_checkpoint(TRUNCATE)` through the host sqlite3 under the
// last-kine-wal-checkpoint cooldown.
func (h *Hygiene) checkKineStorageHealth(ctx context.Context) {
	dbBytes, walBytes, ok := h.kineStoreSizes()
	if !ok {
		// No store at all — headers-only file so a vanished store
		// drops the series instead of pinning a stale size.
		h.emitKineStorageTextfile(0, 0, false)
		h.cycles.WithLabelValues(checkKineStorage, "absent").Inc()
		return
	}
	h.emitKineStorageTextfile(dbBytes, walBytes, true)
	if walBytes <= kineWALCheckpointMinBytes {
		h.cycles.WithLabelValues(checkKineStorage, "ok").Inc()
		return
	}
	if !h.state.RateOK(fileRateKineCheckpoint,
		kineWALCheckpointCooldown) {
		h.cycles.WithLabelValues(checkKineStorage, "checkpoint_cooldown").Inc()
		return
	}
	err := kineCheckpointFn(ctx, h.kineDBPath())
	switch {
	case errors.Is(err, errKineNoSQLite3):
		// No sqlite3 on the host — skip WITHOUT spending the
		// cooldown so a later install still gets the checkpoint.
		h.cycles.WithLabelValues(checkKineStorage, "no_sqlite3").Inc()
	case err != nil:
		h.state.RateSpend(fileRateKineCheckpoint)
		h.state.AppendLogWarn(fmt.Sprintf(
			"suspect: kine wal=%.0fMiB > %dMiB but wal_checkpoint failed: %v",
			float64(walBytes)/(1<<20),
			kineWALCheckpointMinBytes>>20, err))
		h.cycles.WithLabelValues(checkKineStorage, "checkpoint_fail").Inc()
	default:
		h.state.RateSpend(fileRateKineCheckpoint)
		h.state.AppendLog(fmt.Sprintf(
			"ACTION: kine wal_checkpoint(TRUNCATE) — state.db-wal %.0fMiB > %dMiB",
			float64(walBytes)/(1<<20), kineWALCheckpointMinBytes>>20))
		h.actions.WithLabelValues(checkKineStorage, "wal_checkpoint").Inc()
		h.cycles.WithLabelValues(checkKineStorage, "ok").Inc()
	}
}

// kineDBPath / kineWALPath — the SQLite/Kine store locations under
// K0sDir (<K0sDir>/db/state.db and its -wal sidecar).
func (h *Hygiene) kineDBPath() string {
	return filepath.Join(h.cfg.K0sDir, "db", "state.db")
}

func (h *Hygiene) kineWALPath() string {
	return h.kineDBPath() + "-wal"
}

// kineStoreSizes reports the store sizes: state.db + state.db-wal
// when the SQLite backend is present, else the summed size of the
// first existing non-SQLite store dir (embedded etcd / NATS
// JetStream filestore — WAL stays 0 there). ok=false when no store
// exists at all.
func (h *Hygiene) kineStoreSizes() (dbBytes, walBytes int64, ok bool) {
	if fi, err := os.Stat(h.kineDBPath()); err == nil && !fi.IsDir() {
		dbBytes = fi.Size()
		if w, werr := os.Stat(h.kineWALPath()); werr == nil && !w.IsDir() {
			walBytes = w.Size()
		}
		return dbBytes, walBytes, true
	}
	for _, dir := range []string{
		filepath.Join(h.cfg.K0sDir, "etcd"),
		filepath.Join(h.cfg.K0sDir, "nats"),
	} {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			total, _ := dirSizeBounded(dir, kineStoreMaxFiles)
			return total, 0, true
		}
	}
	return 0, 0, false
}

// dirSizeBounded sums regular-file sizes under root, stopping after
// maxFiles entries — etcd member dirs stay small; the cap keeps a
// pathological tree from stalling the cycle. Unreadable entries are
// skipped (best-effort gauge).
func dirSizeBounded(root string, maxFiles int) (int64, error) {
	var total int64
	n := 0
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}
		n++
		if n > maxFiles {
			return fs.SkipAll
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// sqlite3WALCheckpoint is the default kineCheckpointFn: run
// `PRAGMA wal_checkpoint(TRUNCATE)` through the host sqlite3 CLI.
// busy_timeout=5000 caps lock waits at 5s — effectively
// non-blocking for the agent cycle (a busy WAL just errors out and
// retries after the cooldown). errKineNoSQLite3 when the binary is
// absent so the caller skips without spending the cooldown.
func sqlite3WALCheckpoint(ctx context.Context, dbPath string) error {
	bin, err := exec.LookPath("sqlite3")
	if err != nil {
		return errKineNoSQLite3
	}
	cctx, cancel := context.WithTimeout(ctx, kineCheckpointBudget)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, dbPath,
		"PRAGMA busy_timeout=5000; PRAGMA wal_checkpoint(TRUNCATE);")
	cmd.Env = scrubSystemdEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sqlite3 wal_checkpoint: %w: %s",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}

// emitKineStorageTextfile writes the two kine gauges — present=false
// emits headers only so the series goes absent rather than stale.
func (h *Hygiene) emitKineStorageTextfile(dbBytes, walBytes int64, present bool) {
	var p textfileProm
	if present {
		p.gauge(kineDBBytesMetric,
			"Size in bytes of the Kine backing store (state.db, or "+
				"the etcd/JetStream filestore total on non-SQLite backends).",
			float64(dbBytes))
		p.gauge(kineWALBytesMetric,
			"Size in bytes of the Kine SQLite WAL (state.db-wal); "+
				"absent on non-SQLite backends.",
			float64(walBytes))
	} else {
		p.header(kineDBBytesMetric,
			"Size in bytes of the Kine backing store (state.db, or "+
				"the etcd/JetStream filestore total on non-SQLite backends).")
		p.header(kineWALBytesMetric,
			"Size in bytes of the Kine SQLite WAL (state.db-wal); "+
				"absent on non-SQLite backends.")
	}
	h.writeTextfileProm("node-agent-kine-storage.prom", p.String())
}

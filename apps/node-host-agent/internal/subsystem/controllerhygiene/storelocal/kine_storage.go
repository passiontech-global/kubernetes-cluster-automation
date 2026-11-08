// kine_storage.go — W10-CP2 Kine store health:
//
//	Sizes the SQLite state.db(+ -wal) — or the etcd/JetStream
//	filestore on non-SQLite backends — into
//	node_agent_kine_{db,wal}_bytes and forces a sqlite3
//	wal_checkpoint(TRUNCATE) when the WAL grows past the
//	threshold (30m cooldown).
package storelocal

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// Kine store health knobs — package vars rather than Config fields
// (Config lives in controllerhygiene.go, outside this file); tests
// shrink them freely. Defaults mirror the plan.
var (
	WALCheckpointMinBytes = int64(512 << 20) // 512 MiB WAL → checkpoint
	WALCheckpointCooldown = 30 * time.Minute // last-kine-wal-checkpoint budget
	// CheckpointFn runs `PRAGMA wal_checkpoint(TRUNCATE)` —
	// package seam (same role Config.xxxFn seams play elsewhere).
	CheckpointFn = sqlite3WALCheckpoint
	// LargeObjectsCooldown throttles the kine-table size scan —
	// length(value) over live rows is a full-ish table read, keep it
	// off the hot cycle path (last-kine-large-objects budget).
	LargeObjectsCooldown = 15 * time.Minute
	// LargeObjectWarnBytes is the per-key warn threshold: a single
	// object above this is usually a ConfigMap/Secret sprawl accident
	// and drags every watch that decodes it.
	LargeObjectWarnBytes = int64(512 << 10) // 512 KiB
	// LargeObjectsFn runs the top-N value-size query against the
	// kine SQLite DB — package seam (same role CheckpointFn plays).
	LargeObjectsFn = sqlite3KineLargeObjects
)

// ErrNoSQLite3 marks "host has no sqlite3 binary" — distinct
// from a checkpoint failure so the cooldown stays unspent.
var ErrNoSQLite3 = errors.New("sqlite3 binary not found on host")

const (
	kineCheckpointBudget = 2 * time.Minute // per-checkpoint exec bound
	kineStoreMaxFiles    = 1 << 16         // bounded filestore walk

	// Metric names — the Prometheus alerts (KineDatabaseSizeCritical,
	// NodeKubeconfigCertExpiringSoon) key on these exact series.
	kineDBBytesMetric  = "node_agent_kine_db_bytes"
	kineWALBytesMetric = "node_agent_kine_wal_bytes"
	// kineMaxObjectBytesMetric is the kine large-object gauge — the largest
	// live (deleted=0) kine value in bytes (top-1 by length(value)).
	kineMaxObjectBytesMetric = "node_agent_kine_max_object_bytes"

	// KineLargeObjectsRateFile keys the 15m large-object scan
	// cooldown under WatchdogStateDir.
	KineLargeObjectsRateFile = "last-kine-large-objects"
)

// KineLargeObject is one row of the kine value-size scan.
type KineLargeObject struct {
	Name  string
	Bytes int64
}

// StorageCheck is the W10-CP2 Kine store health check as a Check
// — stateless: the checkpoint cadence lives in the
// last-kine-wal-checkpoint budget. It is not its own dispatch-table
// entry: it rides cpFreezeCheck's ungated slot (check.go).
type StorageCheck struct {
	d *cdeps.Deps
	// maxObjBytes/maxObjSeen cache the last successful large-object
	// scan so the gauge persists in the textfile across the 15m
	// cooldown windows (the textfile is rewritten every cycle).
	maxObjBytes float64
	maxObjSeen  bool
}

// Name returns the check label / log context.
func (c *StorageCheck) Name() string { return cdeps.CheckKineStorage }

// Run measures the Kine backing store on this controller and keeps
// the WAL from growing until it fills the root filesystem.
// SQLite/Kine hosts get state.db + state.db-wal sizes; non-SQLite
// backends (embedded etcd, NATS JetStream filestore) get the first
// existing store dir summed with a bounded walk — both land on
// node_agent_kine_db_bytes / node_agent_kine_wal_bytes via the
// node-exporter textfile channel. A WAL over
// WALCheckpointMinBytes triggers `PRAGMA wal_checkpoint(TRUNCATE)`
// through the host sqlite3 under the last-kine-wal-checkpoint
// cooldown.
func (c *StorageCheck) Run(ctx context.Context) {
	dbBytes, walBytes, ok := c.kineStoreSizes()
	if !ok {
		// No store at all — headers-only file so a vanished store
		// drops the series instead of pinning a stale size.
		c.emitKineStorageTextfile(0, 0, false)
		c.d.Cycles.WithLabelValues(cdeps.CheckKineStorage, "absent").Inc()
		return
	}
	// Large-object scan: scan the kine table for oversized live values —
	// SQLite backend only (the query targets the kine table),
	// cooldown-throttled so it stays off the hot cycle path.
	if _, err := os.Stat(c.kineDBPath()); err == nil {
		c.runLargeObjectScan(ctx)
	}
	c.emitKineStorageTextfile(dbBytes, walBytes, true)
	if walBytes <= WALCheckpointMinBytes {
		c.d.Cycles.WithLabelValues(cdeps.CheckKineStorage, "ok").Inc()
		return
	}
	if !c.d.State.RateOK(cdeps.FileRateKineCheckpoint,
		WALCheckpointCooldown) {
		c.d.Cycles.WithLabelValues(cdeps.CheckKineStorage, "checkpoint_cooldown").Inc()
		return
	}
	err := CheckpointFn(ctx, c.kineDBPath())
	switch {
	case errors.Is(err, ErrNoSQLite3):
		// No sqlite3 on the host — skip WITHOUT spending the
		// cooldown so a later install still gets the checkpoint.
		c.d.Cycles.WithLabelValues(cdeps.CheckKineStorage, "no_sqlite3").Inc()
	case err != nil:
		c.d.State.RateSpend(cdeps.FileRateKineCheckpoint)
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"suspect: kine wal=%.0fMiB > %dMiB but wal_checkpoint failed: %v",
			float64(walBytes)/(1<<20),
			WALCheckpointMinBytes>>20, err))
		c.d.Cycles.WithLabelValues(cdeps.CheckKineStorage, "checkpoint_fail").Inc()
	default:
		c.d.State.RateSpend(cdeps.FileRateKineCheckpoint)
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: kine wal_checkpoint(TRUNCATE) — state.db-wal %.0fMiB > %dMiB",
			float64(walBytes)/(1<<20), WALCheckpointMinBytes>>20))
		c.d.Actions.WithLabelValues(cdeps.CheckKineStorage, "wal_checkpoint").Inc()
		c.d.Cycles.WithLabelValues(cdeps.CheckKineStorage, "ok").Inc()
	}
}

// kineDBPath / kineWALPath — the SQLite/Kine store locations under
// K0sDir (<K0sDir>/db/state.db and its -wal sidecar).
func (c *StorageCheck) kineDBPath() string {
	return filepath.Join(c.d.Cfg.K0sDir, "db", "state.db")
}

func (c *StorageCheck) kineWALPath() string {
	return c.kineDBPath() + "-wal"
}

// kineStoreSizes reports the store sizes: state.db + state.db-wal
// when the SQLite backend is present, else the summed size of the
// first existing non-SQLite store dir (embedded etcd / NATS
// JetStream filestore — WAL stays 0 there). ok=false when no store
// exists at all.
func (c *StorageCheck) kineStoreSizes() (dbBytes, walBytes int64, ok bool) {
	if fi, err := os.Stat(c.kineDBPath()); err == nil && !fi.IsDir() {
		dbBytes = fi.Size()
		if w, werr := os.Stat(c.kineWALPath()); werr == nil && !w.IsDir() {
			walBytes = w.Size()
		}
		return dbBytes, walBytes, true
	}
	for _, dir := range []string{
		filepath.Join(c.d.Cfg.K0sDir, "etcd"),
		filepath.Join(c.d.Cfg.K0sDir, "nats"),
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
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger().Debug("controllerhygiene: kine store walk entry skipped — unreadable",
				"path", path, "error", err)
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

// sqlite3WALCheckpoint is the default CheckpointFn: run
// `PRAGMA wal_checkpoint(TRUNCATE)` through the host sqlite3 CLI.
// busy_timeout=5000 caps lock waits at 5s — effectively
// non-blocking for the agent cycle (a busy WAL just errors out and
// retries after the cooldown). ErrNoSQLite3 when the binary is
// absent so the caller skips without spending the cooldown.
func sqlite3WALCheckpoint(ctx context.Context, dbPath string) error {
	bin, err := exec.LookPath("sqlite3")
	if err != nil {
		return ErrNoSQLite3
	}
	cctx, cancel := context.WithTimeout(ctx, kineCheckpointBudget)
	defer cancel()
	// cdeps.ScrubSystemdEnv through the env slot, not scrubArgv: the
	// `env -u` prefix would have to resolve `env` on the pod
	// image's PATH — the filtered environ is applied directly.
	out, err := hostexec.RunCombinedEnv(cctx, cdeps.ScrubSystemdEnv(os.Environ()),
		bin, dbPath, "PRAGMA busy_timeout=5000; PRAGMA wal_checkpoint(TRUNCATE);")
	if err != nil {
		return fmt.Errorf("sqlite3 wal_checkpoint: %w: %s",
			err, strings.TrimSpace(out))
	}
	return nil
}

// runLargeObjectScan runs the top-N kine value-size query under the
// LargeObjectsCooldown budget. A successful scan refreshes the cached
// gauge value and spends the cooldown; a failure spends it too (same
// contract as the checkpoint path) EXCEPT ErrNoSQLite3, which leaves
// the cooldown unspent so a later install still gets the scan. Every
// key above LargeObjectWarnBytes is named in a warning log.
func (c *StorageCheck) runLargeObjectScan(ctx context.Context) {
	if !c.d.State.RateOK(KineLargeObjectsRateFile, LargeObjectsCooldown) {
		return
	}
	rows, err := LargeObjectsFn(ctx, c.kineDBPath())
	switch {
	case errors.Is(err, ErrNoSQLite3):
		return // cooldown unspent — retry once sqlite3 exists
	case err != nil:
		c.d.State.RateSpend(KineLargeObjectsRateFile)
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"suspect: kine large-object scan failed: %v", err))
		return
	}
	c.d.State.RateSpend(KineLargeObjectsRateFile)
	if len(rows) > 0 {
		c.maxObjBytes = float64(rows[0].Bytes) // rows are DESC by length
	} else {
		c.maxObjBytes = 0
	}
	c.maxObjSeen = true
	for _, row := range rows {
		if row.Bytes > LargeObjectWarnBytes {
			c.d.State.AppendLogWarn(fmt.Sprintf(
				"kine large object %.0fKiB > %dKiB: %s",
				float64(row.Bytes)/(1<<10),
				LargeObjectWarnBytes>>10, row.Name))
		}
	}
}

// sqlite3KineLargeObjects is the default LargeObjectsFn: run the
// top-N value-size query through the host sqlite3 CLI.
// busy_timeout=2000 caps lock waits at 2s — a busy DB just errors
// out and retries after the cooldown. ErrNoSQLite3 when the binary
// is absent so the caller skips without spending the cooldown.
func sqlite3KineLargeObjects(ctx context.Context, dbPath string) ([]KineLargeObject, error) {
	bin, err := exec.LookPath("sqlite3")
	if err != nil {
		return nil, ErrNoSQLite3
	}
	cctx, cancel := context.WithTimeout(ctx, kineCheckpointBudget)
	defer cancel()
	// Same env-scrub contract as sqlite3WALCheckpoint.
	out, err := hostexec.RunCombinedEnv(cctx, cdeps.ScrubSystemdEnv(os.Environ()),
		bin, dbPath, "PRAGMA busy_timeout=2000; SELECT name, length(value) "+
			"FROM kine WHERE deleted = 0 ORDER BY length(value) DESC LIMIT 10;")
	if err != nil {
		return nil, fmt.Errorf("sqlite3 kine large objects: %w: %s",
			err, strings.TrimSpace(out))
	}
	var rows []KineLargeObject
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		name, size, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		b, perr := strconv.ParseInt(strings.TrimSpace(size), 10, 64)
		if perr != nil {
			continue
		}
		rows = append(rows, KineLargeObject{Name: name, Bytes: b})
	}
	return rows, nil
}

// emitKineStorageTextfile writes the kine gauges — present=false
// emits headers only so the series goes absent rather than stale.
// The max-object gauge re-uses the value cached by the last
// successful scan so it persists across the cooldown windows.
func (c *StorageCheck) emitKineStorageTextfile(dbBytes, walBytes int64, present bool) {
	var p promfile.Builder
	if present {
		p.Gauge(kineDBBytesMetric,
			"Size in bytes of the Kine backing store (state.db, or "+
				"the etcd/JetStream filestore total on non-SQLite backends).",
			float64(dbBytes))
		p.Gauge(kineWALBytesMetric,
			"Size in bytes of the Kine SQLite WAL (state.db-wal); "+
				"absent on non-SQLite backends.",
			float64(walBytes))
	} else {
		p.Header(kineDBBytesMetric,
			"Size in bytes of the Kine backing store (state.db, or "+
				"the etcd/JetStream filestore total on non-SQLite backends).")
		p.Header(kineWALBytesMetric,
			"Size in bytes of the Kine SQLite WAL (state.db-wal); "+
				"absent on non-SQLite backends.")
	}
	if present && c.maxObjSeen {
		p.Gauge(kineMaxObjectBytesMetric,
			"Largest live (deleted=0) Kine object value in bytes "+
				"(top-1 by length(value)).",
			c.maxObjBytes)
	} else {
		p.Header(kineMaxObjectBytesMetric,
			"Largest live (deleted=0) Kine object value in bytes "+
				"(top-1 by length(value)).")
	}
	c.d.WriteTextfileProm("node-agent-kine-storage.prom", p.String())
}

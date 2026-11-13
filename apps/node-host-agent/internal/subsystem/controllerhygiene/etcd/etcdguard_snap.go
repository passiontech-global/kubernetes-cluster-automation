// etcdguard_snap.go — the pre-maintenance snapshot half of the
// embedded-etcd quota guard: before the online compact+defrag
// rewrites the backend db, a verified etcdctl snapshot must exist
// under EtcdBackupDir (a defrag fault on a single-member etcd is
// otherwise unrecoverable). Split out of etcdguard.go so the check
// cycle stays under the ~500-LOC bar.
package etcd

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// etcdPreMaintSnapInterval caps the pre-maintenance snapshot cadence
// — one `etcdctl snapshot save` per hour (the guard itself is
// hourly, so this usually bounds one save per remediation window).
const etcdPreMaintSnapInterval = time.Hour

// etcdPremaintMinFreeRatio — snapshot creation requires this much
// free on the backup filesystem when no previous premaint snapshot
// pins a byte estimate (parity with the kine backup verifier's
// >30%-free gate: a full disk must not make it worse).
const etcdPremaintMinFreeRatio = 0.30

// etcdPremaintKeep is the premaint-*.db retention bound under
// EtcdBackupDir — the newest two cover the last two remediation
// windows.
const etcdPremaintKeep = 2

// premaintSnapshots returns the premaint-*.db snapshots under dir,
// newest first by the name's unix timestamp (files without a
// parsable stamp sort last).
func premaintSnapshots(dir string) []string {
	m, err := filepath.Glob(filepath.Join(dir, "premaint-*.db"))
	if err != nil {
		return nil
	}
	ts := func(p string) int64 {
		base := filepath.Base(p)
		n, err := strconv.ParseInt(
			strings.TrimSuffix(strings.TrimPrefix(base, "premaint-"), ".db"), 10, 64)
		if err != nil {
			return -1
		}
		return n
	}
	slices.SortFunc(m, func(a, b string) int { return cmp.Compare(ts(b), ts(a)) })
	return m
}

// savePreMaintSnapshot captures a verified etcd snapshot into
// EtcdBackupDir BEFORE the guard's online compact+defrag: the defrag
// rewrites the backend db, so a failed/empty snapshot means no
// rollback point on a single-member etcd and the remediation must
// NOT proceed. true when a fresh valid snapshot exists (either just
// saved this window or a previous premaint snapshot that still
// passes `snapshot status`). The budget spends on the ATTEMPT — a
// failing save retries no more than once per window. A statfs
// headroom gate (kine backup parity) refuses to write onto a nearly
// full backup fs: free >= 1.1x the newest existing snapshot's size,
// else the 30%-free ratio. After a successful save all but the
// newest etcdPremaintKeep premaint snapshots are pruned.
func (c *GuardCheck) savePreMaintSnapshot(ctx context.Context) bool {
	d := c.d
	if err := os.MkdirAll(d.Cfg.EtcdBackupDir, 0o700); err != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: pre-maintenance snapshot dir %s: %v — compact+defrag aborted",
			d.Cfg.EtcdBackupDir, err))
		return false
	}
	// Headroom gate before every attempt — the incoming save tracks
	// the live db size, which the newest existing snapshot estimates.
	freeB, totalB, ferr := d.Cfg.StatFSFn(d.Cfg.EtcdBackupDir)
	if ferr != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: pre-maintenance snapshot statfs %s: %v — compact+defrag aborted",
			d.Cfg.EtcdBackupDir, ferr))
		return false
	}
	prev := premaintSnapshots(d.Cfg.EtcdBackupDir)
	var need int64
	if len(prev) > 0 {
		if fi, err := os.Stat(prev[0]); err == nil && fi.Size() > 0 {
			need = fi.Size() + fi.Size()/10 // 1.1x
		}
	}
	if need == 0 {
		need = int64(etcdPremaintMinFreeRatio * float64(totalB))
	}
	if freeB < need {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: backup fs low on space (free=%d need=%d) — snapshot skipped, compact+defrag aborted",
			freeB, need))
		return false
	}
	if d.State.RateOK(cdeps.FileRateEtcdPreMaintSnap, etcdPreMaintSnapInterval) {
		name := filepath.Join(d.Cfg.EtcdBackupDir, fmt.Sprintf(
			"premaint-%d.db", d.Cfg.Clock.Now().Unix()))
		d.State.RateSpend(cdeps.FileRateEtcdPreMaintSnap)
		if _, err := d.Cfg.EtcdctlFn(ctx, "snapshot", "save", name); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"etcdguard: pre-maintenance snapshot save failed: %v — compact+defrag aborted", err))
			// A failed save can leave a partial/truncated snapshot —
			// never leave it behind as a fake rollback point (the
			// freshness check reuses the newest premaint-*.db).
			if rmErr := os.Remove(name); rmErr != nil && !os.IsNotExist(rmErr) {
				d.State.AppendLogWarn(fmt.Sprintf(
					"etcdguard: failed pre-maintenance snapshot cleanup: %v", rmErr))
			}
			return false
		}
		// etcdctl writes as the invoking user with the process umask —
		// the snapshot embeds the full etcd keyspace (every Secret in
		// the cluster) and must not inherit a group/world-readable
		// mode.
		if err := os.Chmod(name, 0o600); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"etcdguard: pre-maintenance snapshot chmod failed: %v — compact+defrag aborted", err))
			_ = os.Remove(name)
			return false
		}
		// Verify what was actually written — etcdctl can exit 0 on a
		// truncated stream. `snapshot status` parses the file; the
		// size check catches a zero-byte artifact either way.
		if fi, err := os.Stat(name); err != nil || fi.Size() == 0 {
			d.State.AppendLogWarn(fmt.Sprintf(
				"etcdguard: pre-maintenance snapshot %s missing/empty — compact+defrag aborted", name))
			_ = os.Remove(name)
			return false
		}
		if _, err := d.Cfg.EtcdctlFn(ctx, "snapshot", "status", name); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"etcdguard: pre-maintenance snapshot %s failed verification: %v — compact+defrag aborted",
				name, err))
			// Failed verification = partial garbage. Delete it so the
			// next attempt cannot ride it as the "fresh" snapshot.
			if rmErr := os.Remove(name); rmErr != nil {
				d.State.AppendLogWarn(fmt.Sprintf(
					"etcdguard: failed pre-maintenance snapshot cleanup: %v", rmErr))
			}
			return false
		}
		d.State.AppendLog(
			"ACTION: etcdguard pre-maintenance snapshot saved to " + name)
		d.Actions.WithLabelValues(cdeps.CheckEtcd, "premaint_snapshot").Inc()
		// Retention: one fresh dump per remediation window with no
		// expiry would fill the backup fs — keep only the newest two.
		if n := prunePremaint(d.Cfg.EtcdBackupDir); n > 0 {
			d.State.AppendLog(fmt.Sprintf(
				"etcdguard: pruned %d old pre-maintenance snapshots", n))
		}
		return true
	}
	// Inside the hourly budget — the snapshot from the current window
	// is fresh enough; confirm the NEWEST premaint snapshot is still
	// present, non-empty AND passes `snapshot status` before letting
	// the destructive half run (a concurrent cleaner could have
	// wiped or truncated it — any non-empty file under the dir is no
	// proof of a usable rollback point).
	if len(prev) == 0 {
		d.State.AppendLogWarn(
			"etcdguard: no premaint-*.db snapshot under " + d.Cfg.EtcdBackupDir +
				" — compact+defrag aborted")
		return false
	}
	newest := prev[0]
	if fi, err := os.Stat(newest); err != nil || fi.Size() == 0 {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: pre-maintenance snapshot %s missing/empty — compact+defrag aborted", newest))
		return false
	}
	if _, err := d.Cfg.EtcdctlFn(ctx, "snapshot", "status", newest); err != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: pre-maintenance snapshot %s failed verification: %v — compact+defrag aborted",
			newest, err))
		return false
	}
	return true
}

// prunePremaint deletes all but the newest etcdPremaintKeep
// premaint-*.db snapshots under dir — oldest first by name — and
// returns how many were removed. Best-effort: an unremovable file is
// skipped, never fatal to the guard.
func prunePremaint(dir string) int {
	snaps := premaintSnapshots(dir)
	if len(snaps) <= etcdPremaintKeep {
		return 0
	}
	removed := 0
	for _, f := range snaps[etcdPremaintKeep:] {
		if err := os.Remove(f); err == nil {
			removed++
		}
	}
	return removed
}

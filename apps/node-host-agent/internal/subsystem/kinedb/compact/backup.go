// backup.go — the W13-ST2/Gap#4 physical-backup verifier, riding
// the guard cycle (it writes the guard's Result and its series land
// in kine-compact-guard.prom). Was the backupVerify block that sat
// at the tail of the flat package's maint.go.
package compact

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

const (
	// backupMinFreeRatio — creation requires this much free space
	// on the backup filesystem (a full disk must not make it worse).
	backupMinFreeRatio = 0.30
	// backupKeepDumps is the *.dump retention bound under BackupDir —
	// at the default 6h cadence four dumps cover the last 24h.
	backupKeepDumps = 4
)

// backupVerify is the W13-ST2/Gap#4 physical-backup verifier: the
// newest *.dump in BackupDir must be younger than BackupInterval
// AND header-valid. A stale (or absent) dump is refreshed with
// `pg_dump -Fc` inside the postgres container + `pg_restore -l`
// validation, then `podman|docker cp`'d to the host dir — but only
// while the backup filesystem keeps >30% free (a full disk must
// not make it worse). Pre-existing dumps get the cheap PGDMP
// magic sniff; agent-created dumps are verified with a full
// pg_restore -l listing at creation time.
func (g *Guard) backupVerify(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {

	newest, mtime := newestDump(g.d.Cfg.BackupDir)
	if mtime > 0 {
		res.backupSeen = true
		res.backupAge = g.d.Cfg.Clock.Now().Unix() - mtime
		res.backupValid = dumpValidMagic(newest)
	}
	if res.backupSeen && res.backupAge < int64(g.d.Cfg.BackupInterval.Seconds()) {
		return // fresh enough — nothing to create
	}
	if err := os.MkdirAll(g.d.Cfg.BackupDir, 0o750); err != nil {
		note(fmt.Sprintf("backup-mkdir-fail: %v", err))
		return
	}
	// Stale/absent: only create when the fs has headroom.
	if st, err := g.d.Cfg.StatFSFn(g.d.Cfg.BackupDir); err != nil ||
		st <= backupMinFreeRatio {
		note("backup-skipped-low-free")
		return
	}
	// Dump inside the container to its /tmp, verify with
	// pg_restore -l, then cp to the host dir — streaming the
	// dump through stdout would hit the runner capture cap.
	// pg_dump runs under the LONG budget: a bloated kine table
	// outlasts the 2-minute ExecEnv cap (same class of work as
	// VACUUM/REINDEX).
	tmp := "/tmp/kine-backup.dump"
	if _, err := g.d.ExecLongEnv(ctx, kdeps.PsqlPassEnv(pass), []string{g.d.Cfg.Runtime,
		"exec", "-e", "PGPASSWORD", pg,
		"pg_dump", "-Fc", "-U", user, "-d", "postgres", "-f", tmp}, ""); err != nil {
		note(fmt.Sprintf("pg_dump-fail: %v", err))
		// A failed pg_dump can leave a partial file in the
		// container — drop it like the validate-fail path does.
		_, _ = g.d.Exec(ctx, []string{g.d.Cfg.Runtime, "exec", pg, "rm", "-f", tmp}, "")
		return
	}
	if _, err := g.d.Exec(ctx, []string{g.d.Cfg.Runtime, "exec", pg,
		"pg_restore", "-l", tmp}, ""); err != nil {
		note(fmt.Sprintf("pg_restore-validate-fail: %v", err))
		_, _ = g.d.Exec(ctx, []string{g.d.Cfg.Runtime, "exec", pg, "rm", "-f", tmp}, "")
		return
	}
	dest := filepath.Join(g.d.Cfg.BackupDir,
		fmt.Sprintf("kine-%d.dump", g.d.Cfg.Clock.Now().Unix()))
	// cp lands on a .tmp sibling first, then os.Rename publishes —
	// an interrupted cp would leave a truncated file that still
	// passes the 5-byte PGDMP sniff, and newestDump would call it
	// fresh (kine_db_backup_valid=1) for a whole BackupInterval.
	// The .tmp suffix keeps partials invisible to the *.dump glob.
	destTmp := dest + ".tmp"
	if _, err := g.d.Exec(ctx, []string{g.d.Cfg.Runtime, "cp",
		pg + ":" + tmp, destTmp}, ""); err != nil {
		note(fmt.Sprintf("backup-cp-fail: %v", err))
		_ = os.Remove(destTmp)
	} else if err := os.Rename(destTmp, dest); err != nil {
		note(fmt.Sprintf("backup-rename-fail: %v", err))
		_ = os.Remove(destTmp)
	} else {
		res.backupSeen = true
		res.backupAge = 0
		res.backupValid = true
		note("backup-created " + filepath.Base(dest))
		// One fresh dump every BackupInterval with no expiry
		// would fill the backup fs — keep only the newest few.
		pruneDumps(g.d.Cfg.BackupDir)
	}
	_, _ = g.d.Exec(ctx, []string{g.d.Cfg.Runtime, "exec", pg, "rm", "-f", tmp}, "")
}

// pruneDumps deletes all but the newest backupKeepDumps *.dump
// files under dir — oldest first by mtime — plus any *.tmp
// partial a crashed cp never published. Best-effort: an
// unremovable file is skipped, never fatal to the verify.
func pruneDumps(dir string) {
	// *.dump.tmp partials are never valid dumps — always sweep.
	if tmps, err := filepath.Glob(filepath.Join(dir, "*.tmp")); err == nil {
		for _, f := range tmps {
			_ = os.Remove(f)
		}
	}
	m, err := filepath.Glob(filepath.Join(dir, "*.dump"))
	if err != nil || len(m) <= backupKeepDumps {
		return
	}
	type aged struct {
		path string
		mt   int64
	}
	dumps := make([]aged, 0, len(m))
	for _, f := range m {
		if fi, err := os.Stat(f); err == nil {
			dumps = append(dumps, aged{f, fi.ModTime().Unix()})
		}
	}
	if len(dumps) <= backupKeepDumps {
		return
	}
	slices.SortFunc(dumps, func(a, b aged) int {
		return cmp.Compare(b.mt, a.mt) // newest first
	})
	for _, d := range dumps[backupKeepDumps:] {
		_ = os.Remove(d.path)
	}
}

// newestDump returns the newest *.dump file under dir.
func newestDump(dir string) (string, int64) {
	m, err := filepath.Glob(filepath.Join(dir, "*.dump"))
	if err != nil || len(m) == 0 {
		return "", 0
	}
	var best string
	var mt int64
	for _, f := range m {
		if fi, err := os.Stat(f); err == nil && fi.ModTime().Unix() > mt {
			best, mt = f, fi.ModTime().Unix()
		}
	}
	return best, mt
}

// dumpValidMagic reports whether the file starts with the pg_dump
// custom-format magic ("PGDMP").
func dumpValidMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var hdr [5]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == "PGDMP"
}

// backup_test.go — the backup-health physical-backup verifier tests plus
// the guard-side emit coverage of the kine-churn churn series (the
// sampler half lives in the probe suite), lifted out of the flat
// package's w13_test.go.
package compact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// The probe fills Deps.ChurnTop; the guard render owns the series —
// a populated snapshot must render resource-labelled samples in
// kine-compact-guard.prom.
func TestEmitGuardChurn(t *testing.T) {
	k, _, dir := fixture(t, nil)
	k.d.ChurnTop = []kdeps.ChurnEntry{
		{Resource: "pods", Revs: 120}, {Resource: "leases", Revs: 40},
	}
	k.emitGuard(&Result{})
	content := kdepstest.ReadText(t, dir, "kine-compact-guard.prom")
	for _, want := range []string{
		`kine_db_top_churn_revisions_5m{resource="pods"} 120`,
		`kine_db_top_churn_revisions_5m{resource="leases"} 40`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("churn series missing %q:\n%s", want, content)
		}
	}
}

// --- backup-health: physical backup verifier ---

func TestBackupVerifyCreatesWhenStale(t *testing.T) {
	rules := []testutil.ExecRule{
		{Substr: "pg_dump", Out: ""},
		{Substr: "pg_restore", Out: "; Archive created\n"},
		{Substr: "cp pg:", Out: ""},
		{Substr: "rm -f", Out: ""},
	}
	k, fr, dir := fixture(t, rules)
	bdir := filepath.Join(dir, "backups")
	k.d.Cfg.BackupDir = bdir
	// Stub the free-space probe: the real statfs of the test fs is
	// environment-dependent (a tmpfs under memory pressure can dip
	// below the 30% gate and flake the pipeline assertions).
	k.d.Cfg.StatFSFn = func(string) (float64, error) { return 0.9, nil }
	// cp publishes via <dest>.tmp -> rename; the fake exec produces
	// no bytes, so lay down the file a real cp would have written
	// (dest is kine-<TestNow>.dump — the fixture clock is fixed).
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	tmpDump := filepath.Join(bdir, "kine-1700000000.dump.tmp")
	if err := os.WriteFile(tmpDump, []byte("PGDMP fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A stale partial from a crashed earlier run — pruneDumps must
	// sweep it even though it never matches the *.dump glob.
	staleTmp := filepath.Join(bdir, "kine-1690000000.dump.tmp")
	if err := os.WriteFile(staleTmp, []byte("PGD"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &Result{}
	var notes []string
	note := func(s string) { notes = append(notes, s) }
	k.backupVerify(context.Background(), "pg", "postgres", "secret", res, note)
	j := fr.Joined()
	if !strings.Contains(j, "pg_dump -Fc") ||
		!strings.Contains(j, "pg_restore -l") ||
		!strings.Contains(j, "cp pg:") {
		t.Fatalf("backup pipeline not run:\n%s", j)
	}
	if !strings.Contains(j, ".dump.tmp") {
		t.Fatalf("cp did not target the .tmp staging name:\n%s", j)
	}
	if !res.backupSeen || !res.backupValid || res.backupAge != 0 {
		t.Fatalf("res=%+v want seen/valid/age=0", res)
	}
	if _, err := os.Stat(filepath.Join(bdir, "kine-1700000000.dump")); err != nil {
		t.Fatalf("published dump missing after rename: %v", err)
	}
	if _, err := os.Stat(tmpDump); !os.IsNotExist(err) {
		t.Fatal(".tmp staging file left behind after publish")
	}
	if _, err := os.Stat(staleTmp); !os.IsNotExist(err) {
		t.Fatal("stale .tmp partial not swept by pruneDumps")
	}
}

func TestBackupVerifyFreshDumpSkips(t *testing.T) {
	k, fr, dir := fixture(t, nil)
	bdir := filepath.Join(dir, "backups")
	k.d.Cfg.BackupDir = bdir
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	dump := filepath.Join(bdir, "kine-1.dump")
	if err := os.WriteFile(dump, []byte("PGDMP fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &Result{}
	k.backupVerify(context.Background(), "pg", "postgres", "secret", res,
		func(string) {})
	if !res.backupSeen || !res.backupValid {
		t.Fatalf("res=%+v want seen+valid for a fresh PGDMP file", res)
	}
	if fr.Joined() != "" {
		t.Fatalf("fresh dump still triggered creation:\n%s", fr.Joined())
	}
	// A non-PGDMP file → invalid.
	if err := os.WriteFile(dump, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	res2 := &Result{}
	k.backupVerify(context.Background(), "pg", "postgres", "secret", res2,
		func(string) {})
	if res2.backupValid {
		t.Fatal("non-PGDMP dump reported valid")
	}
}

// A young (inside BackupInterval) but INVALID dump must not ride its
// age to the next interval — backupVerify recreates immediately.
func TestBackupVerifyInvalidYoungDumpRecreates(t *testing.T) {
	rules := []testutil.ExecRule{
		{Substr: "pg_dump -Fc", Out: "dumped\n"},
		{Substr: "pg_restore -l", Out: "ok\n"},
		{Substr: "cp pg:", Out: "copied\n"},
	}
	k, fr, dir := fixture(t, rules)
	bdir := filepath.Join(dir, "backups")
	k.d.Cfg.BackupDir = bdir
	k.d.Cfg.StatFSFn = func(string) (float64, error) { return 0.9, nil }
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Fresh (mtime=now) garbage dump — passes the age check, fails
	// the magic sniff.
	dump := filepath.Join(bdir, "kine-1700000000.dump")
	if err := os.WriteFile(dump, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The fake cp writes no bytes — pre-stage the publish target so
	// the rename lands and the dump reads back valid.
	if err := os.WriteFile(dump+".tmp", []byte("PGDMP fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &Result{}
	var notes []string
	k.backupVerify(context.Background(), "pg", "postgres", "secret", res,
		func(s string) { notes = append(notes, s) })
	if !strings.Contains(fr.Joined(), "pg_dump -Fc") {
		t.Fatalf("invalid young dump did not trigger recreation:\n%s notes=%v",
			fr.Joined(), notes)
	}
	if !res.backupValid {
		t.Fatalf("recreated dump not valid: %+v notes=%v", res, notes)
	}
}

func TestNewestDumpAndMagic(t *testing.T) {
	dir := t.TempDir()
	if p, mt := newestDump(dir); p != "" || mt != 0 {
		t.Fatalf("empty dir → %q %d", p, mt)
	}
	old := filepath.Join(dir, "a.dump")
	newer := filepath.Join(dir, "b.dump")
	for _, f := range []string{old, newer} {
		if err := os.WriteFile(f, []byte("PGDMP"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	_ = os.Chtimes(old, past, past)
	if p, _ := newestDump(dir); p != newer {
		t.Fatalf("newestDump=%q want %q", p, newer)
	}
	if !dumpValidMagic(newer) {
		t.Fatal("PGDMP magic not recognized")
	}
	if dumpValidMagic(filepath.Join(dir, "missing")) {
		t.Fatal("missing file reported valid")
	}
}

// --- backupVerify failure paths ---

// A stale dump with no filesystem headroom (or a failed free-space
// probe) is not refreshed — a full disk must not be made worse.
func TestBackupVerifyLowFreeSkips(t *testing.T) {
	for _, free := range []float64{0.1, -1} { // -1 = statfs error
		k, fr, dir := fixture(t, []testutil.ExecRule{
			{Substr: "pg_dump", Err: errors.New("must not run")},
		})
		bdir := filepath.Join(dir, "backups")
		k.d.Cfg.BackupDir = bdir
		k.d.Cfg.StatFSFn = func(string) (float64, error) {
			if free < 0 {
				return 0, errors.New("statfs failed")
			}
			return free, nil
		}
		var notes []string
		k.backupVerify(context.Background(), "pg", "postgres", "secret",
			&Result{}, func(s string) { notes = append(notes, s) })
		if len(notes) != 1 || notes[0] != "backup-skipped-low-free" {
			t.Fatalf("free=%v notes=%v", free, notes)
		}
		if fr.Joined() != "" {
			t.Fatalf("free=%v ran the dump pipeline:\n%s", free, fr.Joined())
		}
	}
}

// A pg_dump failure inside the container notes, cleans the partial
// /tmp file, and publishes nothing.
func TestBackupVerifyDumpFails(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "pg_dump -Fc", Err: errors.New("out of memory")},
	})
	bdir := filepath.Join(dir, "backups")
	k.d.Cfg.BackupDir = bdir
	k.d.Cfg.StatFSFn = func(string) (float64, error) { return 0.9, nil }
	var notes []string
	res := &Result{}
	k.backupVerify(context.Background(), "pg", "postgres", "secret", res,
		func(s string) { notes = append(notes, s) })
	if res.backupSeen {
		t.Fatal("failed dump must not read seen")
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "pg_dump-fail") {
		t.Fatalf("notes=%v", notes)
	}
	// The partial container-side file is rm'd, and no pg_restore
	// validation or cp followed.
	j := fr.Joined()
	if !fr.Ran("rm -f /tmp/kine-backup.dump") {
		t.Fatalf("partial dump not cleaned:\n%s", j)
	}
	if strings.Contains(j, "pg_restore") || strings.Contains(j, "cp pg:") {
		t.Fatalf("pipeline continued past the dump failure:\n%s", j)
	}
}

// A failed pg_restore -l listing rejects the dump — no host copy.
func TestBackupVerifyValidateFails(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "pg_dump -Fc", Out: "dumped\n"},
		{Substr: "pg_restore -l", Err: errors.New("invalid header")},
	})
	bdir := filepath.Join(dir, "backups")
	k.d.Cfg.BackupDir = bdir
	k.d.Cfg.StatFSFn = func(string) (float64, error) { return 0.9, nil }
	var notes []string
	res := &Result{}
	k.backupVerify(context.Background(), "pg", "postgres", "secret", res,
		func(s string) { notes = append(notes, s) })
	if res.backupSeen || res.backupValid {
		t.Fatalf("res=%+v must stay unseen/invalid", res)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "pg_restore-validate-fail") {
		t.Fatalf("notes=%v", notes)
	}
	if !fr.Ran("rm -f /tmp/kine-backup.dump") {
		t.Fatalf("container dump not cleaned:\n%s", fr.Joined())
	}
	if strings.Contains(fr.Joined(), "cp pg:") {
		t.Fatal("invalid dump was copied to the host")
	}
}

// A failed host cp removes the .tmp staging file and publishes
// nothing — the next cycle re-runs the whole pipeline.
func TestBackupVerifyCpFails(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "pg_dump -Fc", Out: "dumped\n"},
		{Substr: "pg_restore -l", Out: "ok\n"},
		{Substr: "cp pg:", Err: errors.New("disk full")},
	})
	bdir := filepath.Join(dir, "backups")
	k.d.Cfg.BackupDir = bdir
	k.d.Cfg.StatFSFn = func(string) (float64, error) { return 0.9, nil }
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	var notes []string
	res := &Result{}
	k.backupVerify(context.Background(), "pg", "postgres", "secret", res,
		func(s string) { notes = append(notes, s) })
	if res.backupSeen {
		t.Fatal("failed cp must not read seen")
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "backup-cp-fail") {
		t.Fatalf("notes=%v", notes)
	}
	ents, err := os.ReadDir(bdir)
	if err != nil || len(ents) != 0 {
		t.Fatalf("backup dir not clean after cp failure: %v %v", ents, err)
	}
}

// pruneDumps keeps the newest backupKeepDumps *.dump files (mtime
// order), sweeps *.tmp partials, and leaves a small dir untouched.
func TestPruneDumpsRetention(t *testing.T) {
	dir := t.TempDir()
	// Six dumps, oldest first — the two oldest must go.
	names := []string{"kine-1.dump", "kine-2.dump", "kine-3.dump",
		"kine-4.dump", "kine-5.dump", "kine-6.dump"}
	base := time.Now()
	for i, n := range names {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte("PGDMP"), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Hour)
		_ = os.Chtimes(p, mt, mt)
	}
	tmp := filepath.Join(dir, "kine-9.dump.tmp")
	if err := os.WriteFile(tmp, []byte("PGD"), 0o600); err != nil {
		t.Fatal(err)
	}
	pruneDumps(dir)
	for _, n := range []string{"kine-1.dump", "kine-2.dump", tmp} {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Fatalf("%s survived the prune", n)
		}
	}
	for _, n := range []string{"kine-3.dump", "kine-4.dump", "kine-5.dump", "kine-6.dump"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("newest dump %s pruned: %v", n, err)
		}
	}

	// A dir at the retention bound is left alone.
	small := t.TempDir()
	for _, n := range names[:backupKeepDumps] {
		if err := os.WriteFile(filepath.Join(small, n), []byte("PGDMP"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pruneDumps(small)
	ents, _ := os.ReadDir(small)
	if len(ents) != backupKeepDumps {
		t.Fatalf("prune touched the retention bound: %d entries", len(ents))
	}
}

// A dump entry that vanished between the glob and the stat (a
// dangling symlink) drops out of the aged list — if that leaves the
// retention bound unmet, nothing is pruned.
func TestPruneDumpsSkipsUnstattable(t *testing.T) {
	dir := t.TempDir()
	base := time.Now()
	for i, n := range []string{"a.dump", "b.dump", "c.dump", "d.dump"} {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte("PGDMP"), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Hour)
		_ = os.Chtimes(p, mt, mt)
	}
	// Two dangling *.dump symlinks inflate the glob past the bound
	// but stat-fail out of the aged list.
	for _, n := range []string{"ghost1.dump", "ghost2.dump"} {
		if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	pruneDumps(dir)
	for _, n := range []string{"a.dump", "b.dump", "c.dump", "d.dump"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("kept dump %s pruned: %v", n, err)
		}
	}
}

// A truncated dump (< the 5-byte magic) fails the header sniff.
func TestDumpValidMagicShortFile(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short.dump")
	if err := os.WriteFile(short, []byte("PG"), 0o600); err != nil {
		t.Fatal(err)
	}
	if dumpValidMagic(short) {
		t.Fatal("two-byte file reported valid")
	}
}

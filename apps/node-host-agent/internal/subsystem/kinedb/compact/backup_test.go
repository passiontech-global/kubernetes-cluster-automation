// backup_test.go — the W13-ST2 physical-backup verifier tests plus
// the guard-side emit coverage of the W13-CP4 churn series (the
// sampler half lives in the probe suite), lifted out of the flat
// package's w13_test.go.
package compact

import (
	"context"
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

// --- W13-ST2: physical backup verifier ---

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

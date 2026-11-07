// w13_test.go — Wave-13 kinedb tests: the W13-CP4 top-churn
// watermark sampler and the W13-ST2 physical-backup verifier.
package kinedb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- W13-CP4: top-5 churn ---

func TestProbeTopChurn(t *testing.T) {
	rules := []testutil.ExecRule{
		{Substr: "split_part(name", Out: "pods|120\nleases|40\n"},
		{Substr: "MAX(id)", Out: "9000\n"},
	}
	k, _, dir := fixture(t, rules)
	// Watermark files: head=8000, ts well past the 5m window → the
	// query runs this round and the watermark advances.
	gdir := filepath.Join(dir, "guard")
	writeIntFile(filepath.Join(gdir, churnFileHead), 8000)
	writeIntFile(filepath.Join(gdir, churnFileTS), testNow-600)
	var notes []string
	note := func(s string) { notes = append(notes, s) }
	k.probeTopChurn(context.Background(), "pg", "postgres", "secret", note)
	if len(k.churnTop) != 2 || k.churnTop[0].resource != "pods" ||
		k.churnTop[0].revs != 120 {
		t.Fatalf("churnTop=%+v", k.churnTop)
	}
	// Watermark advanced to the fresh head.
	if h, _ := readIntFile(filepath.Join(gdir, churnFileHead)); h != 9000 {
		t.Fatalf("churn head=%d want 9000", h)
	}
	// Guard textfile renders the series.
	k.emitGuard(&guardResult{backupSeen: false})
	content := readText(t, dir, "kine-compact-guard.prom")
	if !strings.Contains(content,
		`kine_db_top_churn_revisions_5m{resource="pods"} 120`) {
		t.Fatalf("churn series missing:\n%s", content)
	}
	// A fresh window (<5m) keeps the last result and does NOT query.
	k.churnTop = nil
	writeIntFile(filepath.Join(gdir, churnFileTS), testNow-10)
	k.probeTopChurn(context.Background(), "pg", "postgres", "secret", note)
	if k.churnTop != nil {
		t.Fatalf("churnTop refreshed inside window: %+v", k.churnTop)
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
	k.cfg.BackupDir = filepath.Join(dir, "backups")
	// Stub the free-space probe: the real statfs of the test fs is
	// environment-dependent (a tmpfs under memory pressure can dip
	// below the 30% gate and flake the pipeline assertions).
	k.cfg.statfsFn = func(string) (float64, error) { return 0.9, nil }
	res := &guardResult{}
	var notes []string
	note := func(s string) { notes = append(notes, s) }
	k.backupVerify(context.Background(), "pg", "postgres", "secret", res, note)
	j := fr.Joined()
	if !strings.Contains(j, "pg_dump -Fc") ||
		!strings.Contains(j, "pg_restore -l") ||
		!strings.Contains(j, "cp pg:") {
		t.Fatalf("backup pipeline not run:\n%s", j)
	}
	if !res.backupSeen || !res.backupValid || res.backupAge != 0 {
		t.Fatalf("res=%+v want seen/valid/age=0", res)
	}
}

func TestBackupVerifyFreshDumpSkips(t *testing.T) {
	k, fr, dir := fixture(t, nil)
	bdir := filepath.Join(dir, "backups")
	k.cfg.BackupDir = bdir
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	dump := filepath.Join(bdir, "kine-1.dump")
	if err := os.WriteFile(dump, []byte("PGDMP fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &guardResult{}
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
	res2 := &guardResult{}
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

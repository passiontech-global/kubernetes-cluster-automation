// prune_test.go — the error paths the happy-path sweep suite cannot
// reach: unreadable dirs are skipped like the script's `2>/dev/null`,
// individual removal failures tally and warn instead of aborting the
// bucket, and a cancelled ctx stops every walk.
package concoursecache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// ccNoPerms skips tests that rely on filesystem permission
// enforcement — root sees through mode bits.
func ccNoPerms(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission checks are not enforced for root")
	}
}

// unreadableSub builds <parent>/dead as a mode-000 dir so walkers hit
// a permission error descending into it.
func unreadableSub(t *testing.T, parent string) string {
	t.Helper()
	dead := filepath.Join(parent, "dead")
	if err := os.Mkdir(dead, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dead, 0o755) })
	return dead
}

// The du/find walkers treat unreadable entries like the script's
// `2>/dev/null` — skipped, never fatal.
func TestWalkersSkipUnreadable(t *testing.T) {
	ccNoPerms(t)
	root := t.TempDir()
	ccFile(t, filepath.Join(root, "ok", "f"), 4, 0)
	unreadableSub(t, root)

	if du := diskUsage(context.Background(), root); du == 0 {
		t.Fatal("diskUsage returned 0 — the readable tree was skipped")
	}
	total, perDir := diskUsageByTopDir(context.Background(), root)
	if total == 0 || len(perDir) == 0 {
		t.Fatalf("diskUsageByTopDir = %d,%v — readable tree skipped",
			total, perDir)
	}
	if files := filesByAge(context.Background(), root); len(files) != 1 {
		t.Fatalf("filesByAge = %v want the one readable file", files)
	}
	// makeWritableDirs must survive the same dead dir (its caller
	// retries the rm anyway).
	makeWritableDirs(root)
}

// topLevelDirsByAge lists ONLY first-level dirs — a loose file next
// to them is not a cap candidate (`-type d`).
func TestTopLevelDirsByAgeSkipsFiles(t *testing.T) {
	root := t.TempDir()
	ccFile(t, filepath.Join(root, "loose"), 4, 0)
	ccDir(t, filepath.Join(root, "adir"), 0)

	got := topLevelDirsByAge(root)
	if len(got) != 1 || filepath.Base(got[0].path) != "adir" {
		t.Fatalf("topLevelDirsByAge = %v want just adir", got)
	}
}

// deleteOldFiles: ctx cancellation stops the walk before the first
// entry is evaluated.
func TestDeleteOldFilesCtxCancel(t *testing.T) {
	dir := t.TempDir()
	f := ccFile(t, filepath.Join(dir, "old"), 4, 100*time.Hour)
	p := ccPruner(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.deleteOldFiles(ctx, dir, "go-build", time.Hour, logger())
	ccPresent(t, f)
}

// deleteOldFiles: unreadable subdirs are skipped and a file that
// cannot be removed counts toward the failed tally + warn — neither
// is fatal (the script's `|| true`).
func TestDeleteOldFilesFailures(t *testing.T) {
	ccNoPerms(t)
	dir := t.TempDir()
	unreadableSub(t, dir)

	ro := filepath.Join(dir, "ro")
	ccFile(t, filepath.Join(ro, "stuck"), 4, 100*time.Hour)
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(ro, 0o755) }()

	gone := ccFile(t, filepath.Join(dir, "old"), 4, 100*time.Hour)

	p := ccPruner(t, nil)
	p.deleteOldFiles(context.Background(), dir, "go-build",
		time.Hour, logger())

	ccMissing(t, gone)
	ccPresent(t, filepath.Join(ro, "stuck")) // removal failed, warn only
	if got := testutil.ToFloat64(
		p.filesDeleted.WithLabelValues("go-build")); got != 1 {
		t.Fatalf("filesDeleted=%v want 1 (only the removable file)", got)
	}
}

// deleteEmptyDirs: a dead ctx aborts the collect walk before any
// remove runs.
func TestDeleteEmptyDirsCtxCancel(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "hollow")
	ccDir(t, empty, 0)
	p := ccPruner(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.deleteEmptyDirs(ctx, dir, logger())
	ccPresent(t, empty)
}

// go-build over its high mark: a trim candidate that cannot be
// removed counts into the failed tally and the run warns — it does
// not abort the trim or re-run.
func TestGoBuildTrimRemoveFailure(t *testing.T) {
	ccNoPerms(t)
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gbf"))
	dir := filepath.Join(sc, "go-build")
	ro := filepath.Join(dir, "ro")
	stuck := ccFile(t, filepath.Join(ro, "stuck"), 4, time.Hour)
	fresh := ccFile(t, filepath.Join(dir, "fresh"), 4, 2*time.Hour)
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(ro, 0o755) }()

	p := ccPruner(t, func(c *Config) {
		c.GoBuildHighMark = 1 // always over
		// LowMark must stay >0 (applyDefaults treats 0 as unset):
		// need = sz−1 exceeds the summed file footprints, so every
		// candidate is tried.
		c.GoBuildLowMark = 1
	})
	p.pruneGoBuild(context.Background(), sc, p.cfg, logger())

	ccMissing(t, fresh) // removed — the trim still proceeds past failures
	ccPresent(t, stuck) // removal failed, warn only
}

// capTopLevelDirs: a first-level dir that rm -rf cannot take warns
// but the freed accounting still accrues (the shell's unconditional
// `freed+=dsz`) — the cap loop continues to the next candidate.
func TestCapTopLevelDirsRemoveFailure(t *testing.T) {
	ccNoPerms(t)
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("capf"))
	dir := filepath.Join(sc, "build")
	stuck := filepath.Join(dir, "k-stuck")
	ccFile(t, filepath.Join(stuck, "f"), 4, 0)
	kept := filepath.Join(dir, "k-ok")
	ccFile(t, filepath.Join(kept, "f"), 4, 0)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o755) }()

	p := ccPruner(t, nil)
	// writable=false — the build bucket's rm has no chmod fallback;
	// the warn path is the whole assertion (stuck survives).
	p.capTopLevelDirs(context.Background(), sc, "build", 1, 0,
		false, logger())

	ccPresent(t, stuck)
	ccPresent(t, kept) // cap loop did not reach it either way — dir ro
}

// node-deps on a dead ctx: every phase break is taken (cksum loop,
// lock walk, staging loop) without touching anything.
func TestNodeDepsCtxCancel(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("ndc"))
	nd := filepath.Join(sc, "node-deps")
	old := filepath.Join(nd, "cksum-old")
	ccFile(t, filepath.Join(old, "f"), 4, 0)
	ccDir(t, old, 9*24*time.Hour)
	lock := ccFile(t, filepath.Join(nd, ".lock-x"), 4, 62*time.Minute)

	p := ccPruner(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.pruneNodeDeps(ctx, sc, p.cfg, logger())

	ccPresent(t, old)
	ccPresent(t, lock)
}

// An unreadable node-deps dir warns on BOTH listing phases (aged
// cksum dirs + stale staging dirs) — the sweeps are best-effort.
func TestNodeDepsUnreadableDir(t *testing.T) {
	ccNoPerms(t)
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("ndu"))
	nd := filepath.Join(sc, "node-deps")
	if err := os.MkdirAll(nd, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(nd, 0o755) }()

	p := ccPruner(t, nil)
	p.pruneNodeDeps(context.Background(), sc, p.cfg, logger())
	ccPresent(t, nd) // nothing removed, nothing panicked
}

// node-deps: a stale lock file inside a read-only dir fails its
// remove → lockFailed tally + warn; an aged cksum dir under a
// read-only parent defeats even removeTree's chmod retry → warn.
func TestNodeDepsRemoveFailures(t *testing.T) {
	ccNoPerms(t)
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("ndr"))
	nd := filepath.Join(sc, "node-deps")

	ro := filepath.Join(nd, "ro")
	lock := ccFile(t, filepath.Join(ro, ".lock-stuck"), 4, 62*time.Minute)
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(ro, 0o755) }()

	aged := filepath.Join(nd, "cksum-aged")
	ccFile(t, filepath.Join(aged, "f"), 4, 0)
	ccDir(t, aged, 9*24*time.Hour)
	staging := filepath.Join(nd, "cksum.tmp-9")
	ccFile(t, filepath.Join(staging, "partial"), 4, 0)
	ccDir(t, staging, 62*time.Minute)
	if err := os.Chmod(nd, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(nd, 0o755) }()

	p := ccPruner(t, nil)
	p.pruneNodeDeps(context.Background(), sc, p.cfg, logger())

	ccPresent(t, lock)    // remove failed → warn
	ccPresent(t, aged)    // removeTree failed → warn
	ccPresent(t, staging) // removeTree failed → warn
}

// Sweep: an unreadable openebs root aborts the pass (not a no-op —
// only a MISSING root is benign).
func TestSweepRootReadError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-a-dir")
	ccFile(t, root, 4, 0)

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err == nil {
		t.Fatal("expected a readdir error, not a silent ok")
	}
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("abort")); got != 1 {
		t.Fatalf("cycles abort=%v want 1", got)
	}
}

// enforcePerms: an unreadable shared-cache falls back to enforcing
// the root alone (the ReadDir-failure else branch) — never fatal.
func TestEnforcePermsUnreadable(t *testing.T) {
	ccNoPerms(t)
	sc := t.TempDir()
	unreadableSub(t, sc)
	if err := os.Chmod(sc, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(sc, 0o755) }()

	p := ccPruner(t, nil)
	p.enforcePerms(sc, logger()) // must not panic; sc itself is chmod'd
	// The fd-based pass opens sc O_NOFOLLOW before fchmod — as root
	// (production) the open succeeds and the invariant lands; an
	// unprivileged run cannot open a 0000 dir at all and the pass
	// degrades to the Debug-logged skip (never a panic).
	if os.Geteuid() == 0 {
		if fi, err := os.Stat(sc); err != nil || fi.Mode().Perm() != 0o777 {
			t.Fatalf("sc perm = %v — root-level invariant not enforced", fi)
		}
	} else if fi, err := os.Stat(sc); err != nil || fi.Mode().Perm() != 0o000 {
		t.Fatalf("sc perm = %v — unprivileged run should leave it alone", fi)
	}
}

func TestDiskUsageAndFilesByAgeCtxCancel(t *testing.T) {
	root := t.TempDir()
	ccFile(t, filepath.Join(root, "a", "f"), 64, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if du := diskUsage(ctx, root); du != 0 {
		t.Fatalf("diskUsage on cancelled ctx = %d, want 0", du)
	}
	if total, perDir := diskUsageByTopDir(ctx, root); total != 0 || len(perDir) != 0 {
		t.Fatalf("diskUsageByTopDir on cancelled ctx = (%d, %v), want (0, empty)", total, perDir)
	}
	if files := filesByAge(ctx, root); len(files) != 0 {
		t.Fatalf("filesByAge on cancelled ctx = %v, want empty", files)
	}
}

func TestPruneGoBuildSingleWalkEquivalence(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gb1"))
	dir := filepath.Join(sc, "go-build")
	expired := ccFile(t, filepath.Join(dir, "expired"), 100, 80*time.Hour)
	oldestKept := ccFile(t, filepath.Join(dir, "sub", "oldest"), 100, 30*time.Hour)
	newestKept := ccFile(t, filepath.Join(dir, "sub", "newest"), 100, 10*time.Hour)

	// Compute expected size after expired is removed (mirrors 3-walk accounting,
	// including directory entryBlocks).
	fiOldest, err := os.Lstat(oldestKept)
	if err != nil {
		t.Fatal(err)
	}
	perFile := int64(entryBlocks(fiOldest))
	fiExpired, err := os.Lstat(expired)
	if err != nil {
		t.Fatal(err)
	}
	duAll := int64(diskUsage(context.Background(), dir))
	szAfterAge := duAll - int64(entryBlocks(fiExpired))

	p := ccPruner(t, func(c *Config) {
		c.GoBuildHighMark = 1
		c.GoBuildLowMark = szAfterAge - perFile // trim exactly oldestKept
	})
	p.pruneGoBuild(context.Background(), sc, p.cfg, logger())

	ccMissing(t, expired)
	ccMissing(t, oldestKept)
	ccPresent(t, newestKept)

	// Cancelled ctx during pruneGoBuild skips both age-delete and size-trim.
	root2 := t.TempDir()
	sc2 := mkSharedCache(t, root2, ccPVCName("gb2"))
	keepExpired := ccFile(t, filepath.Join(sc2, "go-build", "old"), 100, 80*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p2 := ccPruner(t, func(c *Config) {
		c.GoBuildHighMark = 1
		c.GoBuildLowMark = 1
	})
	p2.pruneGoBuild(ctx, sc2, p2.cfg, logger())
	ccPresent(t, keepExpired)
}

// ---------------------------------------------------------------------------
// go-build reference-aware pruning — a "-d" output a surviving "-a" index
// entry still references must never be deleted (dangling index entries
// fail in-flight go/vet/golangci-lint builds with "-d: no such file").
// ---------------------------------------------------------------------------

// ccGoIndexPair writes a well-formed Go build-cache index+output pair:
// <dir>/<aid[0:2]>/<aid>-a holding the fixed-width v1 record that
// references oid, plus the <oid>-d output file — both aged by age.
// aid/oid must be 64 lowercase-hex chars (strings.Repeat("a",64) etc.).
func ccGoIndexPair(t *testing.T, dir, aid, oid string, age time.Duration) (string, string) {
	t.Helper()
	indexPath := filepath.Join(dir, aid[:2], aid+"-a")
	outputPath := filepath.Join(dir, oid[:2], oid+"-d")
	rec := fmt.Sprintf("v1 %s %s %20d %20d\n", aid, oid, 0, time.Now().UnixNano())
	if len(rec) != goBuildIndexLen {
		t.Fatalf("index record len %d, want %d", len(rec), goBuildIndexLen)
	}
	for _, p := range []string{indexPath, outputPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(indexPath, []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("output"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	for _, p := range []string{indexPath, outputPath} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	return indexPath, outputPath
}

// The size cap sorts candidates oldest-first — a referenced "-d" that
// is the OLDEST file in the cache must still survive while every
// unprotected file is trimmed away.
func TestGoBuildCapPreservesReferencedOutput(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gbp"))
	dir := filepath.Join(sc, "go-build")
	aid := strings.Repeat("a", 64)
	oid := strings.Repeat("b", 64)
	indexPath, outputPath := ccGoIndexPair(t, dir, aid, oid, time.Hour)

	// Make the protected output the oldest file in the cache — the
	// cap would kill it first without reference awareness.
	old := time.Now().Add(-50 * time.Hour)
	if err := os.Chtimes(outputPath, old, old); err != nil {
		t.Fatal(err)
	}
	stray1 := ccFile(t, filepath.Join(dir, "11", strings.Repeat("1", 64)+"-d"), 100, 30*time.Hour)
	stray2 := ccFile(t, filepath.Join(dir, "22", strings.Repeat("2", 64)+"-a"), 100, 20*time.Hour)
	plain := ccFile(t, filepath.Join(dir, "plain"), 100, 10*time.Hour)

	p := ccPruner(t, func(c *Config) {
		c.GoBuildHighMark = 1 // always over
		// LowMark must stay >0 (applyDefaults treats <=0 as unset):
		// need = sz-1 exceeds every candidate's footprint, so the trim
		// walks the whole candidate list.
		c.GoBuildLowMark = 1
	})
	p.pruneGoBuild(context.Background(), sc, p.cfg, logger())

	ccPresent(t, outputPath) // referenced by the surviving "-a" — survives
	ccMissing(t, stray1)     // unreferenced "-d" — cap fodder
	ccMissing(t, stray2)     // "-a" — cap fodder (a missing index is a miss)
	ccMissing(t, plain)
	// indexPath itself is cap fodder too — deleting an index is a
	// plain cache miss; only its "-d" was protected this pass.
	ccMissing(t, indexPath)
}

// Age prune: a fresh "-a" shields an over-age "-d" for this pass; once
// the index is gone the orphaned output is pruned normally.
func TestGoBuildAgeProtectsThenOrphansOutput(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gba"))
	dir := filepath.Join(sc, "go-build")
	aid := strings.Repeat("c", 64)
	oid := strings.Repeat("d", 64)
	indexPath, outputPath := ccGoIndexPair(t, dir, aid, oid, time.Hour)
	// Age ONLY the output past the 72h limit — the index stays fresh.
	old := time.Now().Add(-80 * time.Hour)
	if err := os.Chtimes(outputPath, old, old); err != nil {
		t.Fatal(err)
	}

	p := ccPruner(t, nil)
	p.pruneGoBuild(context.Background(), sc, p.cfg, logger())
	ccPresent(t, indexPath)
	ccPresent(t, outputPath) // protected despite >72h mtime

	// Remove the index — next pass the output is an orphan and its
	// stale mtime makes it age-prune fodder.
	if err := os.Remove(indexPath); err != nil {
		t.Fatal(err)
	}
	p.pruneGoBuild(context.Background(), sc, p.cfg, logger())
	ccMissing(t, outputPath)
}

// An unreferenced "-d" (no index points at it) prunes by the ordinary
// age rule — the deferred path must not make outputs immortal.
func TestGoBuildOrphanOutputAgePruned(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gbo"))
	dir := filepath.Join(sc, "go-build")
	old := ccFile(t, filepath.Join(dir, "aa", strings.Repeat("e", 64)+"-d"), 4, 80*time.Hour)
	fresh := ccFile(t, filepath.Join(dir, "bb", strings.Repeat("f", 64)+"-d"), 4, time.Hour)

	p := ccPruner(t, nil)
	p.pruneGoBuild(context.Background(), sc, p.cfg, logger())
	ccMissing(t, old)
	ccPresent(t, fresh)
}

// A corrupt "-a" record protects nothing — Go treats it as a miss,
// so its would-be output is just another unreferenced file.
func TestGoBuildCorruptIndexProtectsNothing(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gbc"))
	dir := filepath.Join(sc, "go-build")
	badIndex := ccFile(t, filepath.Join(dir, "aa", strings.Repeat("0", 64)+"-a"), 100, time.Hour)
	orphan := ccFile(t, filepath.Join(dir, "bb", strings.Repeat("1", 64)+"-d"), 4, 80*time.Hour)

	p := ccPruner(t, nil)
	p.pruneGoBuild(context.Background(), sc, p.cfg, logger())
	ccPresent(t, badIndex) // fresh index survives the age rule
	ccMissing(t, orphan)   // unreferenced output still age-pruned
}

// Sibling caches ("go-build-<tag>", e.g. ci-tool's per-phase isolated
// GOCACHEs) get the same pass; unrelated dirs are untouched.
func TestGoBuildSiblingCachesPruned(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gbs"))
	sharedOld := ccFile(t, filepath.Join(sc, "go-build", "old"), 4, 80*time.Hour)
	siblingOld := ccFile(t, filepath.Join(sc, "go-build-lint-ci-main", "old"), 4, 80*time.Hour)
	otherOld := ccFile(t, filepath.Join(sc, "other-cache", "old"), 4, 80*time.Hour)

	p := ccPruner(t, nil)
	p.pruneGoBuild(context.Background(), sc, p.cfg, logger())
	ccMissing(t, sharedOld)
	ccMissing(t, siblingOld)
	ccPresent(t, otherOld)
}

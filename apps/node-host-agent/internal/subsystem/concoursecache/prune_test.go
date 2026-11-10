// prune_test.go — the error paths the happy-path sweep suite cannot
// reach: unreadable dirs are skipped like the script's `2>/dev/null`,
// individual removal failures tally and warn instead of aborting the
// bucket, and a cancelled ctx stops every walk.
package concoursecache

import (
	"context"
	"os"
	"path/filepath"
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

	if du := diskUsage(root); du == 0 {
		t.Fatal("diskUsage returned 0 — the readable tree was skipped")
	}
	total, perDir := diskUsageByTopDir(root)
	if total == 0 || len(perDir) == 0 {
		t.Fatalf("diskUsageByTopDir = %d,%v — readable tree skipped",
			total, perDir)
	}
	if files := filesByAge(root); len(files) != 1 {
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
	if fi, err := os.Stat(sc); err != nil || fi.Mode().Perm() != 0o777 {
		t.Fatalf("sc perm = %v — root-level invariant not enforced", fi)
	}
}

package sweeper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// ccPruner builds a pruner with the script defaults except chown —
// tests run unprivileged (OwnerUID/GID -1 skips it; chmod 0777 stays).
// The statfs seam defaults to an error stub so the host filesystem's
// real fill level never escalates a fixture (fail-open keeps the
// normal limits); pressure tests inject their own via mutate, which
// can also shrink the size marks so the cap logic is exercisable
// without GiB fixtures.
func ccPruner(t *testing.T, mutate func(*ConcourseCacheConfig)) *ConcourseCachePruner {
	t.Helper()
	cfg := ConcourseCacheConfig{
		OwnerUID: -1, OwnerGID: -1,
		statfsFn: func(string, *syscall.Statfs_t) error {
			return errors.New("no fs in test")
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := NewConcourseCachePruner(cfg, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ccPVCName renders a readable test tag as a strict pvc-<uuid> dir
// name — Sweep only enters dirs matching the orphan sweeper's
// pvcNameRe, so fixtures need real UUID shapes (the tag's bytes are
// hex-encoded into the first field, the rest is zeros).
func ccPVCName(tag string) string {
	h := fmt.Sprintf("%x", tag)
	if len(h) > 8 {
		h = h[:8]
	}
	for len(h) < 8 {
		h += "0"
	}
	return "pvc-" + h + "-0000-0000-0000-000000000000"
}

// mkSharedCache creates <root>/<pvc>/shared-cache and returns the
// shared-cache path.
func mkSharedCache(t *testing.T, root, pvc string) string {
	t.Helper()
	sc := filepath.Join(root, pvc, "shared-cache")
	if err := os.MkdirAll(sc, 0o755); err != nil {
		t.Fatal(err)
	}
	return sc
}

// ccFile writes size bytes at path and ages its mtime by age.
func ccFile(t *testing.T, path string, size int, age time.Duration) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return path
}

// ccDir creates dir (with parents) and ages its mtime by age — call
// AFTER populating children since creating entries bumps dir mtime.
func ccDir(t *testing.T, dir string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
}

func ccMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s still present (err=%v)", path, err)
	}
}

func ccPresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s missing: %v", path, err)
	}
}

// A missing openebs root is a no-op, not an error.
func TestConcourseCacheMissingRoot(t *testing.T) {
	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), filepath.Join(t.TempDir(), "gone")); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1", got)
	}
}

// pvc-* dirs without a shared-cache and non-pvc dirs are both
// skipped — the script's `[ -d "$SC" ] || exit 0` plus the pvc-* glob.
func TestConcourseCacheSkipsNonCacheDirs(t *testing.T) {
	root := t.TempDir()
	p := ccPruner(t, nil)

	// pvc dir without shared-cache.
	if err := os.MkdirAll(filepath.Join(root, ccPVCName("nocache")), 0o755); err != nil {
		t.Fatal(err)
	}
	// A pvc-* name that is NOT a strict pvc-<uuid> is skipped by the
	// name belt before the shared-cache check — its cache content
	// stays untouched too.
	loose := ccFile(t, filepath.Join(root, "pvc-1234", "shared-cache",
		"go-build", "old"), 4, 100*time.Hour)
	// A shared-cache that is NOT under a pvc-* dir stays untouched.
	stray := filepath.Join(root, "handmade", "shared-cache", "go-build")
	old := ccFile(t, filepath.Join(stray, "old"), 4, 100*time.Hour)

	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccPresent(t, old)
	ccPresent(t, loose)
}

// The perm invariant: shared-cache + first level forced to 0777.
func TestConcourseCachePermInvariant(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("aaaa"))
	child := filepath.Join(sc, "go-build")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sc, 0o700); err != nil {
		t.Fatal(err)
	}

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{sc, child} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o777 {
			t.Fatalf("%s perm %o, want 0777", d, fi.Mode().Perm())
		}
	}
}

// Symlink safety: a CI task can plant shared-cache/<name> links
// pointing OUTSIDE the cache. enforcePerms must skip them (Lstat
// filter — no chown/chmod onto the host target) and a bucket-dir
// symlink must never be pruned (isDir Lstats, so the link is not a
// dir and every bucket helper returns early). Without this the
// root-running pruner is a host-file takeover gadget.
func TestConcourseCacheSymlinkSafety(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("ln"))

	// Outside target: a dir holding a stale file plus a loose file —
	// both with modes enforcePerms would rewrite if it dereferenced.
	outside := filepath.Join(t.TempDir(), "outside")
	stale := ccFile(t, filepath.Join(outside, "old"), 4, 100*time.Hour)
	loose := ccFile(t, filepath.Join(outside, "loose"), 4, 0)
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o600); err != nil {
		t.Fatal(err)
	}

	// A bucket-name symlink (would be pruned if followed), an
	// arbitrary link, and a link to a single file.
	for _, name := range []string{"go-build", "evil"} {
		if err := os.Symlink(outside, filepath.Join(sc, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(loose, filepath.Join(sc, "loose-file")); err != nil {
		t.Fatal(err)
	}

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}

	// The symlinked bucket dir was never opened: the stale file inside
	// the outside dir survives; every link itself is still there.
	ccPresent(t, stale)
	for _, name := range []string{"go-build", "evil", "loose-file"} {
		if _, err := os.Lstat(filepath.Join(sc, name)); err != nil {
			t.Fatalf("symlink %s gone: %v", name, err)
		}
	}
	// enforcePerms skipped the links: target perms untouched.
	if fi, err := os.Stat(outside); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Fatalf("outside dir perm %o — enforcePerms followed the symlink", fi.Mode().Perm())
	}
	if fi, err := os.Stat(loose); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("outside file perm %o — enforcePerms followed the symlink", fi.Mode().Perm())
	}
}

// go-build: files older than 72h die, younger survive.
func TestConcourseCacheGoBuildAge(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gb"))
	old := ccFile(t, filepath.Join(sc, "go-build", "ab", "old"), 4, 73*time.Hour)
	fresh := ccFile(t, filepath.Join(sc, "go-build", "ab", "fresh"), 4, 71*time.Hour)

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, old)
	ccPresent(t, fresh)
	if got := testutil.ToFloat64(p.filesDeleted.WithLabelValues("go-build")); got != 1 {
		t.Fatalf("go-build filesDeleted=%v want 1", got)
	}
}

// go-build over the high mark: oldest files trimmed until the low
// mark is satisfied — selection is by mtime, not name.
func TestConcourseCacheGoBuildSizeCap(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("gb"))
	dir := filepath.Join(sc, "go-build")
	// All <72h so the age rule cannot fire.
	oldest := ccFile(t, filepath.Join(dir, "f1"), 100, 54*time.Hour)
	mid := ccFile(t, filepath.Join(dir, "f2"), 100, 44*time.Hour)
	newest := ccFile(t, filepath.Join(dir, "f3"), 100, 34*time.Hour)

	sz := int64(diskUsage(dir))
	p := ccPruner(t, func(c *ConcourseCacheConfig) {
		c.GoBuildHighMark = 1       // always over the cap
		c.GoBuildLowMark = sz - 150 // need 150B → frees exactly 2×100B
	})
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, oldest)
	ccMissing(t, mid)
	ccPresent(t, newest)
}

// build + coverage: 48h files deleted, empty dirs swept, fresh kept.
func TestConcourseCacheBuildCoverage(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("bc"))

	for _, bucket := range []string{"build", "coverage"} {
		old := ccFile(t, filepath.Join(sc, bucket, "key", "art"), 4, 49*time.Hour)
		fresh := ccFile(t, filepath.Join(sc, bucket, "key", "new"), 4, 47*time.Hour)
		// Nested empty chain must collapse bottom-up.
		ccDir(t, filepath.Join(sc, bucket, "empty", "inner"), 0)

		p := ccPruner(t, nil)
		if err := p.Sweep(context.Background(), root); err != nil {
			t.Fatal(err)
		}
		ccMissing(t, old)
		ccPresent(t, fresh)
		ccMissing(t, filepath.Join(sc, bucket, "empty"))
	}
}

// build over its cap: oldest first-level <key> dirs removed until the
// low mark is freed.
func TestConcourseCacheBuildSizeCap(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("bc"))
	dir := filepath.Join(sc, "build")
	ccFile(t, filepath.Join(dir, "k-old", "f"), 10, 0)
	ccFile(t, filepath.Join(dir, "k-mid", "f"), 10, 0)
	ccFile(t, filepath.Join(dir, "k-new", "f"), 10, 0)
	ccDir(t, filepath.Join(dir, "k-old"), 54*time.Hour)
	ccDir(t, filepath.Join(dir, "k-mid"), 44*time.Hour)
	ccDir(t, filepath.Join(dir, "k-new"), 34*time.Hour)

	sz := int64(diskUsage(dir))
	dszOld := int64(diskUsage(filepath.Join(dir, "k-old")))
	p := ccPruner(t, func(c *ConcourseCacheConfig) {
		c.BuildHighMark = 1          // always over
		c.BuildLowMark = sz - dszOld // need = exactly k-old's du
	})
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, filepath.Join(dir, "k-old"))
	ccPresent(t, filepath.Join(dir, "k-mid"))
	ccPresent(t, filepath.Join(dir, "k-new"))
}

// affected + ytt: 72h files die, but empty dirs are NEVER swept —
// the script gave these buckets no dir cleanup.
func TestConcourseCacheAffectedYtt(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("ay"))

	for _, bucket := range []string{"affected", "ytt"} {
		old := ccFile(t, filepath.Join(sc, bucket, "dead"), 4, 73*time.Hour)
		fresh := ccFile(t, filepath.Join(sc, bucket, "live"), 4, 71*time.Hour)
		empty := filepath.Join(sc, bucket, "empty-sub")
		ccDir(t, empty, 0)

		p := ccPruner(t, nil)
		if err := p.Sweep(context.Background(), root); err != nil {
			t.Fatal(err)
		}
		ccMissing(t, old)
		ccPresent(t, fresh)
		ccPresent(t, empty) // no -type d -empty for this bucket
	}
}

// nx + moon: 8d files die, empty dirs are swept.
func TestConcourseCacheNxMoon(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("nm"))

	for _, bucket := range []string{"nx", "moon"} {
		old := ccFile(t, filepath.Join(sc, bucket, "stale"), 4, 9*24*time.Hour)
		fresh := ccFile(t, filepath.Join(sc, bucket, "hot"), 4, 7*24*time.Hour)
		ccDir(t, filepath.Join(sc, bucket, "hollow"), 0)

		p := ccPruner(t, nil)
		if err := p.Sweep(context.Background(), root); err != nil {
			t.Fatal(err)
		}
		ccMissing(t, old)
		ccPresent(t, fresh)
		ccMissing(t, filepath.Join(sc, bucket, "hollow"))
	}
}

// Tool caches: 15d files die, empty dirs swept — spot-check trivy,
// sonar and bun (the whole list shares one code path).
func TestConcourseCacheToolBuckets(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("tools"))

	for _, bucket := range []string{"trivy", "sonar", "golangci-lint",
		"uv", "pip", "bin", "py-tools", "bun"} {
		ccFile(t, filepath.Join(sc, bucket, "stale"), 4, 16*24*time.Hour)
		ccFile(t, filepath.Join(sc, bucket, "hot"), 4, 14*24*time.Hour)
		ccDir(t, filepath.Join(sc, bucket, "hollow"), 0)
	}
	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	for _, bucket := range []string{"trivy", "sonar", "golangci-lint",
		"uv", "pip", "bin", "py-tools", "bun"} {
		ccMissing(t, filepath.Join(sc, bucket, "stale"))
		ccPresent(t, filepath.Join(sc, bucket, "hot"))
		ccMissing(t, filepath.Join(sc, bucket, "hollow"))
	}
}

// node-deps: a <cksum> dir whose mtime is >8d is removed even when it
// contains a read-only subtree (chmod -R u+w before rm -rf); a young
// <cksum> dir survives.
func TestConcourseCacheNodeDepsAgedDir(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("nd"))

	oldDir := filepath.Join(sc, "node-deps", "cksum-old")
	ro := filepath.Join(oldDir, "pkg", "sub")
	ccFile(t, filepath.Join(ro, "index.js"), 4, 0)
	if err := os.Chmod(filepath.Join(oldDir, "pkg"), 0o555); err != nil {
		t.Fatal(err)
	}
	ccDir(t, oldDir, 9*24*time.Hour)

	freshDir := filepath.Join(sc, "node-deps", "cksum-fresh")
	ccFile(t, filepath.Join(freshDir, "f"), 4, 0)
	ccDir(t, freshDir, 48*time.Hour)

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, oldDir)
	ccPresent(t, freshDir)
}

// node-deps: .lock-*/.tmp-* files older than 61m die at ANY depth;
// younger ones and regular files survive.
func TestConcourseCacheNodeDepsLockFiles(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("nd"))
	nd := filepath.Join(sc, "node-deps")

	stale1 := ccFile(t, filepath.Join(nd, ".lock-abc"), 4, 62*time.Minute)
	stale2 := ccFile(t, filepath.Join(nd, "cksum-x", ".tmp-99"), 4, 62*time.Minute)
	fresh := ccFile(t, filepath.Join(nd, ".lock-xyz"), 4, 30*time.Minute)
	normal := ccFile(t, filepath.Join(nd, "cksum-x", "index.js"), 4, 62*time.Minute)

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, stale1)
	ccMissing(t, stale2)
	ccPresent(t, fresh)
	ccPresent(t, normal)
	if got := testutil.ToFloat64(p.filesDeleted.WithLabelValues("node-deps")); got != 2 {
		t.Fatalf("node-deps filesDeleted=%v want 2", got)
	}
}

// node-deps: crashed *.tmp-* staging DIRS at depth 1 older than 61m
// are rm -rf'd (they are non-empty so -empty -delete could not);
// a younger one and a same-named file's parent survive.
func TestConcourseCacheNodeDepsStagingDirs(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("nd"))
	nd := filepath.Join(sc, "node-deps")

	stale := filepath.Join(nd, "cksum.tmp-123")
	ccFile(t, filepath.Join(stale, "partial"), 4, 0)
	ccDir(t, stale, 62*time.Minute)
	fresh := filepath.Join(nd, "cksum.tmp-456")
	ccFile(t, filepath.Join(fresh, "partial"), 4, 0)
	ccDir(t, fresh, 30*time.Minute)
	// A .tmp-* DIR at depth >1 is NOT touched by the staging rule
	// (it matches the file rule's name shape but find restricted
	// dirs to -maxdepth 1).
	nested := filepath.Join(nd, "cksum-keep", "inner.tmp-7")
	ccFile(t, filepath.Join(nested, "f"), 4, 0)
	ccDir(t, nested, 62*time.Minute)
	ccDir(t, filepath.Join(nd, "cksum-keep"), 48*time.Hour)

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, stale)
	ccPresent(t, fresh)
	ccPresent(t, nested)
}

// node-deps over its cap: oldest <cksum> dirs rm -rf'd (chmod -R u+w
// first — the losing dir here has a read-only subtree).
func TestConcourseCacheNodeDepsSizeCap(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("nd"))
	dir := filepath.Join(sc, "node-deps")

	oldDir := filepath.Join(dir, "cksum-old")
	ccFile(t, filepath.Join(oldDir, "ro", "f"), 10, 0)
	if err := os.Chmod(filepath.Join(oldDir, "ro"), 0o555); err != nil {
		t.Fatal(err)
	}
	ccFile(t, filepath.Join(dir, "cksum-mid", "f"), 10, 0)
	ccFile(t, filepath.Join(dir, "cksum-new", "f"), 10, 0)
	ccDir(t, oldDir, 54*time.Hour)
	ccDir(t, filepath.Join(dir, "cksum-mid"), 44*time.Hour)
	ccDir(t, filepath.Join(dir, "cksum-new"), 34*time.Hour)

	sz := int64(diskUsage(dir))
	dszOld := int64(diskUsage(oldDir))
	p := ccPruner(t, func(c *ConcourseCacheConfig) {
		c.NodeDepsHighMark = 1
		c.NodeDepsLowMark = sz - dszOld // need = exactly cksum-old's du
	})
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, oldDir)
	ccPresent(t, filepath.Join(dir, "cksum-mid"))
	ccPresent(t, filepath.Join(dir, "cksum-new"))
}

// Buckets under the cap keep everything; buckets that do not exist
// are silently skipped — mirrors every `[ -d ]` guard in the script.
func TestConcourseCacheUnderCapKeepsAll(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("keep"))
	fresh := ccFile(t, filepath.Join(sc, "go-build", "f"), 4, time.Hour)

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccPresent(t, fresh)
}

// Cancellation between pvc dirs aborts the pass with ctx.Err().
func TestConcourseCacheContextCancelled(t *testing.T) {
	root := t.TempDir()
	mkSharedCache(t, root, ccPVCName("a"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := ccPruner(t, nil)
	if err := p.Sweep(ctx, root); err == nil {
		t.Fatal("expected ctx error from a cancelled sweep")
	}
	if got := testutil.ToFloat64(p.cycles.WithLabelValues("abort")); got != 1 {
		t.Fatalf("cycles abort=%v want 1", got)
	}
}

// The package-level entry point applies the script defaults.
func TestSweepConcourseSharedCacheFunc(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("fn"))
	old := ccFile(t, filepath.Join(sc, "ytt", "stale"), 4, 73*time.Hour)
	if err := SweepConcourseSharedCache(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, old)
}

// ---------------------------------------------------------------------------
// H3 — fs-pressure early trigger (max(diskUsedPct, inodeUsedPct))
// ---------------------------------------------------------------------------

// ccStatfs returns a statfsFn seam reporting the given used
// percentages for blocks and inodes. Bfree and Bavail are set alike —
// fsPressure guards on Bavail (unprivileged-free), matching
// workerhygiene's ingest-GC trigger.
func ccStatfs(diskPct, inodePct uint64) func(string, *syscall.Statfs_t) error {
	return func(_ string, st *syscall.Statfs_t) error {
		st.Blocks = 10000
		st.Bfree = 10000 - diskPct*100
		st.Bavail = 10000 - diskPct*100
		st.Files = 10000
		st.Ffree = 10000 - inodePct*100
		return nil
	}
}

// The production seams default in applyDefaults: statfs →
// syscall.Statfs, thresholds 75/85. Built without the ccPruner stub
// so the real syscall.Statfs is exercised.
func TestConcourseCachePressureDefaults(t *testing.T) {
	p, err := NewConcourseCachePruner(
		ConcourseCacheConfig{OwnerUID: -1, OwnerGID: -1},
		prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.statfsFn == nil {
		t.Fatal("statfsFn seam not defaulted")
	}
	if p.cfg.DiskHighPct != 75 || p.cfg.DiskCritPct != 85 {
		t.Fatalf("thresholds = %v/%v, want 75/85",
			p.cfg.DiskHighPct, p.cfg.DiskCritPct)
	}
	// The real statfs answers on a tmpdir — pressure is a sane
	// reading, escalation off.
	pct, ok := p.fsPressure(t.TempDir())
	if !ok || pct < 0 || pct > 100 {
		t.Fatalf("fsPressure = %v,%v, want 0..100,true", pct, ok)
	}
}

// fsPressure reports max(used-bytes %, used-inodes %) — a low byte
// reading must not mask inode exhaustion, and vice versa.
func TestFSPressureMaxRatio(t *testing.T) {
	p := ccPruner(t, func(c *ConcourseCacheConfig) {
		c.statfsFn = ccStatfs(30, 82)
	})
	pct, ok := p.fsPressure(t.TempDir())
	if !ok || pct != 82 {
		t.Fatalf("fsPressure = %v,%v, want 82,true (inode wins)", pct, ok)
	}
	p.cfg.statfsFn = ccStatfs(91, 10)
	pct, ok = p.fsPressure(t.TempDir())
	if !ok || pct != 91 {
		t.Fatalf("fsPressure = %v,%v, want 91,true (bytes win)", pct, ok)
	}
	// Statfs failure → ok=false (caller keeps normal limits).
	p.cfg.statfsFn = func(string, *syscall.Statfs_t) error {
		return errors.New("fs hung")
	}
	if _, ok := p.fsPressure(t.TempDir()); ok {
		t.Fatal("fsPressure ok=true on statfs error")
	}
}

// H3 early trigger: inode exhaustion alone (bytes still low) must
// escalate the prune — here inodes at 90% cross DiskCritPct so every
// file in the prunable buckets is eligible, even a 1h-old one that
// the normal 72h go-build age would keep.
func TestConcourseCacheInodePressureEarlyTrigger(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("ino"))
	f40h := ccFile(t, filepath.Join(sc, "go-build", "f40h"), 4, 40*time.Hour)
	f1h := ccFile(t, filepath.Join(sc, "go-build", "f1h"), 4, time.Hour)

	p := ccPruner(t, func(c *ConcourseCacheConfig) {
		c.statfsFn = ccStatfs(20, 90) // 20% bytes, 90% inodes → crit
	})
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, f40h)
	ccMissing(t, f1h)
}

// Byte pressure between the thresholds escalates to the high level:
// age limits halve — a 40h file dies under the halved 36h go-build
// limit while a 20h file survives.
func TestConcourseCacheDiskPressureHigh(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("hi"))
	old := ccFile(t, filepath.Join(sc, "go-build", "old"), 4, 40*time.Hour)
	fresh := ccFile(t, filepath.Join(sc, "go-build", "fresh"), 4, 20*time.Hour)

	p := ccPruner(t, func(c *ConcourseCacheConfig) {
		c.statfsFn = ccStatfs(78, 30) // 78% bytes → high, not crit
	})
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, old)
	ccPresent(t, fresh)
}

// Below DiskHighPct the pressure reading changes nothing — the same
// ages keep every file.
func TestConcourseCachePressureUnderThreshold(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("lo"))
	f40h := ccFile(t, filepath.Join(sc, "go-build", "f"), 4, 40*time.Hour)

	p := ccPruner(t, func(c *ConcourseCacheConfig) {
		c.statfsFn = ccStatfs(70, 60) // both under 75 → normal limits
	})
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccPresent(t, f40h)
}

// A statfs failure fails open to the normal limits — escalation is
// best-effort on top of the regular cadence prune.
func TestConcourseCacheStatfsErrorFailsOpen(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("err"))
	old := ccFile(t, filepath.Join(sc, "go-build", "old"), 4, 80*time.Hour)
	f40h := ccFile(t, filepath.Join(sc, "go-build", "f40h"), 4, 40*time.Hour)

	p := ccPruner(t, func(c *ConcourseCacheConfig) {
		c.statfsFn = func(string, *syscall.Statfs_t) error {
			return errors.New("fs hung")
		}
	})
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, old)  // normal 72h age still prunes
	ccPresent(t, f40h) // 40h survives — no escalation
}

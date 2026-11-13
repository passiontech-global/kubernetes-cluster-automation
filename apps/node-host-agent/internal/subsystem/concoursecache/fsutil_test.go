// fsutil_test.go — the du/find helper unit contracts: filesByAge
// carries ALLOCATED blocks (not apparent size) so the go-build trim
// accumulator moves in the same du-style units as diskUsage and the
// size marks, and the node-deps lock-file bytesFreed reports the same
// units. Sparse files are the discriminator: huge apparent Size(),
// tiny st_blocks×512 footprint.
package concoursecache

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// ccSparseFile writes a sparse file — 1 byte, a 1MiB hole, 1 byte —
// and ages its mtime. On a filesystem honoring sparseness (tmpfs,
// ext4, overlayfs all do) the allocated footprint stays far below
// the apparent size.
func ccSparseFile(t *testing.T, path string, age time.Duration) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(1<<20, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("y"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFilesByAgeCarriesBlocks: the trim candidates' size field is the
// allocated footprint (entryBlocks), not apparent Size — the pre-fix
// code mixed apparent size into accumulators compared against
// diskUsage totals and the block-unit size marks, so a sparse file's
// bloated apparent size would evict far more than the cap asked for
// and over-report bytesFreed.
func TestFilesByAgeCarriesBlocks(t *testing.T) {
	dir := t.TempDir()
	p := ccSparseFile(t, filepath.Join(dir, "sparse"), 48*time.Hour)

	files := filesByAge(dir)
	if len(files) != 1 {
		t.Fatalf("files = %d want 1", len(files))
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(entryBlocks(fi))
	if files[0].size != want {
		t.Fatalf("filesByAge size = %d, want the allocated footprint %d "+
			"(apparent size %d)", files[0].size, want, fi.Size())
	}
	// The unit consistency the fix exists for: the candidate's size
	// never exceeds the tree du it is trimmed against (a sparse file's
	// apparent size CAN — entryBlocks never does).
	if du := diskUsage(dir); files[0].size > int64(du) {
		t.Fatalf("candidate size %d exceeds tree du %d — unit mismatch",
			files[0].size, du)
	}
}

// TestNodeDepsLockBytesFreedUsesBlocks: the stale .lock-*/.tmp-*
// walk reports bytesFreed in allocated blocks like every other
// bytesFreed site — a sparse lock file contributes its footprint,
// not its apparent size.
func TestNodeDepsLockBytesFreedUsesBlocks(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("nd"))
	nd := filepath.Join(sc, "node-deps")

	lock := ccSparseFile(t, filepath.Join(nd, ".lock-sparse"), 62*time.Minute)
	fi, err := os.Lstat(lock)
	if err != nil {
		t.Fatal(err)
	}
	want := float64(entryBlocks(fi))

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ccMissing(t, lock)
	if got := testutil.ToFloat64(p.bytesFreed); got != want {
		t.Fatalf("bytesFreed = %v, want the allocated footprint %v "+
			"(apparent size %d)", got, want, fi.Size())
	}
}

// TestEntryBlocksSparseNeverFallsBackToApparent: a sparse file's
// st.Blocks is 0 — the pre-fix `ok && st.Blocks > 0` guard fell back
// to apparent Size() exactly there, so a single huge sparse file
// inflated the trim accumulator past the size marks in one step.
// Blocks×512 is returned whenever the stat is syscall-backed, 0
// included; only a non-syscall Sys() (the never-in-practice branch)
// falls back.
func TestEntryBlocksSparseNeverFallsBackToApparent(t *testing.T) {
	p := ccSparseFile(t, filepath.Join(t.TempDir(), "sparse"), 0)
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	if st.Blocks == 0 {
		t.Skip("filesystem did not honor sparseness — nothing to assert")
	}
	want := uint64(st.Blocks) * 512
	if got := entryBlocks(fi); got != want {
		t.Fatalf("entryBlocks = %d want %d (apparent size %d)",
			got, want, fi.Size())
	}
}

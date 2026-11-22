// regression_r21_test.go — R2.1 security regression tests for
// concoursecache: symlinked shared-cache, intermediate/leaf symlink
// escapes (both escaping and intra-root), FIFO DoS in go-build index
// reads, and directory-at-index handling under -race.
package concoursecache

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSweepRejectsSymlinkedSharedCacheAndBucketIntraSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideOld := ccFile(t, filepath.Join(outside, "old"), 8, 200*time.Hour)
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}

	// Case 1: pvc-<uuid>/shared-cache itself is a symlink to outside.
	pvc1 := filepath.Join(root, ccPVCName("symsc"))
	if err := os.MkdirAll(pvc1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(pvc1, "shared-cache")); err != nil {
		t.Fatal(err)
	}

	// Case 2: intra-root symlink bucket go-build -> go-mod, plus
	// escaping intermediate and leaf symlinks inside ytt & node-deps.
	sc := mkSharedCache(t, root, ccPVCName("intra"))
	precious := ccFile(t, filepath.Join(sc, "go-mod", "keep"), 8, 200*time.Hour)
	if err := os.Symlink("go-mod", filepath.Join(sc, "go-build")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sc, "ytt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sc, "ytt", "escape-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideOld, filepath.Join(sc, "ytt", "escape-leaf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(precious, filepath.Join(sc, "ytt", "intra-leaf")); err != nil {
		t.Fatal(err)
	}

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}

	// Outside target and go-mod precious file must be completely untouched.
	ccPresent(t, outsideOld)
	ccPresent(t, precious)
	if fi, err := os.Stat(outside); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("outside dir perm changed: %v %v", fi, err)
	}
}

func TestSweepMakeWritableSkipsIntraRootSymlink(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("rointra"))
	preciousDir := filepath.Join(sc, "go-mod", "ro")
	if err := os.MkdirAll(preciousDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(preciousDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(preciousDir, 0o755) })

	nd := filepath.Join(sc, "node-deps", "cksum-old")
	if err := os.MkdirAll(nd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(preciousDir, filepath.Join(nd, "link-to-gomod")); err != nil {
		t.Fatal(err)
	}
	ccDir(t, nd, 9*24*time.Hour)

	p := ccPruner(t, nil)
	if err := p.Sweep(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(preciousDir); err != nil || fi.Mode().Perm() != 0o500 {
		t.Fatalf("preciousDir perm changed via intra-root symlink: %v %v", fi, err)
	}
}

func TestGoBuildIndexFIFOAndDirDoNotBlockOrCrash(t *testing.T) {
	root := t.TempDir()
	sc := mkSharedCache(t, root, ccPVCName("fifo"))
	gb := filepath.Join(sc, "go-build")
	aa := filepath.Join(gb, "aa")
	if err := os.MkdirAll(aa, 0o755); err != nil {
		t.Fatal(err)
	}

	// Plant a FIFO named like a fresh -a index file so pruneGoBuildDirRoot
	// attempts to read it via goBuildReferencedOutputRoot.
	fifoPath := filepath.Join(aa, strings.Repeat("a", 64)+"-a")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skipf("FIFO not supported: %v", err)
	}
	old := time.Now().Add(-10 * time.Hour)
	if err := os.Chtimes(fifoPath, old, old); err != nil {
		t.Fatal(err)
	}

	// Also plant a directory named like an -a index file.
	dirIdx := filepath.Join(gb, "bb", strings.Repeat("b", 64)+"-a")
	if err := os.MkdirAll(dirIdx, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dirIdx, old, old); err != nil {
		t.Fatal(err)
	}

	p := ccPruner(t, nil)
	done := make(chan error, 1)
	go func() {
		done <- p.Sweep(context.Background(), root)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Sweep failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Sweep blocked opening FIFO at go-build -a index path")
	}
}

//go:build unix

package fsx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

// The EBUSY/EXDEV bind-mount fallback is unix-only (stat_other.go
// reports isBindMountRenameErr=false elsewhere), so these tests are
// unix-tagged: stub the package RenameFile seam, force the errno,
// and prove WriteFileAtomic* degrade to the direct fsync'd write —
// and that any OTHER rename error still propagates.
func TestWriteFileAtomicFallbackOnBindMountErrno(t *testing.T) {
	for _, errno := range []error{syscall.EBUSY, syscall.EXDEV} {
		t.Run(errno.Error(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "etc-hosts")

			orig := RenameFile
			RenameFile = func(string, string) error { return errno }
			t.Cleanup(func() { RenameFile = orig })

			if err := WriteFileAtomic(path, "127.0.0.1 localhost\n"); err != nil {
				t.Fatalf("WriteFileAtomic: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "127.0.0.1 localhost\n" {
				t.Fatalf("fallback content = %q", got)
			}
			// The staging file must have been swept — only the
			// direct-written target remains.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "etc-hosts" {
				t.Fatalf("staging leaked after fallback: %d entries", len(entries))
			}
		})
	}
}

// A rename failure that is NOT the bind-mount blind spot must
// propagate — silently degrading to a torn-write fallback on, say,
// EACCES would hide a real permission problem.
func TestWriteFileAtomicNoFallbackOnOtherRenameError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")

	orig := RenameFile
	RenameFile = func(string, string) error { return syscall.EACCES }
	t.Cleanup(func() { RenameFile = orig })

	if err := WriteFileAtomic(path, "x"); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("WriteFileAtomic = %v, want EACCES", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("non-fallback error must not install the target")
	}
}

// FileStatKey fingerprints dev:ino:size:mtime — an atomic rewrite
// lands a NEW inode so the key MUST change even for identical
// content, and a missing file returns the os.Stat error.
func TestFileStatKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(path, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	k1, err := FileStatKey(path)
	if err != nil {
		t.Fatalf("FileStatKey: %v", err)
	}
	// Same content rewritten atomically → new inode → new key.
	if err := WriteFileAtomic(path, "cert"); err != nil {
		t.Fatal(err)
	}
	k2, err := FileStatKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k2 {
		t.Fatal("atomic rewrite kept the same stat key — inode not rotated")
	}
	if _, err := FileStatKey(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FileStatKey(missing) = %v, want ErrNotExist", err)
	}
}

func TestWriteFileAtomicNoSyncFallbackAndError(t *testing.T) {
	for _, errno := range []error{syscall.EBUSY, syscall.EXDEV} {
		t.Run(errno.Error(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "metric.prom")

			orig := RenameFile
			RenameFile = func(string, string) error { return errno }
			t.Cleanup(func() { RenameFile = orig })

			if err := WriteFileAtomicNoSync(path, "up 1\n"); err != nil {
				t.Fatalf("WriteFileAtomicNoSync: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "up 1\n" {
				t.Fatalf("fallback content = %q, want %q", got, "up 1\n")
			}
		})
	}

	t.Run("other_error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "metric.prom")

		orig := RenameFile
		RenameFile = func(string, string) error { return syscall.EACCES }
		t.Cleanup(func() { RenameFile = orig })

		if err := WriteFileAtomicNoSync(path, "up 1\n"); !errors.Is(err, syscall.EACCES) {
			t.Fatalf("WriteFileAtomicNoSync = %v, want EACCES", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("non-fallback error must not install the target")
		}
	})
}

func resetBindMountMemoForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		bindMountMu.Lock()
		clear(bindMountMemo)
		bindMountMu.Unlock()
	})
}

func TestWriteFileAtomicEBUSYMemoization(t *testing.T) {
	resetBindMountMemoForTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	uncleanPath := filepath.Join(dir, ".", "hosts")

	var renameCalls atomic.Int64
	orig := RenameFile
	RenameFile = func(string, string) error {
		renameCalls.Add(1)
		return syscall.EBUSY
	}
	t.Cleanup(func() { RenameFile = orig })

	if err := WriteFileAtomic(path, "v1\n"); err != nil {
		t.Fatalf("first WriteFileAtomic: %v", err)
	}
	if err := WriteFileAtomic(uncleanPath, "v2\n"); err != nil {
		t.Fatalf("second WriteFileAtomic: %v", err)
	}
	if err := WriteFileAtomicBytes(path, []byte("v3\n")); err != nil {
		t.Fatalf("WriteFileAtomicBytes: %v", err)
	}
	if err := WriteFileAtomicNoSync(path, "v4\n"); err != nil {
		t.Fatalf("WriteFileAtomicNoSync: %v", err)
	}
	if got := renameCalls.Load(); got != 1 {
		t.Fatalf("RenameFile calls = %d, want 1 (EBUSY should be memoized across WriteFileAtomic*)", got)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v4\n" {
		t.Fatalf("content = %q, want %q", got, "v4\n")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "hosts" {
		t.Fatalf("unexpected dir entries: %d", len(entries))
	}

	// EXDEV must NOT be memoized as a bind-mount EBUSY.
	exdevPath := filepath.Join(dir, "exdev")
	var exdevCalls atomic.Int64
	RenameFile = func(string, string) error {
		exdevCalls.Add(1)
		return syscall.EXDEV
	}
	if err := WriteFileAtomic(exdevPath, "a"); err != nil {
		t.Fatalf("EXDEV 1: %v", err)
	}
	if err := WriteFileAtomic(exdevPath, "b"); err != nil {
		t.Fatalf("EXDEV 2: %v", err)
	}
	if got := exdevCalls.Load(); got != 2 {
		t.Fatalf("EXDEV RenameFile calls = %d, want 2 (EXDEV must not memoize)", got)
	}
}

func TestWriteFileAtomicEBUSYMemoInvalidatedOnInodeChange(t *testing.T) {
	resetBindMountMemoForTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")

	var renameCalls atomic.Int64
	orig := RenameFile
	RenameFile = func(string, string) error {
		renameCalls.Add(1)
		return syscall.EBUSY
	}
	t.Cleanup(func() { RenameFile = orig })

	if err := WriteFileAtomic(path, "v1\n"); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, "v2\n"); err != nil {
		t.Fatal(err)
	}
	if got := renameCalls.Load(); got != 1 {
		t.Fatalf("before inode change: renameCalls = %d, want 1", got)
	}

	// Unlink and recreate with a new inode.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new-inode\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(path, "v3\n"); err != nil {
		t.Fatal(err)
	}
	if got := renameCalls.Load(); got != 2 {
		t.Fatalf("after inode change: renameCalls = %d, want 2", got)
	}
}

func TestWriteFileAtomicEBUSYMemoInvalidatedOnRenameSwap(t *testing.T) {
	resetBindMountMemoForTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")

	orig := RenameFile
	t.Cleanup(func() { RenameFile = orig })

	RenameFile = func(string, string) error { return syscall.EBUSY }
	if err := WriteFileAtomic(path, "v1\n"); err != nil {
		t.Fatal(err)
	}

	RenameFile = func(string, string) error { return syscall.EPERM }
	if err := WriteFileAtomic(path, "v2\n"); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("after RenameFile swap: err = %v, want EPERM", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v1\n" {
		t.Fatalf("content = %q, want %q", got, "v1\n")
	}
}

func TestWriteFileAtomicEBUSYMemoEvictedOnDirectWriteError(t *testing.T) {
	resetBindMountMemoForTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")

	orig := RenameFile
	RenameFile = func(string, string) error { return syscall.EBUSY }
	t.Cleanup(func() { RenameFile = orig })

	if err := WriteFileAtomic(path, "v1\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	// Skip when running as root (uid 0 bypasses 0444 write checks).
	if os.Geteuid() == 0 {
		t.Skip("running as root; 0444 does not reject O_WRONLY")
	}

	if err := WriteFileAtomic(path, "v2\n"); err == nil {
		t.Fatal("expected direct write error on 0444 file")
	}
	bindMountMu.RLock()
	_, exists := bindMountMemo[filepath.Clean(path)]
	bindMountMu.RUnlock()
	if exists {
		t.Fatal("memo entry was not evicted after direct write error")
	}

	// Also verify WriteFileAtomicNoSync eviction on direct-write error.
	nsPath := filepath.Join(dir, "metric.prom")
	if err := WriteFileAtomicNoSync(nsPath, "up 1\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nsPath, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(nsPath, 0o644) })
	if err := WriteFileAtomicNoSync(nsPath, "up 2\n"); err == nil {
		t.Fatal("expected NoSync direct write error on 0444 file")
	}
	bindMountMu.RLock()
	_, exists = bindMountMemo[filepath.Clean(nsPath)]
	bindMountMu.RUnlock()
	if exists {
		t.Fatal("NoSync memo entry was not evicted after direct write error")
	}
}

func TestWriteFileAtomicEBUSYMemoCapBounded(t *testing.T) {
	resetBindMountMemoForTest(t)
	dir := t.TempDir()

	orig := RenameFile
	RenameFile = func(string, string) error { return syscall.EBUSY }
	t.Cleanup(func() { RenameFile = orig })

	for i := range bindMountMemoCap + 20 {
		p := filepath.Join(dir, fmt.Sprintf("f-%d", i))
		if err := WriteFileAtomicNoSync(p, "x"); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	bindMountMu.RLock()
	n := len(bindMountMemo)
	bindMountMu.RUnlock()
	if n > bindMountMemoCap {
		t.Fatalf("bindMountMemo len = %d > cap %d", n, bindMountMemoCap)
	}
}

func TestSetRenameFileConcurrentRaceFree(t *testing.T) {
	resetBindMountMemoForTest(t)
	dir := t.TempDir()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 50 {
			restore := SetRenameFile(func(oldpath, newpath string) error {
				return os.Rename(oldpath, newpath)
			})
			restore()
		}
	})
	wg.Go(func() {
		for i := range 50 {
			p := filepath.Join(dir, fmt.Sprintf("f-%d", i%4))
			if err := WriteFileAtomic(p, "ok"); err != nil {
				t.Errorf("WriteFileAtomic: %v", err)
			}
		}
	})
	wg.Wait()
}

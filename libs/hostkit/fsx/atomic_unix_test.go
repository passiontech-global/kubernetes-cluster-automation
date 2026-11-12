//go:build unix

package fsx

import (
	"errors"
	"os"
	"path/filepath"
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

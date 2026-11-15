package hoststate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteEpochFile(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, "", nil, nil)

	okPath := filepath.Join(dir, "last-check")
	if !s.WriteEpochFile(okPath, 1700000123) {
		t.Fatal("WriteEpochFile(valid) returned false, want true")
	}
	if got := s.Epoch(okPath); got != 1700000123 {
		t.Fatalf("Epoch = %d, want 1700000123", got)
	}

	// Non-ENOSPC/EROFS error (parent path is a regular file) returns false.
	fileAsParent := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s.WriteEpochFile(filepath.Join(fileAsParent, "child"), 42) {
		t.Fatal("WriteEpochFile(ENOTDIR) returned true, want false")
	}
}

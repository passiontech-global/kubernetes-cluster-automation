package fsx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalkBytesBounded(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte(strings.Repeat("a", 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.bin"), []byte(strings.Repeat("b", 55)), 0o644); err != nil {
		t.Fatal(err)
	}
	// Symlinks to files or dirs must be skipped (not followed, bytes not double-counted).
	if err := os.Symlink(filepath.Join(root, "a.txt"), filepath.Join(root, "link-a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, filepath.Join(root, "link-sub")); err != nil {
		t.Fatal(err)
	}

	// Standalone walk within maxEntries.
	got, truncated, err := WalkBytesBounded(root, nil, 100)
	if err != nil || truncated || got != 155 {
		t.Fatalf("WalkBytesBounded = (%d, %v, %v), want (155, false, nil)", got, truncated, err)
	}

	// maxEntries truncation stops early and reports truncated=true.
	got, truncated, err = WalkBytesBounded(root, nil, 2)
	if err != nil || !truncated {
		t.Fatalf("WalkBytesBounded(maxEntries=2) = (%d, %v, %v), want truncated=true, err=nil", got, truncated, err)
	}
	if got > 155 {
		t.Fatalf("truncated bytes = %d > 155", got)
	}

	// Shared budget: exact fit consumes budget to 0 without truncating;
	// subsequent walk sees budget==0 and short-circuits as truncated.
	// Entries in root: root, a.txt, link-a, link-sub, sub, b.bin = 6 entries.
	budget := 6
	got, truncated, err = WalkBytesBounded(root, &budget, 100)
	if err != nil || truncated || got != 155 || budget != 0 {
		t.Fatalf("shared budget exact = (%d, %v, %v) rem=%d, want (155, false, nil) rem=0", got, truncated, err, budget)
	}
	got, truncated, err = WalkBytesBounded(root, &budget, 100)
	if err != nil || !truncated || got != 0 {
		t.Fatalf("exhausted budget = (%d, %v, %v), want (0, true, nil)", got, truncated, err)
	}

	// Mid-walk budget exhaustion (budget=3 < 6 entries).
	budget = 3
	_, truncated, err = WalkBytesBounded(root, &budget, 0)
	if err != nil || !truncated || budget != 0 {
		t.Fatalf("mid-walk budget = truncated=%v err=%v rem=%d, want true nil 0", truncated, err, budget)
	}

	// Missing directory is handled cleanly without error.
	got, truncated, err = WalkBytesBounded(filepath.Join(t.TempDir(), "does-not-exist"), nil, 100)
	if err != nil || truncated || got != 0 {
		t.Fatalf("missing dir = (%d, %v, %v), want (0, false, nil)", got, truncated, err)
	}

	// Symlink root is not followed into target directory.
	got, truncated, err = WalkBytesBounded(filepath.Join(root, "link-sub"), nil, 100)
	if err != nil || truncated || got != 0 {
		t.Fatalf("symlink root = (%d, %v, %v), want (0, false, nil)", got, truncated, err)
	}
}

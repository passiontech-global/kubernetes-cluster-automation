package concourse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithNoFollowFDRejectsSymlinkAndType(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := EnforcePermsFD(link, false, -1, -1, CachePerm, nil); err == nil {
		t.Fatal("expected O_NOFOLLOW error on symlink")
	}

	reg := filepath.Join(dir, "file")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnforcePermsFD(reg, false, -1, -1, CachePerm, nil); err == nil ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("allowFile=false on regular file got err=%v", err)
	}
	if err := EnforcePermsFD(reg, true, -1, -1, 0o640, nil); err != nil {
		t.Fatalf("allowFile=true failed: %v", err)
	}
	fi, err := os.Stat(reg)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("perm=%o, want 640", fi.Mode().Perm())
	}
}

func TestDefaultChownFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "chown-fd")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// -1/-1 is a no-op chown on an open fd that succeeds even unprivileged.
	if err := DefaultChownFD(f.Name(), int(f.Fd()), -1, -1); err != nil {
		t.Fatalf("DefaultChownFD(-1,-1): %v", err)
	}
	if err := DefaultChownFD("bad", -1, -1, -1); err == nil {
		t.Fatal("expected error for invalid fd -1")
	}
}

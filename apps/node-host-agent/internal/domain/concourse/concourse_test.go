package concourse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

// TestWithNoFollowFDRejectsFIFOPromptly: a FIFO substituted for a
// cache entry must be rejected by fstat, not hang the OS thread in
// open(). unix.Open has no Go netpoller, so O_NONBLOCK is required.
func TestWithNoFollowFDRejectsFIFOPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("FIFO not supported here: %v", err)
	}
	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		done <- result{err: WithNoFollowFD(fifo, true,
			func(int, *unix.Stat_t) error { return nil })}
	}()
	select {
	case r := <-done:
		if r.err == nil || !strings.Contains(r.err.Error(), "not a dir or regular file") {
			t.Fatalf("FIFO rejection error = %v, want type error", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WithNoFollowFD blocked opening a FIFO (missing O_NONBLOCK)")
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

func TestWithNoFollowRootFDRejectsSymlinksAndFIFO(t *testing.T) {
	outside := t.TempDir()
	outsideDir := filepath.Join(outside, "dir")
	if err := os.Mkdir(outsideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "file")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootDir := t.TempDir()
	realDir := filepath.Join(rootDir, "real")
	if err := os.MkdirAll(filepath.Join(realDir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "reg")
	if err := os.WriteFile(realFile, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Escaping leaf symlink, intra-root leaf symlink, escaping intermediate, intra-root intermediate.
	if err := os.Symlink(outsideDir, filepath.Join(rootDir, "escape-leaf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(rootDir, "intra-leaf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootDir, "escape-mid")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(rootDir, "intra-mid")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real/reg", filepath.Join(rootDir, "intra-file")); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	for _, rel := range []string{"escape-leaf", "intra-leaf", "escape-mid/dir", "intra-mid/sub", "../outside"} {
		if err := EnforcePermsRootFD(root, rel, false, -1, -1, CachePerm, nil); err == nil {
			t.Fatalf("EnforcePermsRootFD(%q) succeeded, expected symlink/escape rejection", rel)
		}
	}
	if err := EnforcePermsRootFD(root, "intra-file", true, -1, -1, 0o644, nil); err == nil {
		t.Fatal("EnforcePermsRootFD on intra-root file symlink succeeded, expected rejection")
	}

	// Real targets unchanged for rejected links, updated for real targets.
	if fi, err := os.Stat(outsideDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("outsideDir perm changed: %v %v", fi, err)
	}
	if fi, err := os.Stat(realDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("realDir perm changed via intra-root link: %v %v", fi, err)
	}

	if err := EnforcePermsRootFD(root, "real/sub", false, -1, -1, 0o755, nil); err != nil {
		t.Fatalf("real/sub failed: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(realDir, "sub")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("real/sub perm=%v want 0755", fi)
	}
	if err := EnforcePermsRootFD(root, "real/reg", true, -1, -1, 0o640, nil); err != nil {
		t.Fatalf("real/reg failed: %v", err)
	}
	if fi, err := os.Stat(realFile); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("real/reg perm=%v want 0640", fi)
	}

	// FIFO rejection without blocking.
	fifo := filepath.Join(rootDir, "pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("FIFO not supported: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- WithNoFollowRootFD(root, "pipe", true, func(int, *unix.Stat_t) error { return nil })
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a dir or regular file") {
			t.Fatalf("FIFO error = %v, want type error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WithNoFollowRootFD blocked on FIFO")
	}
}

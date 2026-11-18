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

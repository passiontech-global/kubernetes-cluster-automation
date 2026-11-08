// host_test.go — the managed-file verbs over a TempDir HostRoot:
// sha256-compared atomic writes, managed removes, dir/exists probes.
package converge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestHostJoin(t *testing.T) {
	h := Host{Root: "/host"}
	if got := h.Join("/etc/nftables.conf"); got != "/host/etc/nftables.conf" {
		t.Fatalf("Join = %q", got)
	}
	if got := h.Join("etc/x"); got != "/host/etc/x" {
		t.Fatalf("Join relative = %q", got)
	}
	rooted := Host{Root: t.TempDir()}
	if got := rooted.Join("/f"); !strings.HasPrefix(got, rooted.Root) {
		t.Fatalf("Join must root under Root, got %q", got)
	}
}

func TestWriteManaged(t *testing.T) {
	t.Run("new file reports changed and lands atomically", func(t *testing.T) {
		h := Host{Root: t.TempDir()}
		changed, err := h.WriteManaged("/sub/dir/f.conf", []byte("v1\n"), 0o640)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Fatal("first write must report changed")
		}
		dst := h.Join("/sub/dir/f.conf")
		if got := testutil.ReadFile(t, dst); got != "v1\n" {
			t.Fatalf("content = %q", got)
		}
		st, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o640 {
			t.Fatalf("mode = %o, want 640", st.Mode().Perm())
		}
		// The tmp+rename contract: no staging file may linger.
		entries, err := os.ReadDir(filepath.Dir(dst))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".converge.tmp") {
				t.Fatalf("staging file left behind: %s", e.Name())
			}
		}
	})

	t.Run("same content reports unchanged", func(t *testing.T) {
		h := Host{Root: t.TempDir()}
		if _, err := h.WriteManaged("/f", []byte("v1"), 0o644); err != nil {
			t.Fatal(err)
		}
		changed, err := h.WriteManaged("/f", []byte("v1"), 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Fatal("identical content must report unchanged")
		}
	})

	t.Run("changed content rewrites and preserves existing mode", func(t *testing.T) {
		h := Host{Root: t.TempDir()}
		// Seed a 0600 file; WriteManaged's mode applies to creates
		// only — an update must keep the file's current perm bits.
		testutil.WriteFile(t, h.Join("/f"), "old")
		if err := os.Chmod(h.Join("/f"), 0o600); err != nil {
			t.Fatal(err)
		}
		changed, err := h.WriteManaged("/f", []byte("new"), 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Fatal("different content must report changed")
		}
		if got := testutil.ReadFile(t, h.Join("/f")); got != "new" {
			t.Fatalf("content = %q", got)
		}
		st, err := os.Stat(h.Join("/f"))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want preserved 600", st.Mode().Perm())
		}
	})

	t.Run("unwritable parent returns error", func(t *testing.T) {
		h := Host{Root: t.TempDir()}
		// A file where a parent dir is needed → MkdirAll fails.
		testutil.WriteFile(t, h.Join("/blocker"), "x")
		changed, err := h.WriteManaged("/blocker/f", []byte("v"), 0o644)
		if err == nil {
			t.Fatal("expected an error writing under a file")
		}
		if changed {
			t.Fatal("a failed write must not report changed")
		}
	})
}

func TestRemoveManaged(t *testing.T) {
	t.Run("existing file is removed", func(t *testing.T) {
		h := Host{Root: t.TempDir()}
		testutil.WriteFile(t, h.Join("/f"), "x")
		removed, err := h.RemoveManaged("/f")
		if err != nil {
			t.Fatal(err)
		}
		if !removed {
			t.Fatal("existing file must report removed")
		}
		if _, err := os.Stat(h.Join("/f")); !os.IsNotExist(err) {
			t.Fatal("file still present after RemoveManaged")
		}
	})

	t.Run("missing file is a no-op success", func(t *testing.T) {
		h := Host{Root: t.TempDir()}
		removed, err := h.RemoveManaged("/gone")
		if err != nil {
			t.Fatalf("absent must not error: %v", err)
		}
		if removed {
			t.Fatal("absent must not report removed")
		}
	})

	t.Run("directory is refused", func(t *testing.T) {
		h := Host{Root: t.TempDir()}
		if err := os.MkdirAll(h.Join("/adir"), 0o755); err != nil {
			t.Fatal(err)
		}
		removed, err := h.RemoveManaged("/adir")
		if err == nil || !strings.Contains(err.Error(), "is a dir") {
			t.Fatalf("err = %v, want 'is a dir'", err)
		}
		if removed {
			t.Fatal("a refused dir must not report removed")
		}
	})
}

func TestEnsureDir(t *testing.T) {
	h := Host{Root: t.TempDir()}
	if err := h.EnsureDir("/a/b/c", 0o750); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(h.Join("/a/b/c"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.IsDir() {
		t.Fatal("EnsureDir did not create the dir")
	}
	// Idempotent on an existing dir.
	if err := h.EnsureDir("/a/b/c", 0o750); err != nil {
		t.Fatal(err)
	}
	// A file in the way is an error.
	testutil.WriteFile(t, h.Join("/blocker"), "x")
	if err := h.EnsureDir("/blocker/sub", 0o755); err == nil {
		t.Fatal("expected an error mkdir-under-file")
	}
}

func TestFileExists(t *testing.T) {
	h := Host{Root: t.TempDir()}
	testutil.WriteFile(t, h.Join("/f"), "x")
	if !h.FileExists("/f") {
		t.Error("existing file must stat clean")
	}
	if err := os.MkdirAll(h.Join("/d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !h.FileExists("/d") {
		t.Error("existing dir must stat clean")
	}
	if h.FileExists("/gone") {
		t.Error("missing path must not exist")
	}
}

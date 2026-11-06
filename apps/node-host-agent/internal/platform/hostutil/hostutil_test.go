package hostutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// stubRename swaps the rename(2) seam for the test duration.
func stubRename(t *testing.T, fn func(oldpath, newpath string) error) {
	t.Helper()
	orig := RenameFile
	RenameFile = fn
	t.Cleanup(func() { RenameFile = orig })
}

func TestWriteFileAtomicHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state-foo")
	if err := WriteFileAtomic(path, "epoch=123\n"); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ReadFile(t, path); got != "epoch=123\n" {
		t.Fatalf("content = %q", got)
	}
	// tmp+rename contract: the .tmp-<base> staging file is gone.
	for _, n := range dirNames(t, dir) {
		if strings.HasPrefix(n, ".tmp-") {
			t.Fatalf("staging file left behind: %s", n)
		}
	}
}

func TestWriteFileAtomicFallbackOnBindMountErrno(t *testing.T) {
	// The DaemonSet bind-mounts /host/etc/hosts — rename(2) over a
	// file-level bind-mount target returns EBUSY; EXDEV (tmp and
	// target on different filesystems) shares the direct-write path.
	for _, errno := range []error{unix.EBUSY, unix.EXDEV} {
		t.Run(errno.Error(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "hosts")
			testutil.WriteFile(t, path, "old-content")

			var gotOld, gotNew string
			stubRename(t, func(oldpath, newpath string) error {
				gotOld, gotNew = oldpath, newpath
				return fmt.Errorf("stub rename: %w", errno)
			})

			if err := WriteFileAtomic(path, "new-content"); err != nil {
				t.Fatal(err)
			}
			if got := testutil.ReadFile(t, path); got != "new-content" {
				t.Fatalf("direct-write fallback landed %q", got)
			}
			// The staging name is .tmp-<base>-<rand> (CreateTemp) —
			// a private name per writer so concurrent stampers never
			// share a staging file.
			if !strings.HasPrefix(gotOld, filepath.Join(dir, ".tmp-hosts-")) ||
				gotNew != path {
				t.Fatalf("rename called with (%q,%q), want (.tmp-hosts-*,%q)",
					gotOld, gotNew, path)
			}
			if _, err := os.Stat(gotOld); !os.IsNotExist(err) {
				t.Fatal("tmp file not cleaned up after fallback")
			}
		})
	}
}

func TestWriteFileAtomicOtherRenameErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	stubRename(t, func(string, string) error { return errors.New("perm denied") })

	err := WriteFileAtomic(path, "x")
	if err == nil || !strings.Contains(err.Error(), "perm denied") {
		t.Fatalf("err = %v, want the rename error", err)
	}
	// The direct-write fallback only runs for EBUSY/EXDEV.
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatal("direct write ran for a non-fallback errno")
	}
	if _, serr := os.Stat(filepath.Join(dir, ".tmp-f")); !os.IsNotExist(serr) {
		t.Fatal("tmp file leaked after rename error")
	}
}

func TestWriteFileAtomicUnwritableDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "f")
	if err := WriteFileAtomic(path, "x"); err == nil {
		t.Fatal("expected error staging tmp file in missing dir")
	}
}

func TestWriteFileDirect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := WriteFileDirect(path, "abcdef"); err != nil {
		t.Fatal(err)
	}
	// Truncates in place — a shorter rewrite leaves no tail.
	if err := WriteFileDirect(path, "xy"); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ReadFile(t, path); got != "xy" {
		t.Fatalf("content = %q", got)
	}
	if err := WriteFileDirect(filepath.Join(dir, "gone", "f"), "x"); err == nil {
		t.Fatal("expected error writing into missing dir")
	}
	// /dev/full fails every write with ENOSPC — covers the
	// write-error branch (Linux-only, skipped elsewhere).
	if _, err := os.Stat("/dev/full"); err == nil {
		if err := WriteFileDirect("/dev/full", "x"); err == nil {
			t.Error("write to /dev/full must fail")
		}
	}
}

func TestWriteFileAtomicBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b")
	if err := WriteFileAtomicBytes(path, []byte("\x00bytes\xff")); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ReadFile(t, path); got != "\x00bytes\xff" {
		t.Fatalf("content = %q", got)
	}
}

func TestUptimeSeconds(t *testing.T) {
	dir := t.TempDir()
	for i, tc := range []struct {
		content string
		want    float64
		wantErr bool
	}{
		{"12345.67 89012.34\n", 12345.67, false},
		{"42", 42, false},
		{"", 0, true},
		{"garbage 1", 0, true},
	} {
		p := filepath.Join(dir, fmt.Sprintf("up%d", i))
		testutil.WriteFile(t, p, tc.content)
		got, err := UptimeSeconds(p)
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err=%v, wantErr=%v", tc.content, err, tc.wantErr)
		}
		if err == nil && got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.content, got, tc.want)
		}
	}
	if _, err := UptimeSeconds(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing uptime file must error")
	}
}

func TestReadTrimmed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	testutil.WriteFile(t, p, "  padded content \n\n")
	if got := ReadTrimmed(p); got != "padded content" {
		t.Fatalf("ReadTrimmed = %q", got)
	}
	if got := ReadTrimmed(filepath.Join(dir, "missing")); got != "" {
		t.Fatalf("missing file = %q, want \"\"", got)
	}
}

func TestReadUintFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "n")
	testutil.WriteFile(t, p, "1500\n")
	if got, ok := ReadUintFile(p); !ok || got != 1500 {
		t.Fatalf("ReadUintFile = %d,%v, want 1500,true", got, ok)
	}
	testutil.WriteFile(t, p, "not-a-number")
	if _, ok := ReadUintFile(p); ok {
		t.Fatal("garbage content parsed ok")
	}
	testutil.WriteFile(t, p, "-5") // unsigned parse must reject
	if _, ok := ReadUintFile(p); ok {
		t.Fatal("negative content parsed ok")
	}
	if _, ok := ReadUintFile(filepath.Join(dir, "missing")); ok {
		t.Fatal("missing file parsed ok")
	}
}

func TestJSONFindIntsCollectsAllMatches(t *testing.T) {
	raw := `{
		"mtu": 1500,
		"MTU": 9000,
		"nested": {"Mtu": 1400, "mtu": "1500"},
		"list": [{"mtu": 1280}, [{"mtu": 1450}]],
		"other": {"size": 100}
	}`
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}

	// Case-insensitive key match, maps AND arrays descended, string
	// values skipped — and EVERY match collected (no first-match
	// nondeterminism).
	var vals []int64
	JSONFindInts(v, &vals, "mtu")
	slices.Sort(vals)
	if want := []int64{1280, 1400, 1450, 1500, 9000}; !slices.Equal(vals, want) {
		t.Fatalf("vals = %v, want %v", vals, want)
	}

	// Several key names in one scan.
	vals = nil
	JSONFindInts(v, &vals, "mtu", "size")
	slices.Sort(vals)
	if want := []int64{100, 1280, 1400, 1450, 1500, 9000}; !slices.Equal(vals, want) {
		t.Fatalf("vals = %v, want %v", vals, want)
	}

	// Scalar input walks to nothing.
	vals = nil
	JSONFindInts(42.0, &vals, "mtu")
	if len(vals) != 0 {
		t.Fatalf("vals = %v, want empty", vals)
	}
}

func TestMTUOfIface(t *testing.T) {
	sysnet := t.TempDir()
	testutil.WriteFile(t, filepath.Join(sysnet, "eth0", "mtu"), "1500\n")
	if got, ok := MTUOfIface(sysnet, "eth0"); !ok || got != 1500 {
		t.Fatalf("MTUOfIface = %d,%v, want 1500,true", got, ok)
	}
	testutil.WriteFile(t, filepath.Join(sysnet, "bad0", "mtu"), "jumbo!")
	if _, ok := MTUOfIface(sysnet, "bad0"); ok {
		t.Fatal("unparseable mtu must read ok=false")
	}
	if _, ok := MTUOfIface(sysnet, "ghost0"); ok {
		t.Fatal("missing iface must read ok=false")
	}
}

func TestRuntimeConfigMTU(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent-runtime-config.json")

	// Several mtu keys at different nesting depths — the MAX wins,
	// deterministic regardless of Go map order.
	testutil.WriteFile(t, p, `{"datapath":{"mtu":1450},"mtu":9000,"list":[{"mtu":1280}]}`)
	if got, ok := RuntimeConfigMTU(p); !ok || got != 9000 {
		t.Fatalf("RuntimeConfigMTU = %d,%v, want 9000,true", got, ok)
	}

	testutil.WriteFile(t, p, `{"no":"mtu here"}`)
	if _, ok := RuntimeConfigMTU(p); ok {
		t.Fatal("config without mtu must read ok=false")
	}
	testutil.WriteFile(t, p, `not json`)
	if _, ok := RuntimeConfigMTU(p); ok {
		t.Fatal("invalid JSON must read ok=false")
	}
	if _, ok := RuntimeConfigMTU(filepath.Join(dir, "missing.json")); ok {
		t.Fatal("missing file must read ok=false")
	}
}

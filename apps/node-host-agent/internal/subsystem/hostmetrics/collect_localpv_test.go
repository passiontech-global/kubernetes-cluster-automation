// collect_localpv_test.go — Wave-9 OpenEBS LocalPV pvc-* dir bytes and the du-walk cache.

package hostmetrics

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLocalPVDirBytes: node_host_agent_localpv_dir_bytes sums the
// regular-file bytes under each pvc-* dir; non-pvc entries are
// ignored.
func TestLocalPVDirBytes(t *testing.T) {
	cfg, _ := fixture(t)
	root := t.TempDir()
	cfg.OpenEBSLocalDir = root
	// pvc-aaa: 1000 + 500 (nested) = 1500; pvc-bbb: 2000.
	for _, d := range []string{"pvc-aaa", "pvc-aaa/sub", "pvc-bbb", "provisioning"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, filepath.Join(root, "pvc-aaa", "data.bin"), strings.Repeat("x", 1000))
	testutil.WriteFile(t, filepath.Join(root, "pvc-aaa", "sub", "more.bin"), strings.Repeat("y", 500))
	testutil.WriteFile(t, filepath.Join(root, "pvc-bbb", "vol.bin"), strings.Repeat("z", 2000))
	// Not a pvc-* dir → ignored entirely.
	testutil.WriteFile(t, filepath.Join(root, "provisioning", "junk.bin"), strings.Repeat("j", 9999))

	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-aaa"})
	if !ok || got != 1500 {
		t.Fatalf("pvc-aaa bytes=%v ok=%v want 1500", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-bbb"})
	if !ok || got != 2000 {
		t.Fatalf("pvc-bbb bytes=%v ok=%v want 2000", got, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "provisioning"}); ok {
		t.Fatal("non-pvc dir emitted a series")
	}
}

// TestLocalPVDirBytesMissingRoot: an absent OpenEBS root emits no
// series at all — "no local-path volumes" stays distinguishable
// from "zero bytes".
func TestLocalPVDirBytesMissingRoot(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.OpenEBSLocalDir = filepath.Join(t.TempDir(), "no-such-dir")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-x"}); ok {
		t.Fatal("series emitted for a missing localpv root")
	}
}

// TestLocalPVDirBytesCache: the du walk is cached for
// LocalPVScanInterval — scrapes inside the window reuse the
// snapshot; past it a fresh walk runs.
func TestLocalPVDirBytesCache(t *testing.T) {
	cfg, _ := fixture(t)
	root := t.TempDir()
	cfg.OpenEBSLocalDir = root
	cfg.LocalPVScanInterval = 15 * time.Minute
	now := time.Now()
	cfg.nowFn = func() time.Time { return now }
	vol := filepath.Join(root, "pvc-cache")
	if err := os.MkdirAll(vol, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(vol, "a.bin"), strings.Repeat("x", 100))

	c := New(cfg)
	got, _ := metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-cache"})
	if got != 100 {
		t.Fatalf("initial bytes=%v want 100", got)
	}
	// Grow the volume — inside the cache window the old snapshot
	// is still served.
	testutil.WriteFile(t, filepath.Join(vol, "b.bin"), strings.Repeat("y", 400))
	got, _ = metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-cache"})
	if got != 100 {
		t.Fatalf("cached bytes=%v want 100 (stale snapshot expected)", got)
	}
	// Past the interval a fresh walk picks up the new file.
	now = now.Add(16 * time.Minute)
	got, _ = metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-cache"})
	if got != 500 {
		t.Fatalf("post-cache bytes=%v want 500", got)
	}
}

// TestLocalPVDirBytesFailedWalkKeepsSnapshot: when the root becomes
// unreadable after a good walk, the last snapshot keeps serving
// rather than blanking every series.
func TestLocalPVDirBytesFailedWalkKeepsSnapshot(t *testing.T) {
	cfg, _ := fixture(t)
	root := t.TempDir()
	cfg.OpenEBSLocalDir = root
	now := time.Now()
	cfg.nowFn = func() time.Time { return now }
	vol := filepath.Join(root, "pvc-keep")
	if err := os.MkdirAll(vol, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(vol, "a.bin"), strings.Repeat("x", 100))

	c := New(cfg)
	got, _ := metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-keep"})
	if got != 100 {
		t.Fatalf("initial bytes=%v want 100", got)
	}
	// Root vanishes + cache expires → failed walk keeps the snapshot.
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	now = now.Add(16 * time.Minute)
	got, ok := metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-keep"})
	if !ok || got != 100 {
		t.Fatalf("after failed walk bytes=%v ok=%v want 100 (kept snapshot)", got, ok)
	}
}

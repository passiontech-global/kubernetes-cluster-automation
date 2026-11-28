// collect_snapshot_test.go — the 10s Collect snapshot cache: scrape
// reuse inside the TTL, refresh past it, per-collector isolation.

package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// TestCollectSnapshotCache: within collectCacheTTL a second Gather
// replays the first snapshot byte-for-byte (the /proc storm a fast
// scrape interval would otherwise cause), a Gather past the TTL
// re-reads, and a second Collector never shares the first's cache.
func TestCollectSnapshotCache(t *testing.T) {
	cfg, _ := fixture(t)
	var nowUnix atomic.Int64
	nowUnix.Store(1760000000)
	cfg.Clock = timex.NewCell(func() time.Time { return time.Unix(nowUnix.Load(), 0) })
	cfg.collectCacheTTL = 10 * time.Second
	testutil.WriteFile(t, cfg.FileNRFile, "100\t0\t1000\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}

	if got, ok := metricValue(t, c, "node_host_agent_filefd_allocated",
		node); !ok || got != 100 {
		t.Fatalf("first gather=%v ok=%v want 100", got, ok)
	}
	// Mutate the fixture inside the TTL — the replay must serve the
	// cached 100, proving the second Gather did not re-read /proc.
	testutil.WriteFile(t, cfg.FileNRFile, "200\t0\t1000\n")
	if got, ok := metricValue(t, c, "node_host_agent_filefd_allocated",
		node); !ok || got != 100 {
		t.Fatalf("cached gather=%v ok=%v want the snapshot's 100", got, ok)
	}
	// A second Collector has its own snapshot — it reads fresh.
	c2 := New(cfg)
	if got, ok := metricValue(t, c2, "node_host_agent_filefd_allocated",
		node); !ok || got != 200 {
		t.Fatalf("second collector=%v ok=%v want fresh 200", got, ok)
	}
	// Past the TTL the first collector re-reads too.
	nowUnix.Add(11)
	if got, ok := metricValue(t, c, "node_host_agent_filefd_allocated",
		node); !ok || got != 200 {
		t.Fatalf("post-TTL gather=%v ok=%v want fresh 200", got, ok)
	}
}

// TestCollectSnapshotCacheDisabled: collectCacheTTL < 0 turns the
// cache off entirely — every Gather re-reads (the fixture's pinned
// mode; asserted here so a future refactor cannot silently re-enable
// it for the whole suite).
func TestCollectSnapshotCacheDisabled(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.FileNRFile, "100\t0\t1000\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if got, ok := metricValue(t, c, "node_host_agent_filefd_allocated",
		node); !ok || got != 100 {
		t.Fatalf("first gather=%v ok=%v want 100", got, ok)
	}
	testutil.WriteFile(t, cfg.FileNRFile, "200\t0\t1000\n")
	if got, ok := metricValue(t, c, "node_host_agent_filefd_allocated",
		node); !ok || got != 200 {
		t.Fatalf("disabled-cache gather=%v ok=%v want fresh 200", got, ok)
	}
}

// TestCollectOffloadsLocalPVAndFSProbes verifies that scrape-time Collect
// (collectCacheTTL > 0) serves background-cached LocalPV and FS probe
// snapshots without blocking on hung statfs syscalls while holding snapMu,
// while WriteTextfile retains fresh synchronous probe semantics.
func TestCollectOffloadsLocalPVAndFSProbes(t *testing.T) {
	cfg, _ := fixture(t)
	now := time.Unix(1760000000, 0)
	cfg.Clock = timex.NewCell(func() time.Time { return now })
	cfg.collectCacheTTL = 10 * time.Second
	cfg.fsProbeTimeout = 500 * time.Millisecond
	cfg.FilesystemTargets = []string{"/mnt/hung"}
	cfg.FSBytesTargets = []string{"/mnt/hung"}

	pvDir := t.TempDir()
	cfg.OpenEBSLocalDir = pvDir
	testutil.WriteFile(t, filepath.Join(pvDir, "pvc-111", "data.bin"), strings.Repeat("x", 123))

	var statfsCalls atomic.Int32
	cfg.statfsFn = func(_ string, st *unix.Statfs_t) error {
		statfsCalls.Add(1)
		st.Files, st.Ffree = 100, 25
		return nil
	}

	c := New(cfg)
	// Latches background tick populates the fs and localpv caches.
	c.Latches().refreshLatches(context.Background())
	if got := statfsCalls.Load(); got != 1 {
		t.Fatalf("refreshLatches statfs calls=%d want 1", got)
	}

	// Now swap statfsFn to hang for 500ms per call; Collect within LatchInterval
	// must return immediately from the background cache without blocking on statfs.
	release := make(chan struct{})
	defer close(release)
	cfg.statfsFn = func(_ string, _ *unix.Statfs_t) error {
		statfsCalls.Add(1)
		<-release
		return nil
	}
	c.cfg.statfsFn = cfg.statfsFn

	start := time.Now()
	if v, ok := metricValue(t, c, "node_host_agent_filesystem_inodes_total",
		map[string]string{"node": "node-a", "mount": "/mnt/hung"}); !ok || v != 100 {
		t.Fatalf("cached inodes_total=%v ok=%v want 100", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_localpv_dir_bytes",
		map[string]string{"node": "node-a", "pvc_volume": "pvc-111"}); !ok || v != 123 {
		t.Fatalf("cached localpv_dir_bytes=%v ok=%v want 123", v, ok)
	}
	if elapsed := time.Since(start); elapsed >= 250*time.Millisecond {
		t.Fatalf("Collect blocked %v, want non-blocking cache hit", elapsed)
	}
	if got := statfsCalls.Load(); got != 1 {
		t.Fatalf("Collect re-invoked statfs (%d calls), want cached 1", got)
	}

	// WriteTextfile preserves fresh synchronous semantics.
	c.cfg.statfsFn = func(_ string, st *unix.Statfs_t) error {
		statfsCalls.Add(1)
		st.Files, st.Ffree = 200, 50
		return nil
	}
	outDir := t.TempDir()
	if err := c.WriteTextfile(outDir); err != nil {
		t.Fatalf("WriteTextfile: %v", err)
	}
	if got := statfsCalls.Load(); got != 2 {
		t.Fatalf("WriteTextfile statfs calls=%d want 2 (fresh probe)", got)
	}
	prom, err := os.ReadFile(filepath.Join(outDir, TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prom), `node_host_agent_filesystem_inodes_total{mount="/mnt/hung",node="node-a"} 200`) {
		t.Fatalf("WriteTextfile did not render fresh inodes:\n%s", string(prom))
	}
}

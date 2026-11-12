// collect_snapshot_test.go — the 10s Collect snapshot cache: scrape
// reuse inside the TTL, refresh past it, per-collector isolation.

package hostmetrics

import (
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// TestCollectSnapshotCache: within collectCacheTTL a second Gather
// replays the first snapshot byte-for-byte (the /proc storm a fast
// scrape interval would otherwise cause), a Gather past the TTL
// re-reads, and a second Collector never shares the first's cache.
func TestCollectSnapshotCache(t *testing.T) {
	cfg, _ := fixture(t)
	now := time.Unix(1760000000, 0)
	cfg.Clock = timex.NewCell(func() time.Time { return now })
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
	now = now.Add(11 * time.Second)
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

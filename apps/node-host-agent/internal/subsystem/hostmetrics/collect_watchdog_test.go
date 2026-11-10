// collect_watchdog_test.go — watchdog state-latch series, the emit-0/seenStates contract, and the legacy node_watchdog_state alias.

package hostmetrics

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

func TestWatchdogStates(t *testing.T) {
	cfg, dirs := fixture(t)
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-kubelet-runtime-stall"), "1730000000\n")
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-node-overloaded"), "1730000001\n")
	testutil.WriteFile(t, filepath.Join(dirs["state"], "consecutive-x"), "3\n") // not a latch
	c := New(cfg)

	for _, st := range []string{"kubelet-runtime-stall", "node-overloaded"} {
		v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
			map[string]string{"node": "node-a", "state": st})
		if !ok || v != 1 {
			t.Fatalf("watchdog_state{%s}=%v ok=%v want 1", st, v, ok)
		}
	}
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "consecutive-x"}); ok {
		t.Fatal("non-latch file emitted a series")
	}
}

func TestWatchdogStateClearsToZero(t *testing.T) {
	cfg, dirs := fixture(t)
	latch := filepath.Join(dirs["state"], "state-dns-fallback")
	testutil.WriteFile(t, latch, "1730000000\n")
	c := New(cfg)
	_, _ = metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "dns-fallback"})

	if err := os.Remove(latch); err != nil {
		t.Fatal(err)
	}
	v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "dns-fallback"})
	if !ok || v != 0 {
		t.Fatalf("cleared state=%v ok=%v want emitted 0 (emit-0 semantics)", v, ok)
	}
}

// TestSeenStatesTTLExpiry: a cleared latch emits 0 while inside
// seenStateTTL, then the bookkeeping entry is dropped and the series
// disappears — the emit-0 window cannot grow seenStates forever.
func TestSeenStatesTTLExpiry(t *testing.T) {
	cfg, dirs := fixture(t)
	now := time.Now()
	cfg.Clock = timex.NewCell(func() time.Time { return now })
	latch := filepath.Join(dirs["state"], "state-tmp-latch")
	testutil.WriteFile(t, latch, "1730000000\n")
	c := New(cfg)
	labels := map[string]string{"node": "node-a", "state": "tmp-latch"}

	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); !ok || v != 1 {
		t.Fatalf("latched state=%v ok=%v want 1", v, ok)
	}
	if err := os.Remove(latch); err != nil {
		t.Fatal(err)
	}
	// First cleared scrape stamps the entry — still emits 0.
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); !ok || v != 0 {
		t.Fatalf("cleared state=%v ok=%v want emitted 0", v, ok)
	}
	// Inside the TTL the emit-0 contract still holds.
	now = now.Add(seenStateTTL - time.Minute)
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); !ok {
		t.Fatal("series dropped before seenStateTTL elapsed")
	}
	// Past the TTL the entry is evicted and the series disappears.
	now = now.Add(2 * time.Minute)
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); ok {
		t.Fatal("series kept after seenStateTTL elapsed")
	}
	if _, ok := c.seen.m["tmp-latch"]; ok {
		t.Fatal("expired cleared state kept in seenStates")
	}
}

// TestSeenStatesCapEvictsOldestCleared: beyond maxSeenStates the
// longest-cleared entries are evicted first; an active latch is
// never evicted.
func TestSeenStatesCapEvictsOldestCleared(t *testing.T) {
	cfg, dirs := fixture(t)
	now := time.Now()
	cfg.Clock = timex.NewCell(func() time.Time { return now })
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-real"), "1730000000\n")
	c := New(cfg)
	// Pre-seed over-cap cleared entries, oldest first.
	for i := 0; i < maxSeenStates+10; i++ {
		c.seen.m[fmt.Sprintf("old-%03d", i)] = now.Add(-time.Duration(i+1) * time.Second)
	}
	labels := map[string]string{"node": "node-a", "state": "real"}
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", labels); !ok || v != 1 {
		t.Fatalf("latched state=%v ok=%v want 1", v, ok)
	}
	if got := len(c.seen.m); got > maxSeenStates {
		t.Fatalf("seenStates = %d, want <= %d", got, maxSeenStates)
	}
	if ts, ok := c.seen.m["real"]; !ok || !ts.IsZero() {
		t.Fatal("active latch missing or got a cleared timestamp")
	}
	// The oldest-cleared entries must have been evicted.
	if _, ok := c.seen.m[fmt.Sprintf("old-%03d", maxSeenStates+9)]; ok {
		t.Fatal("oldest cleared entry was not evicted")
	}
	if _, ok := c.seen.m["old-000"]; !ok {
		t.Fatal("freshest cleared entry was evicted")
	}
}

func TestWatchdogTmpStateFileIgnored(t *testing.T) {
	cfg, dirs := fixture(t)
	// The atomic-write tmp name ".tmp-state-x" (apiprober's
	// writeFileAtomic, workerhygiene's stateEnter) must NOT register
	// a watchdog_state series — the old "state-x.tmp" shape would
	// have cut to a phantom "x.tmp" latch that then sits at 0 forever.
	testutil.WriteFile(t, filepath.Join(dirs["state"], ".tmp-state-atomic"), "1730000000\n")
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-real"), "1730000000\n")
	c := New(cfg)

	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "real"}); !ok || v != 1 {
		t.Fatalf("watchdog_state{real}=%v ok=%v want 1", v, ok)
	}
	for _, st := range []string{"atomic", ".tmp-state-atomic", "state-atomic"} {
		if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
			map[string]string{"node": "node-a", "state": st}); ok {
			t.Fatalf("tmp file emitted watchdog_state{state=%s}", st)
		}
	}
}

func TestWatchdogSkipsNonRegularAndEmptyNames(t *testing.T) {
	cfg, dirs := fixture(t)
	// A directory named state-* is not a latch file — skipped by the
	// IsRegular guard.
	if err := os.MkdirAll(filepath.Join(dirs["state"], "state-dir-latch"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A file named exactly "state-" has an empty latch name — skipped.
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-"), "1730000000\n")
	// A real latch alongside — still collected.
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-real"), "1730000000\n")
	c := New(cfg)

	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "real"}); !ok || v != 1 {
		t.Fatalf("watchdog_state{real}=%v ok=%v want 1", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "dir-latch"}); ok {
		t.Fatal("directory named state-* emitted a series")
	}
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": ""}); ok {
		t.Fatal("file named 'state-' emitted a series")
	}
}

func TestWatchdogStateDirAbsentStillEmitsSeen(t *testing.T) {
	// If the state dir disappears (node-watchdog removed), a
	// previously-seen latch keeps exporting 0 — ReadDir error is
	// tolerated, not fatal.
	cfg, dirs := fixture(t)
	latch := filepath.Join(dirs["state"], "state-net-fail")
	testutil.WriteFile(t, latch, "1730000000\n")
	c := New(cfg)
	_, _ = metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "net-fail"})

	if err := os.RemoveAll(dirs["state"]); err != nil {
		t.Fatal(err)
	}
	v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "net-fail"})
	if !ok || v != 0 {
		t.Fatalf("watchdog_state after dir removal=%v ok=%v want 0", v, ok)
	}
}

// --- legacy prom_emit aliases (node_watchdog_state /
// node_watchdog_egress_relay — the fluxcd PrometheusRules contract) ---

func TestWatchdogLegacyAlias(t *testing.T) {
	cfg, dirs := fixture(t)
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-fail2ban-down"), "1730000000\n")
	c := New(cfg)

	// Alias mirrors the latch with signal=state (no node label).
	if v, ok := metricValue(t, c, "node_watchdog_state",
		map[string]string{"signal": "fail2ban-down"}); !ok || v != 1 {
		t.Fatalf("node_watchdog_state{fail2ban-down}=%v ok=%v want 1", v, ok)
	}
	// Same latch, both series live alongside each other.
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "fail2ban-down"}); !ok || v != 1 {
		t.Fatalf("node_host_agent_watchdog_state=%v ok=%v want 1", v, ok)
	}

	// Cleared latch → the alias keeps emitting an explicit 0, same
	// emit-0 contract as the primary series.
	if err := os.Remove(filepath.Join(dirs["state"], "state-fail2ban-down")); err != nil {
		t.Fatal(err)
	}
	if v, ok := metricValue(t, c, "node_watchdog_state",
		map[string]string{"signal": "fail2ban-down"}); !ok || v != 0 {
		t.Fatalf("node_watchdog_state{fail2ban-down}=%v ok=%v want 0 after clear", v, ok)
	}
}

// TestWatchdogUnreadableDirServesPrevious: a ReadDir failure that is
// NOT NotExist (the dir path placed under a regular file → ENOTDIR)
// must neither stamp latches cleared nor emit false 0s — the previous
// values are served unchanged and the bookkeeping is untouched (no
// manufactured TTL eviction).
func TestWatchdogUnreadableDirServesPrevious(t *testing.T) {
	cfg, dirs := fixture(t)
	now := time.Now()
	cfg.Clock = timex.NewCell(func() time.Time { return now })
	blocker := filepath.Join(filepath.Dir(dirs["state"]), "not-a-dir")
	testutil.WriteFile(t, blocker, "x\n")

	live := filepath.Join(dirs["state"], "state-live")
	testutil.WriteFile(t, live, "1730000000\n")
	c := New(cfg)
	liveLabels := map[string]string{"node": "node-a", "state": "live"}
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", liveLabels); !ok || v != 1 {
		t.Fatalf("live latch=%v ok=%v want 1", v, ok)
	}
	// Clear it: the book stamps the first cleared scrape.
	if err := os.Remove(live); err != nil {
		t.Fatal(err)
	}
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", liveLabels); !ok || v != 0 {
		t.Fatalf("cleared latch=%v ok=%v want 0", v, ok)
	}
	// A fresh live latch alongside the cleared one.
	testutil.WriteFile(t, filepath.Join(dirs["state"], "state-fresh"), "1730000001\n")
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "fresh"}); !ok || v != 1 {
		t.Fatalf("fresh latch=%v ok=%v want 1", v, ok)
	}
	before := make(map[string]time.Time, len(c.seen.m))
	for k, ts := range c.seen.m {
		before[k] = ts
	}

	// ENOTDIR scrape: `fresh` keeps its 1, the cleared `live` keeps
	// its emit-0, and no bookkeeping entry is touched.
	c.cfg.WatchdogStateDir = filepath.Join(blocker, "state")
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state", liveLabels); !ok || v != 0 {
		t.Fatalf("unreadable dir: cleared latch=%v ok=%v want previous 0", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "fresh"}); !ok || v != 1 {
		t.Fatalf("unreadable dir: fresh latch=%v ok=%v want previous 1", v, ok)
	}
	if v, ok := metricValue(t, c, "node_watchdog_state",
		map[string]string{"signal": "fresh"}); !ok || v != 1 {
		t.Fatalf("unreadable dir: legacy alias=%v ok=%v want previous 1", v, ok)
	}
	if len(c.seen.m) != len(before) {
		t.Fatalf("seen book grew/shrank during the unreadable scrape: %d → %d",
			len(before), len(c.seen.m))
	}
	for k, ts := range before {
		if got, ok := c.seen.m[k]; !ok || !got.Equal(ts) {
			t.Fatalf("seen[%q] mutated by the unreadable scrape: %v → %v,%v",
				k, ts, got, ok)
		}
	}
}

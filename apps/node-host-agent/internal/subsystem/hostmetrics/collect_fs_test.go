// collect_fs_test.go — H3 filesystem inode gauges and the H7 hung-mount statfs probe.

package hostmetrics

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// --- H3 + H7: filesystem inode stats + hung-mount probe ---

func TestFilesystemInodeMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/data", "/mnt/logs"}
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		if path == "/mnt/data" {
			st.Files = 1000
			st.Ffree = 250
			return nil
		}
		return unix.ENOENT
	}
	c := New(cfg)

	data := map[string]string{"node": "node-a", "mount": "/mnt/data"}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", data); !ok || v != 1000 {
		t.Fatalf("inodes_total=%v ok=%v want 1000", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_free", data); !ok || v != 250 {
		t.Fatalf("inodes_free=%v ok=%v want 250", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_used_ratio",
		data); !ok || v != 0.75 {
		t.Fatalf("inodes_used_ratio=%v ok=%v want 0.75", v, ok)
	}
	// probe_stalled emits for EVERY configured target — 0 means the
	// probe answered in time.
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		data); !ok || v != 0 {
		t.Fatalf("probe_stalled=%v ok=%v want 0", v, ok)
	}

	// An erroring-but-fast probe still reports stalled=0, while the
	// inode gauges stay absent (no fake numbers).
	logs := map[string]string{"node": "node-a", "mount": "/mnt/logs"}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		logs); !ok || v != 0 {
		t.Fatalf("probe_stalled{/mnt/logs}=%v ok=%v want 0", v, ok)
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", logs); ok {
		t.Fatal("inodes emitted for a failed statfs")
	}
}

func TestFilesystemZeroInodesSkipsRatio(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/empty"}
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		st.Files, st.Ffree = 0, 0
		return nil
	}
	c := New(cfg)
	mnt := map[string]string{"node": "node-a", "mount": "/mnt/empty"}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", mnt); !ok || v != 0 {
		t.Fatalf("inodes_total=%v ok=%v want 0", v, ok)
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_used_ratio", mnt); ok {
		t.Fatal("inodes_used_ratio emitted with Files=0 (div-by-zero)")
	}
}

// TestInodePressureFilesZeroClearsLatch: a latch entered while a
// parsed mount was over the enter threshold must EXIT once the only
// remaining unparseable-looking mount is a Files==0 filesystem
// (btrfs dynamic inodes, pseudo-fs). Before the fix such a mount was
// inconclusive evidence on EVERY pass — parsed never reached probed,
// inodePressureClear stayed false and the heartbeat kept refreshing
// a stale condition True forever (hang-pre-cordon/storm-gate stayed
// gated despite healthy disks). Files==0 counts as parsed healthy
// (ratio 0); the exit asserts the STATE-EXIT transition line.
func TestInodePressureFilesZeroClearsLatch(t *testing.T) {
	cfg, _ := fixture(t)
	logFile := filepath.Join(t.TempDir(), "watchdog.log")
	cfg.FilesystemTargets = []string{"/mnt/btrfs", "/mnt/data"}
	cfg.WatchdogLogFile = logFile
	c := New(cfg)
	l := c.Latches()

	// 96% on /mnt/data → latch enters.
	c.cfg.statfsFn = inodeStatfs(map[string][2]uint64{
		"/mnt/data": {960, 1000}, "/mnt/btrfs": {0, 0},
	})
	l.refreshLatches()
	if !latchExists(t, cfg) {
		t.Fatal("inode-pressure latch not set at 0.96")
	}

	// Recovery: /mnt/data healthy, /mnt/btrfs still answers statfs
	// with no inode table — the pass must count as fully parsed and
	// clear the latch.
	c.cfg.statfsFn = inodeStatfs(map[string][2]uint64{
		"/mnt/data": {500, 1000}, "/mnt/btrfs": {0, 0},
	})
	l.refreshLatches()
	if latchExists(t, cfg) {
		t.Fatal("inode-pressure latch held despite a Files==0 healthy pass")
	}
	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "STATE-EXIT: inode-pressure") {
		t.Fatalf("STATE-EXIT line missing:\n%s", b)
	}

	// No ratio was computed for the Files==0 mount — the worst-mount
	// detail must never divide by zero or go negative; a follow-up
	// healthy pass (already exited) stays a no-op.
	c.cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		st.Files, st.Ffree = 0, 0
		return nil
	}
	l.refreshLatches()
	if latchExists(t, cfg) {
		t.Fatal("inode-pressure latch set from an all-Files==0 pass")
	}
}

func TestFilesystemProbeStalledOnHang(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/hung"}
	// run-tmpfs fs-bytes shares the probe machinery — same mount keeps
	// the one-in-flight-probe-per-mount contract under test.
	cfg.FSBytesTargets = cfg.FilesystemTargets
	release := make(chan struct{})
	defer close(release) // lets the stuck probe goroutine exit
	var calls atomic.Int32
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		calls.Add(1)
		<-release // simulates a mount hung in uninterruptible sleep
		return nil
	}
	c := New(cfg)
	mnt := map[string]string{"node": "node-a", "mount": "/mnt/hung"}

	// The probe exceeds fsProbeTimeout → stalled=1, and no inode
	// series for a mount that never answered.
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		mnt); !ok || v != 1 {
		t.Fatalf("probe_stalled=%v ok=%v want 1 on hung mount", v, ok)
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", mnt); ok {
		t.Fatal("inodes emitted for a hung mount")
	}

	// While the first probe is still stuck in the kernel, the next
	// scrape reports stalled WITHOUT spawning another statfs — at
	// most one goroutine piles up per mount.
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		mnt); !ok || v != 1 {
		t.Fatalf("probe_stalled=%v ok=%v want 1 while still hung", v, ok)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("statfs called %d times want 1 (in-flight probe not re-spawned)", got)
	}
}

func TestFilesystemProbeRecoversAfterHang(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/flaky"}
	release := make(chan struct{})
	var calls atomic.Int32
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		if calls.Add(1) == 1 {
			<-release // first probe hangs past the deadline
			return unix.EIO
		}
		st.Files, st.Ffree = 100, 50
		return nil
	}
	c := New(cfg)
	mnt := map[string]string{"node": "node-a", "mount": "/mnt/flaky"}

	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_probe_stalled",
		mnt); !ok || v != 1 {
		t.Fatalf("probe_stalled=%v ok=%v want 1 while hung", v, ok)
	}

	// Once the stuck syscall returns, the in-flight bookkeeping
	// clears and the next scrape probes fresh → back to 0 with the
	// inode gauges populated.
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		v, ok := metricValue(t, c,
			"node_host_agent_filesystem_probe_stalled", mnt)
		if ok && v == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("probe_stalled never recovered to 0 after unhang")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_filesystem_inodes_total", mnt); !ok || v != 100 {
		t.Fatalf("inodes_total=%v ok=%v want 100 after recovery", v, ok)
	}
}

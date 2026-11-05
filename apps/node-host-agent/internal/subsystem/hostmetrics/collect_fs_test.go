// collect_fs_test.go — H3 filesystem inode gauges and the H7 hung-mount statfs probe.

package hostmetrics

import (
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

func TestFilesystemProbeStalledOnHang(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FilesystemTargets = []string{"/mnt/hung"}
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

// collect_inotify_test.go — A1 inotify instance/watch ratios (proc fd sweep).

package hostmetrics

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// mkFdLink creates a fake /proc/<pid>/fd/<fd> symlink with the
// given target — the fd symlink carries the fd TYPE, which is how
// sweepInotify counts inotify instances (anon_inode:inotify).
func mkFdLink(t *testing.T, proc string, pid, fd int, target string) {
	t.Helper()
	d := filepath.Join(proc, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(d, strconv.Itoa(fd))); err != nil {
		t.Fatal(err)
	}
}

// mkFdinfo writes a fake /proc/<pid>/fdinfo/<fd> with n inotify wd
// lines AND the matching fd symlink pointing at
// anon_inode:inotify — a real inotify fd carries both; the
// instance count comes from the symlink, the watch count from
// fdinfo.
func mkFdinfo(t *testing.T, proc string, pid, fd, n int) {
	t.Helper()
	mkFdLink(t, proc, pid, fd, "anon_inode:inotify")
	d := filepath.Join(proc, strconv.Itoa(pid), "fdinfo")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("pos:\t0\nflags:\t02004000\n")
	for i := 0; i < n; i++ {
		b.WriteString(fmt.Sprintf("inotify wd:%d ino:1 sdev:8 mask:1 ignored_mask:0 fhandle-bytes:8 fhandle-type:1 f_handle:xx\n", i))
	}
	if err := os.WriteFile(filepath.Join(d, strconv.Itoa(fd)),
		[]byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInotifyRatios(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.InotifyMaxInstancesFile, "10\n")
	testutil.WriteFile(t, cfg.InotifyMaxWatchesFile, "100\n")
	mkFdinfo(t, cfg.ProcRoot, 111, 3, 5)  // 1 fd, 5 watches
	mkFdinfo(t, cfg.ProcRoot, 111, 4, 5)  // another fd → 2 inst
	mkFdinfo(t, cfg.ProcRoot, 222, 6, 10) // other pid → 3rd inst
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.3 {
		t.Fatalf("instances ratio=%v ok=%v want 0.3", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_inotify_watches_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.2 {
		t.Fatalf("watches ratio=%v ok=%v want 0.2", got, ok)
	}
}

func TestInotifyCacheServesWithinInterval(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.InotifyMaxInstancesFile, "10\n")
	mkFdinfo(t, cfg.ProcRoot, 111, 3, 1)
	c := New(cfg)
	if got, _ := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"}); got != 0.1 {
		t.Fatalf("first scrape=%v want 0.1", got)
	}
	// More fds appear — the cached sweep must still answer 0.1.
	mkFdinfo(t, cfg.ProcRoot, 111, 9, 1)
	if got, _ := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"}); got != 0.1 {
		t.Fatalf("cached scrape=%v want 0.1", got)
	}
}

// TestInotifyZeroWatchInstanceCounts covers the leak the metric
// exists for: an inotify_init() fd holding ZERO watches emits no
// identifying line in fdinfo — the instance must still count (the
// fd symlink carries the type), else a zero-watch leak reads ~0
// while the host hits max_user_instances.
func TestInotifyZeroWatchInstanceCounts(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.InotifyMaxInstancesFile, "10\n")
	testutil.WriteFile(t, cfg.InotifyMaxWatchesFile, "100\n")
	// fd 3: leaked inotify group — symlink present, NO fdinfo at
	// all (not even a header): instance, 0 watches.
	mkFdLink(t, cfg.ProcRoot, 111, 3, "anon_inode:inotify")
	// fd 4: a socket fd — must not count as an instance.
	mkFdLink(t, cfg.ProcRoot, 111, 4, "socket:[12345]")
	// fd 5: another inotify group, fdinfo present but zero wd
	// lines — also a zero-watch instance.
	mkFdinfo(t, cfg.ProcRoot, 111, 5, 0)
	// fd 6: normal inotify group with 2 watches.
	mkFdinfo(t, cfg.ProcRoot, 111, 6, 2)
	c := New(cfg)
	got, ok := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.3 {
		t.Fatalf("instances ratio=%v ok=%v want 0.3 (3 inotify fds incl. 2 zero-watch)", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_inotify_watches_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.02 {
		t.Fatalf("watches ratio=%v ok=%v want 0.02 (2 watches)", got, ok)
	}
}

// TestInotifyTopWarnOnce: crossing the warn ratio edge-logs the top
// holders once per episode — the second over-threshold scrape is a
// no-op, and an under-threshold scrape re-arms the edge.
func TestInotifyTopWarnOnce(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.InotifyMaxInstancesFile, "10\n")
	testutil.WriteFile(t, cfg.InotifyMaxWatchesFile, "100\n")
	// 8 inotify fds of 10 → 0.8, exactly the warn ratio; a comm file
	// names the holder in the report.
	for fd := 3; fd <= 10; fd++ {
		mkFdinfo(t, cfg.ProcRoot, 111, fd, fd) // fd n carries n watches
	}
	testutil.WriteFile(t, filepath.Join(cfg.ProcRoot, "111", "comm"),
		"cilium-agent\n")
	c := New(cfg)

	got, ok := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"})
	if !ok || got != 0.8 {
		t.Fatalf("instances ratio=%v ok=%v want 0.8", got, ok)
	}
	// The first over-threshold scrape consumed the edge.
	if was := c.ino.noteWarned("instances", true); !was {
		t.Fatal("over-threshold warn flag was not set by the scrape")
	}
	// A second scrape inside the cache interval is served from the
	// sweep cache — the edge flag stays set.
	if got, _ := metricValue(t, c, "node_host_agent_inotify_instances_used_ratio",
		map[string]string{"node": "node-a"}); got != 0.8 {
		t.Fatalf("cached scrape=%v want 0.8", got)
	}
	if was := c.ino.noteWarned("instances", false); !was {
		t.Fatal("under-threshold scrape lost the episode flag")
	}
	// And it re-arms: the next over-threshold scrape warns again.
	if was := c.ino.noteWarned("instances", true); was {
		t.Fatal("edge flag did not re-arm after an under-threshold scrape")
	}
}

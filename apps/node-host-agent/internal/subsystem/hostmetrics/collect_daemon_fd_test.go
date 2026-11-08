// collect_daemon_fd_test.go — daemon-fd per-daemon fd ratio +
// containerd meta.db size.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// procFdFixture seeds one fake process under cfg.ProcRoot.
func procFdFixture(t *testing.T, cfg Config, pid, comm, cmdline string,
	fds int, limits string) {
	t.Helper()
	dir := filepath.Join(cfg.ProcRoot, pid)
	fdDir := filepath.Join(dir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "comm"), comm+"\n")
	if cmdline != "" {
		testutil.WriteFile(t, filepath.Join(dir, "cmdline"), cmdline)
	}
	for i := 0; i < fds; i++ {
		testutil.WriteFile(t, filepath.Join(fdDir, strconv.Itoa(i)), "")
	}
	if limits != "" {
		testutil.WriteFile(t, filepath.Join(dir, "limits"), limits)
	}
}

const fakeLimits = "Limit                     Soft Limit           Hard Limit           Units\n" +
	"Max open files            %s                 1048576              files\n" +
	"Max processes             128                  128                  processes\n"

func TestCollectDaemonFDRatio(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	// containerd: 10 fds of 100 → 0.1; kubelet: 90 of 100 → 0.9.
	procFdFixture(t, cfg, "100", "containerd", "", 10,
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max open files            100                  1048576              files\n")
	procFdFixture(t, cfg, "200", "kubelet", "", 90,
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max open files            100                  1048576              files\n")
	// k0s procs share comm "k0s" — argv[1] decides the label.
	procFdFixture(t, cfg, "300", "k0s",
		"/usr/local/bin/k0s\x00controller\x00--config=/etc/k0s/k0s.yaml\x00", 5,
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max open files            50                   1048576              files\n")
	procFdFixture(t, cfg, "301", "k0s",
		"/usr/local/bin/k0s\x00worker\x00", 4,
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max open files            40                   1048576              files\n")
	// A no-limit postgres proc is skipped; a second postgres proc
	// with a lower ratio must not beat the worst one.
	procFdFixture(t, cfg, "400", "postgres", "", 2, "")
	procFdFixture(t, cfg, "401", "postgres", "", 1,
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max open files            100                  1048576              files\n")
	// Unrelated procs never emit.
	procFdFixture(t, cfg, "500", "bash", "", 3,
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max open files            100                  1048576              files\n")

	for name, want := range map[string]float64{
		"containerd":    0.1,
		"kubelet":       0.9,
		"k0scontroller": 0.1,
		"k0sworker":     0.1,
		"postgres":      0.01,
	} {
		got, ok := metricValue(t, c,
			"node_host_agent_daemon_fd_used_ratio",
			map[string]string{"node": "node-a", "daemon": name})
		if !ok || got != want {
			t.Fatalf("daemon_fd_used_ratio{%s}=%v ok=%v want %v", name, got, ok, want)
		}
	}
	if _, ok := metricValue(t, c, "node_host_agent_daemon_fd_used_ratio",
		map[string]string{"node": "node-a", "daemon": "bash"}); ok {
		t.Fatal("unwatched daemon emitted a series")
	}
}

func TestCollectDaemonFDNoProcRoot(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.ProcRoot = filepath.Join(t.TempDir(), "nope")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_daemon_fd_used_ratio",
		map[string]string{"node": "node-a", "daemon": "kubelet"}); ok {
		t.Fatal("series emitted with unreadable proc root")
	}
}

// TestProcScanSharedAcrossCollectors: daemon-fd and the zombie/D-state
// counters read ONE cached /proc walk — a pid added after the snapshot
// shows in neither collector until the scan interval expires.
func TestProcScanSharedAcrossCollectors(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	procFdFixture(t, cfg, "100", "containerd", "", 10,
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max open files            100                  1048576              files\n")

	if _, ok := metricValue(t, c, "node_host_agent_daemon_fd_used_ratio",
		map[string]string{"node": "node-a", "daemon": "containerd"}); !ok {
		t.Fatal("daemon-fd series missing on the first snapshot")
	}

	// New pids after the snapshot: a zombie and a second containerd.
	// Both collectors must still see ONLY the snapshot's world.
	writeStat(t, cfg, "200", "Z")
	procFdFixture(t, cfg, "201", "containerd", "", 99,
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max open files            100                  1048576              files\n")

	got, ok := metricValue(t, c, "node_host_agent_processes_zombie_count",
		map[string]string{"node": "node-a"})
	if !ok || got != 0 {
		t.Fatalf("zombies=%v ok=%v — stale snapshot must hide pid 200", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_daemon_fd_used_ratio",
		map[string]string{"node": "node-a", "daemon": "containerd"})
	if !ok || got != 0.1 {
		t.Fatalf("containerd ratio=%v ok=%v — stale snapshot must keep 10/100", got, ok)
	}

	// Expire the cache stamp — the next snapshot picks both up.
	c.proc.at = c.cfg.Clock.Now().Add(-2 * defaultProcScanInterval)
	got, ok = metricValue(t, c, "node_host_agent_processes_zombie_count",
		map[string]string{"node": "node-a"})
	if !ok || got != 1 {
		t.Fatalf("zombies after expiry=%v ok=%v want 1", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_daemon_fd_used_ratio",
		map[string]string{"node": "node-a", "daemon": "containerd"})
	if !ok || got != 0.99 {
		t.Fatalf("containerd ratio after expiry=%v ok=%v want 0.99 (worst pid)", got, ok)
	}
}

// writeStat seeds a /proc/<pid>/stat whose state char (the FIRST
// field after the last ')') is state — the zombie/D-state source.
func writeStat(t *testing.T, cfg Config, pid, state string) {
	t.Helper()
	dir := filepath.Join(cfg.ProcRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "stat"),
		"1 (setup) "+state+" 0 0 0 0 -1 0 0 0 0 0 0 0 0 0\n")
}

func TestMatchDaemonK0sSplit(t *testing.T) {
	if got := matchDaemon("k0s", "/usr/bin/k0s\x00worker\x00"); got != "k0sworker" {
		t.Fatalf("k0s worker matched %q", got)
	}
	if got := matchDaemon("k0s", "/usr/bin/k0s\x00controller\x00"); got != "k0scontroller" {
		t.Fatalf("k0s controller matched %q", got)
	}
	// A bare "k0s" comm with no mode token matches nothing.
	if got := matchDaemon("k0s", "/usr/bin/k0s\x00"); got != "" {
		t.Fatalf("modeless k0s matched %q", got)
	}
	if got := matchDaemon("nebula", ""); got != "nebula" {
		t.Fatalf("nebula matched %q", got)
	}
	if got := matchDaemon("sshd", ""); got != "" {
		t.Fatalf("sshd matched %q", got)
	}
}

func TestProcLimitsSoftFD(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "limits")
	testutil.WriteFile(t, p, "Max open files            1024                 1048576              files\n")
	if v, ok := procLimitsSoftFD(p); !ok || v != 1024 {
		t.Fatalf("soft=%v ok=%v want 1024", v, ok)
	}
	testutil.WriteFile(t, p, "Max open files            unlimited            unlimited            files\n")
	if _, ok := procLimitsSoftFD(p); ok {
		t.Fatal("unlimited parsed as a bound")
	}
}

func TestCollectContainerdMetaDB(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	db := c.cfg.ContainerdMetaDBFile // applyDefaults joined HostRoot
	if err := os.MkdirAll(filepath.Dir(db), 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, db, strings.Repeat("x", 12345))
	got, ok := metricValue(t, c,
		"node_host_agent_containerd_metadb_bytes",
		map[string]string{"node": "node-a"})
	if !ok || got != 12345 {
		t.Fatalf("metadb bytes=%v ok=%v want 12345", got, ok)
	}
	// Absent file → no series.
	cfg2, _ := fixture(t)
	c2 := New(cfg2)
	if _, ok := metricValue(t, c2,
		"node_host_agent_containerd_metadb_bytes",
		map[string]string{"node": "node-a"}); ok {
		t.Fatal("metadb emitted with no file")
	}
}

// collect_fsbytes_test.go — W13-KR3 used-byte ratio per mount.
package hostmetrics

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCollectFSBytesRatio(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.FSBytesTargets = []string{"/host/run", "/dev/shm", "/host/var/lib/k0s", "/var/openebs/local"}
	cfg.statfsFn = func(mount string, st *unix.Statfs_t) error {
		switch mount {
		case "/host/run":
			st.Blocks, st.Bavail = 1000, 200 // 0.8 used
		case "/dev/shm":
			st.Blocks, st.Bavail = 100, 90 // 0.1 used
		case "/host/var/lib/k0s":
			st.Blocks, st.Bavail = 0, 0 // skipped
		default:
			return errors.New("not mounted") // skipped
		}
		return nil
	}
	c := New(cfg)

	got, ok := metricValue(t, c,
		"node_host_agent_filesystem_bytes_used_ratio",
		map[string]string{"node": "node-a", "mount": "/host/run"})
	if !ok || got != 0.8 {
		t.Fatalf("fs_bytes_used_ratio{/host/run}=%v ok=%v want 0.8", got, ok)
	}
	got, ok = metricValue(t, c,
		"node_host_agent_filesystem_bytes_used_ratio",
		map[string]string{"node": "node-a", "mount": "/dev/shm"})
	if !ok || got != 0.1 {
		t.Fatalf("fs_bytes_used_ratio{/dev/shm}=%v ok=%v want 0.1", got, ok)
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_filesystem_bytes_used_ratio",
		map[string]string{"node": "node-a", "mount": "/var/openebs/local"}); ok {
		t.Fatal("unstatfs-able mount emitted a series")
	}
}

func TestFSBytesTargetsDefault(t *testing.T) {
	// applyDefaults joins run/k0s under HostRoot — pod mode shape.
	c := New(Config{HostRoot: "/host"})
	want := []string{"/host/run", "/dev/shm", "/host/var/lib/k0s", "/var/openebs/local"}
	if len(c.cfg.FSBytesTargets) != len(want) {
		t.Fatalf("FSBytesTargets=%v want %v", c.cfg.FSBytesTargets, want)
	}
	for i, w := range want {
		if c.cfg.FSBytesTargets[i] != w {
			t.Fatalf("FSBytesTargets[%d]=%q want %q", i, c.cfg.FSBytesTargets[i], w)
		}
	}
	// Standalone HostRoot="/" — /run probed directly.
	c2 := New(Config{HostRoot: "/"})
	if c2.cfg.FSBytesTargets[0] != "/run" {
		t.Fatalf("standalone run target=%q want /run", c2.cfg.FSBytesTargets[0])
	}
}

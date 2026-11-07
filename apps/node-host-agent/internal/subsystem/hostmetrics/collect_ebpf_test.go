// collect_ebpf_test.go — W13-OBS1 unique prog/map id inventory.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestCollectEBPFCounts(t *testing.T) {
	cfg, _ := fixture(t)
	// Two procs referencing overlapping ids — dedupe must hold.
	for _, fx := range []struct {
		pid    string
		fdinfo map[string]string
	}{
		{"10", map[string]string{
			"3": "pos:\t0\nflags:\t01\nprog_id:\t42\nmap_id:\t7\n",
			"4": "pos:\t0\nprog_id:\t42\n", // dup — same program
		}},
		{"20", map[string]string{
			"5": "pos:\t0\nmap_id:\t7\nmap_id:\t9\nprog_id:\t66\n",
		}},
	} {
		pid, _ := strconv.Atoi(fx.pid)
		dir := filepath.Join(cfg.ProcRoot, fx.pid, "fdinfo")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for fd, body := range fx.fdinfo {
			testutil.WriteFile(t, filepath.Join(dir, fd), body)
			// The /fd symlink gates the fdinfo read — only
			// anon_inode:bpf-* targets pass the pre-filter.
			n, _ := strconv.Atoi(fd)
			mkFdLink(t, cfg.ProcRoot, pid, n, "anon_inode:bpf-prog")
		}
	}
	cfg.BpffsDir = filepath.Join(t.TempDir(), "no-bpffs") // absent → skipped
	c := New(cfg)

	got, ok := metricValue(t, c, "node_host_agent_ebpf_programs_count",
		map[string]string{"node": "node-a"})
	if !ok || got != 2 {
		t.Fatalf("ebpf_programs=%v ok=%v want 2 (deduped)", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_ebpf_maps_count",
		map[string]string{"node": "node-a"})
	if !ok || got != 2 {
		t.Fatalf("ebpf_maps=%v ok=%v want 2 (deduped)", got, ok)
	}
}

func TestCollectEBPFAbsentSources(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.ProcRoot = filepath.Join(t.TempDir(), "nope")
	cfg.BpffsDir = filepath.Join(t.TempDir(), "nope")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_ebpf_programs_count",
		map[string]string{"node": "node-a"}); ok {
		t.Fatal("ebpf emitted with no sources")
	}
}

func TestEBPFScanCache(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.BpffsDir = filepath.Join(t.TempDir(), "nope")
	c := New(cfg)
	// First snapshot sweeps (empty proc → counts 0, scanned ok).
	_, _, ok := c.ebpfSnapshot()
	if !ok {
		t.Fatal("sweep not scanned with readable proc root")
	}
	// Freeze the sweep result; a proc added after the cache stamp
	// must not show until EBPFScanInterval passes.
	dir := filepath.Join(cfg.ProcRoot, "10", "fdinfo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "3"), "prog_id:\t99\n")
	mkFdLink(t, cfg.ProcRoot, 10, 3, "anon_inode:bpf-map")
	progs, _, _ := c.ebpfSnapshot()
	if progs != 0 {
		t.Fatalf("cache missed: progs=%d want 0", progs)
	}
	c.ebpf.at = c.cfg.Clock.Now().Add(-2 * defaultEBPFScanInterval)
	progs, _, _ = c.ebpfSnapshot()
	if progs != 1 {
		t.Fatalf("post-expiry progs=%d want 1", progs)
	}
}

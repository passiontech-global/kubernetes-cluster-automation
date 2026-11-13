// procs_scan_bench_test.go — the shared /proc walk benchmark:
// procSnapshot forced past its TTL measures one full sweepProcs pass
// over a fixture proc tree — the stat read + comm gate + fd-dir
// ReadDir work every daemon-fd / zombie scrape pays.
package hostmetrics

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// benchProcTree seeds ~300 pids: a plain mix, the watched daemons
// (containerd, kubelet, both k0s modes) and fd dirs sized 10-90 —
// the shape a busy node answers Readdirnames(-1) with.
func benchProcTree(b *testing.B) (root string, wantPids int) {
	b.Helper()
	root = filepath.Join(b.TempDir(), "proc")
	if err := os.MkdirAll(root, 0o755); err != nil {
		b.Fatal(err)
	}
	seed := func(pid int, comm, cmdline string, fds int) {
		dir := filepath.Join(root, strconv.Itoa(pid))
		fdDir := filepath.Join(dir, "fd")
		if err := os.MkdirAll(fdDir, 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"),
			[]byte(fmt.Sprintf("%d (%s) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid, comm)),
			0o644); err != nil {
			b.Fatal(err)
		}
		if cmdline != "" {
			if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
				b.Fatal(err)
			}
		}
		for i := range fds {
			if err := os.WriteFile(filepath.Join(fdDir, strconv.Itoa(i)), nil, 0o644); err != nil {
				b.Fatal(err)
			}
		}
	}
	for i := range 300 {
		switch i % 10 {
		case 0:
			seed(i, "containerd", "", 30+i%60)
		case 1:
			seed(i, "kubelet", "", 30+i%60)
		case 2:
			seed(i, "k0s", "/usr/local/bin/k0s\x00controller\x00", 10+i%20)
		case 3:
			seed(i, "k0s", "/usr/local/bin/k0s\x00worker\x00", 10+i%20)
		case 4:
			seed(i, "nebula", "", 8)
		default:
			seed(i, fmt.Sprintf("worker-%d", i), "", 0)
		}
		wantPids++
	}
	return root, wantPids
}

// BenchmarkProcSnapshot walks the fixture proc tree once per
// iteration — the TTL is cleared under the cache lock so every call
// takes the sweepProcs path a real scrape pays after expiry.
func BenchmarkProcSnapshot(b *testing.B) {
	b.ReportAllocs()
	root, wantPids := benchProcTree(b)
	c := New(Config{NodeName: "node-a", ProcRoot: root})
	for b.Loop() {
		c.proc.mu.Lock()
		c.proc.at = time.Time{}
		c.proc.mu.Unlock()
		procs, ok := c.procSnapshot()
		if !ok || len(procs) != wantPids {
			b.Fatalf("procSnapshot=%d pids ok=%v want %d", len(procs), ok, wantPids)
		}
	}
}

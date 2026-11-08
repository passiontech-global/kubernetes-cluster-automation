// runtime_kernel_net_shim_test.go — the kernel-net-shim-hygiene
// guard: listen/softnet drops must rise for two consecutive cycles
// before the latch trips (a one-off burst is not degradation), and
// the containerd-shim RSS half trips immediately on a 200MiB shim or
// a 1.5GiB total — including the pid+task-id watchdog warning.
package runtime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func writeNetstat(t *testing.T, procDir string, drops, ovfl int64) {
	t.Helper()
	dir := filepath.Join(procDir, "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("TcpExt: ListenDrops ListenOverflows\n"+
		"TcpExt: %d %d\n", drops, ovfl)
	wdepstest.WriteFile(t, filepath.Join(dir, "netstat"), body)
}

func writeSoftnet(t *testing.T, procDir string, lines ...string) {
	t.Helper()
	dir := filepath.Join(procDir, "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "softnet_stat"),
		strings.Join(lines, "\n")+"\n")
}

func mkShim(t *testing.T, e *env, pid, rssKB int, task string) {
	t.Helper()
	// Linux TASK_COMM_LEN truncates /proc/<pid>/comm to 15 bytes:
	// "containerd-shim".
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, fmt.Sprint(pid), "comm"),
		"containerd-shim\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, fmt.Sprint(pid), "status"),
		fmt.Sprintf("Name:\tcontainerd-shim\nVmRSS:\t%d kB\n", rssKB))
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, fmt.Sprint(pid), "cmdline"),
		"/var/lib/k0s/bin/containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+task+
			"\x00-address\x00/run/k0s/containerd.sock")
	e.Live[pid] = true
}

func TestKernelNetShimHygieneCheck(t *testing.T) {
	e := fixture(t)
	writeNetstat(t, e.ProcDir, 10, 5)
	writeSoftnet(t, e.ProcDir,
		"00000064 00000000 00000003 00000000 00000000",
		"00000064 00000002 00000000 00000000 00000000")
	// One 250MiB shim — the individual threshold is 200MiB.
	mkShim(t, e, 777, 250*1024, "task-abc123")
	// A small healthy shim must still count toward the total.
	mkShim(t, e, 778, 20*1024, "task-ok")

	// Cycle 1: drop counters seed the baseline (no streak yet); the
	// oversized shim already degrades on its own threshold.
	e.H.Cycle(context.Background())
	latchPath := filepath.Join(e.StateDir,
		latchdefs.LatchFilePrefix+latchdefs.LatchKernelNetShim)
	if _, err := os.Stat(latchPath); err != nil {
		t.Fatal("shim over 200MiB did not enter the latch")
	}
	if log := e.LogLines(t); !strings.Contains(log, "pid=777") ||
		!strings.Contains(log, "task=task-abc123") {
		t.Fatalf("watchdog warning missing pid/task:\n%s", log)
	}
	c := e.H.Check(wdeps.CheckKernelNetShim)
	if c == nil {
		t.Fatal("kernel-net-shim-hygiene check not registered")
	}
	if got := e.H.Series.ContainerdShimMaxRSSBytes; got != 250<<20 {
		t.Fatalf("shim max rss=%d want %d", got, 250<<20)
	}
	if got := e.H.Series.ContainerdShimTotalRSSBytes; got != 270<<20 {
		t.Fatalf("shim total rss=%d want %d", got, 270<<20)
	}
	if got := e.H.Series.KernelSoftnetDrops; got != 2 {
		t.Fatalf("softnet drops=%d want 2", got)
	}
	if got := e.H.Series.KernelSoftnetTimeSqueeze; got != 3 {
		t.Fatalf("softnet time_squeeze=%d want 3", got)
	}

	// Shrink the shims and clear the drops: next cycle must exit the
	// latch — the streak never reached 2 rising cycles.
	os.Remove(filepath.Join(e.ProcDir, "777", "status"))
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "777", "status"),
		"Name:\tcontainerd-shim-runc-v2\nVmRSS:\t40960 kB\n")
	e.H.Cycle(context.Background())
	if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
		t.Fatal("latch held after shim RSS + drops cleared")
	}

	// Now drive the kernel-drop half alone: drops must RISE for two
	// consecutive cycles before the latch trips.
	writeNetstat(t, e.ProcDir, 20, 5) // rising cycle 1
	e.H.Cycle(context.Background())
	if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
		t.Fatal("latch tripped on the first rising cycle")
	}
	writeNetstat(t, e.ProcDir, 30, 5) // rising cycle 2 -> latch
	e.H.Cycle(context.Background())
	if _, err := os.Stat(latchPath); err != nil {
		t.Fatal("latch missing after 2 rising drop cycles")
	}
	// Flat counters release the streak — but the latch exits only
	// when no half is still degraded.
	e.H.Cycle(context.Background())
	if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
		t.Fatal("latch held with drops flat and shims small")
	}

	// The node-agent textfile carries all five new series.
	wdeps.PromTextfileDirOverride = t.TempDir()
	t.Cleanup(func() { wdeps.PromTextfileDirOverride = "" })
	e.H.WriteNodeAgentPromTextfile()
	prom, err := os.ReadFile(filepath.Join(
		wdeps.PromTextfileDirOverride, "node-agent-hygiene.prom"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"node_agent_kernel_listen_drops_total ",
		"node_agent_kernel_softnet_drops_total ",
		"node_agent_kernel_softnet_time_squeeze_total ",
		"node_agent_containerd_shim_max_rss_bytes ",
		"node_agent_containerd_shim_total_rss_bytes ",
	} {
		if !strings.Contains(string(prom), want) {
			t.Fatalf("textfile missing %s:\n%s", want, prom)
		}
	}
}

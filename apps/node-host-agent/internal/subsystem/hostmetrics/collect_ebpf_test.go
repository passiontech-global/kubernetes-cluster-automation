// collect_ebpf_test.go — ebpf-inventory unique prog/map id inventory.
package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
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

// TestEBPFPinsWalkedWithoutOpen: the bpffs half is a WALK — every
// non-dir entry counts as a pinned object even though nothing can be
// opened (bpffs rejects readmode opens for whole object classes, and
// a fake dir of regular files proves the walk is the source of
// truth). Pins fold into the maps gauge; the fdinfo prog source is
// unaffected.
func TestEBPFPinsWalkedWithoutOpen(t *testing.T) {
	cfg, _ := fixture(t)

	// One prog id from the fdinfo source.
	dir := filepath.Join(cfg.ProcRoot, "10", "fdinfo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "3"), "prog_id:\t42\n")
	mkFdLink(t, cfg.ProcRoot, 10, 3, "anon_inode:bpf-prog")

	bpf := filepath.Join(t.TempDir(), "bpf")
	if err := os.MkdirAll(filepath.Join(bpf, "cilium", "globals"), 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(bpf, "tc_garbage"), "x")
	testutil.WriteFile(t, filepath.Join(bpf, "cilium", "cyber_deadbeef"), "x")
	testutil.WriteFile(t, filepath.Join(bpf, "cilium", "globals", "cyber_tail_1"), "x")
	cfg.BpffsDir = bpf
	c := New(cfg)

	got, ok := metricValue(t, c, "node_host_agent_ebpf_programs_count",
		map[string]string{"node": "node-a"})
	if !ok || got != 1 {
		t.Fatalf("ebpf_programs=%v ok=%v want 1 (pins never inflate progs)", got, ok)
	}
	got, ok = metricValue(t, c, "node_host_agent_ebpf_maps_count",
		map[string]string{"node": "node-a"})
	if !ok || got != 3 {
		t.Fatalf("ebpf_maps=%v ok=%v want 3 (three walked pins, zero map ids)", got, ok)
	}
}

func TestEBPFScanCache(t *testing.T) {
	cfg, _ := fixture(t)
	now := time.Unix(1760000000, 0)
	cfg.Clock = timex.NewCell(func() time.Time { return now })
	cfg.BpffsDir = filepath.Join(t.TempDir(), "nope")
	c := New(cfg)
	// First snapshot sweeps (empty proc → counts 0, scanned ok).
	_, _, ok, at1 := c.ebpfSnapshotAt()
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
	progs, _, _, at2 := c.ebpfSnapshotAt()
	if progs != 0 {
		t.Fatalf("cache missed: progs=%d want 0", progs)
	}
	if !at2.Equal(at1) {
		t.Fatalf("cached snapshot stamp changed: %v -> %v", at1, at2)
	}
	now = now.Add(2 * defaultEBPFScanInterval)
	progs, _, _, at3 := c.ebpfSnapshotAt()
	if progs != 1 {
		t.Fatalf("post-expiry progs=%d want 1", progs)
	}
	if !at3.After(at1) {
		t.Fatalf("post-expiry stamp %v did not advance past %v", at3, at1)
	}
}

// TestScanBPFIDLinesJunk: fdinfo lines that are not exactly
// "<name> <id>" (headers, truncated rows, non-numeric ids, unknown
// object names) are skipped — only prog_id:/map_id: count.
func TestScanBPFIDLinesJunk(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.BpffsDir = filepath.Join(t.TempDir(), "nope")
	dir := filepath.Join(cfg.ProcRoot, "10", "fdinfo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "3"),
		"pos:\t0\n"+ // single field
			"prog_id: notanumber\n"+ // non-numeric id
			"prog_id:\t42 extra\n"+ // three fields
			"link_id:\t9\n"+ // unknown object name
			"map_id:\t7\n"+
			"prog_id:\t42\n")
	mkFdLink(t, cfg.ProcRoot, 10, 3, "anon_inode:bpf-prog")
	// Empty fdinfo file alongside must be a clean no-op.
	testutil.WriteFile(t, filepath.Join(dir, "4"), "")
	mkFdLink(t, cfg.ProcRoot, 10, 4, "anon_inode:bpf-map")

	c := New(cfg)
	progs, maps, ok := c.ebpfSnapshot()
	if !ok || progs != 1 || maps != 1 {
		t.Fatalf("ebpfSnapshot = (%d, %d, %v), want (1, 1, true)", progs, maps, ok)
	}
}

func TestSharedFDCacheReuse(t *testing.T) {
	cfg, _ := fixture(t)
	now := time.Unix(1760001000, 0)
	cfg.Clock = timex.NewCell(func() time.Time { return now })
	cfg.BpffsDir = filepath.Join(t.TempDir(), "nope")

	// Seed an initial fd under ProcRoot and warm procfs.SharedFDCache directly
	// (simulating workerhygiene populating the shared cache first).
	mkFdinfo(t, cfg.ProcRoot, 11, 3, 4)
	shared := procfs.SharedFDCache(cfg.ProcRoot, cfg.Clock.Now)
	snap := shared.Snapshot(time.Minute)
	if len(snap.Inotify) != 1 || snap.Inotify[0].Watches != 4 {
		t.Fatalf("seed snap Inotify = %+v", snap.Inotify)
	}

	// Mutate ProcRoot within TTL: add another inotify fd and an eBPF fd.
	mkFdinfo(t, cfg.ProcRoot, 22, 5, 10)
	dir := filepath.Join(cfg.ProcRoot, "22", "fdinfo")
	testutil.WriteFile(t, filepath.Join(dir, "6"), "prog_id:\t77\n")
	mkFdLink(t, cfg.ProcRoot, 22, 6, "anon_inode:bpf-prog")

	// hostmetrics.Collector shares the exact same procfs.FDCache and must serve
	// the warmed snapshot without re-walking /proc/*/fd within TTL.
	c := New(cfg)
	if c.fdCache() != shared {
		t.Fatal("hostmetrics did not reuse procfs.SharedFDCache instance")
	}
	inst, watch, _, ok := c.inotifySnapshot()
	if !ok || inst != 1 || watch != 4 {
		t.Fatalf("shared cache miss on inotify: inst=%d watch=%d ok=%v want 1, 4, true", inst, watch, ok)
	}
	progs, _, ok, scanAt := c.ebpfSnapshotAt()
	if !ok || progs != 0 || !scanAt.Equal(snap.At) {
		t.Fatalf("shared cache miss on ebpf: progs=%d ok=%v scanAt=%v want 0, true, %v",
			progs, ok, scanAt, snap.At)
	}

	// Advance clock past TTL: fresh walk picks up PID 22's inotify + eBPF fds.
	now = now.Add(2 * time.Minute)
	inst, watch, _, ok = c.inotifySnapshot()
	if !ok || inst != 2 || watch != 14 {
		t.Fatalf("post-TTL inotify: inst=%d watch=%d ok=%v want 2, 14, true", inst, watch, ok)
	}
	progs, _, _, scanAt2 := c.ebpfSnapshotAt()
	if progs != 1 || !scanAt2.After(snap.At) {
		t.Fatalf("post-TTL ebpf: progs=%d scanAt=%v want 1, >%v", progs, scanAt2, snap.At)
	}
}

// TestEBPFPartialProcFD0000PreservesLatch verifies that a partial /proc walk
// (e.g. /proc/<pid>/fd 0o000 -> snap.Partial=true) makes ebpfSnapshotAt return
// scanned=false even when bpffsDir is readable, suppressing bogus zero metrics
// and preserving LatchEBPFPressure across refreshLatches.
func TestEBPFPartialProcFD0000PreservesLatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	cfg, _ := fixture(t)
	now := time.Unix(1760002000, 0)
	cfg.Clock = timex.NewCell(func() time.Time { return now })
	cfg.EBPFProgsMax = 2
	// Readable bpffs dir (0 pins): bpffsOK=true must NOT override snap.Partial=true.
	bpf := filepath.Join(t.TempDir(), "bpf")
	if err := os.MkdirAll(bpf, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.BpffsDir = bpf

	fdDir := filepath.Join(cfg.ProcRoot, "10", "fd")
	fdinfoDir := filepath.Join(cfg.ProcRoot, "10", "fdinfo")
	if err := os.MkdirAll(fdinfoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(fdinfoDir, "3"), "prog_id:\t101\n")
	testutil.WriteFile(t, filepath.Join(fdinfoDir, "4"), "prog_id:\t102\n")
	mkFdLink(t, cfg.ProcRoot, 10, 3, "anon_inode:bpf-prog")
	mkFdLink(t, cfg.ProcRoot, 10, 4, "anon_inode:bpf-prog")

	c := New(cfg)
	l := c.Latches()
	for range 3 {
		now = now.Add(2 * defaultEBPFScanInterval)
		l.refreshLatches(context.Background())
	}
	latchPath := filepath.Join(cfg.WatchdogStateDir,
		latchdefs.LatchFilePrefix+latchdefs.LatchEBPFPressure)
	if _, err := os.Stat(latchPath); err != nil {
		t.Fatalf("setup: LatchEBPFPressure not armed: %v", err)
	}

	// Make /proc/10/fd unreadable (0o000) -> ScanFDs returns ProcOK=true, Partial=true.
	if err := os.Chmod(fdDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

	now = now.Add(2 * defaultEBPFScanInterval)
	_, _, scanned, _ := c.ebpfSnapshotAt()
	if scanned {
		t.Fatal("ebpfSnapshotAt returned scanned=true on Partial /proc walk")
	}
	if _, ok := metricValue(t, c, "node_host_agent_ebpf_programs_count",
		map[string]string{"node": "node-a"}); ok {
		t.Fatal("collectEBPF emitted metric on Partial /proc walk")
	}
	l.refreshLatches(context.Background())
	if _, err := os.Stat(latchPath); err != nil {
		t.Fatalf("LatchEBPFPressure falsely exited on Partial /proc walk: %v", err)
	}

	// Restore permissions and clear progs -> next fresh scan clears the latch.
	if err := os.Chmod(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(filepath.Join(cfg.ProcRoot, "10"))
	now = now.Add(2 * defaultEBPFScanInterval)
	l.refreshLatches(context.Background())
	if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
		t.Fatalf("LatchEBPFPressure did not exit after recovery: err=%v", err)
	}
}

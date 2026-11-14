// textfile_test.go — the node_agent_* textfile surface: the
// bounded dir-size walk, the statfs watermark probe, the textfile-dir
// resolution, the once-per-cycle writer over canned marker files and
// the capped marker read.
package wdeps_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// TestWalkBytes — regular-file sizes sum across subdirs; the walk
// truncates past the entry cap (total is then a lower bound); an
// unreadable entry is skipped, never fatal.
func TestWalkBytes(t *testing.T) {
	e := fixture(t)
	root := filepath.Join(t.TempDir(), "tree")
	wdepstest.WriteFile(t, filepath.Join(root, "a.txt"), strings.Repeat("x", 100))
	wdepstest.WriteFile(t, filepath.Join(root, "sub", "b.txt"), strings.Repeat("y", 50))
	wdepstest.WriteFile(t, filepath.Join(root, "sub", "c.bin"), strings.Repeat("z", 25))

	total, truncated := e.D.WalkBytes(root)
	if truncated {
		t.Fatal("small tree reported truncated")
	}
	if total != 175 {
		t.Fatalf("total=%d want 175", total)
	}

	// Past the cap the walk stops and reports truncated.
	big := filepath.Join(t.TempDir(), "big")
	for i := range wdepsMaxWalkEntries() + 1 {
		wdepstest.WriteFile(t, filepath.Join(big, strconv.Itoa(i)), "")
	}
	total, truncated = e.D.WalkBytes(big)
	if !truncated {
		t.Fatal("oversized tree not reported truncated")
	}
	if total != 0 {
		t.Fatalf("truncated total=%d want lower bound 0", total)
	}

	// An unreadable entry is skipped, not fatal (non-root walks
	// cannot enter a 0000 dir; root sees it whole — either way the
	// walk must not panic or truncate).
	locked := filepath.Join(t.TempDir(), "locked")
	wdepstest.WriteFile(t, filepath.Join(locked, "keep.txt"), strings.Repeat("k", 10))
	secret := filepath.Join(locked, "secret")
	wdepstest.WriteFile(t, filepath.Join(secret, "s.txt"), strings.Repeat("s", 10))
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(secret, 0o755) }() // keep TempDir cleanup working
	total, truncated = e.D.WalkBytes(locked)
	if truncated {
		t.Fatal("locked dir reported truncated")
	}
	if total < 10 {
		t.Fatalf("total=%d want at least the readable file", total)
	}
}

// wdepsMaxWalkEntries exposes the walk cap for the truncation case —
// the production const is unexported, so restate it here.
func wdepsMaxWalkEntries() int { return 10000 }

// TestDiskUsageAboveWatermark — statfs through the seam: above 80%
// used → true, at/below → false, unmeasurable → false (fail closed).
func TestDiskUsageAboveWatermark(t *testing.T) {
	e := fixture(t)
	cases := []struct {
		name   string
		bavail uint64
		blocks uint64
		err    error
		want   bool
	}{
		{"above watermark", 10, 100, nil, true}, // 90% used
		{"just above", 19, 100, nil, true},      // 81% used
		{"exactly at", 20, 100, nil, false},     // 80% used — not above
		{"below", 30, 100, nil, false},          // 70% used
		{"statfs error", 10, 100, unix.EPERM, false},
		{"zero blocks", 0, 0, nil, false},
	}
	for _, tc := range cases {
		e.D.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
			st.Blocks = tc.blocks
			st.Bavail = tc.bavail
			return tc.err
		}
		if got := e.D.DiskUsageAboveWatermark("/var/lib/k0s"); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// TestPromTextfileDir — the K0sDataDir-derived drop dir; the
// override var wins for tests.
func TestPromTextfileDir(t *testing.T) {
	e := fixture(t)
	want := filepath.Join(filepath.Dir(e.D.Cfg.K0sDataDir), "node-exporter", "textfile")
	if got := e.D.PromTextfileDir(); got != want {
		t.Fatalf("dir=%q want %q", got, want)
	}

	override := filepath.Join(t.TempDir(), "override")
	e.D.Cfg.TextfileDir = override
	if got := e.D.PromTextfileDir(); got != override {
		t.Fatalf("override ignored: dir=%q want %q", got, override)
	}
}

// TestWriteNodeAgentPromTextfile — the writer renders the kmsg
// marker counters (missing/garbage files degrade to 0), the ST2
// gauges and the guard series into node-agent-hygiene.prom; an
// unwritable dir appends the suspect line.
func TestWriteNodeAgentPromTextfile(t *testing.T) {
	e := fixture(t)
	dir := t.TempDir()
	e.D.Cfg.TextfileDir = dir

	wdepstest.WriteFile(t, e.D.Cfg.Host.OOMCountFile, "7\n")
	wdepstest.WriteFile(t, e.D.Cfg.Host.ConntrackDropsFile, "3\n")
	e.D.OrphanHostPathBytes = 1234
	e.D.OrphanHostPathDirs = 2
	e.D.CgroupDyingDescendants = 4
	e.D.CgroupReclaimRuns = 1
	e.D.KernelListenDrops = 9

	e.D.WriteNodeAgentPromTextfile()
	b, err := os.ReadFile(filepath.Join(dir, "node-agent-hygiene.prom"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{
		"node_agent_host_oom_kills_total 7",
		"node_agent_conntrack_drops_detected_total 3",
		"node_agent_orphan_hostpath_bytes 1234",
		"node_agent_orphan_hostpath_dirs 2",
		"node_agent_cgroup_dying_descendants 4",
		"node_agent_cgroup_reclaim_runs_total 1",
		"node_agent_kernel_listen_drops_total 9",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing series %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "# TYPE node_agent_host_oom_kills_total counter") != 1 {
		t.Fatalf("counter TYPE header wrong:\n%s", out)
	}

	// Garbage + missing marker files degrade to 0, never fail.
	wdepstest.WriteFile(t, e.D.Cfg.Host.OOMCountFile, "not-a-number\n")
	if err := os.Remove(e.D.Cfg.Host.ConntrackDropsFile); err != nil {
		t.Fatal(err)
	}
	e.D.WriteNodeAgentPromTextfile()
	b, err = os.ReadFile(filepath.Join(dir, "node-agent-hygiene.prom"))
	if err != nil {
		t.Fatal(err)
	}
	out = string(b)
	if !strings.Contains(out, "node_agent_host_oom_kills_total 0") ||
		!strings.Contains(out, "node_agent_conntrack_drops_detected_total 0") {
		t.Fatalf("marker fallback to 0 missing:\n%s", out)
	}

	// An unwritable drop dir appends the suspect line — the override
	// points under a regular FILE, so the writer's MkdirAll fails
	// with ENOTDIR no matter the user.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("a file, not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	e2 := fixture(t)
	e2.D.Cfg.TextfileDir = filepath.Join(blocker, "sub")
	e2.D.WriteNodeAgentPromTextfile()
	if !strings.Contains(e2.LogLines(t), "node-agent prom textfile unwritable") {
		t.Fatalf("missing suspect line:\n%s", e2.LogLines(t))
	}
}

// TestReadSmallFile — content reads back whole; missing files read
// empty; oversized files are capped, never slurped.
func TestReadSmallFile(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "marker")
	if err := os.WriteFile(small, []byte("42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := wdeps.ReadSmallFile(small); got != "42\n" {
		t.Fatalf("got %q want %q", got, "42\n")
	}
	if got := wdeps.ReadSmallFile(filepath.Join(dir, "absent")); got != "" {
		t.Fatalf("missing file read %q want empty", got)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("a", 5000)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := len(wdeps.ReadSmallFile(big)); got != 4096 {
		t.Fatalf("capped read=%d want 4096", got)
	}
}

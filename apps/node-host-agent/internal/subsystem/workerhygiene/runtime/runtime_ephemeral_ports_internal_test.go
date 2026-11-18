// runtime_ephemeral_ports_internal_test.go — package-internal
// coverage for the P0.3 per-netns census: netnsReps must dedup
// /proc/<pid>/ns/net links so each distinct pod netns gets exactly
// one sock_diag representative (a pid-1-only census is blind to
// every hostNetwork:false workload), and portRangeCeiling parses
// ip_local_port_range with inconclusive verdicts on bad input.
package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// mkNetNS plants <proc>/<pid>/ns/net as a symlink to a fake
// "net:[inode]" target — the shape os.Readlink sees on a real host.
func mkNetNS(t *testing.T, proc string, pid int, inode string) {
	t.Helper()
	dir := filepath.Join(proc, strconv.Itoa(pid), "ns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:["+inode+"]",
		filepath.Join(dir, "net")); err != nil {
		t.Fatal(err)
	}
}

func portsCheck(proc string) *EphemeralPortsCheck {
	return &EphemeralPortsCheck{d: &wdeps.Deps{
		Cfg:  wdeps.Config{ProcRoot: proc},
		Proc: procfs.New(proc),
	}}
}

// TestNetnsRepsDedupesByNetNS pins the census contract: pid 1
// anchors first, every DISTINCT net:[inode] contributes one rep,
// duplicates (containers sharing a netns, hostNetwork pods on the
// host netns) collapse, and pids with no readable ns link are
// skipped rather than counted as a separate namespace.
func TestNetnsRepsDedupesByNetNS(t *testing.T) {
	proc := t.TempDir()
	mkNetNS(t, proc, 1, "100") // host netns
	mkNetNS(t, proc, 2, "200") // pod netns A
	mkNetNS(t, proc, 3, "200") // same pod netns A — dedup
	mkNetNS(t, proc, 4, "300") // pod netns B
	mkNetNS(t, proc, 5, "100") // hostNetwork pod — shares pid 1
	// pid 6 gets no ns/net — skipped, never a phantom rep.
	if err := os.MkdirAll(filepath.Join(proc, "6"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := portsCheck(proc)
	reps := c.netnsReps([]int{2, 3, 4, 5, 6})
	want := []int{1, 2, 4}
	if len(reps) != len(want) {
		t.Fatalf("reps=%v want %v", reps, want)
	}
	for i := range want {
		if reps[i] != want[i] {
			t.Fatalf("reps=%v want %v", reps, want)
		}
	}
}

// TestNetnsRepsPid1AlwaysAnchors: even with an unreadable pid-1 ns
// link the host netns stays in the census — TCPTables(1) was the
// original target and dropping it would regress pre-P0.3 coverage.
func TestNetnsRepsPid1AlwaysAnchors(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	mkNetNS(t, proc, 2, "200")
	c := portsCheck(proc)
	reps := c.netnsReps([]int{2})
	if len(reps) != 2 || reps[0] != 1 || reps[1] != 2 {
		t.Fatalf("reps=%v want [1 2]", reps)
	}
}

// TestEvictPortLeakersNoPruneWhenAPINotOK pins the marker-preservation
// contract: an inconclusive pod LIST must not run PruneMarkers with an
// empty active set, which would erase the leak-window first-seen
// markers and restart ConfirmMarker's window on every API blip.
func TestEvictPortLeakersNoPruneWhenAPINotOK(t *testing.T) {
	d, _ := rtDeps(t)
	d.Cfg.Wave2.PortEvictRunawayPod = true
	marker := "port-leak-stale"
	d.State.RateSpend(marker)
	markerPath := filepath.Join(d.Cfg.WatchdogStateDir, marker)
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("setup marker: %v", err)
	}

	NewEphemeralPorts(d).evictPortLeakers(context.Background(),
		&wdeps.CycleEnv{WorkerActive: true, APIOK: false},
		100, 1000, nil, nil)

	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("inconclusive API pruned port-leak marker: %v", err)
	}
}

// TestEvictPortLeakersPrunesWhenPressureResolved is the companion
// rail: with a conclusive API, a resolved pressure (no CLOSE_WAIT)
// still prunes stale first-seen markers so a future leak starts a
// fresh ConfirmMarker window.
func TestEvictPortLeakersPrunesWhenPressureResolved(t *testing.T) {
	d, _ := rtDeps(t)
	d.Cfg.Wave2.PortEvictRunawayPod = true
	marker := "port-leak-stale"
	d.State.RateSpend(marker)
	markerPath := filepath.Join(d.Cfg.WatchdogStateDir, marker)

	NewEphemeralPorts(d).evictPortLeakers(context.Background(),
		&wdeps.CycleEnv{WorkerActive: true, APIOK: true},
		0, 1000, nil, nil) // closeWait=0 → pressure resolved, no active leaker

	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("resolved pressure did not prune stale port-leak marker: %v", err)
	}
}

// TestPortRangeCeiling pins the ip_local_port_range parse and its
// inconclusive verdicts — a bad read must NOT fabricate a ratio.
func TestPortRangeCeiling(t *testing.T) {
	proc := t.TempDir()
	rel := filepath.Join(proc, portRangeRel)
	if err := os.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		t.Fatal(err)
	}
	c := portsCheck(proc)

	if _, ok := c.portRangeCeiling(); ok {
		t.Fatal("missing ip_local_port_range parsed")
	}
	if err := os.WriteFile(rel, []byte("32768 60999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	span, ok := c.portRangeCeiling()
	if !ok || span != 60999-32768+1 {
		t.Fatalf("span=%d ok=%v want %d", span, ok, 60999-32768+1)
	}
	// Inverted range is malformed evidence, not a negative span.
	if err := os.WriteFile(rel, []byte("60999 32768\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.portRangeCeiling(); ok {
		t.Fatal("inverted range parsed")
	}
}

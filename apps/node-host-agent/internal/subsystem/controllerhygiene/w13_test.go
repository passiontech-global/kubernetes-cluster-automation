// w13_test.go — Wave-13 controller-hygiene tests: the W13-CP1
// terminated-watchers mirror, the W13 Gap#2 single-controller
// streak multiplier and the W13-ST2 etcd snapshot verifier.
package controllerhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// --- W13-CP1: apiserver_terminated_watchers_total mirror ---

func TestParseTerminatedWatchers(t *testing.T) {
	body := "# HELP apiserver_terminated_watchers_total x\n" +
		"# TYPE apiserver_terminated_watchers_total counter\n" +
		"apiserver_terminated_watchers_total 3\n" +
		"apiserver_terminated_watchers_total{reason=\"410 Gone\"} 4\n" +
		"other_metric 9\n"
	total, seen := parseTerminatedWatchers(body)
	if !seen || total != 7 {
		t.Fatalf("total=%v seen=%v want 7/true", total, seen)
	}
	if _, seen := parseTerminatedWatchers("other_metric 1\n"); seen {
		t.Fatal("seen=true without the family")
	}
}

func TestEmitAPFMetricsTerminatedWatchers(t *testing.T) {
	e := fixture(t)
	c := &cpFreezeCheck{d: e.h.deps}
	dir := t.TempDir()
	textfileDirOverride = dir
	defer func() { textfileDirOverride = "" }()
	c.emitAPFMetrics(nil, nil, 42, true)
	b, err := os.ReadFile(filepath.Join(dir, apfPromFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b),
		"\nnode_host_agent_apiserver_terminated_watchers 42") {
		t.Fatalf("terminated-watchers series missing:\n%s", b)
	}
	// Unseen family → headers-only (series absent, not stale).
	c.emitAPFMetrics(nil, nil, 0, false)
	b, _ = os.ReadFile(filepath.Join(dir, apfPromFile))
	if strings.Contains(string(b),
		"\nnode_host_agent_apiserver_terminated_watchers ") {
		t.Fatalf("blind scrape left a stale series:\n%s", b)
	}
}

// --- W13 Gap#2: single-controller streak multiplier ---

func TestSPOFStreakCycles(t *testing.T) {
	e := fixture(t)
	// Fixture wires a peer → not single-controller, no doubling.
	if got := e.h.deps.streakCycles(4); got != 4 {
		t.Fatalf("peer set: streakCycles=%d want 4", got)
	}
	// Explicit topology override wins over the PeerAPI heuristic.
	e.h.cfg.TotalControllers = 3
	if got := e.h.deps.streakCycles(4); got != 4 {
		t.Fatalf("TotalControllers=3: streakCycles=%d want 4", got)
	}
	e.h.cfg.TotalControllers = 1
	if got := e.h.deps.streakCycles(4); got != 8 {
		t.Fatalf("TotalControllers=1: streakCycles=%d want 8", got)
	}
	// Auto: no peer configured → single-controller → doubled.
	e.h.cfg.TotalControllers = 0
	e.h.cfg.Hub.PeerAPI = ""
	if !e.h.deps.singleController() {
		t.Fatal("PeerAPI empty but singleController=false")
	}
	if got := e.h.deps.streakCycles(5); got != 10 {
		t.Fatalf("single-controller streakCycles=%d want 10", got)
	}
}

// --- W13-ST2: etcd snapshot verifier ---

func TestVerifySnapshots(t *testing.T) {
	e := fixture(t)
	snapDir := t.TempDir()
	e.h.cfg.EtcdSnapshotDir = snapDir
	c := &etcdGuardCheck{d: e.h.deps}

	// No snapshot → suspect log, gauge stays 0.
	c.verifySnapshots()
	if got := testutil.ToFloat64(e.h.deps.etcdSnapAge); got != 0 {
		t.Fatalf("etcdSnapAge=%v want 0 with no snapshot", got)
	}
	// A 2h-old non-empty snapshot → age ~7200s.
	snap := filepath.Join(snapDir, "snapshot.db")
	if err := os.WriteFile(snap, []byte("etcd-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := e.now.Add(-2 * time.Hour)
	_ = os.Chtimes(snap, old, old)
	c.verifySnapshots()
	got := testutil.ToFloat64(e.h.deps.etcdSnapAge)
	if got < 7100 || got > 7300 {
		t.Fatalf("etcdSnapAge=%v want ~7200", got)
	}
	// Empty snapshot → suspect path but age still reported.
	if err := os.WriteFile(snap, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(snap, old, old)
	c.verifySnapshots()
	if got := testutil.ToFloat64(e.h.deps.etcdSnapAge); got < 7100 {
		t.Fatalf("etcdSnapAge=%v after empty snapshot", got)
	}
}

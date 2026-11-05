package controllerhygiene

import (
	"context"
	"testing"
	"time"
)

// --- W10-FIX1: kcmQueueSnapshot / kcmQueueStalled ---

func TestParseKCMQueueSnapshot(t *testing.T) {
	body := "leader_election_master_status 1\n" +
		"workqueue_depth{name=\"a\"} 3\n" +
		"workqueue_depth{name=\"b\"} 0\n" +
		"workqueue_adds_total{name=\"a\"} 100\n" +
		"workqueue_adds_total{name=\"b\"} 50\n" +
		"workqueue_retries_total{name=\"a\"} 7\n"
	snap, ok := parseKCMQueueSnapshot(body, 1234)
	if !ok {
		t.Fatal("parsed=false with leader metric present")
	}
	if !snap.Leader || snap.At != 1234 {
		t.Fatalf("leader=%v at=%d", snap.Leader, snap.At)
	}
	if snap.DepthSum != 3 {
		t.Fatalf("depthSum=%v want 3", snap.DepthSum)
	}
	if snap.Depths["a"] != 3 || snap.Adds["a"] != 100 || snap.Retries["a"] != 7 {
		t.Fatalf("bad per-queue maps: %+v", snap)
	}
	// No leader metric → inconclusive.
	if _, ok = parseKCMQueueSnapshot(
		"workqueue_depth{name=\"a\"} 0\n", 1); ok {
		t.Fatal("parsed=true without leader metric")
	}
}

func kcmSnap(at int64, leader bool, depths, adds, retries map[string]float64) *kcmQueueSnapshot {
	s := &kcmQueueSnapshot{
		At: at, Leader: leader,
		Depths: map[string]float64{}, Adds: map[string]float64{},
		Retries: map[string]float64{},
	}
	for k, v := range depths {
		s.Depths[k] = v
		s.DepthSum += v
	}
	for k, v := range adds {
		s.Adds[k] = v
	}
	for k, v := range retries {
		s.Retries[k] = v
	}
	return s
}

func TestKCMQueueStalled(t *testing.T) {
	// (a) THE regression: healthy idle — leader, every queue depth 0,
	// counters flat — must NEVER fire, no matter how many scrapes.
	idle1 := kcmSnap(100, true,
		map[string]float64{"a": 0, "b": 0},
		map[string]float64{"a": 10, "b": 20},
		map[string]float64{"a": 1, "b": 2})
	idle2 := kcmSnap(160, true,
		map[string]float64{"a": 0, "b": 0},
		map[string]float64{"a": 10, "b": 20},
		map[string]float64{"a": 1, "b": 2})
	if kcmQueueStalled(idle1, idle2) {
		t.Fatal("stalled=true on healthy idle depthSum==0")
	}

	// (a) fires: depthSum > 50, adds flat across two scrapes.
	prev := kcmSnap(100, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	cur := kcmSnap(160, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500}, // +0 adds
		map[string]float64{"a": 30})
	if !kcmQueueStalled(prev, cur) {
		t.Fatal("stalled=false on depth>50 with adds delta 0")
	}

	// Same backlog but adds still flowing → workers/informers alive.
	curFlow := kcmSnap(160, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 530},
		map[string]float64{"a": 30})
	if kcmQueueStalled(prev, curFlow) {
		t.Fatal("stalled=true while adds_total still increasing")
	}

	// Shallow backlog → below the arm-(a) threshold.
	shallow := kcmSnap(160, true,
		map[string]float64{"a": 30},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	prevShallow := kcmSnap(100, true,
		map[string]float64{"a": 30},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	if kcmQueueStalled(prevShallow, shallow) {
		t.Fatal("stalled=true on depthSum 30 < 50")
	}

	// (b) fires: one queue depth>20, retries +>200, depth not draining.
	prevR := kcmSnap(100, true,
		map[string]float64{"q": 25},
		map[string]float64{"q": 10},
		map[string]float64{"q": 100})
	curR := kcmSnap(160, true,
		map[string]float64{"q": 25}, // no drain
		map[string]float64{"q": 10},
		map[string]float64{"q": 350}) // +250 retries
	if !kcmQueueStalled(prevR, curR) {
		t.Fatal("stalled=false on retry storm with no depth drain")
	}

	// (b) does NOT fire when the queue is draining.
	curDrain := kcmSnap(160, true,
		map[string]float64{"q": 10},
		map[string]float64{"q": 10},
		map[string]float64{"q": 350})
	if kcmQueueStalled(prevR, curDrain) {
		t.Fatal("stalled=true while queue depth is draining")
	}

	// Counter reset (KCM restart mid-window) → inconclusive.
	reset := kcmSnap(160, true,
		map[string]float64{"a": 5},
		map[string]float64{"a": 3}, // adds went backwards
		map[string]float64{"a": 1})
	if kcmQueueStalled(prev, reset) {
		t.Fatal("stalled=true across a counter reset")
	}

	// Not leader → never fires.
	notLeader := kcmSnap(160, false,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	if kcmQueueStalled(prev, notLeader) {
		t.Fatal("stalled=true on non-leader scrape")
	}

	// Stale prev snapshot (>15m) → inconclusive.
	stale := kcmSnap(100+2000, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	if kcmQueueStalled(prev, stale) {
		t.Fatal("stalled=true on a >15m snapshot gap")
	}

	// No baseline → first scrape never fires.
	if kcmQueueStalled(nil, cur) {
		t.Fatal("stalled=true with nil prev")
	}
}

// --- checkCPFreeze ---

// stalledKCMBody is a metrics body that reads leader + a deep,
// flat-adds backlog — the W10-FIX1 stall signature (never the old
// leader+zero-depth idle false-positive).
const stalledKCMBody = "leader_election_master_status 1\n" +
	"workqueue_depth{name=\"a\"} 60\n" +
	"workqueue_adds_total{name=\"a\"} 500\n" +
	"workqueue_retries_total{name=\"a\"} 30\n"

func TestCPFreezeRestartsAfterThreeDeadCycles(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return false }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\nworkqueue_depth{name=\"a\"} 1\n", nil
	}
	e.alive["https://10.0.0.2:6443/readyz"] = true // peer healthy
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() == 0 {
		t.Fatal("no restart after 3 dead healthz cycles")
	}
	if !e.hasState("cp-component-frozen") {
		t.Fatal("cp-component-frozen latch missing")
	}
}

func TestCPFreezeGatedByDeadPeer(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return false }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	// PeerAPI default is alive[...] → false: peer dead → no restart.
	for i := 0; i < 4; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 0 {
		t.Fatal("restart fired while peer apiserver dead")
	}
	if !e.hasState("cp-component-frozen") {
		t.Fatal("latch should still record the freeze evidence")
	}
}

func TestCPFreezeWorkqueueStalledPastGrace(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return true }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return stalledKCMBody, nil
	}
	e.alive["https://10.0.0.2:6443/readyz"] = true
	e.h.Cycle(context.Background()) // snapshot 1 — no baseline yet
	e.now = e.now.Add(61 * time.Second)
	e.h.Cycle(context.Background()) // snapshot 2 → stalled, stamps quiet-since
	if e.rstN() != 0 {
		t.Fatal("restart before the quiet grace")
	}
	e.now = e.now.Add(11 * time.Minute)
	e.h.Cycle(context.Background())
	if e.rstN() == 0 {
		t.Fatal("no restart after workqueue stalled >10m")
	}
}

// TestCPFreezeHealthyIdleNeverRestarts is the W10-FIX1 regression:
// leader + depthSum==0 across many cycles and well past the old
// quiet grace must produce ZERO restarts — the old kcmLeaderIdle
// fired on exactly this body every hour.
func TestCPFreezeHealthyIdleNeverRestarts(t *testing.T) {
	e := fixture(t)
	e.h.cfg.cpHealthFn = func(context.Context, string) bool { return true }
	e.h.cfg.kcmMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\n" +
			"workqueue_depth{name=\"a\"} 0\n" +
			"workqueue_depth{name=\"b\"} 0\n" +
			"workqueue_adds_total{name=\"a\"} 10\n" +
			"workqueue_adds_total{name=\"b\"} 20\n", nil
	}
	e.alive["https://10.0.0.2:6443/readyz"] = true
	for i := 0; i < 15; i++ {
		e.h.Cycle(context.Background())
		e.now = e.now.Add(61 * time.Second)
	}
	if e.rstN() != 0 {
		t.Fatal("restart fired on healthy idle cluster (W10-FIX1 regression)")
	}
	if e.hasState("cp-component-frozen") {
		t.Fatal("cp-component-frozen latched on healthy idle cluster")
	}
}

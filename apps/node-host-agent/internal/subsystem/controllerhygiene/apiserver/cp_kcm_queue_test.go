package apiserver_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// --- kcm-queue-stall: apiserver.KCMQueueSnapshot / apiserver.KCMQueueStalled ---

func TestParseKCMQueueSnapshot(t *testing.T) {
	body := "leader_election_master_status 1\n" +
		"workqueue_depth{name=\"a\"} 3\n" +
		"workqueue_depth{name=\"b\"} 0\n" +
		"workqueue_adds_total{name=\"a\"} 100\n" +
		"workqueue_adds_total{name=\"b\"} 50\n" +
		"workqueue_retries_total{name=\"a\"} 7\n"
	snap, ok := apiserver.ParseKCMQueueSnapshot(body, 1234)
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
	if _, ok = apiserver.ParseKCMQueueSnapshot(
		"workqueue_depth{name=\"a\"} 0\n", 1); ok {
		t.Fatal("parsed=true without leader metric")
	}
}

func kcmSnap(at int64, leader bool, depths, adds, retries map[string]float64) *apiserver.KCMQueueSnapshot {
	s := &apiserver.KCMQueueSnapshot{
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
	if apiserver.KCMQueueStalled(idle1, idle2) {
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
	if !apiserver.KCMQueueStalled(prev, cur) {
		t.Fatal("stalled=false on depth>50 with adds delta 0")
	}

	// Same backlog but adds still flowing → workers/informers alive.
	curFlow := kcmSnap(160, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 530},
		map[string]float64{"a": 30})
	if apiserver.KCMQueueStalled(prev, curFlow) {
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
	if apiserver.KCMQueueStalled(prevShallow, shallow) {
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
	if !apiserver.KCMQueueStalled(prevR, curR) {
		t.Fatal("stalled=false on retry storm with no depth drain")
	}

	// (b) does NOT fire when the queue is draining.
	curDrain := kcmSnap(160, true,
		map[string]float64{"q": 10},
		map[string]float64{"q": 10},
		map[string]float64{"q": 350})
	if apiserver.KCMQueueStalled(prevR, curDrain) {
		t.Fatal("stalled=true while queue depth is draining")
	}

	// Counter reset (KCM restart mid-window) → inconclusive.
	reset := kcmSnap(160, true,
		map[string]float64{"a": 5},
		map[string]float64{"a": 3}, // adds went backwards
		map[string]float64{"a": 1})
	if apiserver.KCMQueueStalled(prev, reset) {
		t.Fatal("stalled=true across a counter reset")
	}

	// Not leader → never fires.
	notLeader := kcmSnap(160, false,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	if apiserver.KCMQueueStalled(prev, notLeader) {
		t.Fatal("stalled=true on non-leader scrape")
	}

	// Stale prev snapshot (>15m) → inconclusive.
	stale := kcmSnap(100+2000, true,
		map[string]float64{"a": 60},
		map[string]float64{"a": 500},
		map[string]float64{"a": 30})
	if apiserver.KCMQueueStalled(prev, stale) {
		t.Fatal("stalled=true on a >15m snapshot gap")
	}

	// No baseline → first scrape never fires.
	if apiserver.KCMQueueStalled(nil, cur) {
		t.Fatal("stalled=true with nil prev")
	}
}

// --- cdeps.CheckCPFreeze ---

// stalledKCMBody is a metrics body that reads leader + a deep,
// flat-adds backlog — the kcm-queue-stall stall signature (never the old
// leader+zero-depth idle false-positive).
const stalledKCMBody = "leader_election_master_status 1\n" +
	"workqueue_depth{name=\"a\"} 60\n" +
	"workqueue_adds_total{name=\"a\"} 500\n" +
	"workqueue_retries_total{name=\"a\"} 30\n"

// --- KCM parser/snapshot edges ---

func TestParseKCMQueueSnapshotEdges(t *testing.T) {
	// Bare series (no labels) → "" key; labels without name="..." →
	// the raw label text; unparseable values skipped.
	body := "leader_election_master_status{name=\"kcm\"} 1\n" +
		"workqueue_depth 5\n" +
		"workqueue_adds_total{queue=\"x\"} 7\n" +
		"workqueue_retries_total{name=\"q\"} 1.2.3\n"
	snap, ok := apiserver.ParseKCMQueueSnapshot(body, 1)
	if !ok {
		t.Fatal("parsed=false on edge body with leader present")
	}
	if snap.Depths[""] != 5 || snap.Adds["{queue=\"x\"}"] != 7 {
		t.Fatalf("edge keys wrong: %+v", snap)
	}
	if len(snap.Retries) != 0 {
		t.Fatalf("unparseable retry sample parsed: %+v", snap.Retries)
	}
}

func TestKCMQueueStalledEdges(t *testing.T) {
	// Retries counter reset across the window → inconclusive (arm (b)
	// can never run its delta math).
	prev := kcmSnap(100, true,
		map[string]float64{"q": 25},
		map[string]float64{"q": 10},
		map[string]float64{"q": 500})
	cur := kcmSnap(160, true,
		map[string]float64{"q": 25},
		map[string]float64{"q": 10},
		map[string]float64{"q": 5}) // retries went backwards
	if apiserver.KCMQueueStalled(prev, cur) {
		t.Fatal("stalled=true across a retries counter reset")
	}
	// Queue deep + retries storming but absent from the previous
	// depth map — no baseline to prove non-drain → inconclusive.
	prevNoDepth := kcmSnap(100, true,
		map[string]float64{},
		map[string]float64{},
		map[string]float64{"q": 100})
	curStall := kcmSnap(160, true,
		map[string]float64{"q": 25},
		map[string]float64{"q": 10},
		map[string]float64{"q": 350})
	if apiserver.KCMQueueStalled(prevNoDepth, curStall) {
		t.Fatal("stalled=true with no baseline depth for the queue")
	}
}

// A corrupt persisted snapshot reads as "no baseline" — inconclusive,
// never a restart on the first post-corruption scrape.
func TestKCMSnapshotCorruptReadsAsNoBaseline(t *testing.T) {
	e := fixture(t)
	os.WriteFile(filepath.Join(e.State, cdeps.FileKCMQueueSnap),
		[]byte("{not json"), 0o644)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return stalledKCMBody, nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	e.H.Cycle(context.Background()) // corrupt prev → inconclusive
	if e.RstN() != 0 {
		t.Fatal("restart on a corrupt baseline")
	}
	// The bad file was overwritten with valid JSON for the next cycle.
	b, err := os.ReadFile(filepath.Join(e.State, cdeps.FileKCMQueueSnap))
	if err != nil || !strings.Contains(string(b), `"depth_sum":60`) {
		t.Fatalf("snapshot not re-persisted: %q %v", b, err)
	}
}

// When the snapshot path is a directory the atomic write fails —
// the failure must warn, not panic, and the cycle continues.
func TestKCMSnapshotWriteFailureWarns(t *testing.T) {
	e := fixture(t)
	if err := os.MkdirAll(filepath.Join(e.State, cdeps.FileKCMQueueSnap), 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return stalledKCMBody, nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	e.H.Cycle(context.Background()) // must not panic
	if e.CountLogLines("kcm snapshot write failed") == 0 {
		t.Fatalf("snapshot write failure not logged:\n%s", e.LogLines())
	}
}

// A NaN sample never reaches the parser — the workqueue value
// regex only admits numeric text, so the series is skipped and the
// snapshot persists with an empty depth map (inconclusive, never a
// stall input).
func TestKCMSnapshotNaNMarshalSkips(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\n" +
			"workqueue_depth{name=\"a\"} NaN\n", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	e.H.Cycle(context.Background()) // must not panic
	b, err := os.ReadFile(filepath.Join(e.State, cdeps.FileKCMQueueSnap))
	if err != nil {
		t.Fatalf("snapshot not persisted: %v", err)
	}
	if !strings.Contains(string(b), `"depth_sum":0`) {
		t.Fatalf("NaN sample leaked into snapshot: %s", b)
	}
}

package apiserver_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"

	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- W10-FIX1: apiserver.KCMQueueSnapshot / apiserver.KCMQueueStalled ---

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
// flat-adds backlog — the W10-FIX1 stall signature (never the old
// leader+zero-depth idle false-positive).
const stalledKCMBody = "leader_election_master_status 1\n" +
	"workqueue_depth{name=\"a\"} 60\n" +
	"workqueue_adds_total{name=\"a\"} 500\n" +
	"workqueue_retries_total{name=\"a\"} 30\n"

func TestCPFreezeRestartsAfterThreeDeadCycles(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\nworkqueue_depth{name=\"a\"} 1\n", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true // peer healthy
	for i := 0; i < 3; i++ {
		e.H.Cycle(context.Background())
	}
	if e.RstN() == 0 {
		t.Fatal("no restart after 3 dead healthz cycles")
	}
	if !e.HasState("cp-component-frozen") {
		t.Fatal("cp-component-frozen latch missing")
	}
}

func TestCPFreezeGatedByDeadPeer(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	// PeerAPI default is alive[...] → false: peer dead → no restart.
	for i := 0; i < 4; i++ {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatal("restart fired while peer apiserver dead")
	}
	if !e.HasState("cp-component-frozen") {
		t.Fatal("latch should still record the freeze evidence")
	}
}

func TestCPFreezeWorkqueueStalledPastGrace(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return stalledKCMBody, nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	e.H.Cycle(context.Background()) // snapshot 1 — no baseline yet
	e.Now = e.Now.Add(61 * time.Second)
	e.H.Cycle(context.Background()) // snapshot 2 → stalled, stamps quiet-since
	if e.RstN() != 0 {
		t.Fatal("restart before the quiet grace")
	}
	e.Now = e.Now.Add(11 * time.Minute)
	e.H.Cycle(context.Background())
	if e.RstN() == 0 {
		t.Fatal("no restart after workqueue stalled >10m")
	}
}

// TestCPFreezeHealthyIdleNeverRestarts is the W10-FIX1 regression:
// leader + depthSum==0 across many cycles and well past the old
// quiet grace must produce ZERO restarts — the old kcmLeaderIdle
// fired on exactly this body every hour.
func TestCPFreezeHealthyIdleNeverRestarts(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\n" +
			"workqueue_depth{name=\"a\"} 0\n" +
			"workqueue_depth{name=\"b\"} 0\n" +
			"workqueue_adds_total{name=\"a\"} 10\n" +
			"workqueue_adds_total{name=\"b\"} 20\n", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for i := 0; i < 15; i++ {
		e.H.Cycle(context.Background())
		e.Now = e.Now.Add(61 * time.Second)
	}
	if e.RstN() != 0 {
		t.Fatal("restart fired on healthy idle cluster (W10-FIX1 regression)")
	}
	if e.HasState("cp-component-frozen") {
		t.Fatal("cp-component-frozen latched on healthy idle cluster")
	}
}

// --- APF queue-starvation probe ---

// watchdogLogOrEmpty is watchdogLog tolerant of a never-written
// log — "the probe must not log" assertions need it (watchdogLog
// itself t.Fatal's on a missing file).
func watchdogLogOrEmpty(e *env) string {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(e.State), "watchdog.log"))
	if err != nil {
		return ""
	}
	return string(b)
}

func countLogLinesOrEmpty(e *env, needle string) int {
	n := 0
	for _, l := range strings.Split(e.LogLines(), "\n") {
		if strings.Contains(l, needle) {
			n++
		}
	}
	return n
}

// apfBody renders a fixture apiserver /metrics payload: the
// flowcontrol series carry flow_schema+priority_level labels —
// other families must not match the parser.
func apfBody(rejected, inqueue map[string]float64) string {
	var b strings.Builder
	b.WriteString("# HELP apiserver_flowcontrol_rejected_requests_total x\n" +
		"# TYPE apiserver_flowcontrol_rejected_requests_total counter\n")
	for _, kv := range strings.Split(rejectedList(rejected), "\n") {
		if kv != "" {
			b.WriteString(kv + "\n")
		}
	}
	for _, kv := range strings.Split(inqueueList(inqueue), "\n") {
		if kv != "" {
			b.WriteString(kv + "\n")
		}
	}
	b.WriteString("go_goroutines 800\n") // noise — must be ignored
	return b.String()
}

// rejectedList / inqueueList expand a "fs/pl=value" fixture table
// into scrape lines — deterministic order keeps tests readable.
func rejectedList(m map[string]float64) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		fs, pl, _ := strings.Cut(k, "/")
		out = append(out, "apiserver_flowcontrol_rejected_requests_total"+
			"{flow_schema=\""+fs+"\",priority_level=\""+pl+"\"} "+
			strconv.FormatFloat(m[k], 'f', -1, 64))
	}
	return strings.Join(out, "\n")
}

func inqueueList(m map[string]float64) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		fs, pl, _ := strings.Cut(k, "/")
		out = append(out, "apiserver_flowcontrol_current_inqueue_requests"+
			"{flow_schema=\""+fs+"\",priority_level=\""+pl+"\"} "+
			strconv.FormatFloat(m[k], 'f', -1, 64))
	}
	return strings.Join(out, "\n")
}

func TestParseAPFMetrics(t *testing.T) {
	body := apfBody(
		map[string]float64{
			"exempt/exempt":                  3,
			"system:serviceaccounts/wl-high": 40,
			"system:nodes/global-default":    7,
			"probe--f1e2d3c4/metrics":        2,
		},
		map[string]float64{
			"system:serviceaccounts/wl-high": 12,
			"exempt/exempt":                  0,
		})
	rejected, inqueue := apiserver.ParseAPFMetrics(body)
	got := rejected[apiserver.APFSeriesKey{"system:serviceaccounts", "wl-high"}]
	if got != 40 {
		t.Fatalf("rejected=%v want 40", got)
	}
	if rejected[apiserver.APFSeriesKey{"system:nodes", "global-default"}] != 7 {
		t.Fatalf("global-default rejects missing: %v", rejected)
	}
	if inqueue[apiserver.APFSeriesKey{"system:serviceaccounts", "wl-high"}] != 12 {
		t.Fatalf("inqueue=%v want 12", inqueue)
	}
	// No APF families → empty maps, not an error.
	r2, i2 := apiserver.ParseAPFMetrics("go_goroutines 5\n")
	if len(r2) != 0 || len(i2) != 0 {
		t.Fatalf("non-APF body must parse empty: %v %v", r2, i2)
	}
}

// The probe emits the mirrored series into the textfile every cycle
// and suspect-logs only when the reject counters actually grew
// between consecutive scrapes.
func TestAPFProbeEmitsAndLogsRejectGrowth(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { cdeps.TextfileDirOverride = oldTD }()

	body1 := apfBody(
		map[string]float64{"system:serviceaccounts/wl-high": 40},
		map[string]float64{"system:serviceaccounts/wl-high": 12})
	body2 := apfBody(
		map[string]float64{"system:serviceaccounts/wl-high": 57},
		map[string]float64{"system:serviceaccounts/wl-high": 30})
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).APFMetricsFn = func(context.Context) (string, error) {
		return body1, nil
	}
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).ProbeAPF(context.Background()) // scrape 1 — baseline only
	prom, err := os.ReadFile(filepath.Join(
		cdeps.TextfileDirOverride, apiserver.APFPromFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# TYPE node_host_agent_apiserver_apf_rejected_total counter",
		`node_host_agent_apiserver_apf_rejected_total{flow_schema="system:serviceaccounts",priority_level="wl-high"} 40`,
		`node_host_agent_apiserver_apf_inqueue_requests{flow_schema="system:serviceaccounts",priority_level="wl-high"} 12`,
	} {
		if !strings.Contains(string(prom), want) {
			t.Fatalf("textfile missing %q:\n%s", want, prom)
		}
	}
	if e.CountLogLines("APF queue starvation") != 0 {
		t.Fatal("starvation logged on the baseline scrape")
	}

	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).APFMetricsFn = func(context.Context) (string, error) {
		return body2, nil
	}
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).ProbeAPF(context.Background()) // scrape 2 — +17 rejects
	if e.CountLogLines("APF queue starvation") == 0 {
		t.Fatal("no starvation line on reject growth")
	}
	log := e.LogLines()
	if !strings.Contains(log, "flow_schema=system:serviceaccounts") ||
		!strings.Contains(log, "priority_level=wl-high") {
		t.Fatalf("offending flow_schema/priority_level not named:\n%s", log)
	}
	if !strings.Contains(log, "+17 rejects") {
		t.Fatalf("reject delta not logged:\n%s", log)
	}
	prom, _ = os.ReadFile(filepath.Join(cdeps.TextfileDirOverride, apiserver.APFPromFile))
	if !strings.Contains(string(prom), "} 57") {
		t.Fatalf("textfile not refreshed:\n%s", prom)
	}
}

// A scrape failure emits headers only — the series must go absent
// rather than keep a stale counter live.
func TestAPFProbeScrapeFailureDropsSeries(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { cdeps.TextfileDirOverride = oldTD }()

	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).APFMetricsFn = func(context.Context) (string, error) {
		return "", errors.New("connection refused")
	}
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).ProbeAPF(context.Background()) // must not panic
	prom, err := os.ReadFile(filepath.Join(
		cdeps.TextfileDirOverride, apiserver.APFPromFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prom), "# TYPE "+apiserver.APFRejectedMetric) {
		t.Fatalf("headers missing on scrape failure:\n%s", prom)
	}
	for _, line := range strings.Split(string(prom), "\n") {
		if strings.HasPrefix(line, apiserver.APFRejectedMetric+"{") {
			t.Fatalf("stale sample emitted on scrape failure:\n%s", prom)
		}
	}
}

// Counter resets (apiserver restart) re-baseline without firing —
// the same inconclusive posture as a stale KCM snapshot.
func TestAPFProbeCounterResetInconclusive(t *testing.T) {
	e := fixture(t)
	root := t.TempDir()
	oldTD := cdeps.TextfileDirOverride
	cdeps.TextfileDirOverride = filepath.Join(root, "textfile")
	defer func() { cdeps.TextfileDirOverride = oldTD }()

	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).APFMetricsFn = func(context.Context) (string, error) {
		return apfBody(map[string]float64{"a/b": 100}, nil), nil
	}
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).ProbeAPF(context.Background())
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).APFMetricsFn = func(context.Context) (string, error) {
		return apfBody(map[string]float64{"a/b": 3}, nil), nil // reset
	}
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).ProbeAPF(context.Background())
	if e.CountLogLines("APF queue starvation") != 0 {
		t.Fatal("starvation logged across a counter reset")
	}
}

// --- relist-storm: apiserver_terminated_watchers_total mirror ---

func TestParseTerminatedWatchers(t *testing.T) {
	body := "# HELP apiserver_terminated_watchers_total x\n" +
		"# TYPE apiserver_terminated_watchers_total counter\n" +
		"apiserver_terminated_watchers_total 3\n" +
		"apiserver_terminated_watchers_total{reason=\"410 Gone\"} 4\n" +
		"other_metric 9\n"
	total, seen := apiserver.ParseTerminatedWatchers(body)
	if !seen || total != 7 {
		t.Fatalf("total=%v seen=%v want 7/true", total, seen)
	}
	if _, seen := apiserver.ParseTerminatedWatchers("other_metric 1\n"); seen {
		t.Fatal("seen=true without the family")
	}
}

func TestEmitAPFMetricsTerminatedWatchers(t *testing.T) {
	e := fixture(t)
	c := apiserver.NewFreeze(e.H.Deps, nil, nil)
	dir := t.TempDir()
	cdeps.TextfileDirOverride = dir
	defer func() { cdeps.TextfileDirOverride = "" }()
	c.EmitAPFMetrics(nil, nil, 42, true)
	b, err := os.ReadFile(filepath.Join(dir, apiserver.APFPromFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b),
		"\nnode_host_agent_apiserver_terminated_watchers 42") {
		t.Fatalf("terminated-watchers series missing:\n%s", b)
	}
	// Unseen family → headers-only (series absent, not stale).
	c.EmitAPFMetrics(nil, nil, 0, false)
	b, _ = os.ReadFile(filepath.Join(dir, apiserver.APFPromFile))
	if strings.Contains(string(b),
		"\nnode_host_agent_apiserver_terminated_watchers ") {
		t.Fatalf("blind scrape left a stale series:\n%s", b)
	}
}

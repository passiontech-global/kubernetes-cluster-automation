package apiserver_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
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

func TestCPFreezeRestartsAfterThreeDeadCycles(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "leader_election_master_status 1\nworkqueue_depth{name=\"a\"} 1\n", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true // peer healthy
	for range 3 {
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
	for range 4 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatal("restart fired while peer apiserver dead")
	}
	if !e.HasState("cp-component-frozen") {
		t.Fatal("latch should still record the freeze evidence")
	}
}

// TestCPFreezeSuspectPathKeepsLatchAndCounters is the file-split
// regression: the healthz-dead-below-streak cycle must bare-return
// the way the monolithic Run did — no "ok" outcome stacked on the
// suspect counter and no STATE-EXIT clearing an episode's latch
// (Enter's mtime refresh is the janitor-reap defence, so an early
// Exit also weakens that).
func TestCPFreezeSuspectPathKeepsLatchAndCounters(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 3 {
		e.H.Cycle(context.Background()) // streak reached → frozen + heal
	}
	if e.RstN() == 0 || !e.HasState("cp-component-frozen") {
		t.Fatalf("episode not established: rst=%d latch=%v",
			e.RstN(), e.HasState("cp-component-frozen"))
	}
	e.H.Cycle(context.Background()) // dead again, below streak → suspect
	// Cycles 1, 2 and this one are suspect; cycle 3 was the heal.
	if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckCPFreeze, "suspect")); v != 3 {
		t.Fatalf("suspect counter=%v want 3", v)
	}
	if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckCPFreeze, "ok")); v != 1 {
		t.Fatalf("ok counter=%v want 1 (heal cycle only — suspect must not stack ok)", v)
	}
	if !e.HasState("cp-component-frozen") {
		t.Fatal("suspect cycle cleared the episode latch — bare-return lost")
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

// TestCPFreezeHealthyIdleNeverRestarts is the kcm-queue-stall regression:
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
	for range 15 {
		e.H.Cycle(context.Background())
		e.Now = e.Now.Add(61 * time.Second)
	}
	if e.RstN() != 0 {
		t.Fatal("restart fired on healthy idle cluster (kcm-queue-stall regression)")
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

// --- konnectivity-server probe + heal (G4) ---

type nodesTransport struct{ readyWorkers int }

func (nt nodesTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/api/v1/nodes") {
		var items []string
		for i := 0; i < nt.readyWorkers; i++ {
			items = append(items, fmt.Sprintf(
				`{"metadata":{"labels":{"kubernetes.io/hostname":"w%d"}},`+
					`"status":{"conditions":[{"type":"Ready","status":"True"}]}}`, i))
		}
		// One Ready control-plane node always exists — it must NOT
		// count as a worker.
		items = append(items, `{"metadata":{"labels":{"node-role.kubernetes.io/control-plane":""}},`+
			`"status":{"conditions":[{"type":"Ready","status":"True"}]}}`)
		return &http.Response{
			Status:     "200 OK",
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"items":[` + strings.Join(items, ",") + `]}`)),
			Request: req,
		}, nil
	}
	return nil, errors.New("nodesTransport: unexpected url " + req.URL.String())
}

func TestKonnectivityServerProbeAndHeal(t *testing.T) {
	e := fixture(t)
	runDir := t.TempDir()
	e.H.Cfg.K0sRunDir = runDir
	// The UDS exists — the zero-backends reading is the bad signal.
	if err := os.MkdirAll(filepath.Join(runDir, "konnectivity-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "konnectivity-server",
		"konnectivity-server.sock"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	// The supervisor child — comm truncates to 15 chars but the
	// argv basename is what the pid sweep matches.
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server", "--uds-name=x"}, 600)

	// Cycles 1+2: streak below the 3-cycle gate — no kill.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("kill fired before the 3-cycle streak: %v", e.Kills)
	}
	// Cycle 3: unhealthy >= 3 cycles + Ready worker + enforce → kill.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 4242 {
		t.Fatalf("kills=%v want [{4242 SIGKILL}]", e.Kills)
	}
	if log := e.LogLines(); !strings.Contains(log,
		"ACTION: killed konnectivity-server pid=4242") {
		t.Fatalf("watchdog log missing kill ACTION:\n%s", log)
	}
	if v := promtest.ToFloat64(e.H.KonnReadyBackends); v != 0 {
		t.Fatalf("ready_backends gauge=%v want 0", v)
	}
	// The 30-minute restart budget suppresses a second kill.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 {
		t.Fatalf("budget did not suppress repeat kill: %v", e.Kills)
	}
}

func TestKonnectivityNoWorkerSuppressesHeal(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad every cycle
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 0}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	for range 4 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("heal fired with zero Ready workers: %v", e.Kills)
	}
	if log := e.LogLines(); !strings.Contains(log, "no Ready workers") {
		t.Fatalf("suppression not logged:\n%s", log)
	}
	// Scrape failure exports -1, never a fabricated 0.
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, _ string) (string, error) {
		return "", errors.New("refused")
	}
	e.H.Cycle(context.Background())
	if v := promtest.ToFloat64(e.H.KonnReadyBackends); v != -1 {
		t.Fatalf("scrape-failed gauge=%v want -1", v)
	}
}

// --- parser edge branches ---

func TestParseAPFMetricsEdges(t *testing.T) {
	// Unparseable sample values are skipped, not poisoned in.
	r, i := apiserver.ParseAPFMetrics(
		"apiserver_flowcontrol_rejected_requests_total{flow_schema=\"a\"," +
			"priority_level=\"b\"} 1.2.3\n")
	if len(r) != 0 || len(i) != 0 {
		t.Fatalf("unparseable sample parsed: %v %v", r, i)
	}
	// A series with NO label set at all — both apfLabel lookups miss
	// and the key groups under ("", "").
	r, _ = apiserver.ParseAPFMetrics(
		"apiserver_flowcontrol_rejected_requests_total 9\n")
	if r[apiserver.APFSeriesKey{}] != 9 {
		t.Fatalf("bare sample key missing: %v", r)
	}
	// Labels that match neither label regex also land under ("","").
	_, i = apiserver.ParseAPFMetrics(
		"apiserver_flowcontrol_current_inqueue_requests{other=\"x\"} 4\n")
	if i[apiserver.APFSeriesKey{}] != 4 {
		t.Fatalf("unlabelled inqueue sample missing: %v", i)
	}
}

func TestParseTerminatedWatchersEdges(t *testing.T) {
	// A sample whose value is not a float is skipped — the family is
	// only "seen" when at least one sample parses.
	total, seen := apiserver.ParseTerminatedWatchers(
		"apiserver_terminated_watchers_total 1.2.3\n" +
			"apiserver_terminated_watchers_total{reason=\"x\"} 4..5\n")
	if seen || total != 0 {
		t.Fatalf("unparseable family seen=%v total=%v", seen, total)
	}
}

// TestEmitAPFMetricsSortedKeys pins the byte-stable textfile order:
// flow_schema ascending, priority_level breaking ties.
func TestEmitAPFMetricsSortedKeys(t *testing.T) {
	e := fixture(t)
	c := apiserver.NewFreeze(e.H.Deps, nil, nil)
	dir := t.TempDir()
	cdeps.TextfileDirOverride = dir
	defer func() { cdeps.TextfileDirOverride = "" }()
	c.EmitAPFMetrics(map[apiserver.APFSeriesKey]float64{
		{"b", "p2"}: 1,
		{"b", "p1"}: 2,
		{"a", "z"}:  3,
	}, nil, 0, false)
	b, err := os.ReadFile(filepath.Join(dir, apiserver.APFPromFile))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	ia := strings.Index(s, `flow_schema="a",priority_level="z"}`)
	ib1 := strings.Index(s, `flow_schema="b",priority_level="p1"`)
	ib2 := strings.Index(s, `flow_schema="b",priority_level="p2"`)
	if ia < 0 || ib1 < 0 || ib2 < 0 || !(ia < ib1 && ib1 < ib2) {
		t.Fatalf("textfile not schema-then-level sorted:\n%s", s)
	}
}

// TestAPFMetricsDefaultSeamErrors drives the non-Fn path of
// apfMetrics — the mTLS client seam the rv probe shares — through
// every failure shape: no creds, transport error, non-200, and a
// body read error. All degrade to headers-only emission.
func TestAPFMetricsDefaultSeamErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(e *env)
	}{
		{"no_creds", func(e *env) {
			e.H.Cfg.HTTPClient = nil
			e.H.Client = nil // creds files missing → EnsureClient nil
		}},
		{"transport_error", func(e *env) {}}, // rvTransport fails /metrics
		{"status_503", func(e *env) {
			tr := errBodyTransport{status: http.StatusServiceUnavailable}
			e.H.Cfg.HTTPClient = &http.Client{Transport: tr}
			e.H.Client = e.H.Cfg.HTTPClient
		}},
		{"body_read_error", func(e *env) {
			tr := errBodyTransport{status: http.StatusOK, bodyErr: true}
			e.H.Cfg.HTTPClient = &http.Client{Transport: tr}
			e.H.Client = e.H.Cfg.HTTPClient
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			cdeps.TextfileDirOverride = t.TempDir()
			defer func() { cdeps.TextfileDirOverride = "" }()
			tc.mut(e)
			cdepstest.Check[*apiserver.FreezeCheck](
				e.H, cdeps.CheckCPFreeze).ProbeAPF(context.Background())
			prom, err := os.ReadFile(filepath.Join(
				cdeps.TextfileDirOverride, apiserver.APFPromFile))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(prom),
				"# TYPE "+apiserver.APFRejectedMetric) {
				t.Fatalf("headers missing:\n%s", prom)
			}
			if strings.Contains(string(prom),
				apiserver.APFRejectedMetric+"{") {
				t.Fatalf("stale sample emitted:\n%s", prom)
			}
			// A real sample line starts with the metric name — the
			// # HELP/# TYPE header lines never do.
			if strings.Contains(string(prom), "\nnode_host_agent_apiserver_rss_bytes") {
				t.Fatalf("stale RSS sample emitted:\n%s", prom)
			}
		})
	}
}

// errBodyTransport answers /metrics with a fixed status; with
// bodyErr set the body fails mid-read (a truncated TLS stream's
// shape) so io.ReadAll errors after the 200.
type errBodyTransport struct {
	status  int
	bodyErr bool
}

func (t errBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasSuffix(req.URL.Path, "/metrics") {
		return nil, errors.New("errBodyTransport: unexpected " + req.URL.String())
	}
	var body io.ReadCloser = io.NopCloser(strings.NewReader("partial"))
	if t.bodyErr {
		body = io.NopCloser(errReader{})
	}
	return &http.Response{
		Status: strconv.Itoa(t.status), StatusCode: t.status,
		Header: make(http.Header), Body: body, Request: req,
	}, nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read: connection reset by peer")
}

// A successful default-seam scrape carries the RSS sample into the
// textfile (apiserver-rss-gauge) and the new-key + sampling offender branches.
func TestAPFProbeDefaultSeamEmitAndSampling(t *testing.T) {
	e := fixture(t)
	cdeps.TextfileDirOverride = t.TempDir()
	defer func() { cdeps.TextfileDirOverride = "" }()

	// Scrape 1: baseline with an RSS sample — the gauge must appear.
	base := "process_resident_memory_bytes{instance=\"a:6443\"} 1.5e8\n"
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).
		ProbeAPF(context.Background())
	// Default seam fails /metrics via rvTransport — use APFMetricsFn
	// for the content-bearing scrapes instead.
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).APFMetricsFn =
		func(context.Context) (string, error) {
			return base + apfBody(
				map[string]float64{"a/b": 100, "c/d": 100, "e/f": 100,
					"g/h": 100, "i/j": 100, "k/l": 100, "m/n": 100},
				nil), nil
			// deliberately unused
		}
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).ProbeAPF(context.Background())
	prom, err := os.ReadFile(filepath.Join(
		cdeps.TextfileDirOverride, apiserver.APFPromFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prom), "node_host_agent_apiserver_rss_bytes"+" 1.5e+08") &&
		!strings.Contains(string(prom), "node_host_agent_apiserver_rss_bytes"+" 150000000") {
		t.Fatalf("RSS series missing:\n%s", prom)
	}

	// Scrape 2: every baseline key grows AND a brand-new key appears —
	// the new key has no baseline (skipped), the rest overflow the
	// 5-offender sample cap after the delta sort.
	grow := map[string]float64{"a/b": 110, "c/d": 120, "e/f": 130,
		"g/h": 140, "i/j": 150, "k/l": 160, "m/n": 170, "new/one": 999}
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).APFMetricsFn =
		func(context.Context) (string, error) {
			return apfBody(grow, nil), nil
		}
	cdepstest.Check[*apiserver.FreezeCheck](e.H, cdeps.CheckCPFreeze).ProbeAPF(context.Background())
	log := e.LogLines()
	if n := strings.Count(log, "flow_schema="); n == 0 || n > 5 {
		t.Fatalf("offender count %d, want 1-5 (sample cap):\n%s", n, log)
	}
	if strings.Contains(log, "flow_schema=new") {
		t.Fatalf("baseline-less key treated as an offender:\n%s", log)
	}
}

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

// --- healFreeze gating branches ---

// After a cp-freeze restart the rate budget is spent — the next
// frozen episode must land in the cooldown branch, not burn a second
// restart inside MinRestart.
func TestCPFreezeRestartCooldown(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 1 {
		t.Fatalf("precondition: restarts=%d", e.RstN())
	}
	for range 3 {
		e.H.Cycle(context.Background()) // re-freeze inside cooldown
	}
	if e.RstN() != 1 {
		t.Fatalf("cooldown not honored: restarts=%d", e.RstN())
	}
	if e.CountLogLines("in restart cooldown") == 0 {
		t.Fatalf("cooldown not logged:\n%s", e.LogLines())
	}
}

// A failing restart unit is logged as a suspect warn, not swallowed.
func TestCPFreezeRestartFailureWarns(t *testing.T) {
	e := fixture(t)
	oldExec := e.H.Cfg.HostExecFn
	e.H.Cfg.HostExecFn = func(ctx context.Context, quiet bool, d time.Duration,
		name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) >= 2 && args[0] == "restart" {
			return "", errors.New("systemctl:Job failed")
		}
		return oldExec(ctx, quiet, d, name, args...)
	}
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if !strings.Contains(e.LogLines(),
		"suspect: restart k0scontroller.service failed") {
		t.Fatalf("restart failure not warned:\n%s", e.LogLines())
	}
}

func TestCPFreezeDryRunLogsNoRestart(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Sig13.Mode = cdeps.ModeDryRun
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return false }
	e.H.Cfg.KCMMetricsFn = func(context.Context, string) (string, error) {
		return "", nil
	}
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatalf("dry-run restarted: %v", e.RstAt(0))
	}
	if !strings.Contains(e.LogLines(),
		"DRY-RUN: would restart k0scontroller - cp-component-frozen") {
		t.Fatalf("dry-run action not logged:\n%s", e.LogLines())
	}
}

// --- konnectivity-server edge branches ---

// A healthy cycle after a bad one must reset the streak and refresh
// the gauge — bad→good→bad never reaches the 3-cycle gate.
func TestKonnectivityHealthyCycleResetsStreak(t *testing.T) {
	e := fixture(t)
	runDir := t.TempDir()
	e.H.Cfg.K0sRunDir = runDir
	sock := filepath.Join(runDir, "konnectivity-server", "konnectivity-server.sock")
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	for range 2 { // bad, bad — below the gate
		e.H.Cycle(context.Background())
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 2\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Cycle(context.Background()) // healthy — streak resets, gauge=2
	if v := promtest.ToFloat64(e.H.KonnReadyBackends); v != 2 {
		t.Fatalf("gauge=%v want 2", v)
	}
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background()) // bad again — only 1 of 3
	e.H.Cycle(context.Background()) // 2 of 3
	if len(e.Kills) != 0 {
		t.Fatalf("kill fired before the streak rebuilt: %v", e.Kills)
	}
}

// Unhealthy past the gate but the supervisor child is gone — the
// heal must log and stand down instead of killing pid 0.
func TestKonnectivityNoProcessToKill(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad every cycle
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("kill without a process: %v", e.Kills)
	}
	if !strings.Contains(e.LogLines(),
		"konnectivity-server process not found") {
		t.Fatalf("missing-process not logged:\n%s", e.LogLines())
	}
}

// A failing kill is a suspect warn — the streak stays spent but no
// success action is recorded.
func TestKonnectivityKillFailureWarns(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir()
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	oldKill := e.H.Cfg.KillFn
	e.H.Cfg.KillFn = func(int, syscall.Signal) error {
		return errors.New("no such process")
	}
	defer func() { e.H.Cfg.KillFn = oldKill }()
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("failed kill recorded as fired: %v", e.Kills)
	}
	if !strings.Contains(e.LogLines(),
		"konnectivity-server kill pid=4242 failed") {
		t.Fatalf("kill failure not warned:\n%s", e.LogLines())
	}
}

// The pid sweep failing wholesale (procfs unreadable) reads as "no
// process" — heal stands down.
func TestKonnectivityProcRootUnreadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir()
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	for range 2 { // build the streak with a readable procfs
		e.H.Cycle(context.Background())
	}
	if err := os.Chmod(e.Proc, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(e.Proc, 0o755) }()
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("kill fired with unreadable procfs: %v", e.Kills)
	}
}

// ParseKonnectivityReadyBackends: a HELP-style continuation line and
// a bare metric name with no value are inconclusive, never 0.
func TestParseKonnectivityReadyBackendsEdges(t *testing.T) {
	if v, ok := apiserver.ParseKonnectivityReadyBackends(
		"konnectivity_network_proxy_server_ready_backend_connections\n" +
			"other_metric 1\n"); ok {
		t.Fatalf("valueless sample parsed: %v", v)
	}
	if v, ok := apiserver.ParseKonnectivityReadyBackends(
		"# konnectivity_network_proxy_server_ready_backend_connections 3\n"); ok {
		t.Fatalf("comment line parsed: %v", v)
	}
}

// The pid sweep skips pids with an empty/missing cmdline — a decoy
// process without argv must not shadow the real konnectivity-server
// child, and the lowest matching pid wins.
func TestKonnectivityPIDSkipsEmptyCmdline(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir()
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	// A higher-pid second server must be ignored; the empty-argv decoy
	// must be skipped without stopping the sweep.
	e.MkProc(t, 4343, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	e.MkProc(t, 4300, "decoy", nil, 600)
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 1 || e.Kills[0].PID != 4242 {
		t.Fatalf("kills=%v want lowest matching pid 4242", e.Kills)
	}
}

// readyWorkers: no client credentials, a master-labeled-only node
// list, and undecodable JSON all read as zero — heal suppressed.
func TestKonnectivityReadyWorkersEdges(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(e *env)
	}{
		{"no_client", func(e *env) {
			e.H.Cfg.HTTPClient = nil
			e.H.Client = nil
		}},
		{"master_only", func(e *env) {
			e.H.Client = &http.Client{Transport: masterTransport{}}
		}},
		{"bad_json", func(e *env) {
			e.H.Client = &http.Client{Transport: rawTransport{body: "{oops"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.K0sRunDir = t.TempDir()
			e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
				if url == "http://127.0.0.1:8091/metrics" {
					return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
				}
				return "", errors.New("unexpected scrape " + url)
			}
			e.MkProc(t, 4242, "konnectivity-se",
				[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
			tc.mut(e)
			for range 4 {
				e.H.Cycle(context.Background())
			}
			if len(e.Kills) != 0 {
				t.Fatalf("%s: heal fired with zero usable workers: %v",
					tc.name, e.Kills)
			}
		})
	}
}

// masterTransport answers the node list with one Ready node that is
// master-labeled (legacy clusters) — not a worker.
type masterTransport struct{}

func (masterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(
			`{"items":[{"metadata":{"labels":` +
				`{"node-role.kubernetes.io/master":""}},` +
				`"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`)),
		Request: req,
	}, nil
}

// rawTransport answers every request with a fixed body.
type rawTransport struct{ body string }

func (t rawTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader(t.body)),
		Request: req,
	}, nil
}

// Off and dry-run modes must not burn the 30-minute konn restart
// budget — the spend happens atomically inside the enforce branch.
func TestKonnectivityBudgetNotSpentOffOrDryRun(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		wantLog string
	}{
		{"dryrun", cdeps.ModeDryRun, "DRY-RUN: would kill konnectivity-server"},
		{"off", cdeps.ModeOff, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad signal
			e.H.Cfg.Sig13.Mode = tc.mode
			e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
				if url == "http://127.0.0.1:8091/metrics" {
					return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
				}
				return "", errors.New("unexpected scrape " + url)
			}
			e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
			e.MkProc(t, 4242, "konnectivity-se",
				[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
			for range 4 {
				e.H.Cycle(context.Background())
			}
			if len(e.Kills) != 0 {
				t.Fatalf("%s mode killed: %v", tc.name, e.Kills)
			}
			if h := e.H.State.Epoch(filepath.Join(e.State,
				cdeps.FileRateKonnRestart)); h != 0 {
				t.Fatalf("%s mode burned the restart budget (epoch=%d)", tc.name, h)
			}
			log := e.LogLines()
			if tc.wantLog == "" {
				if strings.Contains(log, "DRY-RUN") {
					t.Fatalf("off mode logged a dry-run action:\n%s", log)
				}
			} else if !strings.Contains(log, tc.wantLog) {
				t.Fatalf("dry-run not logged:\n%s", log)
			}
		})
	}
}

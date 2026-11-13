package apiserver_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
)

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

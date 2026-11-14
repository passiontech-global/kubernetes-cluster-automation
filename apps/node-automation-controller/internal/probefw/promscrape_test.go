// promscrape_test.go — the prometheus text-exposition parser pair
// (ParseMetricValue/ParseMetricValues) and FetchPodMetrics through a
// stub transport: the guard errors, the URL shape, the byte cap and
// non-200/transport failures all read as inconclusive.
package probefw

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func TestParseMetricValue(t *testing.T) {
	cases := []struct {
		line, name string
		want       float64
		ok         bool
	}{
		{"ha_connections 3", "ha_connections", 3, true},
		{"ha_connections{pod=\"a\"} 2.5", "ha_connections", 2.5, true},
		// A second field (exemplar/timestamp) is ignored.
		{"ha_connections{pod=\"a\"} 2 1700000000", "ha_connections", 2, true},
		{"# HELP ha_connections help", "ha_connections", 0, false},
		{"", "ha_connections", 0, false},
		{"other_metric 1", "ha_connections", 0, false},
		// Name-prefix collision: "_total" is not a separator.
		{"ha_connections_total 9", "ha_connections", 0, false},
		{"ha_connections abc", "ha_connections", 0, false},
		{"ha_connections{l=\"v\"", "ha_connections", 0, false},
		{"ha_connections{l=\"v\"}", "ha_connections", 0, false},
		// Tab separators, '}' inside quoted label value, and OpenMetrics exemplars.
		{"ha_connections\t4.5\t1700000000", "ha_connections", 4.5, true},
		{`ha_connections{msg="bad\"}"} 7	1700000000`, "ha_connections", 7, true},
		{`ha_connections{pod="a"} 2.5 # {trace_id="abc"} 1.0`, "ha_connections", 2.5, true},
	}
	for _, tc := range cases {
		v, ok := ParseMetricValue(tc.line, tc.name)
		if ok != tc.ok || v != tc.want {
			t.Fatalf("ParseMetricValue(%q,%q) = (%v,%v), want (%v,%v)",
				tc.line, tc.name, v, ok, tc.want, tc.ok)
		}
	}
}

func TestParseMetricValues(t *testing.T) {
	body := `# TYPE scylla_compaction gauge
scylla_compaction{group="0"} 3
scylla_compaction{group="1"} 5
other_metric 9
`
	got := ParseMetricValues(body, "scylla_compaction")
	if fmt.Sprint(got) != "[3 5]" {
		t.Fatalf("ParseMetricValues = %v, want [3 5]", got)
	}
	if got := ParseMetricValues(body, "absent"); len(got) != 0 {
		t.Fatalf("ParseMetricValues absent = %v, want empty", got)
	}
}

func TestFetchPodMetrics(t *testing.T) {
	ctx := t.Context()

	t.Run("nil client errors", func(t *testing.T) {
		if _, err := FetchPodMetrics(ctx, nil, "10.0.0.1", 9180,
			time.Second, 1024); err == nil {
			t.Fatal("want error for nil client")
		}
	})
	t.Run("empty pod IP errors", func(t *testing.T) {
		if _, err := FetchPodMetrics(ctx, &http.Client{}, "", 9180,
			time.Second, 1024); err == nil {
			t.Fatal("want error for empty IP")
		}
	})
	t.Run("200 returns the exposition body", func(t *testing.T) {
		client := &http.Client{Transport: &testhelp.StubTransport{
			Fn: func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "http://10.1.2.3:9180/metrics" {
					return nil, fmt.Errorf("unexpected url %s", r.URL)
				}
				return testhelp.ProbeResponse(200, "m 1\n"), nil
			}}}
		body, err := FetchPodMetrics(ctx, client, "10.1.2.3", 9180,
			time.Second, 1<<20)
		if err != nil || string(body) != "m 1\n" {
			t.Fatalf("FetchPodMetrics = (%q,%v)", body, err)
		}
	})
	t.Run("non-200 is inconclusive", func(t *testing.T) {
		client := &http.Client{Transport: &testhelp.StubTransport{
			Fn: func(r *http.Request) (*http.Response, error) {
				return testhelp.ProbeResponse(503, "down"), nil
			}}}
		if _, err := FetchPodMetrics(ctx, client, "10.1.2.3", 9180,
			time.Second, 1<<20); err == nil {
			t.Fatal("want error for non-200")
		}
	})
	t.Run("transport error is inconclusive", func(t *testing.T) {
		client := &http.Client{Transport: &testhelp.StubTransport{
			Fn: func(r *http.Request) (*http.Response, error) {
				return nil, errors.New("dial refused")
			}}}
		if _, err := FetchPodMetrics(ctx, client, "10.1.2.3", 9180,
			time.Second, 1<<20); err == nil {
			t.Fatal("want error for transport failure")
		}
	})
	t.Run("maxBytes+1 detects truncation", func(t *testing.T) {
		client := &http.Client{Transport: &testhelp.StubTransport{
			Fn: func(r *http.Request) (*http.Response, error) {
				return testhelp.ProbeResponse(200, "metric 12\n"), nil
			}}}
		// "metric 12\n" is 10 bytes > cap 5 — a silent cap would
		// return "metri" as if it were the whole body; the +1 probe
		// byte proves truncation and the fetch must error instead.
		if _, err := FetchPodMetrics(ctx, client, "10.1.2.3", 9180,
			time.Second, 5); err == nil {
			t.Fatal("truncated body must error, not return a partial parse")
		}
	})
	t.Run("body exactly at maxBytes is legal", func(t *testing.T) {
		client := &http.Client{Transport: &testhelp.StubTransport{
			Fn: func(r *http.Request) (*http.Response, error) {
				return testhelp.ProbeResponse(200, "12345"), nil
			}}}
		body, err := FetchPodMetrics(ctx, client, "10.1.2.3", 9180,
			time.Second, 5)
		if err != nil || string(body) != "12345" {
			t.Fatalf("FetchPodMetrics = (%q,%v), want exact-cap body", body, err)
		}
	})
	t.Run("zero timeout uses parent ctx and non-positive maxBytes fails fast", func(t *testing.T) {
		client := &http.Client{Transport: &testhelp.StubTransport{
			Fn: func(r *http.Request) (*http.Response, error) {
				return testhelp.ProbeResponse(200, "m 1\n"), nil
			}}}
		body, err := FetchPodMetrics(ctx, client, "10.1.2.3", 9180, 0, 128)
		if err != nil || string(body) != "m 1\n" {
			t.Fatalf("FetchPodMetrics(timeout=0) = (%q,%v), want (m 1\\n,nil)", body, err)
		}
		if _, err := FetchPodMetrics(ctx, client, "10.1.2.3", 9180, time.Second, 0); err == nil {
			t.Fatal("want error for non-positive maxBytes")
		}
	})
}

// Prometheus text exposition can spell the sample value NaN, +Inf or
// -Inf; strconv.ParseFloat accepts all three but they are not
// samples — stale/absent series emit them and every consuming check
// must read them as "no data" (ok=false), never as a live reading.
func TestParseMetricValueRejectsNaNInf(t *testing.T) {
	for _, line := range []string{
		"ha_connections NaN",
		"ha_connections +Inf",
		"ha_connections -Inf",
		"ha_connections Inf",
		"ha_connections inf",
		"ha_connections -inf",
	} {
		if v, ok := ParseMetricValue(line, "ha_connections"); ok || v != 0 {
			t.Fatalf("%q parsed as (%v,%v), want (0,false)", line, v, ok)
		}
	}
	// Finite values still parse — the rejection is exact, not a
	// widening of the failure posture.
	if v, ok := ParseMetricValue("ha_connections 12.5", "ha_connections"); !ok || v != 12.5 {
		t.Fatalf("finite value rejected: (%v,%v)", v, ok)
	}
}

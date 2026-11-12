// promq_test.go — coverage for the Prometheus instant-query seam:
// endpoint resolution from the HTTP-probe fallback URL, the vector
// decode (malformed samples skipped, never fatal), and the Timeout /
// DefaultClient knobs on Client.
package promq

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Sample.Label — first non-empty label among the candidate keys.
// ---------------------------------------------------------------------------

func TestSampleLabel(t *testing.T) {
	cases := []struct {
		name   string
		metric map[string]string
		keys   []string
		want   string
	}{
		{"first key wins", map[string]string{"a": "1", "b": "2"}, []string{"a", "b"}, "1"},
		{"empty value skipped", map[string]string{"a": "", "b": "2"}, []string{"a", "b"}, "2"},
		{"missing key skipped", map[string]string{"b": "2"}, []string{"a", "b"}, "2"},
		{"all empty or missing", map[string]string{"a": ""}, []string{"a", "z"}, ""},
		{"nil metric", nil, []string{"a"}, ""},
		{"no keys", map[string]string{"a": "1"}, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := (Sample{Metric: c.metric}).Label(c.keys...); got != c.want {
				t.Fatalf("Label(%v) = %q, want %q", c.keys, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ResolveEndpoint — override wins verbatim; else scheme://host +
// /api/v1/query is carved out of the health-probe URL.
// ---------------------------------------------------------------------------

func TestResolveEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		override string
		fallback string
		want     string
		wantErr  bool
	}{
		{
			name:     "override wins",
			override: "http://thanos:9090/api/v1/query",
			fallback: "http://prom:9090/metrics",
			want:     "http://thanos:9090/api/v1/query",
		},
		{
			name:     "override returned verbatim",
			override: "whatever the operator typed",
			fallback: "http://prom:9090/metrics",
			want:     "whatever the operator typed",
		},
		{
			name:     "derived from fallback scheme and host",
			fallback: "https://prometheus.monitoring.svc:8443/metrics?x=1",
			want:     "https://prometheus.monitoring.svc:8443/api/v1/query",
		},
		{
			name:     "fallback with no path",
			fallback: "http://10.0.0.9:9090",
			want:     "http://10.0.0.9:9090/api/v1/query",
		},
		{
			// VictoriaMetrics/Thanos behind a reverse-proxy subpath:
			// the mount prefix must survive into the query endpoint
			// or every PromQL call 404s at the proxy's bare root.
			name:     "proxy subpath mount preserved",
			fallback: "https://mon.example.com/prometheus/-/healthy",
			want:     "https://mon.example.com/prometheus/api/v1/query",
		},
		{
			name:     "nested proxy mount preserved",
			fallback: "https://mon.example.com/obs/vm/-/healthy?x=1",
			want:     "https://mon.example.com/obs/vm/api/v1/query",
		},
		{name: "both empty", wantErr: true},
		{name: "relative fallback", fallback: "/metrics", wantErr: true},
		{name: "hostless scheme", fallback: "prom:9090", wantErr: true},
		{name: "unparseable fallback", fallback: "http://prom\x7f:9090", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveEndpoint(c.override, c.fallback)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ResolveEndpoint(%q, %q) = %q, want error",
						c.override, c.fallback, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveEndpoint(%q, %q): %v", c.override, c.fallback, err)
			}
			if got != c.want {
				t.Fatalf("ResolveEndpoint(%q, %q) = %q, want %q",
					c.override, c.fallback, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// InstantQuery — the wire shape against an httptest server.
// ---------------------------------------------------------------------------

func TestInstantQuerySuccess(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// promq POSTs the query as a form body — ParseForm covers
		// both that and any GET caller.
		_ = r.ParseForm()
		gotQuery = r.FormValue("query")
		_, _ = w.Write([]byte(`{
			"status": "success",
			"data": {"resultType": "vector", "result": [
				{"metric": {"node": "n1", "__name__": "up"}, "value": [1710000000, "1"]},
				{"metric": {"node": "n2"}, "value": [1710000000, "42.5"]}
			]}
		}`))
	}))
	defer srv.Close()

	// The PromQL is full of URL-hostile bytes — it must survive the
	// ?query=… escape round-trip on the wire.
	const query = `max by (node) (rate(load15{job="node"}[5m]))`
	got, err := (&Client{HTTP: srv.Client()}).InstantQuery(
		context.Background(), srv.URL, query)
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != query {
		t.Fatalf("server saw query = %q, want %q", gotQuery, query)
	}
	if len(got) != 2 {
		t.Fatalf("samples = %+v, want 2", got)
	}
	if got[0].Metric["node"] != "n1" || got[0].Value != 1 {
		t.Fatalf("sample[0] = %+v, want node=n1 value=1", got[0])
	}
	if got[1].Label("node") != "n2" || got[1].Value != 42.5 {
		t.Fatalf("sample[1] = %+v, want node=n2 value=42.5", got[1])
	}
}

func TestInstantQueryErrors(t *testing.T) {
	cases := []struct {
		name    string
		code    int
		body    string
		wantErr string
	}{
		{"non-200", http.StatusBadGateway, "boom", "status 502"},
		{"error envelope", http.StatusOK,
			`{"status":"error","errorType":"bad_data","error":"parse error"}`,
			"status=error"},
		{"missing status", http.StatusOK, `{"data":{"result":[]}}`, "status="},
		{"malformed JSON", http.StatusOK, "not json{", "decode prometheus response"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.code)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			_, err := (&Client{HTTP: srv.Client()}).InstantQuery(
				context.Background(), srv.URL, "up")
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, c.wantErr)
			}
		})
	}
}

// A sample is dropped, never fatal, when its value pair is missing,
// non-string, or a non-float string.
func TestInstantQuerySkipsMalformedSamples(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"status": "success",
			"data": {"result": [
				{"metric": {"node": "ok"}, "value": [1710000000, "3.5"]},
				{"metric": {"node": "short"}, "value": [1710000000]},
				{"metric": {"node": "number"}, "value": [1710000000, 7]},
				{"metric": {"node": "notfloat"}, "value": [1710000000, "abc"]},
				{"metric": {"node": "novalue"}}
			]}
		}`))
	}))
	defer srv.Close()

	got, err := (&Client{HTTP: srv.Client()}).InstantQuery(
		context.Background(), srv.URL, "up")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Metric["node"] != "ok" || got[0].Value != 3.5 {
		t.Fatalf("samples = %+v, want only node=ok value=3.5", got)
	}
}

// Timeout bounds the query below the caller ctx: the handler only
// replies after the request dies, so a 5ms budget must error fast.
func TestInstantQueryTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()

	_, err := (&Client{HTTP: srv.Client(), Timeout: 5 * time.Millisecond}).InstantQuery(
		context.Background(), srv.URL, "up")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

// HTTP nil must fall back to http.DefaultClient — the default still
// reaches a localhost test server.
func TestInstantQueryNilHTTPUsesDefaultClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[]}}`))
	}))
	defer srv.Close()

	got, err := (&Client{HTTP: nil}).InstantQuery(context.Background(), srv.URL, "up")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("samples = %+v, want empty", got)
	}
}

// A response larger than the 4 MiB cap must error, never decode a
// silently truncated vector.
func TestInstantQueryTruncationDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 4 MiB + a byte of valid-looking payload: the old
		// LimitReader would have swallowed the tail silently.
		_, _ = w.Write(make([]byte, maxResponseBytes+1))
	}))
	defer srv.Close()

	_, err := (&Client{HTTP: srv.Client()}).InstantQuery(
		context.Background(), srv.URL, "up")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want a truncation error", err)
	}
}

// NaN/Inf sample values are skipped like any other malformed sample:
// ParseFloat accepts them but they poison every downstream
// threshold comparison.
func TestInstantQuerySkipsNonFiniteSamples(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"status": "success",
			"data": {"result": [
				{"metric": {"node": "ok"}, "value": [1710000000, "1.5"]},
				{"metric": {"node": "nan"}, "value": [1710000000, "NaN"]},
				{"metric": {"node": "pinf"}, "value": [1710000000, "+Inf"]},
				{"metric": {"node": "ninf"}, "value": [1710000000, "-Inf"]}
			]}
		}`))
	}))
	defer srv.Close()

	got, err := (&Client{HTTP: srv.Client()}).InstantQuery(
		context.Background(), srv.URL, "up")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Metric["node"] != "ok" || got[0].Value != 1.5 {
		t.Fatalf("samples = %+v, want only node=ok value=1.5", got)
	}
}

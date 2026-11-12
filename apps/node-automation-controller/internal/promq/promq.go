// Package promq is the Prometheus instant-query seam: one small
// client for `GET /api/v1/query?query=...` plus the sample decoding
// every metrics-backed check needs. Extracted from
// clusterhealthprobes' promInstantQuery so any module can read a
// Prometheus vector without re-implementing the wire shape.
package promq

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// maxResponseBytes caps one instant-query response. A vector larger
// than this is a runaway query, not data — and silently truncating
// it would decode a CORRUPT vector (the tail sample cut mid-JSON
// fails decode, but a cut landing exactly on a boundary would parse
// as a complete, wrong answer). Read limit+1 bytes and fail loudly
// instead.
const maxResponseBytes = 4 << 20

// drainOnClose is the leftover-body drain bound: reading the
// remaining bytes before Close lets Go's HTTP transport reuse the
// connection (keep-alive) — without the drain every query forces a
// fresh TCP/TLS handshake to the Prometheus endpoint.
const drainOnClose = 64 << 10

// Sample is one instant-vector result element: the series labels plus
// the scalar value at the query timestamp.
type Sample struct {
	Metric map[string]string
	Value  float64
}

// Label returns the first non-empty label value among keys — covers
// the "label renamed across metric versions" reads.
func (s Sample) Label(keys ...string) string {
	for _, k := range keys {
		if v := s.Metric[k]; v != "" {
			return v
		}
	}
	return ""
}

// Client issues instant queries. HTTP defaults to
// http.DefaultClient; Timeout bounds each query below the caller's
// ctx (0 = no extra deadline).
type Client struct {
	HTTP    *http.Client
	Timeout time.Duration
}

// ResolveEndpoint returns the /api/v1/query URL to query: override
// wins when non-empty, else the endpoint is derived from fallbackURL.
// An error means neither source produced a usable endpoint.
//
// The fallback URL is a HEALTH endpoint (…/-/healthy, …/metrics),
// not the API root — but when Prometheus/VictoriaMetrics/Thanos sits
// behind a reverse-proxy SUBPATH mount (https://host/prometheus/-/healthy)
// the mount prefix must survive into the derived endpoint or every
// query 404s at the proxy's bare root. path.Dir drops exactly the
// last segment — the probe endpoint itself — and url.JoinPath (not
// string concatenation) rebuilds the API path under whatever mount
// prefix remains, so "/prometheus/-/healthy" derives
// "/prometheus/api/v1/query" while "/-/healthy" still derives the
// root "/api/v1/query".
func ResolveEndpoint(override, fallbackURL string) (string, error) {
	if override != "" {
		return override, nil
	}
	u, err := url.Parse(fallbackURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("cannot derive prometheus base from %q", fallbackURL)
	}
	mount := path.Dir(u.EscapedPath())
	// Prometheus-family health endpoints live under the reserved
	// "/-/" namespace (…/-/healthy, …/-/ready) — the "-" segment is
	// part of the endpoint, not the proxy mount, so drop it too.
	if mount == "/-" || strings.HasSuffix(mount, "/-") {
		mount = path.Dir(mount)
	}
	if mount == "." || mount == "/" {
		mount = ""
	}
	return url.JoinPath(u.Scheme+"://"+u.Host+mount, "api", "v1", "query")
}

// InstantQuery runs query against endpoint (a full /api/v1/query
// URL — see ResolveEndpoint) and returns the vector samples. A
// non-200 status or a status!="success" envelope is an error;
// unparseable sample values are skipped, never fatal.
func (c *Client) InstantQuery(ctx context.Context, endpoint, query string) ([]Sample, error) {
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	// POST + form body, not GET ?query=: real PromQL strings run
	// hundreds of bytes and some checks issue queries with label
	// matchers full of quotes/braces — the GET form rides the URL
	// into access logs, proxy request lines and any middlebox with a
	// URL-length cap. The query API accepts both; POST keeps the
	// payload out of every hop's logs.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint, strings.NewReader(url.Values{"query": {query}}.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build prometheus query: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus query: %w", err)
	}
	defer func() {
		// Drain before Close so the transport can reuse the
		// connection — an early return still leaves a bounded tail.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainOnClose))
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read prometheus response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("prometheus response exceeds %d MiB limit — "+
			"refusing to decode a truncated vector", maxResponseBytes>>20)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus query status %d: %.200s",
			resp.StatusCode, string(body))
	}
	var parsed struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode prometheus response: %w", err)
	}
	if parsed.Status != "success" {
		return nil, fmt.Errorf("prometheus query failed: status=%s error=%s",
			parsed.Status, parsed.Error)
	}
	var out []Sample
	for _, r := range parsed.Data.Result {
		if len(r.Value) < 2 {
			continue
		}
		var raw string
		if err := json.Unmarshal(r.Value[1], &raw); err != nil {
			continue
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		// ParseFloat happily accepts "NaN"/"+Inf"/"-Inf" — real
		// Prometheus values. A NaN poisons every downstream
		// comparison (v > threshold is false, v <= threshold is also
		// false), and an Inf reads as a permanent breach; skip them
		// like any other unparseable sample rather than feeding a
		// bogus verdict.
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out = append(out, Sample{Metric: r.Metric, Value: v})
	}
	return out, nil
}

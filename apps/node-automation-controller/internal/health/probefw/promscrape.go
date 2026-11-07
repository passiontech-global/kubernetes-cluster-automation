// promscrape.go — the pod /metrics scrape pair two checks share:
// FetchPodMetrics GETs http://<podIP>:<port>/metrics bounded by a
// ctx timeout and a body byte cap, and ParseMetricValue /
// ParseMetricValues read samples out of the prometheus text
// exposition. Reference shapes: the cloudflared check's
// :2000 ha_connections probe and the scylla compaction/schema
// guard's :9180 scrape — both treat any fetch failure as
// inconclusive (ok=false), never as healthy.
package probefw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FetchPodMetrics GETs the prometheus text exposition at
// http://ip:port/metrics through client, bounded by timeout and
// maxBytes. Every failure shape — unset client, empty IP, request
// build, transport error, non-200 status, truncated read — returns
// an error so the caller's "inconclusive" branch stays a single
// `if err != nil`; the checks that scrape pod metrics cannot tell a
// dead endpoint from a sick pod and must not read either as clean.
func FetchPodMetrics(ctx context.Context, client *http.Client,
	ip string, port int, timeout time.Duration, maxBytes int64) ([]byte, error) {

	if client == nil {
		return nil, errors.New("no http client for pod metrics fetch")
	}
	if ip == "" {
		return nil, errors.New("pod has no IP — metrics unreachable")
	}
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(lctx, http.MethodGet,
		fmt.Sprintf("http://%s:%d/metrics", ip, port), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Drain before Close (bounded): a body bigger than maxBytes
		// leaves the tail unread, which makes the connection
		// unreusable and silently kills keep-alive on client.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pod metrics endpoint returned %s", resp.Status)
	}
	return body, nil
}

// ParseMetricValue parses one prometheus text-format line —
// `name{labels} v` or `name v` — returning the sample value. A
// comment/blank line, a different metric name, or an unparseable
// value reads absent. A second field (exemplar/timestamp) is rare on
// the gauges these checks read — the first token only is taken.
func ParseMetricValue(line, name string) (float64, bool) {
	if line == "" || strings.HasPrefix(line, "#") {
		return 0, false
	}
	rest, ok := strings.CutPrefix(line, name)
	if !ok {
		return 0, false
	}
	var raw string
	switch {
	case strings.HasPrefix(rest, "{"):
		idx := strings.LastIndex(rest, "}")
		if idx < 0 {
			return 0, false
		}
		raw = strings.TrimSpace(rest[idx+1:])
	case strings.HasPrefix(rest, " "):
		raw = strings.TrimSpace(rest)
	default:
		return 0, false
	}
	raw, _, _ = strings.Cut(raw, " ")
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ParseMetricValues returns every sample value of name inside an
// exposition body — the whole-body variant of ParseMetricValue for
// multi-series metrics (scylla reports per-scheduling-group
// compaction and per-endpoint schema-version series on one page).
func ParseMetricValues(body, name string) []float64 {
	var out []float64
	for _, line := range strings.Split(body, "\n") {
		if v, ok := ParseMetricValue(line, name); ok {
			out = append(out, v)
		}
	}
	return out
}

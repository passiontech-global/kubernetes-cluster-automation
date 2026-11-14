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
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// StreamPodMetrics GETs http://ip:port/metrics through client and streams
// the response body directly to fn without buffering the full payload in
// memory, bounded by timeout and maxBytes. A body exceeding maxBytes
// returns an explicit truncation error.
func StreamPodMetrics(ctx context.Context, client *http.Client,
	ip string, port int, timeout time.Duration, maxBytes int64,
	fn func(io.Reader) error) error {

	if client == nil {
		return errors.New("no http client for pod metrics fetch")
	}
	if ip == "" {
		return errors.New("pod has no IP — metrics unreachable")
	}
	if maxBytes <= 0 {
		return errors.New("pod metrics maxBytes must be positive")
	}
	lctx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		lctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	// net.JoinHostPort, not fmt %s:%d — a bare IPv6 pod IP needs
	// brackets or the URL parses as host "::1" port garbage.
	req, err := http.NewRequestWithContext(lctx, http.MethodGet,
		"http://"+net.JoinHostPort(ip, strconv.Itoa(port))+"/metrics", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain before Close (bounded): a body bigger than maxBytes
		// leaves the tail unread, which makes the connection
		// unreusable and silently kills keep-alive on client.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pod metrics endpoint returned %s", resp.Status)
	}
	cr := &cappedReader{r: io.LimitReader(resp.Body, maxBytes+1), max: maxBytes}
	if err := fn(cr); err != nil {
		return err
	}
	if cr.n > maxBytes {
		return fmt.Errorf("pod metrics endpoint body exceeds %d bytes (truncated)", maxBytes)
	}
	return nil
}

type cappedReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, fmt.Errorf("pod metrics endpoint body exceeds %d bytes (truncated)", c.max)
	}
	return n, err
}

// FetchPodMetrics GETs the prometheus text exposition at
// http://ip:port/metrics through client, bounded by timeout and
// maxBytes. Every failure shape — unset client, empty IP, request
// build, transport error, non-200 status, truncated read — returns
// an error so the caller's "inconclusive" branch stays a single
// `if err != nil`; the checks that scrape pod metrics cannot tell a
// dead endpoint from a sick pod and must not read either as clean.
func FetchPodMetrics(ctx context.Context, client *http.Client,
	ip string, port int, timeout time.Duration, maxBytes int64) ([]byte, error) {

	var body []byte
	err := StreamPodMetrics(ctx, client, ip, port, timeout, maxBytes, func(r io.Reader) error {
		var rerr error
		body, rerr = io.ReadAll(r)
		return rerr
	})
	if err != nil {
		return nil, err
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
		idx, ok := findLabelsEnd(rest)
		if !ok {
			return 0, false
		}
		raw = strings.TrimSpace(rest[idx+1:])
	case strings.HasPrefix(rest, " "), strings.HasPrefix(rest, "\t"):
		raw = strings.TrimSpace(rest)
	default:
		return 0, false
	}
	if i := strings.IndexAny(raw, " \t"); i >= 0 {
		raw = raw[:i]
	}
	v, err := strconv.ParseFloat(raw, 64)
	// NaN and ±Inf parse cleanly but are not samples — Prometheus
	// emits them for stale/absent series and every consumer treats
	// them as "no data" (ok=false), never as a live reading.
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

// findLabelsEnd returns the byte index of the closing `}` for a `{...}`
// Prometheus label set, ignoring `}` inside double-quoted label values
// (with `\"` / `\\` escapes) and any trailing OpenMetrics exemplar `{...}`.
func findLabelsEnd(s string) (int, bool) {
	inQuote, escaped := false, false
	for i := 1; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && inQuote {
			escaped = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && c == '}' {
			return i, true
		}
	}
	return -1, false
}

// ParseMetricValues returns every sample value of name inside an
// exposition body — the whole-body variant of ParseMetricValue for
// multi-series metrics (scylla reports per-scheduling-group
// compaction and per-endpoint schema-version series on one page).
func ParseMetricValues(body, name string) []float64 {
	var out []float64
	for line := range strings.SplitSeq(body, "\n") {
		if v, ok := ParseMetricValue(line, name); ok {
			out = append(out, v)
		}
	}
	return out
}

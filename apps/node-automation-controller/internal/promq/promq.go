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
	"net/http"
	"net/url"
	"strconv"
	"time"
)

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
// wins when non-empty, else the endpoint is derived from fallbackURL's
// scheme://host (the same Prometheus the HTTP health probe targets).
// An error means neither source produced a usable endpoint.
func ResolveEndpoint(override, fallbackURL string) (string, error) {
	if override != "" {
		return override, nil
	}
	u, err := url.Parse(fallbackURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("cannot derive prometheus base from %q", fallbackURL)
	}
	return u.Scheme + "://" + u.Host + "/api/v1/query", nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		endpoint+"?query="+url.QueryEscape(query), nil)
	if err != nil {
		return nil, fmt.Errorf("build prometheus query: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus query: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read prometheus response: %w", err)
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
		out = append(out, Sample{Metric: r.Metric, Value: v})
	}
	return out, nil
}

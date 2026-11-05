// http.go — the TCP+HTTP probes behind the subsystem seams. All of
// them wrap ctx in the per-probe timeout and drain the response body
// so the shared transport can reuse the connection on the next cycle.
package probee

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTP2xx GETs url and reports whether the answer is a 2xx — the
// KCM/scheduler healthz contract (500 = component wedged, any other
// failure = unreachable). Insecure TLS: those endpoints serve
// self-signed certs with no loopback SANs.
//
// Mirrors controllerhygiene.probeHTTP2xx (cp_freeze_heal.go).
func HTTP2xx(ctx context.Context, url string, timeout time.Duration) bool {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := insecureClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// HTTPAnyCode GETs url and reports whether ANY HTTP answer came back
// — the liveness probe for checks that only care whether the event
// loop is alive (`curl -ks --max-time 5 -o /dev/null -w '%{http_code}'
// != 000` parity: a 401/403 is an auth denial, not a dead listener).
//
// Mirrors controllerhygiene.probeAnyCode (probes.go).
func HTTPAnyCode(ctx context.Context, url string, timeout time.Duration) bool {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := insecureClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return true
}

// HTTPGet GETs url and returns nil only on a 2xx — the error-shaped
// variant of HTTP2xx (BUG-H7: an HTTP response does not count as
// alive on its own; a wedged service answering 500/503 reads as
// DOWN). Insecure TLS, curl -ks parity.
//
// Mirrors workerhygiene's probeHTTP seam default and nethealth's
// probeHTTPGet — the latter used http.DefaultClient, which differs
// only on https targets (nebula stats is plaintext), so the shared
// insecure client is a superset with zero behavioral delta.
func HTTPGet(ctx context.Context, url string, timeout time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := insecureClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return nil
}

// HTTPStatus GETs url and returns the status code — the variant for
// endpoints where the CODE is the verdict (syncloop 500 vs healthz
// 200, envoy /ready 503) or where ANY answer proves liveness. A
// non-empty bearer attaches an Authorization header (kubelet :10250
// requires auth). Insecure TLS, curl -ks parity.
//
// Mirrors workerhygiene's probeHTTPStatus seam default.
func HTTPStatus(ctx context.Context, url, bearer string, timeout time.Duration) (int, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := insecureClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}

// HTTPBody GETs url and returns the body — the plain-TLS fetch for
// loopback admin endpoints (envoy :9901 stats). A non-200 is an
// error: the caller's verdict is unreadable, not "zero". 4MiB cap.
//
// Mirrors workerhygiene's httpGetBody seam default.
func HTTPBody(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := plainClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// HTTPBodyInsecure GETs url and returns the body — the insecure-TLS
// fetch for self-signed metrics endpoints (KCM :10257 /metrics).
// Deliberately NO status check: the scrape's snapshot parse decides
// whether the body is usable; a 500 still returns what the server
// had. 4MiB cap.
//
// Mirrors controllerhygiene.httpGetInsecure (cp_freeze_heal.go) —
// returns a string because the original (and its kcmMetricsFn seam)
// is string-typed.
func HTTPBodyInsecure(ctx context.Context, url string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := insecureClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// BodyOK GETs url and reports whether the trimmed body is exactly
// "ok" — the kubelet :10248 healthz contract (curl -s body-compare
// parity: a wedged kubelet can still answer HTTP with a non-ok body,
// so any-HTTP-code-alive is not enough). The status code is
// deliberately not checked, matching the original.
//
// Mirrors workerhygiene's probeBodyOK seam default.
func BodyOK(ctx context.Context, url string, timeout time.Duration) bool {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := plainClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return strings.TrimSpace(string(body)) == "ok"
}

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

// httpGet is the shared scaffolding behind every exported probe —
// the NewRequestWithContext/Do/drain boilerplate all seven variants
// used to repeat: per-probe timeout on ctx, one GET (optional
// bearer), the given client's Do, and the body closed when the
// verdict returns. The verdict callback owns everything response-
// shaped — the drain cap, the status test, the body read — so each
// exported probe stays a visible verdict on one response instead of
// a copy of the transport dance. Errors propagate; bool probes fold
// them to false at the call site (as they always did).
func httpGet[V any](ctx context.Context, client *http.Client, url, bearer string,
	timeout time.Duration, verdict func(resp *http.Response) (V, error),
) (V, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		var zero V
		return zero, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		var zero V
		return zero, err
	}
	defer func() { _ = resp.Body.Close() }()
	return verdict(resp)
}

// drainBody discards up to limit bytes of the response body so the
// shared transport can reuse the connection on the next cycle.
func drainBody(resp *http.Response, limit int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
}

// probeBodyCap bounds every body a probe retains — metrics scrapes
// and admin endpoints never legitimately exceed it.
const probeBodyCap = 4 << 20

// readCapped reads the body up to maxBytes and reports a truncated
// capture as an error: LimitReader alone cannot tell "exactly
// maxBytes" from "cut off at maxBytes", and a partial metrics body
// or healthz payload must not parse as complete evidence. Reads
// maxBytes+1 to make the distinction.
func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("response body exceeds %d byte cap", maxBytes)
	}
	return b, nil
}

// clientOrDefault resolves a probe's optional injected client: the
// variadic trailing *http.Client every HTTP probe accepts, nil (or
// absent) meaning the probe's package default (insecureClient or
// plainClient). Callers that only need the default simply omit it.
func clientOrDefault(injected []*http.Client, def *http.Client) *http.Client {
	if len(injected) > 0 && injected[0] != nil {
		return injected[0]
	}
	return def
}

// HTTP2xx GETs url and reports whether the answer is a 2xx — the
// KCM/scheduler healthz contract (500 = component wedged, any other
// failure = unreachable). Insecure TLS: those endpoints serve
// self-signed certs with no loopback SANs.
//
// Mirrors controllerhygiene.probeHTTP2xx (cp_freeze_heal.go).
func HTTP2xx(ctx context.Context, url string, timeout time.Duration,
	client ...*http.Client) bool {
	ok, _ := httpGet(ctx, clientOrDefault(client, insecureClient), url, "", timeout,
		func(resp *http.Response) (bool, error) {
			drainBody(resp, 64<<10)
			return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
		})
	return ok
}

// HTTPAnyCode GETs url and reports whether ANY HTTP answer came back
// — the liveness probe for checks that only care whether the event
// loop is alive (`curl -ks --max-time 5 -o /dev/null -w '%{http_code}'
// != 000` parity: a 401/403 is an auth denial, not a dead listener).
//
// Mirrors controllerhygiene.probeAnyCode (probes.go).
func HTTPAnyCode(ctx context.Context, url string, timeout time.Duration,
	client ...*http.Client) bool {
	ok, _ := httpGet(ctx, clientOrDefault(client, insecureClient), url, "", timeout,
		func(resp *http.Response) (bool, error) {
			drainBody(resp, 64<<10)
			return true, nil
		})
	return ok
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
func HTTPGet(ctx context.Context, url string, timeout time.Duration,
	client ...*http.Client) error {
	_, err := httpGet(ctx, clientOrDefault(client, insecureClient), url, "", timeout,
		func(resp *http.Response) (struct{}, error) {
			drainBody(resp, 1<<20)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return struct{}{}, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
			}
			return struct{}{}, nil
		})
	return err
}

// HTTPStatus GETs url and returns the status code — the variant for
// endpoints where the CODE is the verdict (syncloop 500 vs healthz
// 200, envoy /ready 503) or where ANY answer proves liveness. A
// non-empty bearer attaches an Authorization header (kubelet :10250
// requires auth). Insecure TLS, curl -ks parity.
//
// Mirrors workerhygiene's probeHTTPStatus seam default.
func HTTPStatus(ctx context.Context, url, bearer string, timeout time.Duration,
	client ...*http.Client) (int, error) {
	return httpGet(ctx, clientOrDefault(client, insecureClient), url, bearer, timeout,
		func(resp *http.Response) (int, error) {
			drainBody(resp, 1<<20)
			return resp.StatusCode, nil
		})
}

// HTTPBody GETs url and returns the body — the plain-TLS fetch for
// loopback admin endpoints (envoy :9901 stats). A non-200 is an
// error: the caller's verdict is unreadable, not "zero". 4MiB cap.
//
// Mirrors workerhygiene's httpGetBody seam default.
func HTTPBody(ctx context.Context, url string, timeout time.Duration,
	client ...*http.Client) ([]byte, error) {
	return httpGet(ctx, clientOrDefault(client, plainClient), url, "", timeout,
		func(resp *http.Response) ([]byte, error) {
			if resp.StatusCode != http.StatusOK {
				drainBody(resp, 64<<10)
				return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
			}
			return readCapped(resp.Body, probeBodyCap)
		})
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
func HTTPBodyInsecure(ctx context.Context, url string, timeout time.Duration,
	client ...*http.Client) (string, error) {
	return httpGet(ctx, clientOrDefault(client, insecureClient), url, "", timeout,
		func(resp *http.Response) (string, error) {
			b, err := readCapped(resp.Body, probeBodyCap)
			if err != nil {
				return "", err
			}
			return string(b), nil
		})
}

// BodyOK GETs url and reports whether the trimmed body is exactly
// "ok" — the kubelet :10248 healthz contract (curl -s body-compare
// parity: a wedged kubelet can still answer HTTP with a non-ok body,
// so any-HTTP-code-alive is not enough). The status code is
// deliberately not checked, matching the original.
//
// Mirrors workerhygiene's probeBodyOK seam default.
func BodyOK(ctx context.Context, url string, timeout time.Duration,
	client ...*http.Client) bool {
	ok, _ := httpGet(ctx, clientOrDefault(client, plainClient), url, "", timeout,
		func(resp *http.Response) (bool, error) {
			body, err := readCapped(resp.Body, 1<<20)
			if err != nil {
				return false, err
			}
			return strings.TrimSpace(string(body)) == "ok", nil
		})
	return ok
}

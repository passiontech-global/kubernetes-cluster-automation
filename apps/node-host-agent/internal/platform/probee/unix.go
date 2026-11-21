// unix.go — the unix-socket probes behind the subsystem seams:
// UnixGet (HTTP GET over a unix socket, the cilium-agent API),
// UnixDelete (HTTP DELETE over a unix socket, Cilium zombie endpoint
// reap), and UnixDial (connect+close, the containerd-socket hang probe).
package probee

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// UnixGet GETs path over the unix socket and returns the body — the
// cilium-agent API contract (a non-200 means the endpoint verdict is
// unreadable, not "zero"). The transport is built per call with
// DisableKeepAlives on purpose: a kept-alive unix conn would pin the
// transport readLoop/writeLoop goroutines for IdleConnTimeout, and
// with keep-alives off the conn closes on Body.Close. 4MiB cap.
//
// Mirrors workerhygiene's unixGet seam default.
func UnixGet(ctx context.Context, socket, path string) ([]byte, error) {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(dctx, "unix", socket)
		},
	}
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://localhost"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	// 4 MiB hard cap: LimitReader alone would silently hand back a
	// truncated body — a half-parsed service map reads as "zero
	// backends". Read one byte past the cap and fail on overflow.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if len(body) > 4<<20 {
		return nil, fmt.Errorf("GET %s: body exceeds 4MiB cap", path)
	}
	return body, nil
}

// UnixDelete sends HTTP DELETE for path over the unix socket (e.g.
// Cilium's DELETE /v1/endpoint/{id}). Mirrors UnixGet's per-call
// DisableKeepAlives transport and timeouts so unix connections never
// linger in idle pools.
//
// Cilium's DELETE /v1/endpoint/{id} returns:
//   - 200 OK / 204 No Content: endpoint deleted cleanly.
//   - 206 Partial Content: endpoint deleted from agent/IPAM with minor
//     teardown errors (expected for zombie endpoints whose host netdev
//     is already gone).
//   - 404 Not Found: endpoint already gone (idempotent delete).
//
// All four statuses return nil; any other status fails closed with an
// error.
func UnixDelete(ctx context.Context, socket, path string) error {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(dctx, "unix", socket)
		},
	}
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		"http://localhost"+path, nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusPartialContent, http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("DELETE %s: status %d", path, resp.StatusCode)
	}
}

// UnixDial connects to the unix socket under the deadline — a
// successful dial IS the verdict (the containerd-socket hang probe:
// a wedged listener stops accepting). A close error, e.g. the peer
// reset first, must not downgrade the success.
//
// Mirrors workerhygiene's probeUnixSock seam default.
func UnixDial(ctx context.Context, socket string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

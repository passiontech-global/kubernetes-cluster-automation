// unix.go — the unix-socket probes behind the subsystem seams:
// UnixGet (HTTP over a unix socket, the cilium-agent API) and
// UnixDial (connect+close, the containerd-socket hang probe).
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return body, err
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

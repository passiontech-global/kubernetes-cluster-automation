// unix.go — the unix-socket probes behind the subsystem seams:
// UnixGet (HTTP GET over a unix socket, the cilium-agent API),
// UnixDelete (HTTP DELETE over a unix socket, Cilium zombie endpoint
// reap), and UnixDial (connect+close, the containerd-socket hang probe).
package probee

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx"
)

const maxUnixClients = 64

var (
	unixClientsMu sync.Mutex
	unixClients   = map[string]*http.Client{}
)

// unixClient returns a pooled keep-alive *http.Client bound exclusively to
// filepath.Clean(socket) so repeated UnixGet/UnixDelete probes to the same
// socket reuse persistent connections while distinct sockets stay isolated.
func unixClient(socket string) *http.Client {
	key := filepath.Clean(socket)
	unixClientsMu.Lock()
	defer unixClientsMu.Unlock()
	if cl, ok := unixClients[key]; ok {
		return cl
	}
	if len(unixClients) >= maxUnixClients {
		for k, old := range unixClients {
			old.CloseIdleConnections()
			delete(unixClients, k)
			break
		}
	}
	tr := &http.Transport{
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(dctx, "unix", key)
		},
	}
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	unixClients[key] = cl
	return cl
}

// UnixGet GETs path over the unix socket and returns the body — the
// cilium-agent API contract (a non-200 means the endpoint verdict is
// unreadable, not "zero"). Uses a socket-keyed pooled keep-alive
// transport (90s IdleConnTimeout) so repeated per-cycle probes reuse
// one connection. 4MiB cap.
//
// Mirrors workerhygiene's unixGet seam default.
func UnixGet(ctx context.Context, socket, path string) ([]byte, error) {
	cl := unixClient(socket)
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
		httpx.DrainAndClose(resp.Body, 64<<10)
		return nil, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	// 4 MiB hard cap: ReadBounded reads one byte past the cap to distinguish
	// an exact-cap body from overflow (a half-parsed service map reads as
	// "zero backends").
	body, truncated, err := httpx.ReadBounded(resp.Body, 4<<20)
	httpx.DrainAndClose(resp.Body, 64<<10)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("GET %s: body exceeds 4MiB cap", path)
	}
	return body, nil
}

// UnixDelete sends HTTP DELETE for path over the unix socket (e.g.
// Cilium's DELETE /v1/endpoint/{id}), sharing UnixGet's socket-keyed
// pooled keep-alive transport.
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
	cl := unixClient(socket)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		"http://localhost"+path, nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	httpx.DrainAndClose(resp.Body, 64<<10)
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

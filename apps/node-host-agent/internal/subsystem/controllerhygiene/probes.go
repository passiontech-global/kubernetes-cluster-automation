// probes.go — the network liveness probes behind the Config seams:
// the shared insecure probeClient (probeAnyCode, and the CP-freeze
// probeHTTP2xx/httpGetInsecure in cp_freeze_heal.go) plus the pg-wire
// StartupMessage check behind pgWireFn (lib.sh pg_wire_ok).
package controllerhygiene

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// pgWireOK is the native-Go port of lib.sh pg_wire_ok: send a
// Postgres StartupMessage (user=postgres db=postgres, protocol 3.0)
// and check the first response byte — 'R' auth request / 'S' param
// status / 'N' notice / 'K' backend key = healthy; 'E' error, RST or
// timeout = broken (pgbouncer "server login has been failing").
// The dial is container-side on purpose: the pod is hostNetwork, so
// the DB host:port is reached exactly as the host would reach it.
func pgWireOK(ctx context.Context, hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "5432"
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	params := "user\x00postgres\x00database\x00postgres\x00\x00"
	msg := append([]byte{0, 3, 0, 0}, params...) // 196608 big-endian
	pkt := make([]byte, 4, 4+len(msg))
	binary.BigEndian.PutUint32(pkt, uint32(len(msg)+4)) // length incl. itself
	pkt = append(pkt, msg...)
	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return false
	}
	return strings.IndexByte(pgAuthOK, b[0]) >= 0
}

// probeClient is shared by every probeAnyCode call — a fresh
// Transport per probe would pin an idle connection (and its TLS
// buffers) on the apiserver between cycles. IdleConnTimeout bounds
// that pool (90s > the 60s cycle, so the conn is reused each probe).
var probeClient = func() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // mirrors curl -ks
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: tr}
}()

// probeAnyCode is the default liveness probe: ANY HTTP response code
// means ALIVE — the shell targets a process-level wedge (event loop
// dead, no TLS accept), not readyz content. `curl -ks --max-time 5
// -o /dev/null -w '%{http_code}' != 000` parity.
func probeAnyCode(ctx context.Context, url string, timeout time.Duration) bool {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return true
}

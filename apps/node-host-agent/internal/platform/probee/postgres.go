// postgres.go — the Postgres wire-protocol liveness probe: a
// StartupMessage handshake whose first response byte proves the
// server (or pgbouncer frontend) actually speaks the protocol —
// the check that catches "port open, auth/backend dead" states a
// TCP connect cannot see.
package probee

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"
)

// pgAuthOK is the first-response-byte healthy set: 'R' auth request
// / 'S' param status / 'N' notice / 'K' backend key.
const pgAuthOK = "RSNK"

// PGStartupMessage builds the Postgres protocol-3.0 StartupMessage.
func PGStartupMessage(user, db string) []byte {
	params := "user\x00" + user + "\x00database\x00" + db + "\x00\x00"
	msg := append([]byte{0, 3, 0, 0}, params...) // 196608 big-endian
	pkt := make([]byte, 4, 4+len(msg))
	binary.BigEndian.PutUint32(pkt, uint32(len(msg)+4)) // length incl. itself
	return append(pkt, msg...)
}

// PGFirstByteOK classifies the first server response byte: 'R' auth
// request / 'S' param status / 'N' notice / 'K' backend key = healthy;
// 'E' (ErrorResponse, e.g. server_login_retry), RST or timeout = broken.
func PGFirstByteOK(b byte) bool {
	return strings.IndexByte(pgAuthOK, b) >= 0
}

// PGWireProbe is the native-Go port of lib.sh pg_wire_ok: send a
// Postgres StartupMessage (user=postgres db=postgres, protocol 3.0)
// and check the first response byte — 'R' auth request / 'S' param
// status / 'N' notice / 'K' backend key = healthy; 'E' error, RST or
// timeout = broken (pgbouncer "server login has been failing").
// The 8s dial+deadline budget matches the shell `timeout 8` parity.
func PGWireProbe(ctx context.Context, hostport string) bool {
	return PGWireProbeWithTimeout(ctx, hostport, 8*time.Second)
}

// PGWireProbeWithTimeout is PGWireProbe with an explicit dial+IO timeout.
func PGWireProbeWithTimeout(ctx context.Context, hostport string, timeout time.Duration) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "5432"
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(PGStartupMessage("postgres", "postgres")); err != nil {
		return false
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return false
	}
	return PGFirstByteOK(b[0])
}

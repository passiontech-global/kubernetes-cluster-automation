// Package sdnotify is the shared sd_notify unixgram sender — the
// `systemd-notify` wire format in pure Go: one datagram per message
// to the address NOTIFY_SOCKET carries.
//
// Two senders used to keep private copies of the same '@'-
// translation + bounded write — internal/agent's sd-watchdog self-
// watchdog feed (one conn, READY=1 then WATCHDOG=1 on a cadence) and
// controllerhygiene's apiserver watchdog feeder (re-dial per
// message) — and the mechanism was duplicated verbatim. The
// primitives here are that common mechanism: Dial owns the
// '@'-prefixed abstract-socket name translation, Send owns the
// per-write deadline, SendOnce is dial+send+close for the one-shot
// caller. Semantics are copied verbatim from the originals so both
// call sites swap in with zero behavioral delta.
//
// NOTIFY_SOCKET itself is a systemd contract, not a
// NODE_HOST_AGENT_* knob — the callers read and pass it; this
// package only speaks the wire format.
package sdnotify

import (
	"net"
	"strings"
	"time"
)

// SocketEnv is the env var name systemd uses to publish the notify
// socket address — a systemd contract, not a NODE_HOST_AGENT_* knob
// (which is why it is a plain const here rather than an envnames
// entry). Callers read os.Getenv(SocketEnv) and pass the address to
// Dial/SendOnce.
const SocketEnv = "NOTIFY_SOCKET"

// sendDeadline bounds each datagram write — datagram writes are
// near-instant, so the deadline only covers a pathological socket
// state (a full receive queue behind a hung reader). A wedged
// notify socket must never hang the caller's feed loop: systemd
// watchdogs exist to kill wedged processes, and a feeder that
// itself hangs on the notify write defeats the watchdog's purpose.
const sendDeadline = 5 * time.Second

// Dial opens the unixgram notify socket at sock. '@'-prefixed names
// are systemd's abstract-socket convention — the leading '@' is
// replaced by a NUL byte so "@org/freedesktop/notify" dials the
// abstract namespace instead of a literal '@' filesystem path.
func Dial(sock string) (*net.UnixConn, error) {
	addr := sock
	if strings.HasPrefix(addr, "@") {
		addr = "\x00" + addr[1:]
	}
	return net.DialUnix("unixgram", nil,
		&net.UnixAddr{Name: addr, Net: "unixgram"})
}

// Send writes msg as one datagram on conn under sendDeadline — the
// caller owns the conn and decides whether a send error is fatal
// (agent logs and keeps looping; the feeder treats it as a probe
// failure).
func Send(conn *net.UnixConn, msg string) error {
	_ = conn.SetDeadline(time.Now().Add(sendDeadline))
	_, err := conn.Write([]byte(msg))
	return err
}

// SendOnce dials sock, sends msg, closes — for one-shot senders
// (controllerhygiene's feeder) that re-dial per message rather than
// holding a conn open across an interval cadence.
func SendOnce(sock, msg string) error {
	conn, err := Dial(sock)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return Send(conn, msg)
}
